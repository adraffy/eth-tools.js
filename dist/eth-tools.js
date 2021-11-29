// TODO: figure out why Int32Array/Uint32Array is slow

// primary api
function keccak(bits = 256) { return new Fixed(bits,        0b1); } // [1]0*1
function sha3(bits = 256)   { return new Fixed(bits,      0b110); } // [011]0*1
function shake(bits)        { return new Extended(bits, 0b11111); } // [11111]0*1

// returns Uint8Array from string
// accepts only string
function bytes_from_str(s) {
	if (typeof s !== 'string') throw TypeError('expected string');
	s = unescape(encodeURIComponent(s)); // explode utf16
	let {length} = s;
	let v = new Uint8Array(length);
	for (let i = 0; i < length; i++) {
		v[i] = s.charCodeAt(i);
	}
	return v;
}

// accepts hex-string, 0x-prefix is optional
// returns Uint8Array
function bytes_from_hex(s) {
	if (typeof s !== 'string') throw TypeError('expected string');
	let pos = 0;
	if (s.startsWith('0x')) pos += 2; // skip prefix
	if (s.length & 1) s = `0${s}`; // zero-pad odd length
	let len = (s.length - pos) >> 1;
	let v = new Uint8Array(len);
	for (let i = 0; i < len; i++) {
		let b = parseInt(s.slice(pos, pos += 2), 16);
		if (Number.isNaN(b)) throw new TypeError('expected hex byte');
		v[i] = b;
	}
	return v;
}

// returns hex from Uint8Array
// no 0x-prefix
function hex_from_bytes(v) {
	return [...v].map(x => x.toString(16).padStart(2, '0')).join('');
}

// returns str from Uint8Array
function str_from_bytes(v) {
	/*
	let cps = [];
	let pos = 0;
	let cp = 0;
	let need = 0;
	while (pos < v.length) {
		let b0 = v[pos++];
		if (need > 0) {
			if ((b0 >> 6) != 2) throw new Error('malformed utf8: expected continuation')
			cp = (cp << 6) | (b0 & 0b111111);
			if (--need == 0) cps.push(cp);
			continue;
		}
		if (b0 < 0b01111111) {
			cps.push(b0);
		} else if (b0 < 0b11011111) {
			cp = b0 & 0b11111;
			need = 1;
		} else if (b0 < 0b11101111) {
			cp = b0 & 0b1111;
			need = 2;
		} else {
			cp = b0 & 0b111;
			need = 3;
		}
	}
	if (need > 0) throw new RangeError('malformed utf8: expected more bytes');
	return String.fromCodePoint(...ret);
	*/
	try {
		return decodeURIComponent(escape(String.fromCharCode(...v)));
	} catch (err) {
		throw new Error('malformed utf8');
	}
}

class KeccakHasher {
	constructor(capacity_bits, suffix) {
		const C = 1600;
		if (capacity_bits & 0x1F) throw new Error('capacity % 32 != 0');
		if (capacity_bits < 0 || capacity_bits >= C) throw new Error(`capacity must be [0,${C})`);
		this.sponge = Array(50).fill(0); 
		//this.sponge = new Int32Array(50); //RC.length + 2); 
		this.block_count = (C - capacity_bits) >> 5;
		this.block_index = 0; // current block index
		this.suffix = suffix; // padding byte
		this.ragged_block = 0; // ragged block bytes
		this.ragged_shift = 0; // ragged block width
	}
	// update the hasher
	// throws on bad input
	update(v) {
		if (!(v instanceof Uint8Array)) {
			if (v instanceof ArrayBuffer) { 
				v = new Uint8Array(v);
			} else if (Array.isArray(v)) { 
				v = Uint8Array.from(v);
			} else if (typeof v === 'string') {
				v = bytes_from_str(v);
			} else {
				throw new TypeError('expected bytes');
			}
		}
		let off = 0;
		let len = v.length;
		if (this.ragged_shift > 0) { // make aligned
			off = this._add_ragged(v, 0);
			if (off == len) return this; // chainable
		}
		let {sponge, block_index, block_count} = this;
		for (; off + 4 <= len; off += 4) {
			sponge[block_index++] ^= v[off] | (v[off+1] << 8) | (v[off+2] << 16) | (v[off+3] << 24);
			if (block_index == block_count) {
				permute32(sponge);
				block_index = 0;
			}
		}
		this.block_index = block_index;
		if (off < len) this._add_ragged(v, off); // store remainder [1-3 bytes]
		return this; // chainable
	}
	// adds [0,4]-bytes, returns quantity
	_add_ragged(v, off) {
		let {ragged_shift, ragged_block} = this;
		let added = 0;
		for (; off < v.length && ragged_shift < 32; added++, off++, ragged_shift += 8) {
			ragged_block |= v[off] << ragged_shift;
		}
		if (ragged_shift == 32) {
			this._add_block(ragged_block);
			ragged_shift = 0;
			ragged_block = 0;
		} 
		this.ragged_block = ragged_block;
		this.ragged_shift = ragged_shift;
		return added; 
	}
	// digest a little-endian 32-bit word
	// warning: unsafe if ragged_shift > 0
	_add_block(x) {
		let {sponge, block_index, block_count} = this;
		sponge[block_index++] ^= x;
		if (block_index == block_count) {
			permute32(sponge);
			block_index = 0;
		}
		this.block_index = block_index;
	}	
	// idempotent
	// called automatically by subclasses
	finalize() {
		let {sponge, suffix, ragged_shift, block_index, block_count} = this;
		if (ragged_shift) {
			if (ragged_shift == -1) return this; // already finalized, chainable
			suffix = this.ragged_block | (suffix << ragged_shift);
		}
		sponge[block_index] ^= suffix;
		sponge[block_count - 1] ^= 0x80000000;
		permute32(sponge);
		this.ragged_shift = -1; // mark as finalized
	}
}

class Extended extends KeccakHasher {
	constructor(bits, padding) {
		super(bits << 1, padding);
		this.size0 = bits >> 2; // default output size
		this.byte_offset = 0; // byte-offset of output
	}
	hex(size) { return hex_from_bytes(this.bytes(size)); }
	bytes(size) {
		this.finalize();
		if (!size) size = this.size0;
		let {sponge, byte_offset, block_count} = this;
		let trim = (byte_offset & 3);
		let blocks = (trim > 0) + ((size + 3) >> 2);
		let output = new Int32Array(blocks);
		let block_index = (byte_offset >> 2) % block_count;
		for (let i = 0; i < blocks; i++) {
			output[i] = sponge[block_index++];
			if (block_index == block_count) {
				permute32(sponge);
				block_index = 0;
			}
		}
		this.byte_offset = byte_offset + size;
		return new Uint8Array(output.buffer, trim, size);
	}
}

class Fixed extends KeccakHasher {
	constructor(bits, padding) {
		super(bits << 1, padding);
		this.size = bits >> 5;
	}
	get hex() { return hex_from_bytes(this.bytes); }
 	get bytes() {
		this.finalize();
		let {size, sponge: state} = this;
		let v = new Int32Array(size);
		for (let i = 0; i < size; i++) {
			v[i] = state[i];
		}		
		return new Uint8Array(v.buffer);
	}
}

// from tests/get_round_const.js
const RC = [1,0,32898,0,32906,-2147483648,-2147450880,-2147483648,32907,0,-2147483647,0,-2147450751,-2147483648,32777,-2147483648,138,0,136,0,-2147450871,0,-2147483638,0,-2147450741,0,139,-2147483648,32905,-2147483648,32771,-2147483648,32770,-2147483648,128,-2147483648,32778,0,-2147483638,-2147483648,-2147450751,-2147483648,32896,-2147483648,-2147483647,0,-2147450872,-2147483648];

// https://github.com/emn178/js-sha3/blob/master/src/sha3.js
function permute32(s) {
	for (let n = 0; n < 48; n += 2) {
		let c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
		let c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
		let c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
		let c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
		let c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
		let c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
		let c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
		let c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
		let c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
		let c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49];

		let h = c8 ^ ((c2 << 1) | (c3 >>> 31));
		let l = c9 ^ ((c3 << 1) | (c2 >>> 31));
		s[0] ^= h;
		s[1] ^= l;
		s[10] ^= h;
		s[11] ^= l;
		s[20] ^= h;
		s[21] ^= l;
		s[30] ^= h;
		s[31] ^= l;
		s[40] ^= h;
		s[41] ^= l;
		h = c0 ^ ((c4 << 1) | (c5 >>> 31));
		l = c1 ^ ((c5 << 1) | (c4 >>> 31));
		s[2] ^= h;
		s[3] ^= l;
		s[12] ^= h;
		s[13] ^= l;
		s[22] ^= h;
		s[23] ^= l;
		s[32] ^= h;
		s[33] ^= l;
		s[42] ^= h;
		s[43] ^= l;
		h = c2 ^ ((c6 << 1) | (c7 >>> 31));
		l = c3 ^ ((c7 << 1) | (c6 >>> 31));
		s[4] ^= h;
		s[5] ^= l;
		s[14] ^= h;
		s[15] ^= l;
		s[24] ^= h;
		s[25] ^= l;
		s[34] ^= h;
		s[35] ^= l;
		s[44] ^= h;
		s[45] ^= l;
		h = c4 ^ ((c8 << 1) | (c9 >>> 31));
		l = c5 ^ ((c9 << 1) | (c8 >>> 31));
		s[6] ^= h;
		s[7] ^= l;
		s[16] ^= h;
		s[17] ^= l;
		s[26] ^= h;
		s[27] ^= l;
		s[36] ^= h;
		s[37] ^= l;
		s[46] ^= h;
		s[47] ^= l;
		h = c6 ^ ((c0 << 1) | (c1 >>> 31));
		l = c7 ^ ((c1 << 1) | (c0 >>> 31));
		s[8] ^= h;
		s[9] ^= l;
		s[18] ^= h;
		s[19] ^= l;
		s[28] ^= h;
		s[29] ^= l;
		s[38] ^= h;
		s[39] ^= l;
		s[48] ^= h;
		s[49] ^= l;

		let b00 = s[0];
		let b01 = s[1];
		let b32 = (s[11] << 4) | (s[10] >>> 28);
		let b33 = (s[10] << 4) | (s[11] >>> 28);
		let b14 = (s[20] << 3) | (s[21] >>> 29);
		let b15 = (s[21] << 3) | (s[20] >>> 29);
		let b46 = (s[31] << 9) | (s[30] >>> 23);
		let b47 = (s[30] << 9) | (s[31] >>> 23);
		let b28 = (s[40] << 18) | (s[41] >>> 14);
		let b29 = (s[41] << 18) | (s[40] >>> 14);
		let b20 = (s[2] << 1) | (s[3] >>> 31);
		let b21 = (s[3] << 1) | (s[2] >>> 31);
		let b02 = (s[13] << 12) | (s[12] >>> 20);
		let b03 = (s[12] << 12) | (s[13] >>> 20);
		let b34 = (s[22] << 10) | (s[23] >>> 22);
		let b35 = (s[23] << 10) | (s[22] >>> 22);
		let b16 = (s[33] << 13) | (s[32] >>> 19);
		let b17 = (s[32] << 13) | (s[33] >>> 19);
		let b48 = (s[42] << 2) | (s[43] >>> 30);
		let b49 = (s[43] << 2) | (s[42] >>> 30);
		let b40 = (s[5] << 30) | (s[4] >>> 2);
		let b41 = (s[4] << 30) | (s[5] >>> 2);
		let b22 = (s[14] << 6) | (s[15] >>> 26);
		let b23 = (s[15] << 6) | (s[14] >>> 26);
		let b04 = (s[25] << 11) | (s[24] >>> 21);
		let b05 = (s[24] << 11) | (s[25] >>> 21);
		let b36 = (s[34] << 15) | (s[35] >>> 17);
		let b37 = (s[35] << 15) | (s[34] >>> 17);
		let b18 = (s[45] << 29) | (s[44] >>> 3);
		let b19 = (s[44] << 29) | (s[45] >>> 3);
		let b10 = (s[6] << 28) | (s[7] >>> 4);
		let b11 = (s[7] << 28) | (s[6] >>> 4);
		let b42 = (s[17] << 23) | (s[16] >>> 9);
		let b43 = (s[16] << 23) | (s[17] >>> 9);
		let b24 = (s[26] << 25) | (s[27] >>> 7);
		let b25 = (s[27] << 25) | (s[26] >>> 7);
		let b06 = (s[36] << 21) | (s[37] >>> 11);
		let b07 = (s[37] << 21) | (s[36] >>> 11);
		let b38 = (s[47] << 24) | (s[46] >>> 8);
		let b39 = (s[46] << 24) | (s[47] >>> 8);
		let b30 = (s[8] << 27) | (s[9] >>> 5);
		let b31 = (s[9] << 27) | (s[8] >>> 5);
		let b12 = (s[18] << 20) | (s[19] >>> 12);
		let b13 = (s[19] << 20) | (s[18] >>> 12);
		let b44 = (s[29] << 7) | (s[28] >>> 25);
		let b45 = (s[28] << 7) | (s[29] >>> 25);
		let b26 = (s[38] << 8) | (s[39] >>> 24);
		let b27 = (s[39] << 8) | (s[38] >>> 24);
		let b08 = (s[48] << 14) | (s[49] >>> 18);
		let b09 = (s[49] << 14) | (s[48] >>> 18);

		s[0] = b00 ^ (~b02 & b04);
		s[1] = b01 ^ (~b03 & b05);
		s[10] = b10 ^ (~b12 & b14);
		s[11] = b11 ^ (~b13 & b15);
		s[20] = b20 ^ (~b22 & b24);
		s[21] = b21 ^ (~b23 & b25);
		s[30] = b30 ^ (~b32 & b34);
		s[31] = b31 ^ (~b33 & b35);
		s[40] = b40 ^ (~b42 & b44);
		s[41] = b41 ^ (~b43 & b45);
		s[2] = b02 ^ (~b04 & b06);
		s[3] = b03 ^ (~b05 & b07);
		s[12] = b12 ^ (~b14 & b16);
		s[13] = b13 ^ (~b15 & b17);
		s[22] = b22 ^ (~b24 & b26);
		s[23] = b23 ^ (~b25 & b27);
		s[32] = b32 ^ (~b34 & b36);
		s[33] = b33 ^ (~b35 & b37);
		s[42] = b42 ^ (~b44 & b46);
		s[43] = b43 ^ (~b45 & b47);
		s[4] = b04 ^ (~b06 & b08);
		s[5] = b05 ^ (~b07 & b09);
		s[14] = b14 ^ (~b16 & b18);
		s[15] = b15 ^ (~b17 & b19);
		s[24] = b24 ^ (~b26 & b28);
		s[25] = b25 ^ (~b27 & b29);
		s[34] = b34 ^ (~b36 & b38);
		s[35] = b35 ^ (~b37 & b39);
		s[44] = b44 ^ (~b46 & b48);
		s[45] = b45 ^ (~b47 & b49);
		s[6] = b06 ^ (~b08 & b00);
		s[7] = b07 ^ (~b09 & b01);
		s[16] = b16 ^ (~b18 & b10);
		s[17] = b17 ^ (~b19 & b11);
		s[26] = b26 ^ (~b28 & b20);
		s[27] = b27 ^ (~b29 & b21);
		s[36] = b36 ^ (~b38 & b30);
		s[37] = b37 ^ (~b39 & b31);
		s[46] = b46 ^ (~b48 & b40);
		s[47] = b47 ^ (~b49 & b41);
		s[8] = b08 ^ (~b00 & b02);
		s[9] = b09 ^ (~b01 & b03);
		s[18] = b18 ^ (~b10 & b12);
		s[19] = b19 ^ (~b11 & b13);
		s[28] = b28 ^ (~b20 & b22);
		s[29] = b29 ^ (~b21 & b23);
		s[38] = b38 ^ (~b30 & b32);
		s[39] = b39 ^ (~b31 & b33);
		s[48] = b48 ^ (~b40 & b42);
		s[49] = b49 ^ (~b41 & b43);

		s[0] ^= RC[n];
		s[1] ^= RC[n + 1];
	}
}

// expects a string
// returns 64-char hex-string, no 0x-prefix
// https://eips.ethereum.org/EIPS/eip-137#name-syntax
function namehash(name) {
	if (typeof name !== 'string') throw new TypeError('Expected string');
	let buf = new Uint8Array(64); 
	if (name.length > 0) {
		for (let label of name.split('.').reverse()) {
			buf.set(keccak().update(label).bytes, 32);
			buf.set(keccak().update(buf).bytes, 0);
		}
	}
	return hex_from_bytes(buf.subarray(0, 32));
}

// accepts address as string (0x-prefix is optional) 
// returns 0x-prefixed checksummed address 
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
function checksum_address(s) {
	if (typeof s !== 'string') throw new TypeError('expected string');
	if (s.startsWith('0x')) s = s.slice(2);
	s = s.toLowerCase();
	if (!/^[a-f0-9]{40}$/.test(s)) throw new TypeError('expected 40-char hex');
	let hash = keccak().update(s).hex;
	return '0x' + [...s].map((x, i) => hash.charCodeAt(i) >= 56 ? x.toUpperCase() : x).join('');
}

function is_valid_address(s) {
	return /^(0x)?[a-f0-9]{40}$/i.test(s);
}

function is_null_hex(s) {
	return /^(0x)?[0]+$/i.test(s);
}

const BASE_58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; // removed: "IOl0+/"

// https://tools.ietf.org/id/draft-msporny-base58-01.html
function base58_from_bytes(v) {
	let digits = [];
	let zero = 0;
	for (let x of v) {
		if (digits.length == 0 && x == 0) {
			zero++;
			continue;
		}
		for (let i = 0; i < digits.length; ++i) {
			let xx = (digits[i] << 8) | x;
			digits[i] = xx % 58;
			x = (xx / 58) | 0;
		}
		while (x > 0) {
			digits.push(x % 58);
			x = (x / 58) | 0;
		}
	}
	for (; zero > 0; zero--) digits.push(0);
	return String.fromCharCode(...digits.reverse().map(x => BASE_58.charCodeAt(x)));
}

function number_from_abi(x) {
	if (typeof x === 'string') {
		if (/^(0x)?[a-f0-9]{0,12}$/i.test(x)) return parseInt(x, 16); // worth it?
		x = bytes_from_hex(x);
	} else if (Array.isArray(x)) {
		x = Uint8Array.from(x);
	} else if (ArrayBuffer.isView(x)) {
		x = new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
	} else if (x instanceof ArrayBuffer) {
		x = new Uint8Array(x, 0, x.byteLength);			
	} else {
		throw new TypeError('unknown number to byte conversion');
	}
	if (x.length > 7) {  // 53 bits => 7 bytes, so everything else must be 0
		let n = x.length - 7;
		for (let i = 0; i < n; i++) if (x[i] > 0) throw new RangeError('overflow');
		x = x.subarray(n);
	}
	let n = 0;
	for (let i of x) n = (n * 256) + i;
	if (!Number.isSafeInteger(n)) throw new RangeError('overflow');
	return n;
}

class ABIDecoder {
	static from_hex(x) { return new this(bytes_from_hex(x)); }
	constructor(buf) {
		this.buf = buf;
		this.pos = 0;
	}
	get remaining() { return this.buf.length - this.pos; }
	read(n) {
		let {pos, buf} = this;
		let end = pos + n;
		if (end > buf.length) throw new Error('overflow');
		let v = buf.subarray(pos, end);
		this.pos = end;
		return v;
	}
	byte() {
		let {pos, buf} = this;
		if (pos >= buf.length) throw new Error('overflow');
		this.pos = pos + 1;
		return buf[pos];
	}
	big(n = 32) { return BigInt('0x' + hex_from_bytes(this.read(n))); }
	number(n = 32) { return number_from_abi(this.read(n)); }
	string() { return str_from_bytes(this.memory()); }
	memory() {
		let pos = this.number();
		let end = pos + 32;
		let {buf} = this;
		if (end > buf.length) throw new RangeError('overflow');
		let len = number_from_abi(buf.subarray(pos, end));
		pos = end;
		end += len;
		if (end > buf.length) throw new RangeError('overflow');
		return buf.subarray(pos, end);
	}
	addr(checksum = true) {
		if (this.number(12) != 0) throw new TypeError('expected zero');
		let v = this.read(20);
		let addr = hex_from_bytes(v);
		return checksum ? checksum_address(addr) : `0x${addr}`; 
	}
	//https://github.com/multiformats/unsigned-varint
	uvarint() { 
		let acc = 0;
		let scale = 1;
		const MASK = 0x7F;
		while (true) {
			let next = this.byte();
			acc += (next & 0x7F) * scale;
			if (next <= MASK) break;
			if (scale > 0x400000000000) throw new RangeException('overflow'); // Ceiling[Number.MAX_SAFE_INTEGER/128]
			scale *= 128;
		}
		return acc;
	}
}

function set_bytes_to_number(v, i) {
	if (typeof i === 'number') {
		if (!Number.isSafeInteger(i)) throw new RangeError('overflow');					
		for (let pos = v.length - 1; i && pos >= 0; pos--) {
			v[pos] = i;
			i = Math.floor(i / 256);	
		}
	} else if (i instanceof BigInt) {
		let s = i.toString(16);
		let {length} = s;
		for (let pos = v.length - 1, off = length; pos >= 0 && off > 0; pos--, off -= 2) {
			v[pos] = parseInt(s.slice(Math.max(0, off - 2), off), 16);
		}
	} else {
		throw new TypeError(`unknown integer: ${i}`);
	}
}

class ABIEncoder {
	static method(method) {
		if (typeof method !== 'string') throw new TypeError('expected string');
		let N = 4;
		let enc = new ABIEncoder(N); // method signature doesn't contribute to offset
		if (method.includes('(')) {
			enc.add_bytes(keccak().update(method).bytes.subarray(0, N));
		} else {
			enc.add_hex(method);
			if (enc.pos != N) throw new Error('method should be a signature or 8-char hex');
		}
		return enc;
	}
	constructor(offset = 0, capacity = 256) {
		if (!Number.isSafeInteger(capacity) || capacity < 1) throw new TypeError('expected positive initial capacity');
		this.buf = new Uint8Array(capacity);
		this.pos = 0;
		this.offset = offset;
		this.tails = [];
	}
	reset() {
		this.buf.fill(0);
		this.tails.length = 0;
		this.pos = 0;
		return this; // chainable
	}
	build_hex() { return '0x' + hex_from_bytes(this.build()); }
	build() {
		let {pos, tails, offset} = this;
		let len = tails.reduce((a, [_, v]) => v.length, 0);
		if (len > 0) {
			this.alloc(len);
			let {buf} = this;
			for (let [off, v] of tails) {
				set_bytes_to_number(buf.subarray(off, off + 32), pos - offset); // global offset
				buf.set(v, pos);
				pos += v.length;
			}
		}
		return this.buf.subarray(0, pos);
	}
	// return an UInt8Array view-slice into the buffer
	alloc(n) {
		if (typeof n !== 'number' || n < 1) throw new TypeError('expected positive size');
		let {buf, pos} = this;
		let end = pos + n;
		if (end > buf.length) {
			let bigger = new Uint8Array(Math.max(buf.length + n, buf.length << 1));
			bigger.set(buf);
			this.buf = buf = bigger;
		}
		this.pos = end;
		return buf.subarray(pos, end);
	}
	big(i, n = 32) {
		let v = bytes_from_hex(i.toString(16));
		if (v.length > n) v = v.subarray(v.length - n);
		this.alloc(n).set(v, n - v.length);
		return this; // chainable
	}
	number(i, n = 32) {
		set_bytes_to_number(this.alloc(n), i);
		return this; // chainable
	}
	string(s) { return this.memory(bytes_from_str(s)); } // chainable
	memory(v) {
		let {pos} = this; // remember offset
		this.alloc(32); // reserve spot
		let tail = new Uint8Array((v.length + 63) & ~31); // len + bytes + 0* [padded]
		set_bytes_to_number(tail.subarray(0, 32), v.length);
		tail.set(v, 32);
		this.tails.push([pos, tail]);
		return this; // chainable
	}
	addr(x) {
		let v = bytes_from_hex(x); // throws
		if (v.length != 20) throw new TypeError('expected address');
		this.alloc(32).set(v, 12);
		return this; // chainable
	}
	// these are dangerous
	add_hex(s) { return this.add_bytes(bytes_from_hex(s)); } // throws
	add_bytes(v) {
		if (!(v instanceof Uint8Array)) {
			if (v instanceof ArrayBuffer) { 
				v = new Uint8Array(v);
			} else if (Array.isArray(v)) { 
				v = Uint8Array.from(v);
			} else if (typeof v === 'string') {
				v = bytes_from_str(v);
			} else {
				throw new TypeError('expected bytes');
			}
		}
		this.alloc(v.length).set(v);
		return this; // chainable
	}
}

class TableReader {
	constructor(table) {
		this.table = table;
		this.pos = 0;
	}
	get more() {
		return this.pos < this.table.length;
	}
	read_byte() { return this.table[this.pos++]; }
	read() { // unsigned pseudo-huffman (note: assumes tables are valid)
		let {table, pos} = this;
		let x0 = table[pos];
		if (x0 < 0x80) {
			this.pos += 1;
			return x0;
		}
		if (x0 < 0xFF) {
			this.pos += 2;
			return 0x80 + (((x0 & 0x7F) << 8) | table[pos+1]);
		}
		this.pos += 4;
		return 0x7F80 + ((table[pos+1] << 16) | (table[pos+2] << 8) | table[pos+3]);
	}
	read_signed() { // eg. [0,1,2,3...] => [0,-1,1,-2,...]
		let i = this.read();		
		return (i & 1) ? (~i >> 1) : (i >> 1);
	}
}


// from coder-v2.js
function bytes_from_base64(s) {
	return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
function decode2(v) {
	let buf = 0;
	let n = 0;
	let ret = [];
	next: for (let x of v) {
		buf = (buf << 8) | x;
		n += 8;
		while (n >= 3) {
			switch ((buf >> (n - 2)) & 3) { // upper 2 bits
				case 3:
					if (n < 10) continue next;
					ret.push((buf >> (n -= 10)) & 255);
					continue;
				case 2: 
					if (n < 6) continue next;
					ret.push((buf >> (n -= 6)) & 15);
					continue;
				default:
					ret.push((buf >> (n -= 3)) & 3); 
			}
		}
	}
	return ret;
}

// compressed lookup tables
// Ignored/Disallowed/Mapped/Valid/Deviation [IdnaMappingTable.txt]
const TABLE_I = decode2(bytes_from_base64('4DLTwWQnlM7ZPD72dULP/jXsbxDgNvP/jPsgk/+vxPc4DcM='));
const TABLE_D = decode2(bytes_from_base64('GWo1T41NjWTTmYyFngefm4DGmyZpSTih4DnTt5yZZkmc3oxuSbEcWPAaAcwWdrZbs7WYq844ia5cfp0o8BkJoSWLGclyKlJSUGRGVYymZpEsWM5RRSJlkSbM8hM+I1M0lnFjOUZVUWWjfIrJ5yzQksWM5RlVKSc7kRlWJVIzNmRokppt2SStmRGY3YrLaWcXOIKksyTotFSKqfFizi5qMqpLMk6mRkVRVtpZzMszSYgsaLOJPGDSSp2ZJiTRNUnZnUmO5KiTKcYJOLqUkzKpSZBpBySTJzkhvNuS8BkGTmUrgL1wG0GRTkmRZSZFkJkU5JkV5zkyLQ1kDxqbVlMuCBxx6zPi1OMU4pZaWVZmiyhVTVTTGc1zazPlcujVY+bJLJC8qUteWSY1NW8+WgnHVXNVNcsfzHTXl53SjPHe88nytV0ZXLwPLKZZMplQSSScfWamclszuRTSWysz3NTmxmiwk0PFSWa0piXWTJa8hvyHEWsrOoGiTgNQNq4HN8ZrxXFNC4XPnwG+rIDwHuy5aTKVnE6uximczmczmczmcznfsixo6zZwGrZXn51ZJbHLlZzM5UdUsxDROA/4yHED+GaPN6eA9zFOAzijgNLlRJlxjO3VNnFGjUWTbpXjz041yZCc3puVS2fGMcqmUympnM5zyTflVN1eSWYvJmPQcJwH3LasmnsllsNplJKKO+4hwFc3AdYs2nOQVLFCZVPiBU11RmMikNpJZJJJO/I2o1T41NjUmgnHnMplMm2WZ8RsONHEyjersi3uVyZa9YNrOX5dwCx15jfjkmSU49LlcuPHJZLsq4DHlVNkkmSSZRRmldhvM5RrN5nK0PgO3pxaqjGJjlRp0WZE5YUysXOkUU5hiZUuQvG5ToGcSYosyKloLOOpyVT0z6BkGTyWU5s8dWNy41PJZPqGk5vmduZz5dRVwHTY+cqLS07KKMqxbGsmxzFMXp06TJKc+MtuMz1TZqcSoyenYDileJHLNBnJMhvNc2dy1TSGhJYsZyjKakk0ZjLOp3LwFeuGXHtIoq4DJs2WTZFotdU1uJ51NVm2Nq+TF+AznPNk1OyhFUFHHilZTVo1Cy5V43pFGp26TwHD0nLTdVjryBYsbtJnKOWMlGmiqaYo5KUZp6uA7bGeAzc35lbweN7Nt5lr4DROJ8zY7eD6/j9R4Hx+hznge5nx81SaiapseU1WjVVGc4rLifBZhrey6XJnM+I6BLWruX3ijhNWyqnotnkM5R4Do8teIyUcDZxHCbXLa6Z6lRyPuZcsXp3TPOA3arJ1pVG4Yro3AY1ilmr04zwE+qnRykUlIbCTOdBMioM5xwyGUlzngPUXAdIuCz6+U38H6GP8BsM5xFTlGXgNVy13KqRcB4GP4jnUp4TYJzIUbzwGirEMp0ySqRcFyOiaZnvAaFIcbKJRNRkJJmMhJJLKJRJJJJKJUhnMhkJNRxGVmU4jmi4Djssk2Sy9Xm85LisuNcBJnGO25ZJTOrpuAxrg9YlxB2vdLNZnskN9kmcUVTZRRjyWncB6llylcrnpx11yzVVTUUT08BiZzfJauD4b/xk+wZBx/cz8Bry5ZXc52PF8/tBrPAZUc/OvnXuF2LkvL/+rbs14DcP/W/ch'));
const TABLE_N = decode2(bytes_from_base64('0HGuA0LZcX4DfjPmHBZS+E+qbEaDTkmovgLxiHA5UMgz/gOBybgfi47IZuc57iMSyvhe/T1rc6Og6vInw2LaI+CxOeTFKnnnAeTR3GwUTZBVRkFFGQUTZBjVGgcBwk3e+vNVPZJu3AY3JxWlcF09PFd7puNbAMaHDctmHr49wnDvtfZE3Ae0XwHpmqYYrwGYYpLtc71jgNcfAZG5cS3abvv4klyhTYoJLv3/HUO6x3zvkfN08FzUnp/FwGl1e/m8+NbFNjQyqb4NSklyhTYpW+/0kTcB7RfAemapnNwGYKaxTWJ2WSc/3XB8nlH/nRew4CjJOA+DgMcr4D/jfjBnyDgejf/niNl4TR8z/88twHF7bkHL8B6oyD/xlfgfLkGNf+tc30Y0BjQE4OJYgMavGNC2TGjRUJMjc9xrxAY1joxoOSZUWGfEjjWRuSYy1Sz4ocayMY0BjQGNAY0BjQGNAY0BjQGNAY0BjQGNCTEeGyAz5IcRyNTZNPiOSmfJDiORqbJp8RyUz5IcRyNTZNPiOSmfJDiORqbJp8RyUz5IcRyNTZNXVw3TioCoCoCochwGRf+9S2ThNok/96NnuOSDXWsdY4JY1xei8Vk1Ww8='));
const TABLE_W = [decode2(bytes_from_base64('4DKuA0KjXSlw3JScNyp3zRuA6RSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSTWKRzKRSSUKRSKRzKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSLgNvPAbspFIuB5VcHoB4HH1IuBx48Di64HHCjwOKvgMiPAbwZDwOIrgccMysJPA47JwOWGZTHgcnUikXA5seBy9cDmz4HK1wObHgcvXA5oUeBy1SLgc4PA5jJRiORKRSKRSKRSKRzKRSKRSKRSKRSTWLgM/OqHdFIpFIpFIpFIpFIpFIpFIpFIpFIpFIuA4FcBxSkUikUikUikUlHp/IfT9FcB4Z9XGH6fjrgWeB5IzHgKVIpFIpNi4PTTwe+Hg93OIHg+OMhsPB8mZMo4PVDwe2m41Hg+61zgNWKWSLgPMyvgL1IuA/NcB/lPAbxPwFp4XaZeF6pIrQMSOkmw40cQLNJrWZKRSKRSKRSKRSKRSKRbSbjIsVMq4CZbSdw2bgNMUikUikUikUikUikUikUikUikqxRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRzKRSKRSKRSOZSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRScTr3J5xwOd933E1mX9xkPFycx6ZkOKGYog4gcyP/jxNQ4DJP/HmameA4o8Bw6kKPBbhVwWtngvoPBfKZDIUZDlZ4PXij2nxHuO/MhR4PaDIUeD2lUGQ8Dnh4HNzwelHtZCj3Hmmgo9x6B7T2zwe4nuPek7LPSjw2dnEjMUeF/go44airuA2zI+D1U8Hrp4PZDwWkngtYPB7WeD3IyGiTtesPa52dfPa9ge10s62TLiBxQo8Dl54HPCj2nSHtOhKPB9HJwv+aD2mJKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRSKRST7PLwAUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUmt8BkikUikxLtvVSSSWdJJZ32+iFHgCe3neNVdt+R7ek9vce3rozuXuAUeAzU9vbQpe3+Ao8Bpp7b2T2/YWcBrJ7b1z23wHtvbxbuJNf7/PzuVXhelJ4Xj2eF5EvhfCaDihxI8HoR4PYZcQMxWzZDLwe4Pg9nKIIIPAf8eA/sgzEKSSQoogifEFw2PLhsdWOngN0PAcKUpCClcZJa3w2XHGSDjR7zIpfC9kgo0FYuZMalkeLnESjiRnkxqWR4ucRKOJcDlXvdsVwOge/mPDft6/xL09rPa9Ie139+nqykUi9PtToB0EyL0/Cc0/r8ucYPB4kUfUSkUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikUikpxJSS1b7wGucB2H+axqnz5Jb/4yPvTqBxw4kc0OsG45Qc0PCcUdMNhy45QcqO1HKjix4DtjwGeHODUc8OJHNjjRzI7QckObHhdoPAYgeDxg5ccQOLHJDwGMHg86OwHgNwOXHJjlh2wzHgtUOKHGDjR4DaDiBqPAbUcUONHEDvRyI5IeAyA8JUdcOVHhdINR4DJjkBxo5UdONR4HljmB0A8PuB4CQ5cd0OYHEjcdoNR0A8P9x4L/jjBqNBxA5IZDwGRHgcwNR4LJjih2Q3HEjiB4DNjceB0g3HYjkR148DrRuORHgrjwG+Gw8B9h4DLjrh4LdDwHFHg/8ObHcjsx4Cg4sbDoR4DGDih4LNDccSOJHIDjxoPAY8aDYeHyo54eDyo4wcuPA9scaPAXHXDwf3HHjjx0Y6UeBuOMHgJjwO4HPjwORHKjUeBzg8B+B4DejYajw3mHEjwHcHgO0Mx148BqRxo0G48Boh0Q2HHDwHnHZjQeA+4zHJjwO8HYDceAsOKGY4oc8PBcseC6A4odMOWHEDihoOoGg5EajjRzY48cQO7HHjRlv/jv9jzT39IXi+8ZiuA3f/xLSUeA9I8B554D1CquA6WS7IcZKPAfIUaDIajQZDwH8ngUZDwLKMhkKNBkmxI0HFDcajwHlFScBrZRmOJFGQ4oZpP4z48BzB4DhTyOSHkchOjHQz5vnHzcxO/nLzyvoHg9xPIbXwGS8Z1R5H2jxvLHq+Qxn/xqvOmQqSwyFTf+O22g8R2B4TGDxHYHhMYPCYweI7A8R2B4TGDxHYHhMYPCYweExg8JjD5zz1/43H3zwHMHgOFPI5IeQtPC5keG1M8NqB4XmzxOkHp7jyWjHh/tPE8ufU9I/p8Z52w8JUeB8E9H9R8n4T3msHs/QPTTnzPRPm+QeI8E9vOft2w/7/p4Sw9luB9Xuj/4xLZzwnIHs8UPdZidGOhnn82PJ7KeA+88hnB2E9tvR8/Qz/dh/LZTxeIZB6G5mQyGQyFGQyGQyGQyGQyGQyGQzGQyT4oZjMZpsSMn5eZ/42vNlIpFIpFIpFIpFIpFIpFIpFIpFIpFIpFIpMUyhSKRSKRSKRSKRSKRSKRSL/x4uQmTgJf/HjZcpFIpFIpFJJQpFIpFIpFIpFIpFIpFIpFIpFIpFIpFIpFIpFIpFIpFIpFIhTiykX/jlOFP/jlOMUikUiklqX/jyvNf/jyvYUklCkUikUikUikUikX/jy5TiZqOLFraDlpyw/+PR+w8N3akUikUikUikWun/x5XRnteYP/jlP0Uk901ikxr/x5+1mY4sf/Hn8U//HnY6dY4L4//HmZQeH6A/+PSxc/+PS06r/x6VPm4v/45P9j5WTnz8sPB8Ge720+B3p4r5j/4xf7iD/4txU/hwB/jEzw6PIe4eo2Y8j3B4z9DwW7Hgf8PHdcfM5k8L2R4b/DwvFHoM+PM+0eQ44/+MX108Tsx67njxvXHp+kPX7Ef/Cxs9J2x6vRDw3XHzO1Pe88eMuPpZSeQxo8Zkx4rpD3eSH/w7zwfxHgfOPR6YeL548b/R4nLjyPaHi+KPAZYeO6Y8lMeH/o8Jyx8rWzwOzHh/CPF+ked/Y8tux6b0T8e2ni/KPdZweH7w83254zUD0+4Hk/qP996eG5Q818R4e48D9R5vwDwPIHr+oP/ifcT7X5H3PdOPn0MgPDeIeL+Y9JxB5XaT6HwnjfmPg7wf5pPNe4eH9Y9NtR4PUj4mYny9IPo/uef1Q9F257z/jx2TnrvUPpZ6eI7Y954x5rEDxmhHvdfPj7YfF888lyZ7/Tj31J6Oo+Z9p4T9jwGgHrPwPUaYeK5A8hox43ej/uZngsaPE/EeK3I8bmR5P8jyPsHuOGPEf0eH9o7cf/GMfKen9Y8R8R8fVj8Otnhe4PAbAeE7Q8pyR4PzDwwPFI8P6h4Tdjzn3Hk/vPK/UeF84/+F8p4DmDwfaHt+WPX7oeD1A+voJ4H2Dw3GHj/mPQdAeRxE+R0J4/qjxOuHg8mPCaIem6w8B9x5X4jwHsHo9cPEyHgMkPA5Af/GI8yfT8Y9fxh4niD9eWnpM1PCZQeV6g8BkR5LNDxGpHj8YPEbQec/Q8twB53oj+PEn3vMP/ifyT1OyHgNwPFY4eCzY8VrR4LIDwvSHiPKPbY4f/F2wnoUfoxQ/+LcZPM64ehyI+ED73engvyPG5MeW2A+Lvx/8U5yeD0w8hlh5L3DwP7Hgs0PD/0eN8I8HnB5LrjyWWHJDyOrHiesP/ifxT227HtO5PdfMeFxA9Foh6D0jxX0HhMQP28eeL+g9P3R43uTwGVHgtkPJ5GeD809p/x/jrz9G2H4d3OynmO+PD+0ez4Y+FkJ6Lsjxmpn0OOPG66eb4I8yz6n3nmulPEcA+E7Rc32j6jqz4WMHhvAPCbIdENx1Q93ce0688Lvy4zKlxOmPigeBqk4/ZDjR1g8RzB5nKzxeZH/xdyJ4H8jwGmHgt4ObHgNaPCYweA1I8Boh4PMDwGoHhv4OKHh/MPA5QdMPAaQeGzo8B0x4D3jwe0HidkPAeMeB5A8JjB4D+jwe3HiNePAe0cWJOIGw3HYCjwHyHgEeB/48H9Byo7geB+I8B0x4PUDwHMEHg88PEfkeA4w8Fqx3A8F2h2o8J7h4DhDxnrHge4O8H76z/70Xcj/7WVv59jPDc8eAxk8Hp54Oo7seCuOzHhPGPAXngKDwGJHhNwPAZkeA6I5AeB5w8DYeG9Q3HgOgPAUHgfWPAbYeArPAcYdbPAdIeAkPBdAeAzA7YeB4g8D3h4DxjQd2PD+MeAR4LjjwXaHHzwGXHgd4PBZAeL/I8VsZ4DdDwG7HgrjwHVHajwOiGQ8B6xyI5keAyw4meC5g8HpR4HnjwH7HgdAPAdkeCxQ8DceGxo8B3R4blDweIHgKjkB4H0juR1k7YZTkJ4DGDwGRHgt8PB/AeB/Q8D5x4HOjw/GHgNOPAbMeA4o6QcYOwHhcuPEcof/XI+4azy3RH/3uH3niN2OhH/30nQHlOOPh8Mf/ef8+eAxbR//HZ+ucjMxUmUGTKOA44g4oQQQZiCCDIQQQayCCDUQQQayCCDqxBBBkIIIOhkEEEkEEGYgggoggg2EEkGQg1kHICDaQcwIIINhBBBoIIILIIIOJEFEEEGogogggykEEHKCCiMi0sggg5oQSQZCFMQayDQQbiCCDwHGkYnwHDEEEcDyXo/VNlRWM8/wpM/P8EUaSjaUZSsRvn5/WZef4AqX39Px3i9oKIKIKIKIKIIIKIKIIIKIKIIIKIIIKIIIKIIIKIIIKIKIKIKIKIIIKIIIKIIIKIIIKIIIKIIIKIIIKIIINxBBBRBBBRBBBRBBBRBBBRBBBRBBBRBRBRBBGM8X3JWo+llxR9LLz7+eFHFzwO6HETwGQmQyGQyHdDIZDo53I8BmZkMhkMhRkMhkMhkMhkMhkMhkMxkMk+KGYzGabEjJPiRoPAZmUu+7Mo8B6R4DzzwHqFVcB0sl2WdBvpRxJVknv+IXEZlLwHeHVuFyb/zoGwFcDtn/nhtXKPB6qeC+Y8BWuAyA/+PSmP/j0iSeAxso9r+h7X8TYeAxY8BSWWd2PBbOeC2o7Sc6OmFHfT/7znsD/5+/az/48rvz/7znrj/7znbT/7zncD/7zzmzwW+FHg+LPB8kf/ec84f/ec8qUZDqBZ/8ekj/49H/znp9PUl6ehnJCjicn/vOdkOUf+NN2L/3nv8qQpzOYrFadJpKzMlW41wHvcDIeB4zFOC4KjvMexLvJyJ+7/495jJmMhxg0k4lfR3mPYl3k5E/d/8e8xkzGQ4waScSvo7zHsS7ycifu/+PeYyZjIcYNJOJX0d5j2Jd5ORP3f/HvMZMxkOMGknEr6O8x7Eu8nIn7v/j3mMmYyHGDSSc6I5XteExQo0GZZkcrNJxQ5NLlpsOIHFzjRyEzHEyjMZDYZDIdoPAYwcxOxrgLTQs2eZrOpctNhxA4ucaWNnEyjMsQVE+NypZ0q1IclNinONLG3WsQVC4DgFwGKrgLTQs2eZnFDkxtUhRyU2HEDi5xpY2cTKMyxAyGQ7QtmXAbmUaDMcwKOVmk4ocmly02HEDi5xo5CZjiZRmMhsMhkmyM0GZZkcrNJxQ5NLlpsOIHFzjRyEzHEyjMZDYZDJwP4cXlpx7gNW+Ca74usPG7OeO5U+LxJ7uo8pzh+HEj8H5nlOJPXbweV4I8tx56bFzzP/Hm99PT+Mem6U+r5R4/xT13KH5vxPEfae1zY8xvp4EHqspOJH/xKj8mjnnvxPF2HneoPqakfV7k9b7h4Hcj5mxntNwPHbaSeb9Y+KTw1B/brsV+L6zy3n/+OGy/ivjNJxI/+vm0I/+vkZ4DHDjR4C48BuBz48Bjhy89v8J/95H3B/9fVrJuOQHJj/6+fyj/7yHRT3HuHTD/6+f/D/6+f5zjR4XLzwugHEj/8g9Q//INTOOHufHPdZwcWOsGo91oZ7r5DIc2OWHFijkR2Q4gcSOZHFDIQQf/X2+0f/XZ/ue48s5Uf/X38Qf/X37ebDlR4DsDwGlnIDoB3Q8BlBzQ8BMcgOhEHKjkhxA48eCyg8Dz54HojwNZ0Y8RrJ43TjwPfnTDmR4DgzwHnEngN2P/r+PwP/r+NjNRx45QcQPAA/+v7sPASH/1/W9nXjjB4DHTwHOHxtvXj9odsIP/r/eUP/r/OJOVHHjjB/9f95R/9f92JuWcHyPBPk58ccPAZIdlP/t5cf/Z8E/+z4x/9nbzKciPAaUUfK+U+Xjh1Y5UdYPl8af/epeEf/epcafL+gzGY5Qf/kqxA//JT05/90fMQf/Xhe+fFz0g+Zmp/97psR93xD/74XbziR8zjz5n3HZjih0Q8ByB86052fO3A/+7Qf/dnMngOCNBkLOuHKDpBxs4sdeOUGg5ocWPASHgMoOjHgN4P/u/+D/7xDHTwBPAawc2PAaEf/eIc0f/eIY6eAzk5ufS3U+n+xyo58dLPp8qfV0Y50f/eK94f/eKeaeB6o8B7p9X3z624H1uROjnrPcMx6rVjwGjns+iP85OfF/w0Gw70cVP/vGdgP/vcdzPsfEeA2k8DjR2Y/+8Y1A/+8Yz08Brp4Haj7W2n2vKPAaEeAuPAf4f/eMbsf/eMXn3ZT7vJH/3jfGH/3jeSn3eLPu+QdaObFH/3j2SHuuDPd68f/eO+uf/eQ64f/eQbyccPAaWeA946gdyO1nUDjxxo/+8f7I/+8g1M8Dux34/D+p+LsDOf/eQcof/eRZeeC2o/+8g2A7Af/eQXngNmOamU/JxJ+T6DsxrO2H/11O4H/11Gfn/3kXeH/3kVq4DmDjRzY/+8n/A/+8n485Uf/eU+AeBz4/+8p7M5Efpz0/TuR+nWSD9XPHKjlRyg8BUfq90/XyR/95d0h/95dt5/95flB/95d4Z/9ex7x/9evzp/95n0Ry48BzB/99DecYP26wf/eab8SdOOaH/3mnUlEHVj9vQn7skP3UngMgP/vp+OP/vOMdO+HgAfv1E/++rmP/vOsfP/vO6Dqx/9519Z4DOD+H7n8eiOKGo/+8+9o8D6xC/99j5J/99n6R/96BpJmP5eGf/fa5kf/ef+2fz+M/piBpOdH/3ovGH/3onin9NDP62HdjwEx/XoT/777aDnx/999rZ/99/wB/96Pnp/96RQf/ej+ieA0o4sf/elZUeAxI/+9KlP/vS8QP/vSvvP/r5teP/vX+TP850eAyI/zt5/n5j5nIn/3zWyHHD8/hnEj/6+PtTMea7Q/+MW+U/35hrOSH39TPv74ZDih1I/+9Ryw/+9Ry07geAsPAYoeA5M8B2h1Q8BsB4HhzwG3GQ5Af/eo5oeB+o8B1Z/9+f6Z/8CwyHRj/7136D/713Sz/71TED/79THTQf/fq5AeB8I/+/X00/+FpRxg4sZDwAOgngOMOrngOuPAZCeAmObLgM2OgH/xJx5/8S6cZj/71ziD/71vnzcf/Evon/xNUf/GUf6f/ko2Y8B+B/9/L55xI/+KMyPAY0eA7o8Dix/97Dkx/97BvJyw8Bmh4DOD/72P8D/4271T/63T8Tjp2g/+t21w/+t05M8BpB/97b2hzY/+9rzE8BnR0A/+9s7o/+9s6U8D3R4DvijwGbngt6OcH/3uGlH/3tuun/xjG1n/xjHiH/3uAP/yT9Cf/GNZ0fx6E/lsR/97p4h4HKj/8l/rnED/4xvVD/73j1D/8mJ5ef/kxTSD/73nlSDnh/973zR/971k5/8Y37p/8Y5th4DfDmx3g/+Mc98//Jj+iH/3wHdngfcPAf0f/GQe6c+P/jId0P/vh9OP/yZRlZ/+TKOaPA8keA4Y/++Iys/+Mj0k/+Mj8Y1G44objpR/98dV8=')), decode2(bytes_from_base64('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')), decode2(bytes_from_base64('4DPNi7/pu/58y9/03f9GV3/Rd/z/HZzz2+cAceWzcA8e5DO+g+QBzAcBtXfnHbsarpy7FeAt7/pu/5k19/03f8qr+/6bv+hJ7/pO/6Evv+m7/nTL3/Sd/zpff9F3/Ok9/0Hf86Z+/6bv+bJ7/nu/5s09/03f8uae/6Lv+XMvf893/Lk9/zXf8vJsQEmNYyJcex0TgCTGsZEuPY6Ltx7/qO/6HgMk8PcAHMBx/QeF/dGO7zs5/8admB/8adlo/8adlx/8adlq/8adli/8ab4uNYqqsQx/NPf/zgM0yFcBbwGPbGc1m4DFHwGI8BiW5nHeAyTNztNvAWPe+AVh4C3gLspWv51sU/AYvuWIya7wGLcBKa9w0E5bwGJZ7Joe4bGa9w1U37xwEsuVYrUbtV0BY1q23vINJ3ibK8oxR5jjtxsybTTlmZbmdC0TgJzoWjbys6x7RVlWWamck0LITj+hYisp3PgLjjOa4wcexrd6NqzDZTm2YZCaeAn4DInfluoSYzq9Vfwdaf/Gw8kf/Gw8eP/Gw8gf/Gw8ev/Gw8cf/Gw8fJ/42HjD/42Hj5v/Gw8Uf/Gw8fR/42HiD/42Hj6v/Gw8Mf/Gw8fZ/42HhD/42Hj7v/Gw8Ef/Gw8fiH/jYeAP/jYeNf/jYeSP/jYeNP/jYeQP/jYeNH/jYeOP/jYeNX/jYeMP/jYeNk/8bDxR/8bDkOIY60cikxvEt1OyYlud+wPFqTLkhxmnJDkqyQ14vkleMjdTsWKbqtyk3U7sNzOwYpua3CTczunheh4Xhu+rHTjE2OmzEsdORZDNkuITXuyeYqSV0CWXEvC77wvPOL+F9HhefVu5/8aX9R/8aX84/8aX9B/8aX86/8aX8x/8aX88n/jS/kP/jS/nm/8aX8R/8aX89H/jS/gP/jS/nq/8aX7x/8aX89n/jS/cP/jS/nu/8aX7R/8aX8+If+NL9g/+NL+V/+NL+o/+NL+U/+NL+g/+NL+Uf+NL+Y/+NL+Vf+NL+Q/+NL+WT/xpfxH/xpfyzf+NL+A/+NL+Wj/xpfvH/xpfy1f+NL9w/+NL+Wz/xpftH/xpfy3f+NL9g/+NL+OX/xpf1H/xpfxv/xpf0H/xpe914t/40fhKxMZRZlHFb1rNR1DWbOB0XgN8xyY5Dj0hyHIFrmmyZkc1mJcxLmzA5rRlxzXNsxLzbLzLm2Wl5ll5OZZeRmFRznMKDldZN1qNludHK8ky82ZJl5syTMTdkgOR5IDj94OIXg4hkAOQ25gchtzA5DfnhyvIstNmRZabMiByHIgcdxHODkt+XHHb8uON45l5xTHMvOKY4DjeOVHIcZzI4vjAOL4wDi+MUHHcWBxXFqjj+LUG/JcuM+S5cZZsvOVTAnLcwJy3OjXlucGnLwcwy8HMMry4nK8uJWXnLll5zDLycyy/MCMvzo05ijmGY5kRlrOZZblzGYyHMnmJzZgrMcwKzHODLmeZFZnmRWZ50ZTUZzQVSDVSDnNmcHP5M8OfyZ0c9ozg5/Rmxz3Nqjn+bUHOcyqOdrODnOZUHK6c2OT350crtzo5PiOdGvL88NaqIznOiM7zwimo0io3zVGfMc6N82XnLstzA4vjFRtkqM+Zo5hlucGvL8yLkBOX5kVmaJWdHOTnhpzHPDiNFR0OrOjbIDi+M5kcfyAHI6c4M+Z55lOU49wHOHgOfk4DnKOA7nHqv/Gp/P/7xbnsaxI5XjWKHLcaxY5fjWMHMcaxrWeAu4DJ8SPAYxwGU4keAxbgMnxQ8Bi3AZTinPfV/68PNfe8H3vEyT3vJFnAbl73efb2H29aT3e1d3s5Pebh3m2k+ttXrbOT/4Plf+D45Px/98f9k/+Lpv/FzJ8XEvFvJ+qb6n8=')), bytes_from_base64('n9e/5AAAAIB7v4G/pr+lARWADBkAABAaGQAAiBXDBAAAAIh0nG5eVmcBS4ASK2cBAoAiMW8CBE5QgAUED4AogCGAIgSAIXxLCgE5gAQFJAWAHXAKJAGAG3pVeAiAGXweXQQvIRZ4AmdmEoAFDEBYHwEGK2OAMmcKKnGAHlUGLHMWfAUbX3wMBCNpOFYBIzZnRgQBTQpGAwAiSyor7f6RtZ9p08gK/wByJQ8DFh8CwtDCw4ABHmLC5MLTB/8ASqyLADoABgE/ODUSASgvMCsBDB4VGAEnBCoHARUWDAUBAikiAgQngLaAyTo='), bytes_from_base64('sofg0CITgBplDjeAAHlyEQJlgAAEVwoCL3IRL1YBgAd4XS+AEgZvfGN2NwsdVoABcFUDGGMuHkYEK2eAEEsMAholFx+ACAIlUSB6IREZKndgGAMnFjNYIQwCDlUrgAJY4IEhBsLiwsM='), bytes_from_base64('spbg2oAAFzZnRoAZ4HEhBsLiwsOAAQ==')];
// CheckJoiners [DerivedGeneralCategory.txt]
const TABLE_M = decode2(bytes_from_base64('4LgNw4Dk5+A4fLSSiidIrzDFcQOyzqZIyZGcexvW686ppOMSGksy5W88oyrGDkObM4kZ6ljrzgmdJOk1LGinnBMsiTZx5M1vOCaCy8UWLTF5wTOknO6ljxzuVsyUnKJc3JnLMk6rWOvOCZyzJOq1jkmbozlmSk1LHXoxkmJNGJLPSp7KNiKprm0pY2SSZFmOKFS1nJKTsmKYvJIy1O5LbCapOCz98HmUmOPHVjy0DIKTlrJ3VZEd2sks4DW5c5qOOo5hj+Yy5fiOTU2PHrc4uzDFOAxhnFZDMU+A0bQOC1DIeL358BadgyDgeqm2lfrqkhqyBaguA5AsyHF5ZDqazLEsaxK05NRjNuWSZfdkh0O6w0LLXmRLSlROUyyrgNsoK87sDwWw4hiGIcHpp4DYjwGKy8NMypZMoch4DJVwPeycC1wGM15jJvTzW/KSlVJltc5z15JdiCyw2PMLqJCtcsmPAZBZismbozpJ0mpKdy8BoGJYudRxTgNrnVONrUsR2q3Zb+A4C/gN1mKUhJXAWzqdnHKsonMlBpry7EOBxWg0alixu3qZkozk6FKUZeA9uTy95lzufg+YJzeeTUTWvMytcj8OXLF+B56VzUUKfHpOAxR8PnebyZlQbji0pv4T0JziKnKMvAcLPwH7nPZOF2CfbZ//r5jNeA3D'));
// CONTEXTJ [DerivedCombiningClass.txt, DerivedJoiningType.txt]  
const TABLE_V = bytes_from_base64('iM2AAIAAgACAAIAAgACAAG4BEX1wgACASoA1AYZaAR+AHoIOgGRmAUcBkQz6ByaAGIAPbYC2gHfd0oWHKg86egGADHWANWOAdYAAgH2AAHd1gI6AhAGAIlQTUoEmgIUBUg==');
const TABLE_LD = decode2(bytes_from_base64('4XoDKSTLJaZysjVGIYlkxVJJKyho4k5ZDSSSVj9bvUhKam0rIdWlRNRNRMiOOlS4lVKlMb+O744xrN2RE/+MQxXM/h82Wgy1F1ScBiJJbKJRxxcB6ORE8DxjOI2PHJFZlxKkKRRKMq/8az2miQ=='));
const TABLE_RD = decode2(bytes_from_base64('4XoCceNWRos6+TjCqaOIE49juZ6VkOq4zOTIZJcTZU2I2nG+O744xrN2RE/+MQxXMvh86Ykp0mpGaXgMQxLF5uA9LI+B4zFbJMbxLLiZTQZJF/41ntdE'));
const TABLE_T = decode2(bytes_from_base64('4DLTwPpbhwHJz8Bw+WklFE6RWTl2K4gdlnUyRkyEk49jet151TScYkNJZlyt55RlWMHIM3JMlEhc9Sx050ZJKDiixopZyZFIk2ceTNazkySlSHFFi0xOdFEyUGdVrHjnpsOZFnNyXKzJOq1jpzoozGVYoscWcqSSg4osdOkGdk60VPZRsRVNc2lLGySTm9xlKlrOSUnZpDMUljKkeISWlKY3ngs/fB5k8dWPLHloCM9BVdJy1k7qsiO7ORUmZ8BraRzomcklUTVI5hj+YyZgTKTKcopsWQSJF5wSmS86oS4DGGbTPIZi1wGjaBwPFlLGpcxllm2DIeL358BadgyDgeqk2tfrqkhqyBaguA5AsyHGVKeAxdY1iVpyajGa8ueYFSJZOdDmSSsNBy85mS0pUTlSoPAbcUZD53YHgthxDEMQ4DTzwG8vgeBPAbEeAxWXhpmVLJlDkPAZKuB72TgWuAxmvMZN7ObX5SUqnmMiU5z15JKaM+NizSmqRHX2iVMeAyAujFVnKZyWdy8BodCZOLnVJiZEVwG3STIrG1qtCJW1ElTE7K1IZeA4OkrgOARMh4DEJEpDkFWUTKSg0zJ5daVwOLTmYnUsWU5RW9TMlGcnSEyTwHtrlO7p7bN5c7n4PmDn8monzM4Rk5H3MuWL8D0DpxBT49JwGKPh87zeTMqDccWlN/CehOcRU5Rl4DhZ+A/c57JwuwT7bR/9fL5qce2DgBwG4Q=='));
// emoji-zwj-sequences.txt
const ZWNJ_EMOJI = (() => {
	let r = new TableReader(decode2(bytes_from_base64('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')));
	let buckets = []; // stored by post-idna length
	while (r.more) {
		let n = r.read();       // group size
		let w = r.read_byte();  // group width
		let p = r.read();       // bit positions of zwnj
		let m = [];
		for (let i = 0; i < n; i++) m.push([]);
		let b = w;
		for (let i = 0; i < w; i++) { // signed delta-encoded, transposed
			if (p & (1 << (i - 1))) {
				m.forEach(v => v.push(0x200D)); // insert zwnj
				--b; // discount
			} else {
				let y = 0;
				for (let v of m) v.push(y += r.read_signed());
			}
		}
		let bucket = buckets[b];
		if (!bucket) buckets[b] = bucket = [];
		bucket.push(...m);
	}
	for (let v of buckets) if (v) v.sort((a, b) => a[0] - b[0]); // store sorted
	return buckets;
})();

// upgrade emoji to fully-qualified w/o FEOF
// expects list of code-points
// returns list of code-points
function upgrade_zwnj_emoji(v) {
	let ret = [];
	next_cp: for (let i = 0, n = v.length; i < n; i++) {
		let cp0 = v[i];
		next_bucket: for (let b = Math.min(n - i, ZWNJ_EMOJI.length); b >= 1; b--) { // only consider emoji that fit
			let bucket = ZWNJ_EMOJI[b];
			if (!bucket) continue;
			next_emoji: for (let emoji of bucket) { // todo: binary search
				let c = emoji[0] - cp0;
				if (c < 0) continue;
				if (c > 0) continue next_bucket;
				let j = i + 1;
				for (let k = 1; k < emoji.length; k++) {
					let cp = emoji[k];
					if (cp == 0x200D) continue;
					if (cp != v[j++]) continue next_emoji;
				}
				ret.push(emoji); // apply upgrade
				i += b - 1;
				continue next_cp;
			}
		}
		ret.push(cp0);
	}
	return ret.flat();
}

// member are 1-tuples [unsigned(cp)]
function lookup_member(table, cp) {
	let x = 0;
	let r = new TableReader(table); 
	while (r.more) {
		x += r.read();
		if (x == cp) return true;
		if (x > cp) break;
	}
	return false;
}

// member are 2-tuples [unsigned(cp), n] 
function lookup_member_span(table, cp) {
	let x = 0;
	let r = new TableReader(table); 
	while (r.more) {
		x += r.read();
		let d = cp - x;
		if (d < 0) break;
		let n = r.read();
		if (d < n) return true;
		x += n;
	}
	return false;
}

// linear are 3-tuples [unsigned(cp), n, signed(mapped)]
function lookup_linear(table, cp) {
	let x = 0, y = 0;
	let r = new TableReader(table);
	while (r.more) {
		x += r.read();
		let d = cp - x;
		if (d < 0) break;
		let n = r.read();
		y += r.read_signed();		
		if (d < n) return y + d;
		x += n;
	}
}

// mapped are (1+w)-tuples [unsigned(cp), signed(mapped...)]
function lookup_mapped(table, width, cp) {
	let x = 0, y = 0;
	let r = new TableReader(table);
	while (r.more) {		
		x += r.read();
		if (x > cp) break;
		if (x == cp) {
			let v = [];
			for (let j = 0; j < width; j++) {
				v.push(y += r.read_signed());
			}
			return v;
		}
		for (let j = 0; j < width; j++) {
			y += r.read_signed();
		}	
	}
}

// adapted from https://github.com/mathiasbynens/punycode.js
// overflow removed because only used after idna
// note: not safe to export for general use
// string -> string
function puny_decode(input) {
	let output = [];
	
	let index = input.lastIndexOf('-');
	for (let i = 0; i < index; ++i) {
		let code = input.charCodeAt(i);
		if (code >= 0x80) throw new Error('punycode: expected basic');
		output.push(code);
	}
	index++; // skip delimiter
	
	// https://datatracker.ietf.org/doc/html/rfc3492#section-3.4
	const BASE = 36; 
	const T_MIN = 1;
	const T_MAX = 26;
	const DELTA_SKEW = 38;
	const DELTA_DAMP = 700;
	const BASE_MIN = BASE - T_MIN;
	const MAX_DELTA = (BASE_MIN * T_MAX) >> 1;

	let bias = 72;
	let n = 0x80;

	let i = 0;
	const {length} = input;
	while (index < length) {
		let prev = i;
		for (let w = 1, k = BASE; ; k += BASE) {
			if (index >= length) throw new Error('punycode: invalid');
			let code = input.charCodeAt(index++);
			if (code < 0x3A) { // 30 + 0A
				code -= 0x16;
			} else if (code < 0x5B) { // 41 + 1A
				code -= 0x41;
			} else if (code < 0x7B) { // 61 + 1A
				code -= 0x61;
			} else {
				throw new Error(`punycode: invalid byte ${code}`);
			}
			i += code * w;
			const t = k <= bias ? T_MIN : (k >= bias + T_MAX ? T_MAX : k - bias);
			if (code < t) break;
			w *= BASE - t;
		}
		const out = output.length + 1;
		let delta = i - prev;
		delta = prev == 0 ? (delta / DELTA_DAMP)|0 : delta >> 1;
		delta += (delta / out)|0;
		let k = 0;
		while (delta > MAX_DELTA) {
			delta = (delta / BASE_MIN)|0;
			k += BASE;
		}
		bias = (k + BASE * delta / (delta + DELTA_SKEW))|0;
		n += (i / out)|0;
		i %= out;
		output.splice(i++, 0, n);
	}	
	return String.fromCodePoint(...output);
}

// warning: these should not be used directly
// expects code-point (number)
// is_* returns boolean
// get_* returns number, list of numbers, or undefined (code-points)
function is_disallowed(cp) {
	return lookup_member_span(TABLE_D, cp);
}
function is_ignored(cp) {
	return lookup_member_span(TABLE_I, cp);
}
function is_combining_mark(cp) {
    return lookup_member_span(TABLE_M, cp);
}
function get_mapped(cp) {
	let mapped = lookup_linear(TABLE_N, cp);
	if (mapped) return mapped;
	for (let i = 0; i < TABLE_W.length; i++) {	
		mapped = lookup_mapped(TABLE_W[i], i + 1, cp);
		if (mapped) return mapped;
	}
}

// expects a string 
// throws TypeError if not a string
// returns a string normalized according to IDNA 2008, according to UTS-46 (v14.0.0), +CONTEXTJ, +ZWJ EMOJI
function idna(s, ignore_disallowed = false) {
	if (typeof s !== 'string') throw new TypeError('expected string');
	let v =  [...s].map(x => x.codePointAt(0)); // convert to code-points
	const empty = [];
	return String.fromCodePoint(...upgrade_zwnj_emoji(v.map((cp, i) => {
		if (is_disallowed(cp)) {
			if (ignore_disallowed) return empty;
			throw new Error(`disallowed: 0x${cp.toString(16).padStart(2, '0')}`);
		}
		if (is_ignored(cp)) return empty;
		if (cp === 0x200C) { // https://datatracker.ietf.org/doc/html/rfc5892#appendix-A.1
			// rule 1: V + cp
			// V = Combining_Class "Virama"
			if (i > 0 && lookup_member(TABLE_V, v[i - 1])) { 
				return cp; // allowed
			}
			// rule 2: {L,D} + T* + cp + T* + {R,D}
			// L,D,T,R = Joining_Type
			if (i > 0 && i < v.length - 1) { // there is room on either side
				let head = i - 1;
				while (head > 1 && lookup_member_span(TABLE_T, v[head])) head--; // T*
				if (lookup_member_span(TABLE_LD, v[head])) { // L or D
					let tail = i + 1;
					while (tail < v.length - 1 && lookup_member_span(TABLE_T, v[tail])) tail++; // T*
					if (lookup_member_span(TABLE_RD, v[tail])) { // R or D
						return cp; // allowed
					}
				}
			}
			return empty; // ignore
		} else if (cp === 0x200D) { // https://datatracker.ietf.org/doc/html/rfc5892#appendix-A.2
			// rule 1: V + cp
			// V = Combining_Class "Virama"
			if (i > 0 && lookup_member(TABLE_V, v[i - 1])) { 
				return cp; // allowed
			}
			return empty; // ignore
		}
		return get_mapped(cp) ?? cp;
	}).flat())).normalize('NFC');
}

// primary api
// expects a string 
// throws TypeError if not a string
// returns a normalized string ready for namehash
// throws Error if not normalizable
function ens_normalize(name, ignore_disallowed = false) { // https://unicode.org/reports/tr46/#Processing
	// idna() will:
	// 1. map all full-stops to "." (see: Section 2.3 and Section 4.5)
	// 2. apply ContextJ rules (see: Section 4.1 Rule #7) [as-of v14.0.0, ContextJ does not span a stop]
	// 3. apply Section 4 Processing Rule #1 (Map) and Rule #2 (Normalize)
	return idna(name, ignore_disallowed).split('.').map(label => { // Section 4 Processing Rule #3 (Break) + Section 4.1 Rule #4
		if (label.startsWith('xn--')) { // Rule #4 (Convert)
			label = idna(puny_decode(label.slice(4)), ignore_disallowed);
		}
		// Section 4.1 Rule #1 (NFC) is already satisfied by idna()
		// apply Section 4.1 Rule #2
		if (label.length >= 4 && label[2] == '-' && label[3] == '-') throw new Error(`double-hyphen at label[3:4]: ${label}`);
		// apply Section 4.1 Rule #3
		if (label.startsWith('-')) throw new Error(`hyphen at label start: ${label}`);
		if (label.endsWith('-')) throw new Error(`hyphen at label end: ${label}`);
		// apply Section 4.1 Rule #5
		if (label.length > 0 && is_combining_mark(label.codePointAt(0))) throw new Error(`mark at label start: ${label}`);
		// Section 4.1 Rule #6 (Valid) is satisfied by idna() following EIP-137 (transitional=N, useSTD3AsciiRules=Y)
		// Section 4.1 Rule #7 (ContextJ) is satisfied by idna() 
		// Section 4.1 Rule #8 NYI
		return label;
	}).join('.');
}

var ADDR_TYPES = {
  "777": 833,
  "3333": 333333,
  "BTC": 0,
  "LTC": 2,
  "DOGE": 3,
  "RDD": 4,
  "DASH": 5,
  "PPC": 6,
  "NMC": 7,
  "FTC": 8,
  "XCP": 9,
  "BLK": 10,
  "NSR": 11,
  "NBT": 12,
  "MZC": 13,
  "VIA": 14,
  "XCH": 8444,
  "RBY": 16,
  "GRS": 17,
  "DGC": 18,
  "CCN": 828,
  "DGB": 20,
  "MONA": 22,
  "CLAM": 23,
  "XPM": 24,
  "NEOS": 25,
  "JBS": 26,
  "ZRC": 27,
  "VTC": 28,
  "NXT": 29,
  "BURST": 30,
  "MUE": 31,
  "ZOOM": 32,
  "VASH": 33,
  "CDN": 34,
  "SDC": 35,
  "PKB": 36,
  "PND": 37,
  "START": 38,
  "MOIN": 39,
  "EXP": 40,
  "EMC2": 41,
  "DCR": 42,
  "XEM": 43,
  "PART": 44,
  "ARG": 45,
  "SHR": 48,
  "GCR": 49,
  "NVC": 50,
  "AC": 51,
  "BTCD": 52,
  "DOPE": 53,
  "TPC": 54,
  "AIB": 55,
  "EDRC": 56,
  "SYS": 57,
  "SLR": 58,
  "SMLY": 59,
  "ETH": 60,
  "ETC": 61,
  "PSB": 62,
  "LDCN": 63,
  "XBC": 65,
  "IOP": 66,
  "NXS": 67,
  "INSN": 68,
  "OK": 69,
  "BRIT": 70,
  "CMP": 71,
  "CRW": 72,
  "BELA": 73,
  "ICX": 74,
  "FJC": 75,
  "MIX": 76,
  "XVG": 77,
  "EFL": 78,
  "CLUB": 79,
  "RICHX": 80,
  "POT": 81,
  "QRK": 82,
  "TRC": 83,
  "GRC": 84,
  "AUR": 85,
  "IXC": 86,
  "NLG": 87,
  "BITB": 88,
  "BTA": 1657,
  "XMY": 90,
  "BSD": 91,
  "UNO": 92,
  "MTR": 18000,
  "GB": 94,
  "SHM": 95,
  "CRX": 96,
  "BIQ": 97,
  "EVO": 98,
  "STO": 99,
  "BIGUP": 100,
  "GAME": 101,
  "DLC": 102,
  "ZYD": 103,
  "DBIC": 104,
  "STRAT": 105,
  "SH": 106,
  "MARS": 107,
  "UBQ": 108,
  "PTC": 109,
  "NRO": 110,
  "ARK": 111,
  "USC": 112,
  "THC": 113,
  "LINX": 114,
  "ECN": 115,
  "DNR": 116,
  "PINK": 117,
  "ATOM": 118,
  "PIVX": 119,
  "FLASH": 120,
  "ZEN": 121,
  "PUT": 122,
  "ZNY": 123,
  "UNIFY": 124,
  "XST": 125,
  "BRK": 126,
  "VC": 127,
  "XMR": 128,
  "VOX": 129,
  "NAV": 130,
  "FCT": 7777777,
  "EC": 132,
  "ZEC": 133,
  "LSK": 134,
  "STEEM": 135,
  "XZC": 136,
  "RBTC": 137,
  "RPT": 139,
  "LBC": 140,
  "KMD": 141,
  "BSQ": 142,
  "RIC": 143,
  "XRP": 144,
  "BCH": 145,
  "NEBL": 146,
  "ZCL": 147,
  "XLM": 148,
  "NLC2": 149,
  "WHL": 150,
  "ERC": 151,
  "DMD": 152,
  "BTM": 153,
  "BIO": 154,
  "XWCC": 155,
  "BTG": 156,
  "BTC2X": 157,
  "SSN": 158,
  "TOA": 159,
  "BTX": 160,
  "ACC": 161,
  "BCO": 5249353,
  "ELLA": 163,
  "PIRL": 164,
  "NANO": 256,
  "VIVO": 166,
  "FRST": 167,
  "HNC": 168,
  "BUZZ": 169,
  "MBRS": 170,
  "HC": 171,
  "HTML": 172,
  "ODN": 173,
  "ONX": 174,
  "RVN": 175,
  "GBX": 176,
  "BTCZ": 177,
  "POA": 178,
  "NYC": 179,
  "MXT": 180,
  "WC": 181,
  "MNX": 182,
  "BTCP": 183,
  "MUSIC": 184,
  "BCA": 185,
  "CRAVE": 186,
  "STAK": 187,
  "WBTC": 188,
  "LCH": 189,
  "EXCL": 190,
  "LCC": 192,
  "XFE": 193,
  "EOS": 194,
  "TRX": 195,
  "KOBO": 196,
  "HUSH": 197,
  "BANANO": 198,
  "ETF": 199,
  "OMNI": 200,
  "BIFI": 201,
  "UFO": 202,
  "CNMC": 203,
  "BCN": 204,
  "RIN": 205,
  "ATP": 206,
  "EVT": 207,
  "ATN": 208,
  "BIS": 209,
  "NEET": 210,
  "BOPO": 211,
  "OOT": 212,
  "ALIAS": 213,
  "MONK": 842,
  "BOXY": 215,
  "FLO": 216,
  "MEC": 217,
  "BTDX": 218,
  "XAX": 219,
  "ANON": 220,
  "LTZ": 221,
  "BITG": 222,
  "ICP": 223,
  "SMART": 224,
  "XUEZ": 225,
  "HLM": 226,
  "WEB": 227,
  "ACM": 228,
  "NOS": 229,
  "BITC": 230,
  "HTH": 231,
  "TZC": 232,
  "VAR": 233,
  "IOV": 234,
  "FIO": 235,
  "BSV": 236,
  "DXN": 237,
  "QRL": 238,
  "PCX": 239,
  "LOKI": 240,
  "NIM": 242,
  "SOV": 243,
  "JCT": 244,
  "SLP": 245,
  "EWT": 246,
  "UC": 401,
  "EXOS": 248,
  "ECA": 249,
  "SOOM": 250,
  "XRD": 1022,
  "FREE": 252,
  "NPW": 253,
  "BST": 254,
  "BTCC": 257,
  "ZEST": 259,
  "ABT": 260,
  "PION": 261,
  "DT3": 262,
  "ZBUX": 263,
  "KPL": 264,
  "TPAY": 265,
  "ZILLA": 266,
  "ANK": 267,
  "BCC": 268,
  "HPB": 269,
  "ONE": 1023,
  "SBC": 271,
  "IPC": 272,
  "DMTC": 273,
  "OGC": 274,
  "SHIT": 275,
  "ANDES": 276,
  "AREPA": 277,
  "BOLI": 278,
  "RIL": 279,
  "HTR": 280,
  "FCTID": 281,
  "BRAVO": 282,
  "ALGO": 283,
  "BZX": 284,
  "GXX": 285,
  "HEAT": 286,
  "XDN": 287,
  "FSN": 288,
  "CPC": 337,
  "BOLD": 290,
  "IOST": 291,
  "TKEY": 292,
  "USE": 293,
  "BCZ": 294,
  "IOC": 295,
  "ASF": 296,
  "MASS": 297,
  "FAIR": 298,
  "NUKO": 299,
  "GNX": 300,
  "DIVI": 301,
  "CMT": 1122,
  "EUNO": 303,
  "IOTX": 304,
  "ONION": 305,
  "8BIT": 306,
  "ATC": 307,
  "BTS": 308,
  "CKB": 309,
  "UGAS": 310,
  "ADS": 311,
  "ARA": 312,
  "ZIL": 313,
  "MOAC": 314,
  "SWTC": 315,
  "VNSC": 316,
  "PLUG": 317,
  "MAN": 318,
  "ECC": 319,
  "RPD": 320,
  "RAP": 321,
  "GARD": 322,
  "ZER": 323,
  "EBST": 324,
  "SHARD": 325,
  "LINDA": 326,
  "CMM": 327,
  "BLOCK": 328,
  "AUDAX": 329,
  "LUNA": 330,
  "ZPM": 331,
  "KUVA": 332,
  "MEM": 333,
  "CS": 498,
  "SWIFT": 335,
  "FIX": 336,
  "VGO": 338,
  "DVT": 339,
  "N8V": 340,
  "MTNS": 341,
  "BLAST": 342,
  "DCT": 343,
  "AUX": 344,
  "USDP": 345,
  "HTDF": 346,
  "YEC": 347,
  "QLC": 348,
  "TEA": 349,
  "ARW": 350,
  "MDM": 351,
  "CYB": 352,
  "LTO": 353,
  "DOT": 354,
  "AEON": 355,
  "RES": 356,
  "AYA": 357,
  "DAPS": 358,
  "CSC": 359,
  "VSYS": 360,
  "NOLLAR": 361,
  "XNOS": 362,
  "CPU": 363,
  "LAMB": 364,
  "VCT": 365,
  "CZR": 366,
  "ABBC": 367,
  "HET": 368,
  "XAS": 369,
  "VDL": 370,
  "MED": 371,
  "ZVC": 372,
  "VESTX": 373,
  "DBT": 374,
  "SEOS": 375,
  "MXW": 376,
  "ZNZ": 377,
  "XCX": 378,
  "SOX": 379,
  "NYZO": 380,
  "ULC": 381,
  "RYO": 88888,
  "KAL": 383,
  "XSN": 384,
  "DOGEC": 385,
  "BMV": 386,
  "QBC": 387,
  "IMG": 388,
  "QOS": 389,
  "PKT": 390,
  "LHD": 391,
  "CENNZ": 392,
  "HSN": 393,
  "CRO": 394,
  "UMBRU": 395,
  "TON": 607,
  "NEAR": 397,
  "XPC": 398,
  "ZOC": 399,
  "NIX": 400,
  "GALI": 402,
  "OLT": 403,
  "XBI": 404,
  "DONU": 405,
  "EARTHS": 406,
  "HDD": 407,
  "SUGAR": 408,
  "AILE": 409,
  "TENT": 410,
  "TAN": 411,
  "AIN": 412,
  "MSR": 413,
  "SUMO": 414,
  "ETN": 415,
  "BYTZ": 416,
  "WOW": 417,
  "XTNC": 418,
  "LTHN": 419,
  "NODE": 420,
  "AGM": 421,
  "CCX": 422,
  "TNET": 423,
  "TELOS": 424,
  "AION": 425,
  "BC": 426,
  "KTV": 427,
  "ZCR": 428,
  "ERG": 429,
  "PESO": 430,
  "BTC2": 431,
  "XRPHD": 432,
  "WE": 433,
  "KSM": 434,
  "PCN": 435,
  "NCH": 436,
  "ICU": 437,
  "LN": 438,
  "DTP": 439,
  "BTCR": 1032,
  "AERGO": 441,
  "XTH": 442,
  "LV": 443,
  "PHR": 444,
  "VITAE": 445,
  "COCOS": 446,
  "DIN": 447,
  "SPL": 448,
  "YCE": 449,
  "XLR": 450,
  "KTS": 556,
  "DGLD": 452,
  "XNS": 453,
  "EM": 454,
  "SHN": 455,
  "SEELE": 456,
  "AE": 457,
  "ODX": 458,
  "KAVA": 459,
  "GLEEC": 476,
  "FIL": 461,
  "RUTA": 462,
  "CSDT": 463,
  "ETI": 464,
  "ZSLP": 465,
  "ERE": 466,
  "DX": 467,
  "CPS": 468,
  "BTH": 469,
  "MESG": 470,
  "FIMK": 471,
  "AR": 472,
  "OGO": 473,
  "ROSE": 474,
  "BARE": 475,
  "CLR": 477,
  "RNG": 478,
  "OLO": 479,
  "PEXA": 480,
  "MOON": 481,
  "OCEAN": 482,
  "BNT": 483,
  "AMO": 484,
  "FCH": 485,
  "LAT": 486,
  "COIN": 487,
  "VEO": 488,
  "CCA": 489,
  "GFN": 490,
  "BIP": 491,
  "KPG": 492,
  "FIN": 493,
  "BAND": 494,
  "DROP": 495,
  "BHT": 496,
  "LYRA": 497,
  "RUPX": 499,
  "THETA": 500,
  "SOL": 501,
  "THT": 502,
  "CFX": 503,
  "KUMA": 504,
  "HASH": 505,
  "CSPR": 506,
  "EARTH": 507,
  "ERD": 508,
  "CHI": 509,
  "KOTO": 510,
  "OTC": 511,
  "SEELEN": 513,
  "AETH": 514,
  "DNA": 515,
  "VEE": 516,
  "SIERRA": 517,
  "LET": 518,
  "BSC": 9006,
  "BTCV": 520,
  "ABA": 521,
  "SCC": 522,
  "EDG": 523,
  "AMS": 524,
  "GOSS": 525,
  "BU": 526,
  "GRAM": 527,
  "YAP": 528,
  "SCRT": 529,
  "NOVO": 530,
  "GHOST": 531,
  "HST": 532,
  "PRJ": 533,
  "YOU": 534,
  "XHV": 535,
  "BYND": 536,
  "JOYS": 537,
  "VAL": 616,
  "FLOW": 539,
  "SMESH": 540,
  "SCDO": 541,
  "IQS": 542,
  "BIND": 543,
  "COINEVO": 544,
  "SCRIBE": 545,
  "HYN": 546,
  "BHP": 547,
  "BBC": 1111,
  "MKF": 549,
  "XDC": 550,
  "STR": 551,
  "SUM": 997,
  "HBC": 553,
  "BCS": 555,
  "LKR": 557,
  "TAO": 558,
  "XWC": 559,
  "DEAL": 560,
  "NTY": 561,
  "TOP": 562,
  "STARS": 563,
  "AG": 564,
  "CICO": 565,
  "IRIS": 566,
  "NCG": 567,
  "LRG": 568,
  "SERO": 569,
  "BDX": 570,
  "CCXX": 571,
  "SLS": 572,
  "SRM": 573,
  "VLX": 574,
  "VIVT": 575,
  "BPS": 576,
  "NKN": 577,
  "ICL": 578,
  "BONO": 579,
  "PLC": 580,
  "DUN": 581,
  "DMCH": 582,
  "CTC": 583,
  "KELP": 584,
  "GBCR": 585,
  "XDAG": 586,
  "PRV": 587,
  "SCAP": 588,
  "TFUEL": 589,
  "GTM": 590,
  "RNL": 591,
  "GRIN": 592,
  "MWC": 593,
  "DOCK": 594,
  "POLYX": 595,
  "DIVER": 596,
  "XEP": 597,
  "APN": 598,
  "TFC": 599,
  "UTE": 600,
  "MTC": 601,
  "NC": 602,
  "XINY": 603,
  "DYN": 3381,
  "BUFS": 605,
  "STOS": 606,
  "TAFT": 608,
  "HYDRA": 609,
  "NOR": 610,
  "WCN": 613,
  "OPT": 614,
  "PSWAP": 615,
  "XOR": 617,
  "SSP": 618,
  "DEI": 619,
  "AXL": 620,
  "ZERO": 621,
  "NOBL": 624,
  "EAST": 625,
  "LORE": 628,
  "BTSG": 639,
  "LFC": 640,
  "AZERO": 643,
  "XLN": 646,
  "ZRB": 648,
  "UCO": 650,
  "PIRATE": 660,
  "SFRX": 663,
  "ACT": 666,
  "PRKL": 667,
  "SSC": 668,
  "GC": 669,
  "YUNGE": 677,
  "Voken": 678,
  "Evrynet": 680,
  "KAR": 686,
  "CET": 688,
  "VEIL": 698,
  "XDAI": 700,
  "MCOIN": 707,
  "CHC": 711,
  "XTL": 713,
  "BNB": 714,
  "SIN": 715,
  "DLN": 716,
  "MCX": 725,
  "BMK": 731,
  "ATOP": 737,
  "RAD": 747,
  "XPRT": 750,
  "BALLZ": 768,
  "COSA": 770,
  "BR": 771,
  "BTW": 777,
  "UIDD": 786,
  "ACA": 787,
  "BNC": 788,
  "TAU": 789,
  "BEET": 800,
  "DST": 3564,
  "QVT": 808,
  "DVPN": 811,
  "VET": 818,
  "CLO": 820,
  "BDB": 822,
  "CRUZ": 831,
  "SAPP": 832,
  "KYAN": 834,
  "AZR": 835,
  "CFL": 836,
  "DASHD": 837,
  "TRTT": 838,
  "UCR": 839,
  "PNY": 840,
  "BECN": 841,
  "SAGA": 843,
  "SUV": 844,
  "ESK": 845,
  "OWO": 846,
  "PEPS": 847,
  "BIR": 848,
  "DSM": 852,
  "PRCY": 853,
  "MOB": 866,
  "IF": 868,
  "LUM": 880,
  "ZBC": 883,
  "ADF": 886,
  "NEO": 888,
  "TOMO": 889,
  "XSEL": 890,
  "LKSC": 896,
  "XEC": 1899,
  "LMO": 900,
  "HNT": 904,
  "FIS": 907,
  "SAAGE": 909,
  "META": 916,
  "FRA": 917,
  "DIP": 925,
  "RUNE": 931,
  "LTP": 955,
  "MATIC": 966,
  "TWINS": 970,
  "XAZAB": 988,
  "AIOZ": 989,
  "PEC": 991,
  "OKT": 996,
  "LBTC": 1776,
  "BCD": 999,
  "BTN": 1000,
  "TT": 1001,
  "BKT": 1002,
  "NODL": 1003,
  "FTM": 1007,
  "HT": 1010,
  "ELV": 1011,
  "BIC": 1013,
  "EVC": 1020,
  "ONT": 1024,
  "KEX": 1026,
  "MCM": 1027,
  "RISE": 1120,
  "ETSC": 1128,
  "DFI": 1129,
  "CDY": 1145,
  "HOO": 1170,
  "ALPH": 1234,
  "MOVR": 1285,
  "DFC": 1337,
  "HYC": 1397,
  "TENTSLP": 1410,
  "BEAM": 1533,
  "ELF": 1616,
  "AUDL": 1618,
  "ATH": 1620,
  "NEW": 1642,
  "BCX": 1688,
  "XTZ": 1729,
  "BBP": 1777,
  "JPYS": 1784,
  "VEGA": 1789,
  "ADA": 1815,
  "TES": 1856,
  "CLC": 1901,
  "VIPS": 1919,
  "CITY": 1926,
  "XX": 1955,
  "XMX": 1977,
  "TRTL": 1984,
  "EGEM": 1987,
  "HODL": 1989,
  "PHL": 1990,
  "SC": 1991,
  "MYT": 1996,
  "POLIS": 1997,
  "XMCC": 1998,
  "COLX": 1999,
  "GIN": 2000,
  "MNP": 2001,
  "KIN": 2017,
  "EOSC": 2018,
  "GBT": 2019,
  "PKC": 2020,
  "SKT": 2021,
  "XHT": 2022,
  "MCASH": 2048,
  "TRUE": 2049,
  "IoTE": 2112,
  "XRG": 2137,
  "ASK": 2221,
  "QTUM": 2301,
  "ETP": 2302,
  "GXC": 2303,
  "CRP": 2304,
  "ELA": 2305,
  "SNOW": 2338,
  "AOA": 2570,
  "REOSC": 2894,
  "LUX": 3003,
  "XHB": 3030,
  "COS": 3077,
  "SEQ": 3383,
  "DEO": 3552,
  "NAS": 2718,
  "BND": 2941,
  "CCC": 3276,
  "ROI": 3377,
  "FC8": 4040,
  "YEE": 4096,
  "IOTA": 4218,
  "AXE": 4242,
  "XYM": 4343,
  "FIC": 5248,
  "HNS": 5353,
  "FUND": 5555,
  "STX": 5757,
  "VOW": 5895,
  "SLU": 5920,
  "GO": 6060,
  "MOI": 6174,
  "BPA": 6666,
  "SAFE": 19165,
  "ROGER": 6969,
  "TOPL": 7091,
  "BTV": 7777,
  "SKY": 8000,
  "PAC": 8192,
  "KLAY": 8217,
  "BTQ": 8339,
  "SBTC": 8888,
  "NULS": 8964,
  "BTP": 8999,
  "AVAX": 9000,
  "ARB": 9001,
  "BOBA": 9002,
  "LOOP": 9003,
  "STARK": 9004,
  "AVAXC": 9005,
  "NRG": 9797,
  "BTF": 9888,
  "GOD": 9999,
  "FO": 10000,
  "RTM": 10226,
  "XRC": 10291,
  "XPI": 10605,
  "ESS": 11111,
  "IPOS": 12345,
  "MINA": 12586,
  "BTY": 13107,
  "YCC": 13108,
  "SDGO": 15845,
  "XTX": 16181,
  "ARDR": 16754,
  "FLUX": 19167,
  "RITO": 19169,
  "XND": 20036,
  "PWR": 22504,
  "BELL": 25252,
  "CHX": 25718,
  "ESN": 31102,
  "TEO": 33416,
  "BTCS": 33878,
  "BTT": 34952,
  "FXTC": 37992,
  "AMA": 39321,
  "AXIV": 43028,
  "EVE": 49262,
  "STASH": 49344,
  "CELO": 52752,
  "KETH": 65536,
  "GRLC": 69420,
  "GWL": 70007,
  "ZYN": 77777,
  "WICC": 99999,
  "HOME": 100500,
  "STC": 101010,
  "STRAX": 105105,
  "AKA": 200625,
  "GENOM": 200665,
  "ATS": 246529,
  "PI": 314159,
  "VALUE": 333332,
  "X42": 424242,
  "VITE": 666666,
  "SEA": 888888,
  "ILT": 1171337,
  "ETHO": 1313114,
  "XERO": 1313500,
  "LAX": 1712144,
  "EPK": 3924011,
  "HYD": 4741444,
  "BHD": 5249354,
  "PTN": 5264462,
  "WAN": 5718350,
  "WAVES": 5741564,
  "SEM": 7562605,
  "ION": 7567736,
  "WGR": 7825266,
  "OBSR": 7825267,
  "AFS": 8163271,
  "XDS": 15118976,
  "AQUA": 61717561,
  "HATCH": 88888888,
  "kUSD": 91927009,
  "GENS": 99999996,
  "EQ": 99999997,
  "FLUID": 99999998,
  "QKC": 99999999,
  "FVDC": 608589380
};

// https://docs.ens.domains/ens-deployments
const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'; // ens registry contract on mainnet
const RESOLVED = Symbol('ENSResolved');

function resolved_value() {
	return new Date();
}

async function ens_address_from_node(provider, node) {
	let resolver = await call_registry_resolver(provider, node);
	let address = false;
	if (!is_null_hex(resolver)) {
		address = await call_resolver_addr(provider, resolver, node);
	}
	return {node, resolver, address};
}

// https://eips.ethereum.org/EIPS/eip-137
async function ens_address_from_name(provider, name0, ...a) {	
	let name = ens_normalize(name0, ...a); // throws
	let node = namehash(name);
	return {name0, name, ...await ens_address_from_node(provider, node), [RESOLVED]: resolved_value()};
}

// https://eips.ethereum.org/EIPS/eip-181
async function ens_name_from_address(provider, address) {
	address = checksum_address(address); // throws
	let node = namehash(`${address.slice(2).toLowerCase()}.addr.reverse`); 
	let resolver = await call_registry_resolver(provider, node);
	let ret = {node, resolver, address, [RESOLVED]: resolved_value()};
	if (!is_null_hex(resolver)) {
		const SIG = '691f3431'; // name(bytes)
		ret.name = ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).add_hex(node))).string();
	}
	return ret;
}

// https://medium.com/the-ethereum-name-service/step-by-step-guide-to-setting-an-nft-as-your-ens-profile-avatar-3562d39567fc
async function ens_avatar(provider, input) {
	let ret = await resolve_name_from_input(provider, input);
	let {node, resolver, address} = ret;
	if (is_null_hex(resolver)) return {type: 'none', ...ret};
	if (!address) ret.address = address = await call_resolver_addr(provider, resolver, node);
	let avatar = await call_resolver_text(provider, resolver, node, 'avatar');
	if (avatar.length == 0) return {type: 'null', ...ret}; 
	ret.avatar = avatar;
	if (avatar.includes('://') || avatar.startsWith('data:')) return {type: 'url', ...ret};
	// parse inline format
	let parts = avatar.split('/');
	let part0 = parts[0];
	if (part0.startsWith('eip155:')) {
		if (parts.length < 2) throw new Error('Invalid avatar format: expected type');
		let chain = parseInt(part0.slice(part0.indexOf(':') + 1));
		if (chain != 1) throw new Error('Avatar not on mainnet');
		let part1 = parts[1];
		if (part1.startsWith('erc721:')) {
			if (parts.length < 3) throw new Error('Invalid avatar format: expected token');
			let contract = part1.slice(part1.indexOf(':') + 1);
			let token = parts[2];
			let token_big = BigInt(token);
			const SIG_tokenURI = 'c87b56dd'; // tokenURI(uint256)
			const SIG_ownerOf  = '6352211e'; // ownerOf(uint256)
			let [owner, meta_uri] = await Promise.all([
				call(provider, contract, ABIEncoder.method(SIG_ownerOf).big(token_big)),
				call(provider, contract, ABIEncoder.method(SIG_tokenURI).big(token_big))
			]);
			owner = ABIDecoder.from_hex(owner).addr();
			meta_uri = ABIDecoder.from_hex(meta_uri).string();
			return {type: 'erc721', ...ret, contract, token, meta_uri, is_owner: address === owner};
		} else if (part1.startsWith('erc1155:')) {
			if (parts.length < 3) throw new Error('Invalid avatar format: expected token');
			let contract = part1.slice(part1.indexOf(':') + 1);
			let token = parts[2];
			let hex_token = BigInt(token).toString(16).padStart(64, '0'); // no 0x
			const SIG_tokenURI  = '0e89341c'; // uri(uint256)
			const SIG_balanceOf = '00fdd58e'; // balanceOf(address,uint256)
			let [balance, meta_uri] = await Promise.all([
				call(provider, contract, ABIEncoder.method(SIG_balanceOf).addr(address).add_hex(hex_token)),
				call(provider, contract, ABIEncoder.method(SIG_tokenURI).add_hex(hex_token))
			]);
			balance = ABIDecoder.from_hex(balance).number();
			meta_uri = ABIDecoder.from_hex(meta_uri).string().replace(/{id}/, hex_token); // 1155 standard
			return {type: 'erc1155', ...ret, contract, token, meta_uri, is_owner: balance > 0};
		} 			
	}
	return {type: 'unknown', ...ret};	
}

// https://eips.ethereum.org/EIPS/eip-634
// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/TextResolver.sol
async function ens_text_record(provider, input, keys) {
	if (typeof keys === 'string') keys = [keys];
	if (!Array.isArray(keys)) throw new TypeError('Expected key or array of keys');
	let ret = await resolve_name_from_input(provider, input);
	let {node, resolver} = ret;
	if (!is_null_hex(resolver)) {
		let values = await Promise.all(keys.map(x => call_resolver_text(provider, resolver, node, x)));
		ret.text = Object.fromEntries(keys.map((k, i) => [k, values[i]]));
	}
	return ret;
}

// https://eips.ethereum.org/EIPS/eip-2304
// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/AddrResolver.sol
async function ens_addr_record(provider, input, addresses) {
	if (!Array.isArray(addresses)) addresses = [addresses];
	addresses = addresses.map(resolve_addr_type_from_input); // throws
	let ret = await resolve_name_from_input(provider, input);
	let {node, resolver} = ret;
	if (!is_null_hex(resolver)) {
		let values = await Promise.all(addresses.map(([_, type]) => call_resolver_addr_for_type(provider, resolver, node, type)));
		ret.addr = Object.fromEntries(addresses.map(([name, _], i) => [name, values[i]]));
	}
	return ret;
}

// https://eips.ethereum.org/EIPS/eip-1577
// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/ContentHashResolver.sol
async function ens_contenthash_record(provider, input) {
	let ret = await resolve_name_from_input(provider, input);
	let {node, resolver} = ret;
	if (!is_null_hex(resolver)) {
		const SIG = 'bc1c58d1'; // contenthash(bytes32)
		let v =ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).add_hex(node))).memory();
		if (v.length > 0) {
			ret.contenthash = v;
			// https://github.com/multiformats/multicodec
			let dec = new ABIDecoder(v);
			if (dec.uvarint() == 0xE3) { // ipfs
				if (dec.byte() == 0x01 && dec.byte() == 0x70) { // check version and content-type
					ret.contenthash_url = `ipfs://${base58_from_bytes(dec.read(dec.remaining))}`;
				}
			}
		}
	}
	return ret;
}

// https://github.com/ethereum/EIPs/pull/619
// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/PubkeyResolver.sol
async function ens_pubkey_record(provider, input) {
	let ret = await resolve_name_from_input(provider, input);
	let {node, resolver} = ret;
	if (!is_null_hex(resolver)) {
		const SIG = 'c8690233'; // pubkey(bytes32)
		let dec = ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).add_hex(node)));
		ret.pubkey = {x: dec.read(32), y: dec.read(32)};
	}
	return ret;
}

// see: test/build-address-types.js
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
function resolve_addr_type_from_input(x) {
	if (typeof x === 'string') {
		let type = ADDR_TYPES[x];
		if (typeof type !== 'number') throw new Error(`Unknown address type for name: ${x}`);
		return [x, type];
	} else if (typeof x === 'number') {		
		let pos = Object.values(ADDR_TYPES).indexOf(x);
		let name;
		if (pos >= 0) {
			name = Object.keys(ADDR_TYPES)[pos];
		} else {
			name = '0x' + x.toString(16).padStart(4, '0');
		}
		return [name, x];
	} else {
		throw new TypeError('Expected address type or name');
	}
}

// turn a name/address/object into {name, node, resolver}
async function resolve_name_from_input(provider, input) {
	if (typeof input === 'object') { // previously resolved object? 
		if (RESOLVED in input) return input; // trusted
		input = input.name ?? input.address; // fallback
	}
	if (typeof input === 'string') { // name or address
		input = input.trim();
		if (input.length > 0) {
			let ret;
			try { 
				ret = await ens_name_from_address(provider, input); // assume address, will throw if not
			} catch (ignored) {		
				ret = {name: ens_normalize(input)}; // assume name, throws
			}
			let {name} = ret;
			if (!name) throw new Error(`No name for address`);
			let node = namehash(name);
			let resolver = await call_registry_resolver(provider, node);
			return {...ret, node, resolver, [RESOLVED]: resolved_value()};
		}
	}
	throw new TypeError('Expected name or address');
}

async function call_registry_resolver(provider, node) {
	const SIG = '0178b8bf'; // resolver(bytes32)
	try {
		return ABIDecoder.from_hex(await call(provider, ENS_REGISTRY, ABIEncoder.method(SIG).add_hex(node))).addr();
	} catch (cause) {
		throw new Error('Invalid response from registry', {cause});
	}
}

async function call_resolver_addr(provider, resolver, node) {
	const SIG = '3b3b57de'; // addr(bytes32)
	try {
		return ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).add_hex(node))).addr();
	} catch (cause) {
		throw new Error('Invalid response from resolver for addr', {cause});
	}
}

async function call_resolver_text(provider, resolver, node, key) {
	const SIG = '59d1d43c'; // text(bytes32,string)
	try {
		return ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).add_hex(node).string(key))).string();
	} catch (cause) {
		throw new Error(`Invalid response from resolver for text: ${key}`, {cause});
	}
}

async function call_resolver_addr_for_type(provider, resolver, node, type) {
	const SIG = 'f1cb7e06'; // addr(bytes32,uint256);
	try {
		return ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).add_hex(node).number(type))).memory();
	} catch (cause) {
		throw new Error(`Invalid response from resolver for addr of type: 0x${type.toString(16).padStart(4, '0')}`, {cause});
	}
}

function call(provider, to, enc) {
	if (typeof provider === 'object') {
		if (provider.request) {
			provider = provider.request.bind(provider); 
		} else if (provider.sendAsync) { // support boomer tech
			provider = provider.sendAsync.bind(provider);
		} // what else?
	}
	if (typeof provider !== 'function') throw new TypeError('unknown provider');
	return provider({method: 'eth_call', params:[{to, data: enc.build_hex()}, 'latest']});
}

// TODO: this is still a work in progress
function smol_provider(url, WebSocket) {
	const CONNECT_TIMEOUT = 10000;
	const REQUEST_TIMEOUT = 5000;
	let _ws, _id, _reqs;
	return async (args) => {
		if (_ws === undefined) { // disconnected state
			let queue = _ws = []; // change state		 
			let s = new WebSocket(url);
			let timer, ful;
			try {  
				await new Promise((ful, rej) => {
					ful = ful;
					rej = rej;
					timer = setTimeout(() => rej(new Error('Timeout')), CONNECT_TIMEOUT);
					s.addEventListener('close', rej);
					s.addEventListener('error', rej);
					s.addEventListener('open', ful, {once: true});
				});
			} catch (err) {
				_ws = undefined; // reset state
				s.removeEventListener('open', ful);
				for (let {rej} of queue) rej(err);
				s.close();
				throw err;
			} finally {
				clearTimeout(timer);
			} 
			s.removeEventListener('error', ful);   
			s.removeEventListener('close', ful);	  
			_ws = s; // connected state
			_id = 0;
			_reqs = {};
			for (let {ful} of queue) ful();
			s.addEventListener('message', ({data}) => {
				let json = JSON.parse(data);
				let request = _reqs[json.id];
				if (!request) return;
				delete _reqs[json.id];
				clearTimeout(request.timer);
				let {result, error} = json;
				if (result) return request.ful(result);
				let err = new Error(error?.message ?? 'Unknown Error');
				if ('code' in error) err.code = error.code;
				request.rej(err);
			});
			function die(err) {
				if (s !== _ws) return;
				_ws = undefined; // reset state
				for (let {rej} of Object.values(_reqs)) rej(err);
				_reqs = undefined;
			}
			s.addEventListener('close', (e) => die(Error('Unexpected close')));
			s.addEventListener('error', die);
		} else if (Array.isArray(_ws)) { // already connecting
			await new Promimse((ful, rej) => {
				_ws.push({ful, rej});
			});
		}
		let id = ++_id; 
		let reqs = _reqs;
		return new Promise((ful, rej) => {			  
			let timer = setTimeout(() => {
				delete reqs[id];
				rej(new Error('Timeout'));
			}, REQUEST_TIMEOUT);
			_reqs[id] = {timer, ful, rej};
			_ws.send(JSON.stringify({jsonrpc: '2.0', id, ...args}));
		});
	};
}

class FetchProvider {
	constructor(url, fetch_api) {
		if (!fetch_api) fetch_api = globalThis.fetch.bind(globalThis); 
		if (typeof fetch_api !== 'function') throw new TypeError('fetch api should be a function');
		if (typeof url !== 'string') throw new TypeError('expected url');
		this.fetch_api = fetch_api;
		this.url = url;	
		this.id = 0;
		this.retry_max = 2;
		this.retry_ms = 2000;
	}
	async request(obj, attempt = 0) {
		if (typeof obj !== 'object') throw new TypeError('expected object');
		let res = await this.fetch_api(this.url, {
			method: 'POST',
			body: JSON.stringify({...obj, jsonrpc: '2.0', id: ++this.id})
		});
		if (res.status !== 200) throw new Error(`provider error: ${res.status}`);
		let json;
		try {
			json = await res.json();
		} catch (err) {
			throw new Error('expected json');
		}
		let {error} = json;
		if (error) { // assume object?		
			if (error.code === -32000 && attempt < this.retry_max) {
				// "header not found" bug?
				await new Promise(ful => setTimeout(ful, this.retry_ms));
				return this.request(obj, attempt + 1);
			}
			let err = new Error(error.message ?? 'unknown rpc error');
			err.code = error.code;
			throw err;
		}
		return json.result;
	}
}

export { ABIDecoder, ABIEncoder, ADDR_TYPES, FetchProvider, base58_from_bytes, bytes_from_hex, bytes_from_str, checksum_address, ens_addr_record, ens_address_from_name, ens_address_from_node, ens_avatar, ens_contenthash_record, ens_name_from_address, namehash as ens_node_from_name, ens_normalize, ens_pubkey_record, ens_text_record, get_mapped, hex_from_bytes, idna, is_combining_mark, is_disallowed, is_ignored, is_null_hex, is_valid_address, keccak, namehash, number_from_abi, sha3, shake, smol_provider, str_from_bytes };
