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

// returns Uint8Array from hex
// 0x- is optional
// accepts hex-string of even length
function bytes_from_hex(s) {
	if (typeof s !== 'string') throw TypeError('expected string');
	let {length} = s;
	if (length & 1) throw new TypeError('expected string of hex bytes');
	let pos = 0;
	if (s.startsWith('0x')) pos += 2;
	let len = (length - pos) >> 1;
	let v = new Uint8Array(len);
	for (let i = 0; i < len; i++) {
		let b = parseInt(s.slice(pos, pos += 2), 16);
		if (Number.isNaN(b)) throw new TypeError('expected hex byte');
		v[i] = b;
	}
	return v;
}

// returns hex from Uint8Array
// no 0x-
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

function is_null_address(s) {
	return /^(0x)?[0]{40}$/i.test(s);
}

/*
export function method_signature(x) {
	if (typeof x === 'string') {	
		return keccak().update(x).hex.slice(0, 8);
	} else {
		throw new TypeError('unknown input');
	}
}
*/

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
	big(n = 32) { return BigInt('0x' + hex_from_bytes(this.read(n))); }
	number(n = 32) { return number_from_abi(this.read(n)); }
	string() {
		let pos = this.number();
		let end = pos + 32;
		let {buf} = this;
		if (end > buf.length) throw new RangeError('overflow');
		let len = number_from_abi(buf.subarray(pos, end));
		pos = end;
		end += len;
		if (end > buf.length) throw new RangeError('overflow');
		return decodeURIComponent([...buf.subarray(pos, end)].map(x => `%${x.toString(16).padStart(2, '0')}`).join(''));
	}
	addr(checksum = true) {
		if (this.number(12) != 0) throw new TypeError('expected zero');
		let v = this.read(20);
		let addr = hex_from_bytes(v);
		return checksum ? checksum_address(addr) : `0x${addr}`; 
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
			enc.bytes(keccak().update(method).bytes.subarray(0, N));
		} else {
			enc.hex(method);
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
		return this;
	}
	number(i, n = 32) {
		set_bytes_to_number(this.alloc(n), i);
		return this; // chainable
	}
	string(s) {
		if (typeof s !== 'string') throw new TypeError('expcted string');
		let {pos} = this; // remember offset
		this.alloc(32); // reserve spot
		let v = bytes_from_str(s);
		let tail = new Uint8Array((v.length + 63) & ~31); // len + bytes + 0*
		set_bytes_to_number(tail.subarray(0, 32), v.length);
		tail.set(v, 32);
		this.tails.push([pos, tail]);
		return this; // chainable
	}
	hex(s) { return this.bytes(bytes_from_hex(s)); } // throws
	bytes(v) {
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
	addr(x) {
		let v = bytes_from_hex(x); // throws
		if (v.length != 20) throw new TypeError('expected address');
		this.alloc(32).set(v, 12);
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
const TABLE_W = [decode2(bytes_from_base64('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')), decode2(bytes_from_base64('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')), decode2(bytes_from_base64('4DPNi7/pu/58y9/03f9GV3/Rd/z/HZzz2+cAceWzcA8e5DO+g+QBzAcBtXfnHbsarpy7FeAt7/pu/5k19/03f8qr+/6bv+hJ7/pO/6Evv+m7/nTL3/Sd/zpff9F3/Ok9/0Hf86Z+/6bv+bJ7/nu/5s09/03f8uae/6Lv+XMvf893/Lk9/zXf8vJsQEmNYyJcex0TgCTGsZEuPY6Ltx7/qO/6HgMk8PcAHMBx/QeF/dGO7zs5/8admB/8adlo/8adlx/8adlq/8adli/8ab4uNYqqsQx/NPf/zgM0yFcBbwGPbGc1m4DFHwGI8BiW5nHeAyTNztNvAWPe+AVh4C3gLspWv51sU/AYvuWIya7wGLcBKa9w0E5bwGJZ7Joe4bGa9w1U37xwEsuVYrUbtV0BY1q23vINJ3ibK8oxR5jjtxsybTTlmZbmdC0TgJzoWjbys6x7RVlWWamck0LITj+hYisp3PgLjjOa4wcexrd6NqzDZTm2YZCaeAn4DInfluoSYzq9Vfwdaf/Gw8kf/Gw8eP/Gw8gf/Gw8ev/Gw8cf/Gw8fJ/42HjD/42Hj5v/Gw8Uf/Gw8fR/42HiD/42Hj6v/Gw8Mf/Gw8fZ/42HhD/42Hj7v/Gw8Ef/Gw8fiH/jYeAP/jYeNf/jYeSP/jYeNP/jYeQP/jYeNH/jYeOP/jYeNX/jYeMP/jYeNk/8bDxR/8bDkOIY60cikxvEt1OyYlud+wPFqTLkhxmnJDkqyQ14vkleMjdTsWKbqtyk3U7sNzOwYpua3CTczunheh4Xhu+rHTjE2OmzEsdORZDNkuITXuyeYqSV0CWXEvC77wvPOL+F9HhefVu5/8aX9R/8aX84/8aX9B/8aX86/8aX8x/8aX88n/jS/kP/jS/nm/8aX8R/8aX89H/jS/gP/jS/nq/8aX7x/8aX89n/jS/cP/jS/nu/8aX7R/8aX8+If+NL9g/+NL+V/+NL+o/+NL+U/+NL+g/+NL+Uf+NL+Y/+NL+Vf+NL+Q/+NL+WT/xpfxH/xpfyzf+NL+A/+NL+Wj/xpfvH/xpfy1f+NL9w/+NL+Wz/xpftH/xpfy3f+NL9g/+NL+OX/xpf1H/xpfxv/xpf0H/xpe914t/40fhKxMZRZlHFb1rNR1DWbOB0XgN8xyY5Dj0hyHIFrmmyZkc1mJcxLmzA5rRlxzXNsxLzbLzLm2Wl5ll5OZZeRmFRznMKDldZN1qNludHK8ky82ZJl5syTMTdkgOR5IDj94OIXg4hkAOQ25gchtzA5DfnhyvIstNmRZabMiByHIgcdxHODkt+XHHb8uON45l5xTHMvOKY4DjeOVHIcZzI4vjAOL4wDi+MUHHcWBxXFqjj+LUG/JcuM+S5cZZsvOVTAnLcwJy3OjXlucGnLwcwy8HMMry4nK8uJWXnLll5zDLycyy/MCMvzo05ijmGY5kRlrOZZblzGYyHMnmJzZgrMcwKzHODLmeZFZnmRWZ50ZTUZzQVSDVSDnNmcHP5M8OfyZ0c9ozg5/Rmxz3Nqjn+bUHOcyqOdrODnOZUHK6c2OT350crtzo5PiOdGvL88NaqIznOiM7zwimo0io3zVGfMc6N82XnLstzA4vjFRtkqM+Zo5hlucGvL8yLkBOX5kVmaJWdHOTnhpzHPDiNFR0OrOjbIDi+M5kcfyAHI6c4M+Z55lOU49wHOHgOfk4DnKOA7nHqv/Gp/P/7xbnsaxI5XjWKHLcaxY5fjWMHMcaxrWeAu4DJ8SPAYxwGU4keAxbgMnxQ8Bi3AZTinPfV/68PNfe8H3vEyT3vJFnAbl73efb2H29aT3e1d3s5Pebh3m2k+ttXrbOT/4Plf+D45Px/98f9k/+Lpv/FzJ8XEvFvJ+qb6n8=')), bytes_from_base64('n9e/5AAAAIB7v4G/pr+lARWADBkAABAaGQAAiBXDBAAAAIh0nG5eVmcBS4ASK2cBAoAiMW8CBE5QgAUED4AogCGAIgSAIXxLCgE5gAQFJAWAHXAKJAGAG3pVeAiAGXweXQQvIRZ4AmdmEoAFDEBYHwEGK2OAMmcKKnGAHlUGLHMWfAUbX3wMBCNpOFYBIzZnRgQBTQpGAwAiSyor7f6RtZ9p08gK/wByJQ8DFh8CwtDCw4ABHmLC5MLTB/8ASqyLADoABgE/ODUSASgvMCsBDB4VGAEnBCoHARUWDAUBAikiAgQngLaAyTo='), bytes_from_base64('sofg0CITgBplDjeAAHlyEQJlgAAEVwoCL3IRL1YBgAd4XS+AEgZvfGN2NwsdVoABcFUDGGMuHkYEK2eAEEsMAholFx+ACAIlUSB6IREZKndgGAMnFjNYIQwCDlUrgAJY4IEhBsLiwsM='), bytes_from_base64('spbg2oAAFzZnRoAZ4HEhBsLiwsOAAQ==')];
// CheckJoiners [DerivedGeneralCategory.txt]
const TABLE_M = decode2(bytes_from_base64('4LgNw4Dk5+A4fLSSiidIrzDFcQOyzqZIyZGcexvW686ppOMSGksy5W88oyrGDkObM4kZ6ljrzgmdJOk1LGinnBMsiTZx5M1vOCaCy8UWLTF5wTOknO6ljxzuVsyUnKJc3JnLMk6rWOvOCZyzJOq1jkmbozlmSk1LHXoxkmJNGJLPSp7KNiKprm0pY2SSZFmOKFS1nJKTsmKYvJIy1O5LbCapOCz98HmUmOPHVjy0DIKTlrJ3VZEd2sks4DW5c5qOOo5hj+Yy5fiOTU2PHrc4uzDFOAxhnFZDMU+A0bQOC1DIeL358BadgyDgeqm2lfrqkhqyBaguA5AsyHF5ZDqazLEsaxK05NRjNuWSZfdkh0O6w0LLXmRLSlROUyyrgNsoK87sDwWw4hiGIcHpp4DYjwGKy8NMypZMoch4DJVwPeycC1wGM15jJvTzW/KSlVJltc5z15JdiCyw2PMLqJCtcsmPAZBZismbozpJ0mpKdy8BoGJYudRxTgNrnVONrUsR2q3Zb+A4C/gN1mKUhJXAWzqdnHKsonMlBpry7EOBxWg0alixu3qZkozk6FKUZeA9uTy95lzufg+YJzeeTUTWvMytcj8OXLF+B56VzUUKfHpOAxR8PnebyZlQbji0pv4T0JziKnKMvAcLPwH7nPZOF2CfbZ//r5jNeA3D'));
// CONTEXTJ [DerivedCombiningClass.txt, DerivedJoiningType.txt]  
const TABLE_V = bytes_from_base64('iM2AAIAAgACAAIAAgACAAG4BEX1wgACASoA1AYZaAR+AHoIOgGRmAUcBkQz6ByaAGIAPbYC2gHfd0oWHKg86egGADHWANWOAdYAAgH2AAHd1gI6AhAGAIlQTUoEmgIUBUg==');
const TABLE_LD = decode2(bytes_from_base64('4XoDKSTLJaZysjVGIYlkxVJJKyho4k5ZDSSSVj9bvUhKam0rIdWlRNRNRMiOOlS4lVKlMb+O744xrN2RE/+MQxXM/h82Wgy1F1ScBiJJbKJRxxcB6ORE8DxjOI2PHJFZlxKkKRRKMq/8az2miQ=='));
const TABLE_RD = decode2(bytes_from_base64('4XoCceNWRos6+TjCqaOIE49juZ6VkOq4zOTIZJcTZU2I2nG+O744xrN2RE/+MQxXMvh86Ykp0mpGaXgMQxLF5uA9LI+B4zFbJMbxLLiZTQZJF/41ntdE'));
const TABLE_T = decode2(bytes_from_base64('4DLTwPpbhwHJz8Bw+WklFE6RWTl2K4gdlnUyRkyEk49jet151TScYkNJZlyt55RlWMHIM3JMlEhc9Sx050ZJKDiixopZyZFIk2ceTNazkySlSHFFi0xOdFEyUGdVrHjnpsOZFnNyXKzJOq1jpzoozGVYoscWcqSSg4osdOkGdk60VPZRsRVNc2lLGySTm9xlKlrOSUnZpDMUljKkeISWlKY3ngs/fB5k8dWPLHloCM9BVdJy1k7qsiO7ORUmZ8BraRzomcklUTVI5hj+YyZgTKTKcopsWQSJF5wSmS86oS4DGGbTPIZi1wGjaBwPFlLGpcxllm2DIeL358BadgyDgeqk2tfrqkhqyBaguA5AsyHGVKeAxdY1iVpyajGa8ueYFSJZOdDmSSsNBy85mS0pUTlSoPAbcUZD53YHgthxDEMQ4DTzwG8vgeBPAbEeAxWXhpmVLJlDkPAZKuB72TgWuAxmvMZN7ObX5SUqnmMiU5z15JKaM+NizSmqRHX2iVMeAyAujFVnKZyWdy8BodCZOLnVJiZEVwG3STIrG1qtCJW1ElTE7K1IZeA4OkrgOARMh4DEJEpDkFWUTKSg0zJ5daVwOLTmYnUsWU5RW9TMlGcnSEyTwHtrlO7p7bN5c7n4PmDn8monzM4Rk5H3MuWL8D0DpxBT49JwGKPh87zeTMqDccWlN/CehOcRU5Rl4DhZ+A/c57JwuwT7bR/9fL5qce2DgBwG4Q=='));
// emoji-zwj-sequences.txt
const ZWNJ_EMOJI = (() => {
	let r = new TableReader(decode2(bytes_from_base64('snxX/3tOoAAAIADztI/941xACA/941xI/941xQH/vaeW0lAoaQNJQ/97TqDCISUoWISy/+9p1AAAAIAADitQ87SP/eNcIggh/7xriR/7xrhEJBxH0f+9p1BhFFJShFcVqmKSr/3u2xAAAAAAAAAD/3tG7ABABABABAD/3u2yAAAAAAAAAD/3tG8JKeRKdSKdKSdJa/TlX/vadQAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAA4rUAAAAAAAAAB/72jdgAEAAgAEAAgAJwAAAAgAAAAgAAAAgAAAAgAAABOAEAEAEAEAPO0gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/3tPLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAf+9p1AAAAAAAAAAAAAAAIAAgAIAAgAIAAgAIAAgAIADitQAAAAAAAAAH/vaN2SSnSSnSSnSSnSSnSSnSSnSSnSSnSSnSSnSSnSSnSSnSSlSU8iU6kU6Uk6S4DNJ6v/e06gAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABxWoAAAAAAAAAAAAAAAAAAAAAAf+9o3YAAABAAAAIAAABAAAAIAAACcAAAAAAAAIAAAAAAAAIAAAAAAAAIAAAAAAAAIAAAAAAAATgAAAIAAABAAAAIAAABAAAAedpAAH/vI/yAH/vI/xAA/95H+QA/95H+IAH/vI/yAH/vI/xAA/95H+QA/95H+IAH/vI/yAH/vI/xAAAAH/vI/yAAAH/vI/xAAAAH/vI/yAAAH/vI/xAAAAH/vI/yAAAH/vI/xAAAAH/vI/yAAAH/vI/xAAAAH/vI/yAAAH/vI/xAH/vI/yAA/95H+IA/95H+QAH/vI/xAH/vI/yAA/95H+IA/95H+QAH/vI/xAH/vI/yAA/97TqAAAAAAAAAAAAAAAAAAAAAAAAAQABACABAAQABACABAAQABACABAAQABACABAAQABACAHFagAAAAAAAAAAAAAAAAAAAAAB/72jdkkpUlOklPIlOklOpFOklOlJOklOkpUkp0kpUlKkp0kp0kp5Ep5Ep0kp0kp1Ip1Ip0kp0kp0pJ0pJ0kp0kp0lKkmkp0kp5Ep0kp1Ip0kp0pJ0kp0lKklwGfs/+9p1AIEAAAAAAAAAIAAAAAAAAAcVqAAAAAAAAAA/95Nl4/941igQsCCHAeIEEEJBQMUCFAQ4HXBwOQBBCgSBDgMqGRBBDhNgGPCQIITBBDgN0CGUBBCoSBBBBBBBBBDittACAHFagAP/eS6yP/eM88FlGNaZZwetXLhu2/97TpiK/945ka4DZP/eMfZtWJZdkVHATScDji4DVquCyjJOF7rGl/7ybz1wGyf+8Y+zasSy7IqOAmk4HHFwGrVcFlGScL3WNL/3k3nrgNk/94x9m1Yll2RUcBNJwOOLgNWq4LKMk4XusaX/vJ95kcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjkcjk/95PriSlSUqS4jm+Kyj/3lGR/+8Z0L/3jWn8Tu3/vHe+/95Ltf/vHfI4H/5uC3/gMy4Lw5F/73TIgAOK1EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcVqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/95Nl4AAAA/941igAAAAQAAAAsAAAACAAAACAAAAHAeIAAAAJAAAAAgAAABIAAAAKAAAABigAAAAQAAAAoAAAACAAAAHA64AAAAOByAAAAAIAAAAIAAAAUAAAACQAAAAIAAAAcBlQAAAAyIAAAAIAAAAIAAAAcJsAAAAAx4AAAASAAAABAAAABAAAACgAAAAIAAAAcBugAAAAQAAAAygAAAAIAAAAIAAAAVAAAACQAAAAIAAAAIAAAAIAAAAIAAAAIAAAAIAAAAIAAAAcVtIAAAAAAAAAQAAAAAAAAA4rUAAAAAAAAAB/72jdkkpwAAAAAAAAAgAAAAAAAAAgAAAAAAAAAgAAAAAAAAAgAAAAAAAABOAAAAAAAAAEAAAAAAAAAEAAAAAAAAAEAAAAAAAAAEAAAAAAAAAJwAAAAAAAAAgAAAAAAAAAgAAAAAAAAAgAAAAAAAAAgAAAAAAAABOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwggghOEEEEJwAgAgAgAgBOAEAEAEAEAJwAgAgAgAgB/72fiAAP/eNa6uA2T/3jH2bViWXZFRwE0nA44uA1argsoyThe6xpf+8m89cBsn/vGPs2rEsuyKjgJpOBxxcBq1XBZRknC91jS/95N564DZP/eMfZtWJZdkVHATScDji4DVquCyjJOF7rGl/7ybz1wGyf+8Y+zasSy7IqOAmk4HHFwGrVcFlGScL3WNL/3k3nrgNk/94x9m1Yll2RUcBNJwOOLgNWq4LKMk4XusaX/vJvPXAbJ/7xj7NqxLLsio4CaTgccXAatVwWUZJwvdY0v/eTeeuA2T/3jH2bViWXZFRwE0nA44uA1argsoyThe6xpf+8m89cBsn/vGPs2rEsuyKjgJpOBxxcBq1XBZRknC91jS/95N564DZP/eMfZtWJZdkVHATScDji4DVquCyjJOF7rGl/7ybz1wGyf+8Y+zasSy7IqOAmk4HHFwGrVcFlGScL3WNL/3k3nrgNk/94x9m1Yll2RUcBNJwOOLgNWq4LKMk4XusaX/vJvPXAbJ/7xj7NqxLLsio4CaTgccXAatVwWUZJwvdY0v/eTeeuA2T/3jH2bViWXZFRwE0nA44uA1argsoyThe6xpf+8m89cBsn/vGPs2rEsuyKjgJpOBxxcBq1XBZRknC91jS/95N564DZP/eMfZtWJZdkVHATScDji4DVquCyjJOF7rGl/7yfeZHI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5HI5P/eT64kpUlKkpUlKkpUlKkpUlKkpUlKkpUlKkpUlKkg==')));
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

// expects a string
// returns 64-char hex-string, no 0x-prefix
// https://eips.ethereum.org/EIPS/eip-137#name-syntax
function ens_namehash(name) {
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

// https://docs.ens.domains/ens-deployments
const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'; // ens registry contract on mainnet

// https://eips.ethereum.org/EIPS/eip-137
async function ens_address_from_name(provider, name0) {	
	let name = ens_normalize(name0); // throws
	let namehash = ens_namehash(name);
	let resolver = await call_resolver(provider, namehash);
	let address = false;
	if (!is_null_address(resolver)) {
		address = await call_resolver_addr(provider, resolver, namehash);
	}
	return {name, name0, namehash, resolver, address};
}

// https://eips.ethereum.org/EIPS/eip-181
async function ens_name_from_address(provider, address) {
	address = checksum_address(address); // throws
	let namehash = ens_namehash(`${address.slice(2).toLowerCase()}.addr.reverse`); 
	let resolver = await call_resolver(provider, namehash);
	let name = false;
	if (!is_null_address(resolver)) {			
		const SIG = '691f3431'; // name(bytes)
		name = ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).hex(namehash))).string();
	}
	return {address, namehash, resolver, name};
}

// https://medium.com/the-ethereum-name-service/step-by-step-guide-to-setting-an-nft-as-your-ens-profile-avatar-3562d39567fc
async function ens_avatar(provider, input) {
	let name, address = false;
	try {
		// if the name is actually an address, reverse it
		// this will bail immediately if not an address
		({name, address} = await ens_name_from_address(provider, input)); 
	} catch (ignored) {		
		name = ens_normalize(input); // throws
	}
	if (name === false) throw new Error(`No name for address`);
	let namehash = ens_namehash(name);
	let resolver = await call_resolver(provider, namehash);
	if (is_null_address(resolver)) {
		return {type: 'none', name};
	}
	if (!address) {
		address = await call_resolver_addr(provider, resolver, namehash);
	}
	let avatar = await call_resolver_text(provider, resolver, namehash, 'avatar');
	if (avatar.length == 0) { 
		return {type: 'null', name, address};
	}
	if (avatar.includes('://') || avatar.startsWith('data:')) {
		return {type: 'url', name, address, avatar};
	}
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
			meta_uri = ABIDecoder.from_hex(meta).string();
			return {type: 'erc721', name, address, avatar, contract: contract, token, meta_uri, is_owner: address === owner};
		} else if (part1.startsWith('erc1155:')) {
			if (parts.length < 3) throw new Error('Invalid avatar format: expected token');
			let contract = part1.slice(part1.indexOf(':') + 1);
			let token = parts[2];
			let hex_token = '0x' + BigInt(token).toString(16).padStart(64, '0');
			const SIG_tokenURI  = '0e89341c'; // uri(uint256)
			const SIG_balanceOf = '00fdd58e'; // balanceOf(address,uint256)
			let [balance, meta_uri] = await Promise.all([
				call(provider, contract, ABIEncoder.method(SIG_balanceOf).addr(address).hex(hex_token)),
				call(provider, contract, ABIEncoder.method(SIG_tokenURI).hex(hex_token))
			]);
			balance = ABIDecoder.from_hex(balance).number();
			meta_uri = ABIDecoder.from_hex(meta_uri).string().replace(/{id}/, hex_token); // 1155 standard
			return {type: 'erc1155', name, address, avatar, contract: contract, token, meta_uri, is_owner: balance > 0};
		} 			
	}
	return {type: 'unknown', name, address, avatar};	
}

async function call_resolver(provider, namehash) {
	const SIG = '0178b8bf'; // resolver(bytes32)
	try {
		return ABIDecoder.from_hex(await call(provider, ENS_REGISTRY, ABIEncoder.method(SIG).hex(namehash))).addr();
	} catch (err) {
		throw wrap_error('Invalid response from registry', err);
	}
}

async function call_resolver_addr(provider, resolver, namehash) {
	const SIG = '3b3b57de'; // addr(bytes32)
	try {
		return ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).hex(namehash))).addr();
	} catch (err) {
		throw wrap_error('Invalid response from resolver for addr()', err)
	}
}

async function call_resolver_text(provider, resolver, namehash, key) {
	const SIG = '59d1d43c'; // text(bytes32,string)
	try {
		return ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).hex(namehash).string(key))).string();
	} catch (err) {
		throw wrap_error(`Invalid response from resolver for text(${key})`, err);
	}
}

function call(provider, to, enc) {
	if (typeof provider === 'object') {
		let og = provider;
		if (og.request) {
			provider = (...a) => og.request(...a);
		} else if (og.sendAsync) {
			provider = (...a) => og.sendAsync(...a);
		}
	}
	if (typeof provider !== 'function') throw new TypeError('unknown provider');
	return provider({method: 'eth_call', params:[{to, data: enc.build_hex()}, 'latest']});
}

function wrap_error(s, err) {
	let wrap = new Error(s);
	wrap.reason = err;
	return wrap;
}

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
		if (!fetch_api) fetch_api = fetch;
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

export { ABIDecoder, ABIEncoder, FetchProvider, bytes_from_hex, bytes_from_str, checksum_address, ens_address_from_name, ens_avatar, ens_name_from_address, ens_namehash, ens_normalize, get_mapped, hex_from_bytes, idna, is_combining_mark, is_disallowed, is_ignored, is_null_address, is_valid_address, keccak, number_from_abi, sha3, shake, smol_provider, str_from_bytes };
