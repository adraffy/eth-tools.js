// TODO: figure out why Int32Array/Uint32Array is slow

// primary api
function keccak(bits = 256) { return new Fixed(bits,        0b1); } // [1]0*1
function sha3(bits = 256)   { return new Fixed(bits,      0b110); } // [011]0*1
function shake(bits)        { return new Extended(bits, 0b11111); } // [11111]0*1

// returns hex from Uint8Array
// no 0x-prefix
function hex_from_bytes(v) {
	return [...v].map(x => x.toString(16).padStart(2, '0')).join('');
}
// accepts hex-string, 0x-prefix is optional
// returns Uint8Array
function bytes_from_hex(s) {
	if (typeof s !== 'string') throw TypeError('expected string');
	if (s.startsWith('0x')) {
		if (s.length == 2) throw new TypeError('expected digits'); // disallow "0x"
		s = s.slice(2);
	}
	if (s.length & 1) {
		s = `0${s}`; // zero-pad odd length (rare)
	}
	let len = s.length >> 1;
	let v = new Uint8Array(len);
	for (let i = 0, pos = 0; i < len; i++) {
		let b = parseInt(s.slice(pos, pos += 2), 16);
		if (Number.isNaN(b)) throw new TypeError('expected hex byte');
		v[i] = b;
	}
	return v;
}

// returns Uint8Array from string
// accepts only string
function bytes_from_utf8(s) {
	if (typeof s !== 'string') throw TypeError('expected string');
	try {
		s = unescape(encodeURIComponent(s));
	} catch (cause) {
		throw new Error('malformed utf8', {cause});
	}
	let {length} = s;
	let v = new Uint8Array(length);
	for (let i = 0; i < length; i++) {
		v[i] = s.charCodeAt(i);
	}
	return v;
}
function utf8_from_bytes(v) {
	try {
		return decodeURIComponent(escape(String.fromCharCode(...v)));
	} catch (cause) {
		throw new Error('malformed utf8', {cause});
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
				v = bytes_from_utf8(v);
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
			if (ragged_shift == -1) return; // already finalized
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
		let {size, sponge} = this;
		let v = new Int32Array(size);
		for (let i = 0; i < size; i++) {
			v[i] = sponge[i];
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

function compare_arrays(a, b) {
	let {length: n} = a;
	let c = n - b.length;
	for (let i = 0; c == 0 && i < n; i++) c = a[i] - b[i];
	return c;
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

function is_checksum_address(s) {
	try {
		return checksum_address(input_name) === input_name;
	} catch (ignored) {
	}
}

function is_null_hex(s) {
	return /^(0x)?[0]+$/i.test(s);
}

const NULL_ADDRESS = '0x0000000000000000000000000000000000000000';

function is_multihash(s) {
	try {
		let v = bytes_from_base58(s);
		return v.length >= 2 && v.length == 2 + v[1];
	} catch (ignored) {
		return false;
	}
}

class Uint256 {
	static zero() {
		return new this(new Uint8Array(32));
	}
	static from_number(i) {
		return this.zero().set_number(i);
	}
	static from_bytes(v) { 
		return new this(left_truncate_bytes(v, 32));
	}
	static from_hex(s) {
		return this.from_bytes(bytes_from_hex(s));
	}
	static from_dec(s) {
		if (!/^[0-9]+$/.test(s)) throw new TypeError('expected decimal digits');
		let n = s.length;
		if (n < 10) this.from_number(parseInt(s, 10));
		let v = new Uint8Array(Math.max(32, n));
		let w = 0;
		for (let i = 0; i < n; i++) {
			let carry = s.charCodeAt(i) - 0x30;
			for (let i = 0; i < w; i++) {
				carry += v[i] * 10;
				v[i] = carry;
				carry >>= 8;
			}
			while (carry > 0) {
				v[w++] = carry;
				carry >>= 8;
			}
		}
		for (let a = Math.min(w, 15); a >= 0; a--) {
			let b = 31 - a;
			let temp = v[a];
			v[a] = v[b];
			v[b] = temp;
		}
		return new this(v.slice(0, 32));
	}
	static from_str(s) { // this works like parseInt
		return s.startsWith('0x') ? this.from_hex(s) : this.from_dec(s);
	}
	constructor(v) {
		if (!(v instanceof Uint8Array)) throw new TypeError('expected bytes');
		if (v.length != 32) throw new TypeError('expected 32 bytes');
		this.bytes = v;
	}
	compare(v) {
		if (!(v instanceof Uint256)) throw new TypeError('expected Uint256');
		return compare_arrays(this.bytes, v.bytes);	
	}
	set_number(i) {
		set_bytes_to_unsigned(this.bytes, i);
		return this;
	}
	get number() {
		return unsigned_from_bytes(this.bytes);
	}
	get hex() {
		return '0x' + hex_from_bytes(this.bytes);
	}
	get dec() {
		let digits = [0];
		for (let x of this.bytes) {
			for (let i = 0; i < digits.length; ++i) {
				let xx = (digits[i] << 8) | x;
				digits[i] = xx % 10;
				x = (xx / 10) | 0;
			}
			while (x > 0) {
				digits.push(x % 10);
				x = (x / 10) | 0;
			}
		}
		return String.fromCharCode(...digits.reverse().map(x => 0x30 + x));
	}
	toJSON() {
		return this.hex;
	}
	toString() {
		return `Uint256(${this.hex})`;
	}
}

function unsigned_from_bytes(v) {
	if (v.length > 7) {  // 53 bits => 7 bytes, so everything else must be 0
		let n = v.length - 7;
		for (let i = 0; i < n; i++) if (v[i] > 0) throw new RangeError('overflow');
		v = v.subarray(n);
	}
	let n = 0;
	for (let i of v) n = (n * 256) + i;
	if (!Number.isSafeInteger(n)) throw new RangeError('overflow');
	return n;
}

function set_bytes_to_unsigned(v, i) {
	if (!Number.isSafeInteger(i)) throw new RangeError('overflow');	
	if (i < 0) throw new RangeError('underflow'); 	
	for (let pos = v.length - 1; pos >= 0; pos--) {
		v[pos] = i;
		i = Math.floor(i / 256);	
	}
}

// return exactly n-bytes
// this always returns a copy
function left_truncate_bytes(v, n) {
	let {length} = v;
	if (length == n) return v.slice();
	if (length > n) return v.slice(n - length); // truncate
	let copy = new Uint8Array(n);
	copy.set(v, n - length); // zero pad
	return copy;
}

// parse an arbitrarily-sized hex/dec integer
// return null on parse failure
// return null on overflow
// return exactly n-bytes
function bytes_from_digits_or_null(s, n) {
	try {
		let v = parse_bytes_from_digits(s);
		if (v.length > n) return null; // overflow
		return left_truncate_bytes(v, n)
	} catch (ignored) {
		return null;
	}
}

function drop_leading_zeros(v) {
	let {length} = v;
	let i = 0;
	while (i < length && v[i] == 0) i++;
	return v.subarray(i);
}

function parse_bytes_from_digits(s) {
	s = s.trim();
	if (s.startsWith('0x')) return drop_leading_zeros(bytes_from_hex(s));
	let {length} = s;
	if (length == 0) throw new Error('expected digits');
	let n = (length + 1) >> 1;
	let v = new Uint8Array(n);
	let w = n;
	for (let j = 0; j < length; j++) {
		let carry = s.charCodeAt(j) - 48;
		if (carry < 0 || carry > 9) throw new Error('expected decimal digits');
		for (let i = n - 1; i >= w; i--) {
			carry += v[i] * 10;
			v[i] = carry;
			carry >>= 8;
		}
		while (carry > 0) {
			v[--w] = carry;
			carry >>= 8;
		}
	}
	return v.subarray(w);
}

// convenience for making an eth_call
// return an ABIDecoder
// https://eth.wiki/json-rpc/API#eth_call
// https://www.jsonrpc.org/specification
// https://docs.soliditylang.org/en/latest/abi-spec.html
async function eth_call(provider, tx, enc = null, tag = 'latest') {
	if (typeof provider !== 'object') throw new TypeError('expected provider');
	if (typeof tx === 'string') tx = {to: tx};
	if (enc instanceof ABIEncoder) tx.data = enc.build_hex();
	try {
		return ABIDecoder.from_hex(await provider.request({method: 'eth_call', params:[tx, tag]}));
	} catch (err) {
		if (err.code == -32000 && err.message === 'execution reverted') {
			err.reverted = true;
		}
		throw err;
	}
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
		if (end > buf.length) throw new RangeError('buffer overflow');
		let v = buf.subarray(pos, end);
		this.pos = end;
		return v;
	}
	byte() {
		let {pos, buf} = this;
		if (pos >= buf.length) throw new RangeError('buffer overflow');
		this.pos = pos + 1;
		return buf[pos];
	}
	boolean() { return this.number() > 0; }	
	number(n = 32) { return unsigned_from_bytes(this.read(n)); }
	uint256() { return new Uint256(this.read(32)); }
	string() { return utf8_from_bytes(this.memory()); }
	memory() {
		let pos = this.number();
		let end = pos + 32;
		let {buf} = this;
		if (end > buf.length) throw new RangeError('buffer overflow');
		let len = unsigned_from_bytes(buf.subarray(pos, end));
		pos = end;
		end += len;
		if (end > buf.length) throw new RangeError('buffer overflow');
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
	constructor(offset = 0, capacity = 256, packed = false) {
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
				set_bytes_to_unsigned(buf.subarray(off, off + 32), pos - offset); // global offset
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
	bytes_hex(s) { return this.bytes(bytes_from_hex(s)); }
	bytes(v) { 
		this.alloc((v.length + 31) & ~31).set(v);		
		return this; // chainable
	}
	number(i, n = 32) {
		if (i instanceof Uint256) {
			let buf = this.alloc(n);
			if (n < 32) {
				buf.set(i.bytes.subarray(32 - n));
			} else {
				buf.set(i.bytes, n - 32);
			}
		} else {
			set_bytes_to_unsigned(this.alloc(n), i);
		}
		return this; // chainable
	}
	string(s) { return this.memory(bytes_from_utf8(s)); } // chainable
	memory(v) {
		let {pos} = this; // remember offset
		this.alloc(32); // reserve spot
		let tail = new Uint8Array((v.length + 63) & ~31); // len + bytes + 0* [padded]
		set_bytes_to_unsigned(tail.subarray(0, 32), v.length);
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
			} else {
				throw new TypeError('expected bytes');
			}
		}
		this.alloc(v.length).set(v);
		return this; // chainable
	}
}

// https://tools.ietf.org/id/draft-msporny-base58-03.html

// removed: "IOl0+/"
const BASE_58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; 

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

function bytes_from_base58$1(s) {
	if (typeof s !== 'string') throw new TypeError('expected string');
	let v = new Uint8Array(s.length);
	let zeros = 0;
	let n = 0;
	for (let c of s) {
		let carry = BASE_58.indexOf(c);
		if (carry < 0) throw new TypeError('expected base58 string');
		if (n == 0) {
			if (carry == 0) {
				zeros++;
				continue;
			} else {
				n = 1;
			}
		}
		for (let i = 0; i < n; i++) {
			carry += v[i] * 58;
			v[i] = carry;
			carry >>= 8;
		}
		while (carry > 0) {
			v[n++] = carry;
			carry >>= 8;
		}
	}
	n += zeros;
	for (let a = 0, b = n - 1; a < b; a++, b--) {
		let temp = v[a];
		v[a] = v[b];
		v[b] = temp;
	}
	return v.subarray(0, n);
}

// minimal window.ethereum provider
// https://docs.metamask.io/guide/ethereum-provider.html
class FetchProvider {
	constructor({url, chain_id = 1, fetch: fetch_api}) {
		if (typeof url !== 'string') throw new TypeError('expected url');
		if (!fetch_api) fetch_api = globalThis.fetch.bind(globalThis); 
		if (typeof fetch_api !== 'function') throw new TypeError('fetch should be a function');
		this.url = url;	
		this.fetch_api = fetch_api;
		this.chain_id = chain_id;
		this.id = 0;
	}
	get chainId() { return this.chain_id; }
	async request(obj) {
		if (typeof obj !== 'object') throw new TypeError('expected object');
		let res = await this.fetch_api(this.url, {
			method: 'POST',
			body: JSON.stringify({...obj, jsonrpc: '2.0', id: ++this.id})
		});
		if (res.status !== 200) throw new Error(`provider fetch error: ${res.status}`);
		let json;
		try {
			json = await res.json();
		} catch (cause) {
			throw new Error('expected json', {cause});
		}
		let {error} = json;
		if (error) {
			console.log(json);
			let err = new Error(error.message ?? 'unknown error');
			err.code = error.code;
			throw err;
		}
		return json.result;
	}
}

class WebSocketProvider {
	constructor({url, chain_id, WebSocket: ws_api, request_timeout = 10000, idle_timeout = 500}) {
		if (typeof url !== 'string') throw new TypeError('expected url');
		if (!ws_api) ws_api = globalThis.WebSocket;
		if (!ws_api) throw new Error('unknown WebSocket implementation');
		this.url = url;
		this.ws_api = ws_api;
		this.chain_id = chain_id;
		this.request_timeout = request_timeout;
		this.idle_timeout = idle_timeout;
		this.idle_timer = undefined;
		this.ws = undefined;
		this.reqs = undefined;
		this.id = 0;
	}
	get chainId() { return this.chain_id; }
	restart_idle() {
		if (this.idle_timeout > 0) {
			if (Object.keys(this.reqs).length == 0) {
				let {ws} = this; // snapshot
				this.idle_timer = setTimeout(() => {
					//console.log('Disconnect: idle');
					ws.close();	
				}, this.idle_timeout);
			} else {
				clearTimeout(this.idle_timer);
			}
		}
	}
	async request(obj) {
		if (typeof obj !== 'object') throw new TypeError('expected object');
		await this.connect();
		const id = ++this.id; 
		const {reqs, ws} = this; // snapshot
		this.restart_idle();
		return new Promise((ful, rej) => {
			let timer = setTimeout(() => {
				delete reqs[id];
				rej(new Error('Timeout'));
			}, this.request_timeout);
			reqs[id] = {timer, ful, rej};
			ws.send(JSON.stringify({jsonrpc: '2.0', id, ...obj}));
		});
	}
	async connect() {
		let {ws} = this;
		if (ws === undefined) {
			let queue = this.ws = []; // change state		 
			let s = new this.ws_api(this.url);
			//console.log('Connecting...');
			let timer, handler;
			try {  
				await new Promise((ful, rej) => {
					handler = () => {
						s.removeEventListener('error', rej); 
						s.removeEventListener('close', rej);
						ful();						
					};
					timer = setTimeout(() => rej(new Error('Timeout')), this.request_timeout);
					s.addEventListener('close', rej);
					s.addEventListener('error', rej);
					s.addEventListener('open', handler, {once: true});
				});
			} catch (err) {
				//console.log(`Connect error: ${err}`);
				this.ws = undefined; // reset state
				s.removeEventListener('open', handler);
				for (let {rej} of queue) rej(err);
				s.close();
				throw err;
			} finally {
				clearTimeout(timer);
			} 
			//console.log('Connected');
			this.ws = s; // connected state
			this.id = 0;
			this.reqs = {};
			// setup error handlers
			let die = (err) => {
				if (s !== this.ws) return;
				this.ws = undefined; // reset state
				for (let {rej} of Object.values(this.reqs)) rej(err);
				this.reqs = undefined;
				clearTimeout(this.idle_timer);
			};
			s.addEventListener('close', () => die(new Error('Unexpected close')));
			s.addEventListener('error', die);
			// process waiters
			for (let {ful} of queue) ful();
			// handle requests
			let {reqs} = this; // snapshot
			s.addEventListener('message', ({data}) => {
				let json = JSON.parse(data);
				let request = reqs[json.id];
				if (!request) return;
				this.restart_idle();
				delete reqs[json.id];
				clearTimeout(request.timer);
				let {result, error} = json;
				if (result) return request.ful(result);
				let err = new Error(error?.message ?? 'Unknown Error');
				if ('code' in error) err.code = error.code;
				request.rej(err);
			});
			this.restart_idle();
		} else if (Array.isArray(ws)) { // already connecting
			await new Promise((ful, rej) => {
				ws.push({ful, rej});
			});
		}
	}
}

function retry(provider, retry = 2, delay = 1000) {
	if (typeof retry !== 'number' || retry < 1) throw new TypeError('expected retry > 0');
	if (typeof delay !== 'number' || delay < 0) throw new TypeError('expected delay >= 0');
	async function unfucked(args) {
		let n = 0;
		while (true) {
			try {
				return await provider.request(args);
			} catch (err) {
				if (err.code === -32000 && err.message === 'header not found' && n++ < retry) { 
					// this seems to be an geth bug (infura, cloudflare, metamask)
					await new Promise(ful => setTimeout(ful, delay));
					continue;
				}
				throw err;
			}
		}
	}
	return new Proxy(provider, {
		get: function(obj, prop) {
			return prop === 'request' ? unfucked : obj[prop];
		}
	});
}

function decode_arithmetic(bytes) {
	let pos = 0;
	function u16() { return (bytes[pos++] << 8) | bytes[pos++]; }
	
	// decode the frequency table
	let symbol_count = u16();
	let total = 1;
	let acc = [0, 1]; // first symbol has frequency 1
	for (let i = 1; i < symbol_count; i++) {
		acc.push(total += u16());
	}

	// skip the sized-payload that the last 3 symbols index into
	let skip = u16();
	let pos_payload = pos;
	pos += skip;

	let read_width = 0;
	let read_buffer = 0; 
	function read_bit() {
		if (read_width == 0) {
			// this will read beyond end of buffer
			// but (undefined|0) => zero pad
			read_buffer = (read_buffer << 8) | bytes[pos++];
			read_width = 8;
		}
		return (read_buffer >> --read_width) & 1;
	}

	const N = 31;
	const FULL = 2**N;
	const HALF = FULL >>> 1;
	const QRTR = HALF >> 1;
	const MASK = FULL - 1;

	// fill register
	let register = 0;
	for (let i = 0; i < N; i++) register = (register << 1) | read_bit();

	let symbols = [];
	let low = 0;
	let range = FULL; // treat like a float
	while (true) {
		let value = Math.floor((((register - low + 1) * total) - 1) / range);
		let start = 0;
		let end = symbol_count;
		while (end - start > 1) { // binary search
			let mid = (start + end) >>> 1;
			if (value < acc[mid]) {
				end = mid;
			} else {
				start = mid;
			}
		}
		if (start == 0) break; // first symbol is end mark
		symbols.push(start);
		let a = low + Math.floor(range * acc[start]   / total);
		let b = low + Math.floor(range * acc[start+1] / total) - 1;
		while (((a ^ b) & HALF) == 0) {
			register = (register << 1) & MASK | read_bit();
			a = (a << 1) & MASK;
			b = (b << 1) & MASK | 1;
		}
		while (a & ~b & QRTR) {
			register = (register & HALF) | ((register << 1) & (MASK >>> 1)) | read_bit();
			a = (a << 1) ^ HALF;
			b = ((b ^ HALF) << 1) | HALF | 1;
		}
		low = a;
		range = 1 + b - a;
	}
	let offset = symbol_count - 4;
	return symbols.map(x => { // index into payload
		switch (x - offset) {
			case 3: return offset + 0x10100 + ((bytes[pos_payload++] << 16) | (bytes[pos_payload++] << 8) | bytes[pos_payload++]);
			case 2: return offset + 0x100 + ((bytes[pos_payload++] << 8) | bytes[pos_payload++]);
			case 1: return offset + bytes[pos_payload++];
			default: return x - 1;
		}
	});
}	

// returns an iterator which returns the next symbol
function decode_payload(s) {
	let values = decode_arithmetic(Uint8Array.from(atob(s), c => c.charCodeAt(0)));
	let pos = 0;
	return () => values[pos++];
}

// eg. [0,1,2,3...] => [0,-1,1,-2,...]
function signed(i) { 
	return (i & 1) ? (~i >> 1) : (i >> 1);
}

function read_counts(n, next) {
	let v = Array(n);
	for (let i = 0; i < n; i++) v[i] = 1 + next();
	return v;
}

function read_ascending(n, next) {
	let v = Array(n);
	for (let i = 0, x = -1; i < n; i++) v[i] = x += 1 + next();
	return v;
}

function read_deltas(n, next) {
	let v = Array(n);
	for (let i = 0, x = 0; i < n; i++) v[i] = x += signed(next());
	return v;
}

// returns [[x, n], ...] s.t. [x,3] == [x,x+1,x+2]
function read_member_table(next) {
	let v1 = read_ascending(next(), next);
	let n = next();
	let vX = read_ascending(n, next);
	let vN = read_counts(n, next);
	return [
		...v1.map(x => [x, 1]),
		...vX.map((x, i) => [x, vN[i]])
	].sort((a, b) => a[0] - b[0]);
}

// returns array of 
// [x, ys] => single replacement rule
// [x, ys, n, dx, dx] => linear map
function read_mapped_table(next) {
	let ret = [];
	while (true) {
		let w = next();
		if (w == 0) break;
		ret.push(read_linear_table(w, next));
	}
	while (true) {
		let w = next() - 1;
		if (w < 0) break;
		ret.push(read_replacement_table(w, next));
	}
	return ret.flat().sort((a, b) => a[0] - b[0]);
}

function read_ys_transposed(n, w, next) {
	if (w == 0) return [];
	let m = [read_deltas(n, next)];
	for (let j = 1; j < w; j++) {
		let v = Array(n);
		let prev = m[j - 1];
		for (let i = 0; i < n; i++) {
			v[i] = prev[i] + signed(next());
		}
		m.push(v);
	}
	return m;
}

function read_replacement_table(w, next) { 
	let n = 1 + next();
	let vX = read_ascending(n, next);
	let mY = read_ys_transposed(n, w, next);
	return vX.map((x, i) => [x, mY.map(v => v[i])])
}

function read_linear_table(w, next) {
	let dx = 1 + next();
	let dy = next();
	let n = 1 + next();
	let vX = read_ascending(n, next);
	let vN = read_counts(n, next);
	let mY = read_ys_transposed(n, w, next);
	return vX.map((x, i) => [x, mY.map(v => v[i]), vN[i], dx, dy]);
}

/*
export function read_zwj_emoji(next) {
	let buckets = [];
	for (let k = next(); k > 0; k--) {
		let n = 1 + next(); // group size
		let w = 1 + next(); // group width w/o ZWJ
		let p = 1 + next(); // bit positions of zwj
		let z = []; // position of zwj
		let m = []; // emoji vectors
		for (let i = 0; i < n; i++) m.push([]);
		for (let i = 0; i < w; i++) {
			if (p & (1 << (i - 1))) {
				w++; // increase width
				z.push(i); // remember position
				m.forEach(v => v.push(0x200D)); // insert zwj
			} else {
				read_deltas(n, next).forEach((x, i) => m[i].push(x));
			}
		}
		for (let b of z) {
			let bucket = buckets[b];
			if (!bucket) buckets[b] = bucket = [];
			bucket.push(...m);
		}
	}
	return buckets;
}

export function read_emoji(next, sep) {
	let ret = {};
	for (let k = next(); k > 0; k--) {
		let n = 1 + next(); // group size
		let w = 1 + next(); // group width w/o sep
		let p = 1 + next(); // bit positions of sep
		let z = []; // position of sep
		let m = []; // emoji vectors
		for (let i = 0; i < n; i++) m.push([]);
		for (let i = 0; i < w; i++) {
			if (p & (1 << (i - 1))) {
				w++; // increase width
				z.push(i); // remember position
				m.forEach(v => v.push(sep)); // insert 
			} else {
				read_deltas(n, next).forEach((x, i) => m[i].push(x));
			}
		}
		for (let v of m) {
			let bucket = ret[v[0]];
			if (!bucket) bucket = ret[v[0]] = [];
			bucket.push(v.slice(1));
		}
	}
	for (let bucket of Object.values(ret)) {
		bucket.sort((a, b) => b.length - a.length);
	}
	return ret;
}
*/

function read_member_function(r) {
	let table = read_member_table(r);
	return cp => lookup_member(table, cp);
}

function lookup_member(table, cp) {
	for (let [x, n] of table) {
		let d = cp - x;
		if (d < 0) break;
		if (d < n) return true;
	}
	return false;
}

function lookup_mapped(table, cp) {
	for (let [x, ys, n, dx, dy] of table) {
		let d = cp - x;
		if (d < 0) break;
		if (n > 0) {
			if (d < dx * n && d % dx == 0) {
				let r = d / dx;
				return ys.map(y => y + r * dy);
			} 
		} else if (d == 0) {
			return ys;
		}
	}
}

// my suggested inline ascii-safe unicode escape
// this is ES6 \u{X} without the \u
function quote_cp(cp) {
	return `{${cp.toString(16).padStart(2, '0').toUpperCase()}}`;
}

function escape_unicode(s) {
	// printable w/o:
	// 0x22 " (double-quote)
	// 0x7F DEL
	return s.replace(/[^\x20-\x21\x23-\x7E]/gu, x => quote_cp(x.codePointAt(0)));
	//return s.replace(/[^\.\-a-z0-9]/igu, x => quote_cp(x.codePointAt(0)));
}

function explode_cp(s) {
	if (typeof s != 'string') throw new TypeError(`expected string`);	
	return [...s].map(c => c.codePointAt(0));
}

// https://datatracker.ietf.org/doc/html/rfc3492
// adapted from https://github.com/mathiasbynens/punycode.js
// puny format: "xn--{ascii}-{0-9a-z}"
// this function receives normalized cps such that:
// * no uppercase 
// * no overflow (#section-6.4)

function puny_decode(cps) {
	let ret = [];
	let pos = cps.lastIndexOf(0x2D); // hyphen
	for (let i = 0; i < pos; i++) {
		let cp = cps[i];
		if (cp >= 0x80) throw new Error('expected ASCII');
		ret.push(cp);
	}
	pos++; // skip hyphen
	// #section-5
	const BASE = 36; 
	const T_MIN = 1;
	const T_MAX = 26;
	const SKEW = 38;
	const DAMP = 700;
	const MAX_DELTA = (BASE - T_MIN) * T_MAX >> 1;
	let i = 0, n = 128, bias = 72;
	while (pos < cps.length) {
		let prev = i;
		for (let w = 1, k = BASE; ; k += BASE) {
			if (pos >= cps.length) throw new Error(`invalid encoding`);
			let cp = cps[pos++];
			if (cp >= 0x30 && cp <= 0x39) { // 0-9
				cp -= 0x16; // 26 + (code - 0x30)
			} else if (cp >= 0x61 && cp <= 0x7A) { // a-z
				cp -= 0x61;
			} else {
				throw new Error(`invalid character ${cp}`);
			}
			i += cp * w;
			const t = k <= bias ? T_MIN : (k >= bias + T_MAX ? T_MAX : k - bias);
			if (cp < t) break;
			w *= BASE - t;
		}
		let len = ret.length + 1;
		let delta = prev == 0 ? (i / DAMP)|0 : (i - prev) >> 1;
		delta += (delta / len)|0;
		let k = 0;
		for (; delta > MAX_DELTA; k += BASE) {
			delta = (delta / (BASE - T_MIN))|0;
		}
		bias = (k + (BASE - T_MIN + 1) * delta / (delta + SKEW))|0;
		n += (i / len)|0;
		i %= len;
		ret.splice(i++, 0, n);
	}	
	return ret;
}

// this returns [[]] if empty
// {e:[],u:[]} => emoji
// {v:[]} => chars
function tokenized_idna(cps, emoji_parser, tokenizer) {
	let chars = [];
	let tokens = [];
	let labels = [tokens];
	function drain() { 
		if (chars.length > 0) {
			tokens.push({v: chars}); 
			chars = [];
		}
	}
	for (let i = 0; i < cps.length; i++) {
		if (emoji_parser) {
			let [len, e] = emoji_parser(cps, i);
			if (len > 0) {
				drain();
				tokens.push({e, u:cps.slice(i, i+len)}); // these are emoji tokens
				i += len - 1;
				continue;
			}
		} 
		let cp = cps[i];
		let token = tokenizer(cp);
		if (Array.isArray(token)) { // this is more characters
			chars.push(...token);
		} else {
			drain();
			if (token) { // this is a token
				tokens.push(token);
			} else { // this is a label separator
				tokens = []; // create a new label
				labels.push(tokens);
			}
		}
	}
	drain();
	return labels;
}

// returns an emoji parser
function emoji_parser_factory(r) {	
	const REGIONAL = read_member_function(r);
	const KEYCAP_OG = read_member_function(r);
	const KEYCAP_FIXED = read_member_function(r);
	const EMOJI_OPT = read_member_function(r);
	const EMOJI_REQ = read_member_function(r);
	const MODIFIER = read_member_function(r);
	const MODIFIER_BASE = read_member_function(r);
	const TAG_SPEC = read_member_function(r);

	const FE0F = 0xFE0F;
	const ZWJ = 0x200D;
	const KEYCAP_END = 0x20E3;
	const TAG_END = 0xE007F;

	function find_emoji_chr_mod_pre(cps, pos) {
		let cp = cps[pos];
		let cp2 = cps[pos+1]; // out of bounds, but unassigned
		// emoji_modifier_sequence := emoji_modifier_base emoji_modifier
		let base = MODIFIER_BASE(cp);
		if (base && cp2 && MODIFIER(cp2)) {
			return [2, [cp, cp2]];
		}
		// emoji_modifier_base is a emoji_character 
		// emoji_presentation_sequence := emoji_character \x{FE0F}
		// but some emoji dont need presentation
		// and previously valid emoji are already registered
		// we call these emoji optional
		let opt = base || EMOJI_OPT(cp); 
		if (cp2 == FE0F) {
			// these have optional FE0F 
			if (opt) return [2, [cp]]; // drop FE0F
			// these require FE0F
			// these are the new emoji 
			// all future emoji should be added 
			// through this mechanism, if appropriate 
			if (EMOJI_REQ(cp)) return [2, [cp, FE0F]]; // keep FE0F
		}
		// emoji_character 
		// we also allow single regional 
		if (base || opt || REGIONAL(cp) || MODIFIER(cp)) {
			return [1, [cp]];	
		}
	}

	return function(cps, pos) {
		let cp = cps[pos];
		let len = cps.length;
		// [ED-14] emoji flag sequence
		// https://www.unicode.org/reports/tr51/#def_emoji_flag_sequence
		// A sequence of two Regional Indicator characters, where the corresponding ASCII characters are valid region sequences as specified 
		if (pos+1 < len && REGIONAL(cp)) {
			// emoji_flag_sequence := regional_indicator regional_indicator
			let cp2 = cps[pos+1];
			if (REGIONAL(cp2)) {
				return [2, [cp, cp2]];
			}
		} 
		// [ED-14c] emoji keycap sequence
		// https://unicode.org/reports/tr51/#def_emoji_keycap_sequence
		// A sequence of the following form: 
		// emoji_keycap_sequence := [0-9#*] \x{FE0F 20E3}
		let keycap_og = KEYCAP_OG(cp);
		if (pos+1 < len && keycap_og && cps[pos+1] == KEYCAP_END) {
			return [2, [cp, KEYCAP_END]];
		} else if (pos+2 < len && (keycap_og || KEYCAP_FIXED(cp)) && cps[pos+1] == FE0F && cps[pos+2] == KEYCAP_END) {
			return [3, keycap_og ? [cp, KEYCAP_END] : [cp, FE0F, KEYCAP_END]];		
		}
		// [ED-15] emoji core sequence
		// emoji_core_sequence := emoji_character | emoji_presentation_sequence | emoji_keycap_sequence | emoji_modifier_sequence | emoji_flag_sequence 
		// [ED-15a] emoji zwj element
		// emoji_zwj_element := emoji_character | emoji_presentation_sequence | emoji_modifier_sequence
		// [ED-16] emoji zwj sequence 
		// emoji_zwj_sequence := emoji_zwj_element ( \x{200d} emoji_zwj_element )+
		// [ED-17] emoji sequence
		// emoji_sequence := emoji_core_sequence | emoji_zwj_sequence | emoji_tag_sequence 
		let emoji0 = find_emoji_chr_mod_pre(cps, pos);
		if (!emoji0) return [0];
		let [pos2, stack] = emoji0;
		pos2 += pos;
		let zwj = false;
		while (pos2+1 < len && cps[pos2] === ZWJ) {
			let emoji = find_emoji_chr_mod_pre(cps, pos2 + 1);
			if (!emoji) break;
			zwj = true;
			pos2 += 1 + emoji[0];
			stack.push(ZWJ, ...emoji[1]);
		}
		if (!zwj) {
			// [ED-14a] emoji tag sequence (ETS) 
			// https://www.unicode.org/reports/tr51/#def_emoji_tag_sequence
			// A sequence of the following form:
			//  emoji_tag_sequence := tag_base tag_spec tag_end
			//   tag_base := emoji_character 
			//             | emoji_modifier_sequence     => emoji_modifier_base emoji_modifier
			//             | emoji_presentation_sequence => emoji_character \x{FE0F}
			//   tag_spec := [\x{E0020}-\x{E007E}]+
			//   tag_end  := \x{E007F}		
			if (pos2+2 < len && TAG_SPEC(cps[pos2])) {
				let pos3 = pos2 + 1;
				while (pos3+1 < len && TAG_SPEC(cps[pos3])) pos3++;
				if (cps[pos3++] == TAG_END) {
					// these are crazy dangerous because they don't render
					// ignore the sequence
					// return [pos3 - pos, stack.concat(cps.slice(pos2, pos3 - pos2))];
					return [pos3 - pos, stack];
				}
			}
		}
		return [pos2 - pos, stack];	};
}

var PAYLOAD$3 = 'ABIAAQB6AEAAOAAoACYAHwAiABgAFgAOAAsACwAMAY8AfgADApQhCD9xcXFxcXFxcW5hcbsGoY8Bf9URLHl4F4mAXgAn6F1DBPgbACv4ZqZU5nHucWhm/wCYRQRDAJcASQwtAe8FzAOHOfQyBvsC+GifBANGRZDdAC4CJSwCIi8GFTgCJSwmLyQpNix4JTpMcXV+rQEGGggji3raLA6mlfECCAxleXQSxKUjTyElAibgTiIC0gHv1AZQBLNgQ6JNVpJS9wlNAHRfAXiOWADp7D9QqYZpggAHGwscRNcB8gB0/yE9LHw3ZzYcITAjCk8BAlASEDEWAjEMCTgFzVsHDywSYVMEXgVBSgCFDAQFAckCphERETMDM2uMA88yLkEnJgYTLi6LB7kBPw0nVwsQ4gE7YHTHG0MAJpANNxIqJ15uH1IFEQDKAm4FfB2eATAAeIwtpywlOBhEJwRXng4sHLli4Q5IYl7584oYIwciAIlLCW1CAFQULjWxMQNQS/8RUSEBKAMWiQavLFEEUAT7AK0E1WULFc3RYR4GDAkRFRAxEhEDAQEABx8IASgjAAJR4QwFEpUiGzjHDw5ylPEUpACEAX4jBRwWExgAGwkSAkFoCRgIAA5XWI6qYXEEjBQARAEhDhAt2CcBFwASAEoTJBMCNQUSphsCAEEXDnKU8Q4OA70WBRQQHmoJLG5nEwoIDmNYjqphcQSGGgBJASASEDPYKA9QDyQSCgQMShMjAxQGAzUCcRkkAIsAuokwVSwLAmIGPhgnKACLCRkAEicBAQbgO8+xBTABBxcQJgAEQDf6MASDMBD0HwwoDAsu9wDA6hMtcgxWABIITU3k0SHxGPGp8QBhA+dvYj7xAEEFTY2l8Q8x0RWBKEEG8QtKx0dLASBJGLFQ8QBfWx4AFKXRDyrPFXMcIgEPEjzcS9Wn/KALJxnXU2YJOBWKOmP82gdIgmNcRsDi+p7FBLYbwm9Uzs1RfCbNpY30PNDOtZBhbqPBybOPeWa7oi+ySNuja7E79Fz+oJqkWRGdXLqRl46pfoUDu0uKXTiGuFf3GtJzAXtJmxI3V8am/mpQnjfi99U7ZkojTh6fKYexodlCUm8Nn5tkJXqdPwxaQiU29Pa8nQxhFccS0ZzA2p+XNo3r68FBGjQNasxwtQH/0ELiOQLNuyc0YqOxCPnfFsvASXVP7enrn5p48UHDGS6NU/kYR37WSJ7+CN+nV4NqWlRTc/nQOuWoDD2Cnkn26E21fE+79xMXG2voqdtyef5eUY6MOoAAPIvdUDW+i16JSxe2+srXAYVvzbE8SKhyxzjFf2rMlgMycfXR8nl6/xF97xDwBSNLExVnK4YUGbAMpgGeHD0vHVXsIK20HyDdJQ9a5Uhwta5o+Tw/HpthmalqVX7v90SgUzjZaEahH3JPOhT8k+LFPClF+c5gMeKg';

let r$3 = decode_payload(PAYLOAD$3);
const VIRAMA = read_member_function(r$3);
const JOIN_T = read_member_function(r$3);
const JOIN_LD = read_member_function(r$3);
const JOIN_RD = read_member_function(r$3);
const SCRIPT_GREEK = read_member_function(r$3);
const SCRIPT_HEBREW = read_member_function(r$3);
const SCRIPT_HKH = read_member_function(r$3);

// chunks is a list of textual code-points
// chunks can be empty and contain empty lists
function validate_context(cps) {
	// apply relative checks
	for (let i = 0, e = cps.length - 1; i <= e; i++) {
		switch (cps[i]) {
			case 0x200C: { 
				// ZERO WIDTH NON-JOINER (ZWNJ)
				// ContextJ: https://datatracker.ietf.org/doc/html/rfc5892#appendix-A.1	
				// If Canonical_Combining_Class(Before(cp)) .eq.  Virama Then True;
				if (i > 0 && VIRAMA(cps[i - 1])) continue;
				// If RegExpMatch((Joining_Type:{L,D})(Joining_Type:T)*\u200C(Joining_Type:T)*(Joining_Type:{R,D})) Then True;
				if (i > 0 && i < e) { // there is room on either side
					let head = i - 1;
					while (head > 0 && JOIN_T(cps[head])) head--; // T*
					if (JOIN_LD(cps[head])) { // L or D
						let tail = i + 1;
						while (tail < e && JOIN_T(cps[tail])) tail++; // T*
						if (JOIN_RD(cps[tail])) { // R or D
							continue;
						}
					}
				}
				break;
			}
			case 0x200D: {
				// ZERO WIDTH JOINER (ZWJ)
				// ContextJ: https://datatracker.ietf.org/doc/html/rfc5892#appendix-A.2
				// If Canonical_Combining_Class(Before(cp)) .eq.  Virama Then True;
				if (i > 0 && VIRAMA(cps[i-1])) continue;
				break;
			}
			case 0x00B7: {
				// MIDDLE DOT
				// ContextO: https://datatracker.ietf.org/doc/html/rfc5892#appendix-A.3
				// Between 'l' (U+006C) characters only, used to permit the Catalan
				// character ela geminada to be expressed.
				if (i > 0 && i < e && cps[i-1] == 0x6C && cps[i+1] == 0x6C) continue; 
				break;
			}
			case 0x0375: {
				// GREEK LOWER NUMERAL SIGN (KERAIA)
				// ContextO: https://datatracker.ietf.org/doc/html/rfc5892#appendix-A.4
				// The script of the following character MUST be Greek.
				if (i < e && SCRIPT_GREEK(cps[i+1])) continue; 
				break;
			}
			case 0x05F3:
				// HEBREW PUNCTUATION GERESH
				// ContextO: https://datatracker.ietf.org/doc/html/rfc5892#appendix-A.5
				// The script of the preceding character MUST be Hebrew.
			case 0x05F4: {
				// HEBREW PUNCTUATION GERSHAYIM
				// ContextO: https://datatracker.ietf.org/doc/html/rfc5892#appendix-A.6		
				// The script of the preceding character MUST be Hebrew.
				if (i > 0 && SCRIPT_HEBREW(cps[i-1])) continue;
				break;
			}
			default: continue;
		}
		// the default behavior above is to continue if the context is valid
		// we only fall-through if no context was matched
		throw new Error(`No context for "${escape_unicode(String.fromCodePoint(cps[i]))}"`);
	}
	// apply global checks
	//
	// ARABIC-INDIC DIGITS
	// ContextO: https://datatracker.ietf.org/doc/html/rfc5892#appendix-A.8
	// Can not be mixed with Extended Arabic-Indic Digits.
	// For All Characters: If cp .in. 06F0..06F9 Then False; End For;
	// EXTENDED ARABIC-INDIC DIGITS
	// ContextO: https://datatracker.ietf.org/doc/html/rfc5892#appendix-A.9
	// Can not be mixed with Arabic-Indic Digits.
	// For All Characters: If cp .in. 0660..0669 Then False; End For
	if (cps.some(cp => cp >= 0x0660 && cp <= 0x0669) && cps.some(cp => cp >= 0x06F0 && cp <= 0x06F9)) {
		throw new Error(`Disallowed arabic-indic digit mixture`);
	}
	// KATAKANA MIDDLE DOT
	// ContextO: https://datatracker.ietf.org/doc/html/rfc5892#appendix-A.7
	// The effect of this rule is to require at least one character in the label to be in one of those scripts.
	// For All Characters: If Script(cp) .in. {Hiragana, Katakana, Han} Then True; End For;
	if (cps.includes(0x30FB) && !cps.some(cp => SCRIPT_HKH(cp))) {
		throw new Error(`Disallowed katakana`);
	}
}

var PAYLOAD$2 = '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';

let r$2 = decode_payload(PAYLOAD$2);
const COMBINING_RANK = Array(1 + r$2()).fill().map(() => read_member_table(r$2));
const DECOMP = read_mapped_table(r$2);
const COMP_EXCLUSIONS = read_member_table(r$2);

// algorithmic hangul
// https://www.unicode.org/versions/Unicode14.0.0/ch03.pdf
const S0 = 0xAC00;
const L0 = 0x1100;
const V0 = 0x1161;
const T0 = 0x11A7;
const L_COUNT = 19;
const V_COUNT = 21;
const T_COUNT = 28;
const N_COUNT = V_COUNT * T_COUNT;
const S_COUNT = L_COUNT * N_COUNT;
const S1 = S0 + S_COUNT;
const L1 = L0 + L_COUNT;
const V1 = V0 + V_COUNT;
const T1 = T0 + T_COUNT;

function is_hangul(cp) {
	return cp >= S0 && cp < S1;
}
function decompose(cp, next) {
	if (cp < 0x80) {
		next(cp);
	} else if (is_hangul(cp)) {
		let s_index = cp - S0;
		let l_index = s_index / N_COUNT | 0;
		let v_index = (s_index % N_COUNT) / T_COUNT | 0;
		let t_index = s_index % T_COUNT;
		next(L0 + l_index);
		next(V0 + v_index);
		if (t_index > 0) next(T0 + t_index);
	} else {
		let mapped = lookup_mapped(DECOMP, cp);
		if (mapped) {
			for (let cp of mapped) {
				decompose(cp, next);
			}
		} else {
			next(cp);
		}
	}
}
function compose_pair(a, b) {
	if (a >= L0 && a < L1 && b >= V0 && b < V1) { // LV
		let l_index = a - L0;
		let v_index = b - V0;
		let lv_index = l_index * N_COUNT + v_index * T_COUNT;
		return S0 + lv_index;
	} else if (is_hangul(a) && b > T0 && b < T1 && (a - S0) % T_COUNT == 0) {
		return a + (b - T0);
	} else {
		for (let [combined, v] of DECOMP) {		
			if (v.length == 2 && v[0] == a && v[1] == b) {
				if (lookup_member(COMP_EXCLUSIONS, combined)) break;
				return combined;
			}
		}
	}
	return -1;
}

function decomposer(cps, callback) {
	let stack = [];
	cps.forEach(cp => decompose(cp, next));
	drain();
	function drain() {
		stack.sort((a, b) => a[0] - b[0]).forEach(([rank, cp]) => callback(rank, cp));
		stack.length = 0;
	}
	function next(cp) {
		let rank = 1 + COMBINING_RANK.findIndex(table => lookup_member(table, cp));
		if (rank == 0) {
			drain();
			callback(rank, cp);
		} else {
			stack.push([rank, cp]);
		}
	}
}

function nfc(cps) {
	let ret = [];
	let stack = [];
	let prev_cp = -1;
	let prev_rank = 0;
	decomposer(cps, next);
	if (prev_cp >= 0) ret.push(prev_cp);
	ret.push(...stack);	
	return ret;
	function next(rank, cp) {
		if (prev_cp === -1) {
			if (rank == 0) {
				prev_cp = cp;
			} else {
				ret.push(cp);
			}
		} else if (prev_rank > 0 && prev_rank >= rank) {
			if (rank == 0) {
				ret.push(prev_cp, ...stack);
				stack.length = 0;
				prev_cp = cp;
			} else {
				stack.push(cp);
			}
			prev_rank = rank;
		} else {
			let composed = compose_pair(prev_cp, cp);
			if (composed >= 0) {
				prev_cp = composed;
			} else if (prev_rank == 0 && rank == 0) {
				ret.push(prev_cp);
				prev_cp = cp;
			} else {
				stack.push(cp);
				prev_rank = rank;
			}
		}
	}
}

var PAYLOAD$1 = 'ACUAAQDpAIEAfgBLAFkAawBgADAAVQAmACMAIgAlACAAPQAXABMAFQAOAA0ADAATABIAEgAPABEACwAMAAwAFAAlAA4CiAD2AAMEfQRvDCAA6xbF2ewNxQcEpzEwUhdEIQ4MFPFdAQR+Xghu/sUJhTcAxgAjDIIT11i1UgSFFg5DORgJEggA8l1t/b8GgzAAwgAECncPWK5LBIPsVokBEm8EjVUKOSQHJQoSRAAkpU4lim0AaUYDM38ErACLsk0bwwE9Py5BYQFLAfUFWXmEMgEEQlUcDdxTNj3nMabMOtteTE7wrBKhLiUA8HAuAPZKIwPMS5cW4WkBPiA9AKFuMnGFBgKIGAkPEAICHRQQGRAAWAgAGCY2AV4+HA4+By4BCA4OI0IXAgIaFiELCt72BhR4WAC0AEQCQgLeyQ4dAQs6OQo9Pg4eH4lDGN5VrgAeDh4wDkUlAh4sAgwCAg8NFgAeVCqOBxMZTm4C7AM6BA5lDjQhjj4LAQ4HFn4GBg4dIwAeCQcuIxMRAhsmDoEeGY4WHRkODB6ufj0uEAQMHAAuEm4jBwAeqR0C304J7k4DDg6uIt4BHjAOFQGhni4hKxbeA94hzgAuCW5OEZ6O3gcfAAAQXn40JiAANBIYGBgYGgEVFANZAN4VACAODgPOB/4eVAgODI6l3g8evhVuKC4G3gr+3v7eAJ8xaoQEDxUHDgILBgBXBxchNAFdNxI3ACQGChYOFg4aCZ70BBMHIyzewwQWNDgJPA4LDhCFQRieVWsAGw0uRCASIgQOBxEYUyqCDxlMSDdZCwsPAgQDfAICBhIAFQgUDwIBEg0WERARCQ0xCAYMJwQEAwJ5TaJBAw0BJQEXLw45KRYW1gO0AAEAaklS1AUcGTMlHwAyERcXFxcA3gsKGBsKpb4PF7wVYBwPAPwSKf7c/twFvADjBN8+AQMAA34ADpgelQ9gBRwYYgLm2WYCr9PLGBAJzhANkwEBZU0AcmA8UgHw1AIsBJ8CuREAEAVbADUN4E45AeJxUvNSfwK0AOB9Bl1loWFBA3QYGBgYChoNDlwFIYoDANxjAOdXAMYA2gDfYwGgAzQB6QAzACJ4BL8PPhcAyYhoAKEBMQFUACzlXkPODDwAAzsRChOJRRjAVa4AW09gAAYaAdRQsm8MAndjAC4uCIcD9wTsCFObqROxVN4azu4OThg91H4Cu14+Hg4uAD5yA0j+3v7e/t7+3v7e/t7+3v7e/t7+3v7e/t4A0Pzs/t7+3gIADg4AhG8GAKAAMQFSRzw3tAIeFQABKyA1CkIDArZSNxYGADJxFeAM7kwEnod/ygAbEhkPHAIlEhkTHBEWIxlvEic5XmJrmgYHEHhnxxmTgt4PaXlhsZIQPA4SE81ODwW9wQY9BKBNMI86Q38/5DoAYUwBZXtFAdEsUJZzaW8HCL0B3wBh7A4qGWkkVCMJDh0QPD0eAx4lukgZTkBLLjdyAbYCkyAgWHm8HxsuFBMAGxt4pgHuCv3PAShNdLQIMAATfSQXFEtbDFHyBDQFaQqLAR0AZXkalBkSJQUxFESLGQmmT841T0vm4HcFCA8AdjhaLwBBStseAz1L7BFBDgEVA3YGnBk+BD3oAJoEwlILFppOCwIeDBUQzntD+oaxJbOqEsPmVoztmeEOgU272aOQMCbwOpB/Ypso4k/TTLW0oWpP3Rz3gHw2yY1UgZPtktnZk107pZPg3CQ+O2NJZ4RdQ8VrO8v8sA5Nf64eb7biK378+U434pbsbN5D/nUXJvQoZ2tsF7kCJBqxJCTNIptt2KVrMk9oCmdP0yza2mLjtAXAvD9RwvMgHNASOAHQHieInuWJb1575ohdCFscyN5HjENm6r3fmapvd12TrCubUm7XFYfHvmy8dSIQOESuJavaW0D8rbUXGUc7rPRuiWRnOFLlYcrqLc3LiwzjN7uzF6ECR7SY0Tzdx+FJN5Dl8dSD9VRuo2SKneiXQYjuXJ70nT50AuF9I7taX6vp5rEML9UbCTMpLStDd8XHbeVYsjSuXkuxcXDGzy11XOqM4/Ld+ZRABTvb0FzlY8mXbveszS4/glZhNu5eLJmy5AooQTWVutjvuWDrsDkUZ9am2TOeKMG8TLHRwjVBB4FhPtiujqXvesGvWwQ1w3s89y+jX47rIhp+El9c2QFM4BVQggIR28OeFU3V5TjwdLSSW8/9MAJ+qPuP74Iy+oDcIeIjgCJGHt52YnnwJV5+xKR+HjQws+fTAiOhcOW+zy609VzzQk+y0A7kdHdBBsXBB36UOFdzdYujG5PO1IXoFWrs3trl6gV4JKHvTsSvFdHz22LQv21L1uh45KVqrt+uUQyVd6ulDXkU/TOXxUk+HcujwWsIGjbyNKggFFDe5Mc4eHSKGezjtMlWeigB0nB6+8BrawOjtBF04xeKukf+o037M7ExZxCAGsVZ0PpTtc1TJlHhU+eUkh3LpBhTs2XCQewf98wydOE14KvF948SMOcIGmBFbIJR1V45meM46ACb1xWIaoJ3MkVdmkp7LuDsLQXzO742rKyrd/KspPEmjyviR3dNO/MNxJTes46EMlMdsAMMLPebHcs5hRcRuz1/3OWqWFHqsh7caP90rBA5z+0izaxZSEowxCpGcXJQmNX9ZRy7Wv2wppZZq5X96vy3Rhy6NkxfjqH4/xB5uK7Icux88zxeKS7HmRvYcD8R+lFRBO5I2hpXjDgvpLU+7LiZ7rsriL2IYSB5FoDZgc0aM7b51cp3qP5LO1LVPlSZunn1e/++/NlO4eEbUxhPePIEkeDKLV5SOXSS+SdvvpIbWH7fhP2kZRVCfvWrXrTny8dF2vD0/c17qfSxPu4hBzxzYL0X0HiW3j4APx7arPhNWGGOMWyuGGwuycrdUX3N1O3MCM+qWMORw+vbHSf7dxpmse8hGZvWaY9vtOvMRlFdhveoSnJLhb63k7kZxhLgSnbSVrw4SgaQmAVbn9aMlXJUuAW5/7DeZtB3AXYZJsC8u7TQ3U6MRQH3W0Y+TbKy23n6WDnjFbCNWCdxG69uYaQ65G91unS+/VBV5ogka0CGR7Pv1YajbSPKr+opmKCb8f/fHsNZ6yFhw4UYHSVjedw+2yeZ5IuZ6t35SPLGkb2zQC2XtoVv4vfHXPMH9GXD0mvawBsT2wVm/NdfNcvMGrXSpnK8FBBUUazjP+S4U5ffPk0rTU/FefFYW+Y2Ir95i4j0HghljDTPXjDwRIS9jeeG8RSNJV1X7TJVb/w2cACSCwugUvUcxGm9OQL9SDI=';

let r$1 = decode_payload(PAYLOAD$1);
const BIDI_R_AL = read_member_table(r$1);
const BIDI_L = read_member_table(r$1);
const BIDI_AN = read_member_table(r$1);
const BIDI_EN = read_member_table(r$1);
const BIDI_ECTOB = read_member_table(r$1);
const BIDI_NSM = read_member_table(r$1);

// [Validity] 8.) If CheckBidi, and if the domain name is a Bidi domain name, then the label 
// must satisfy all six of the numbered conditions in [IDNA2008] RFC 5893, Section 2.
// * The spec is ambiguious regarding when you can determine a domain name is bidi
// * According to IDNATestV2, this is calculated AFTER puny decoding
// https://unicode.org/reports/tr46/#Notation
// A Bidi domain name is a domain name containing at least one character with BIDI_Class R, AL, or AN

function is_bidi_label(cps) {
	return cps.some(cp => lookup_member(BIDI_R_AL, cp) || lookup_member(BIDI_AN, cp));
}

function validate_bidi_label(cps) {
	if (cps.length == 0) return;
	// https://www.rfc-editor.org/rfc/rfc5893.txt
	// 1.) The first character must be a character with Bidi property L, R, 
	// or AL.  If it has the R or AL property, it is an RTL label; if it
	// has the L property, it is an LTR label.
	let last = cps.length - 1;
	if (lookup_member(BIDI_R_AL, cps[0])) { // RTL 
		// 2.) In an RTL label, only characters with the Bidi properties R, AL,
		// AN, EN, ES, CS, ET, ON, BN, or NSM are allowed.
		if (!cps.every(cp => lookup_member(BIDI_R_AL, cp) 
			|| lookup_member(BIDI_AN, cp)
			|| lookup_member(BIDI_EN, cp)
			|| lookup_member(BIDI_ECTOB, cp) 
			|| lookup_member(BIDI_NSM, cp))) throw new Error(`RTL: disallowed properties`);
		// 3. In an RTL label, the end of the label must be a character with
		// Bidi property R, AL, EN, or AN, followed by zero or more
		// characters with Bidi property NSM.
		while (lookup_member(BIDI_NSM, cps[last])) last--;
		last = cps[last];
		if (!(lookup_member(BIDI_R_AL, last) 
			|| lookup_member(BIDI_EN, last) 
			|| lookup_member(BIDI_AN, last))) throw new Error(`RTL: disallowed ending`);
		// 4. In an RTL label, if an EN is present, no AN may be present, and vice versa.
		let en = cps.some(cp => lookup_member(BIDI_EN, cp));
		let an = cps.some(cp => lookup_member(BIDI_AN, cp));
		if (en && an) throw new Error(`RTL: AN+EN`);
	} else if (lookup_member(BIDI_L, cps[0])) { // LTR
		// 5. In an LTR label, only characters with the Bidi properties L, EN,
		// ES, CS, ET, ON, BN, or NSM are allowed.
		if (!cps.every(cp => lookup_member(BIDI_L, cp) 
			|| lookup_member(BIDI_EN, cp)
			|| lookup_member(BIDI_ECTOB, cp)
			|| lookup_member(BIDI_NSM, cp))) throw new Error(`LTR: disallowed properties`);
		// 6. end with L or EN .. 0+ NSM
		while (lookup_member(BIDI_NSM, cps[last])) last--;
		last = cps[last];
		if (!lookup_member(BIDI_L, last) 
			&& !lookup_member(BIDI_EN, last)) throw new Error(`LTR: disallowed ending`);
	} else {
		throw new Error(`unknown direction`);
	}
}

var PAYLOAD = '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';

// built: 2021-12-23T21:04:48.791Z
let r = decode_payload(PAYLOAD);
const STOP = read_member_function(r);
const VALID = read_member_function(r);
const IGNORED = read_member_function(r);
const MAPPED = read_mapped_table(r);
const COMBINING_MARKS = read_member_function(r);
const EMOJI_PARSER = r() && emoji_parser_factory(r);

// emoji tokens are as-is
// text tokens are normalized
// note: it's safe to apply to entire 
// string but you'd have to retokenize
function flatten_label_tokens(tokens) {
	return tokens.flatMap(token => token.e ?? nfc(token.v));
}

function label_error(cps, message) {
	return new Error(`Disallowed label "${escape_unicode(String.fromCodePoint(...cps))}": ${message}`);
}

// Primary API
// throws TypeError if not a string
// throws Error if not normalizable
// returns a string ready for namehash
function ens_normalize(name) { 
	// 
	// Original Specification: 
	// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-137.md
	// "UTS46 with the options transitional=false and useSTD3AsciiRules=true."
	// * IDNA 2003 or 2008 = not-specified
	// * CheckHyphens = true
	// * CheckJoiners = true
	// * CheckBidi = not-specified
	// * ContextJ = not-specified
	// * ContextO = not-specified
	//
	// This Library:
	// * IDNA 2008 w/ an UTS-51 emoji parser
	// * Alternative stops are disallowed
	// * ContextJ = ContextO = true
	// * CheckBidi = yes (if xbidi = no)
	// see: build-tables.js
	//
	// https://www.unicode.org/reports/tr51/
	// https://unicode.org/reports/tr46/#Processing
	// https://unicode.org/reports/tr46/#Validity_Criteria
	// [Processing] 1.) Map
	// [Processing] 2.) Normalize: Normalize the domain_name string to Unicode Normalization Form C.
	// [Processing] 3.) Break: Break the string into labels at U+002E ( . ) FULL STOP.
	const HYPHEN = 0x2D; // HYPHEN MINUS
	let labels = tokenized_idna(explode_cp(name), EMOJI_PARSER, cp => {
		// ignored: Remove the code point from the string. This is equivalent to mapping the code point to an empty string.
		if (STOP(cp)) return;
		if (IGNORED(cp)) return [];
		// deviation: Leave the code point unchanged in the string.
		// valid: Leave the code point unchanged in the string.		
		if (VALID(cp)) return [cp];
		// mapped: Replace the code point in the string by the value for the mapping in Section 5, IDNA Mapping Table.
		let mapped = lookup_mapped(MAPPED, cp);
		if (mapped) return mapped;
		// disallowed: Leave the code point unchanged in the string, and record that there was an error.
		throw new Error(`Disallowed character "${escape_unicode(String.fromCodePoint(cp))}"`);
	}).map(tokens => {
		let cps = flatten_label_tokens(tokens);
		// [Processing] 4.) Convert/Validate
		if (cps.length >= 4 && cps[2] == HYPHEN && cps[3] == HYPHEN) { // "**--"
			if (cps[0] == 0x78 && cps[1] == 0x6E) { // "xn--"
				let cps_decoded;
				try {
					// Attempt to convert the rest of the label to Unicode according to Punycode [RFC3492].
					// If that conversion fails, record that there was an error, and continue with the next label.
					cps_decoded = puny_decode(cps.slice(4));
					// With either Transitional or Nontransitional Processing, sources already in Punycode are validated without mapping. 
					// In particular, Punycode containing Deviation characters, such as href="xn--fu-hia.de" (for fuß.de) is not remapped. 
					// This provides a mechanism allowing explicit use of Deviation characters even during a transition period. 
					[tokens] = tokenized_idna(cps_decoded, EMOJI_PARSER, cp => VALID(cp) ? [cp] : []);
					let expected = flatten_label_tokens(tokens);
					if (cps_decoded.length != expected.length || !cps_decoded.every((x, i) => x == expected[i])) throw new Error('not normalized');
				} catch (err) {
					throw label_error(cps, `punycode: ${err.message}`);
				}
				// Otherwise replace the original label in the string by the results of the conversion. 
				cps = cps_decoded;
				// warning: this could be empty
				// warning: this could be "**--"
			}
		}
		if (cps.length > 0) {
			// [Validity] 1.) The label must be in Unicode Normalization Form NFC.
			// => satsified by nfc() via flatten_label_tokens()
			// [Validity] 2.) If CheckHyphens, the label must not contain a U+002D HYPHEN-MINUS character in both the third and fourth positions.
			// note: we check this here (rather than above) because puny can expand into "aa--bb"
			if (cps.length >= 4 && cps[2] == HYPHEN && cps[3] == HYPHEN) throw label_error(cps, `invalid label extension`);
			// [Validity] 3.) If CheckHyphens, the label must neither begin nor end with a U+002D HYPHEN-MINUS character.
			if (cps[0] == HYPHEN) throw label_error(cps, `leading hyphen`);
			if (cps[cps.length - 1] == HYPHEN) throw label_error(cps, `trailing hyphen`);		
			// [Validity] 4.) The label must not contain a U+002E ( . ) FULL STOP.
			// => satisfied by [Processing] 3.) Break
			// [Validity] 5.) The label must not begin with a combining mark, that is: General_Category=Mark.
			if (COMBINING_MARKS(cps[0])) throw label_error(cps, `leading combining mark`);
			// [Validity] 6.) For Nontransitional Processing, each value must be either valid or deviation.
			// => satisfied by tokenized_idna()
			// [Validity] 7.) If CheckJoiners, the label must satisify the ContextJ rules
			// this also does ContextO
			try {
				// emoji should be invisible to context rules
				// IDEA: replace emoji w/a generic character 
				validate_context(tokens.flatMap(({v}) => v ?? []));
			} catch (err) {
				throw label_error(cps, err.message);
			}
			// [Validity] 8.) see below
		}
		return tokens;
	});
	// [Validity] 8.) If CheckBidi, and if the domain name is a Bidi domain name, then the label 
	// must satisfy all six of the numbered conditions in [IDNA2008] RFC 5893, Section 2.
	/*BIDI*/
	// * The spec is ambiguious regarding when you can determine a domain name is bidi
	// * According to IDNATestV2, this is calculated AFTER puny decoding
	// https://unicode.org/reports/tr46/#Notation
	// A Bidi domain name is a domain name containing at least one character with BIDI_Class R, AL, or AN
	let text_labels = labels.map(tokens => tokens.flatMap(({v}) => v ?? []));
	if (text_labels.some(is_bidi_label)) {
		for (let i = 0; i < labels.length; i++) {
			try {
				validate_bidi_label(text_labels[i]);
			} catch (err) {
				throw label_error(flatten_label_tokens(labels[i]), `bidi: ${err.message}`);
			}
		}
	}
	/*~BIDI*/
	return labels.map(tokens => String.fromCodePoint(...flatten_label_tokens(tokens))).join('.');
}

// Secondary API
// throws TypeError if not a string
// turns a name into tokens: eg. "R💩affy.eth"
// this is much nicer than exposing the predicates
// [[{m:0x52, to:[0x72]},{e:[0x1F4A9]},{t:[61,66,66]}],[{t:[65,74,68]}]]
function ens_tokenize(name) {
	return tokenized_idna(explode_cp(name), EMOJI_PARSER, cp => {
		if (STOP(cp)) return {};
		if (VALID(cp)) return [cp];
		if (IGNORED(cp)) return {i: cp};
		let mapped = lookup_mapped(MAPPED, cp);
		if (mapped) return {m: cp, u: mapped};
		return {d: cp};
	})[0];
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

// expects a string
// warning: this does not normalize
// https://eips.ethereum.org/EIPS/eip-137#name-syntax
function labelhash(label) {
	return keccak().update(label).bytes
}
function hash_from_label(label) {
	return new Uint256(labelhash(label));
}
function node_from_ens_name(name) {
	if (typeof name !== 'string') throw new TypeError('expected string');
	let buf = new Uint8Array(64); 
	if (name.length > 0) {
		for (let label of name.split('.').reverse()) {
			buf.set(labelhash(label), 32);
			buf.set(keccak().update(buf).bytes, 0);
		}
	}
	return new Uint256(buf.slice(0, 32));
}

const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'; // ens registry contract on mainnet
const RESOLVED = Symbol('ENSResolved');

function resolved_value() {
	return new Date();
}

// turn a name/address/object into {node, resolver, ...}
async function ens_resolve(provider, input) {
	if (input instanceof Uint256) { // node
		let resolver = await call_registry_resolver(provider, input);
		return {node: input, resolver, [RESOLVED]: resolved_value()};
	}
	if (typeof input === 'object') { // previously resolved object? 
		if (RESOLVED in input) return input; // trusted
		input = input.node ?? input.name ?? input.address; // fallback
	}
	if (typeof input === 'string') { // name or address
		input = input.trim();
		if (input.length > 0) {
			let name0 = input;
			try { 
				// assume input is address
				name0 = await ens_name_for_address(provider, input); 
			} catch (ignored) {
			}
			if (!name0) {
				// this only happens if input was address
				// and no primary was set
				throw new Error(`No primary for address`);
			}
			let name = ens_normalize(input);
			let node = node_from_ens_name(name);
			let resolver = await call_registry_resolver(provider, node);
			return {name0, name, node, resolver, [RESOLVED]: resolved_value()};
		}
	}
	throw new TypeError('Expected name or address');
}

// this lookups up an address for name
// it also stores the result into the record
async function lookup_address(provider, input) {
	let ret = await ens_resolve(provider, input);
	let {resolver, node, address} = ret;
	if (is_null_hex(resolver)) return; // no resolver
	if (address) return address; // already looked up
	ret.address = address = await call_resolver_addr(provider, resolver, node);
	return address;
}

/*
// https://eips.ethereum.org/EIPS/eip-137
export async function address_from_ens_name(provider, name0) {	
	let name = ens_normalize(name0); // throws 
	let node = node_from_ens_name(name);
	return {name0, name, ...await address_from_node(provider, node), [RESOLVED]: resolved_value()};
}
*/
/*
export async function is_available(provider, input) {
	let ret = await ens_resolve(provider, input);
	let {resolver, node, address} = ret;
	
	const SIG = '96e494e8'; // available(uint256)
	let available = (await eth_call(provider, ENS_REGISTRY, ABIEncoder.method(SIG).number(node))).boolean();
	return {name0, name, node, available};
}


export async function ens_label_owner(provider, name0) {
	let name = ens_normalize(name0); // throws 
	let [label, rest] = name.split('.', 2);
	if (!rest) throw new Error('top level');
	let node = ens_node_from_name(rest);
	let domain = await ens_address_from_node(provider, node);
	if (!domain) throw new Error(`domain does not exist: ${rest}`);
	domain.name = rest;
	let token = labelhash(label);
	let ret = {name, label, token, domain};
	try {
		const SIG = '6352211e'; // ownerOf(uint256)
		ret.owner = (await eth_call(provider, address, ABIEncoder.method(SIG).add_hex(token))).addr();
	} catch (err) {
		if (!err.reverted) throw err;
	}
	return ret;
}
*/

// https://eips.ethereum.org/EIPS/eip-181
// warning: this doesn't have to be normalized
async function ens_name_for_address(provider, address) {
	if (typeof address === 'object') ({address} = address);
	address = checksum_address(address); // throws
	let rev_node = node_from_ens_name(`${address.slice(2).toLowerCase()}.addr.reverse`); 
	let rev_resolver = await call_registry_resolver(provider, rev_node);
	if (is_null_hex(rev_resolver)) return; // undefined
	const SIG = '691f3431'; // name(bytes)
	return (await eth_call(provider, rev_resolver, ABIEncoder.method(SIG).number(rev_node))).string();
}

// https://medium.com/the-ethereum-name-service/step-by-step-guide-to-setting-an-nft-as-your-ens-profile-avatar-3562d39567fc
// https://medium.com/the-ethereum-name-service/major-refresh-of-nft-images-metadata-for-ens-names-963090b21b23
// https://github.com/ensdomains/ens-metadata-service
async function ens_avatar(provider, input) {
	let ret = await ens_resolve(provider, input);
	let {node, resolver, address} = ret;
	if (is_null_hex(resolver)) return {type: 'none', ...ret};
	if (!address) ret.address = await call_resolver_addr(provider, resolver, node);
	ret.avatar = await call_resolver_text(provider, resolver, node, 'avatar');
	return {...ret, ...await parse_avatar(ret.avatar, provider, ret.address)};
}

// note: the argument order here is non-traditional
async function parse_avatar(avatar, provider = null, address = false) {
	if (typeof avatar !== 'string') throw new Error('Invalid avatar: expected string');
	if (avatar.length == 0) return {type: 'null'}; 
	if (avatar.includes('://') || avatar.startsWith('data:')) return {type: 'url'};
	let parts = avatar.split('/');
	let part0 = parts[0];
	if (part0.startsWith('eip155:')) { // nft format  
		if (parts.length < 2) return {type: 'invalid', error: 'expected contract'};
		if (parts.length < 3) return {type: 'invalid', error: 'expected token'};
		let chain = parseInt(part0.slice(part0.indexOf(':') + 1));
		if (!(chain > 0)) return {type: 'invalid', error: 'expected chain id'};
		let part1 = parts[1];
		if (part1.startsWith('erc721:')) {
			let contract = part1.slice(part1.indexOf(':') + 1);
			if (!is_valid_address(contract)) return  {type: 'invalid', error: 'expected contract address'};
			let token;
			try {
				token = Uint256.from_str(parts[2]);
			} catch (err) {
				return {type: 'invalid', error: 'expected uint256 token'};
			}
			let ret = {type: 'nft', interface: 'erc721', contract, token, chain};
			if (provider && parseInt(provider.chainId) === chain) {
				const SIG_tokenURI = 'c87b56dd'; // tokenURI(uint256)
				const SIG_ownerOf  = '6352211e'; // ownerOf(uint256)
				try {
					let [owner, meta_uri] = await Promise.all([
						eth_call(provider, contract, ABIEncoder.method(SIG_ownerOf).number(token)).then(x => x.addr()),
						eth_call(provider, contract, ABIEncoder.method(SIG_tokenURI).number(token)).then(x => x.string())
					]);
					ret.owner = owner;
					ret.meta_uri = meta_uri;
					if (address) {
						ret.owned = address === owner ? 1 : 0;
					}
				} catch (err) {
					return {type: 'invalid', error: `invalid response from contract`};
				}
			}
			return ret;
		} else if (part1.startsWith('erc1155:')) {
			// https://eips.ethereum.org/EIPS/eip-1155
			let contract = part1.slice(part1.indexOf(':') + 1);
			if (!is_valid_address(contract)) return  {type: 'invalid', error: 'invalid contract address'};
			let token;
			try {
				token = Uint256.from_str(parts[2]);
			} catch (err) {
				return {type: 'invalid', error: 'expected uint256 token'};
			}
			let ret = {type: 'nft', interface: 'erc1155', contract, token, chain};
			if (provider && parseInt(provider.chainId) === chain) {
				const SIG_uri       = '0e89341c'; // uri(uint256)
				const SIG_balanceOf = '00fdd58e'; // balanceOf(address,uint256)
				try {
					let [balance, meta_uri] = await Promise.all([
						!address ? -1 : eth_call(provider, contract, ABIEncoder.method(SIG_balanceOf).addr(address).number(token)).then(x => x.number()),
						eth_call(provider, contract, ABIEncoder.method(SIG_uri).number(token)).then(x => x.string())
					]);
					// The string format of the substituted hexadecimal ID MUST be lowercase alphanumeric: [0-9a-f] with no 0x prefix.
					ret.meta_uri = meta_uri.replace('{id}', hex_from_bytes(token.bytes)); 
					if (address) {
						ret.owned = balance;
					}
				} catch (err) {
					return {type: 'invalid', error: `invalid response from contract`};
				}
			}
			return ret;
		} else {
			return {type: 'invalid', error: `unsupported contract interface: ${part1}`};
		}		
	}
	return {type: 'unknown'};
}

// https://eips.ethereum.org/EIPS/eip-634
// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/TextResolver.sol
async function ens_text_record(provider, input, keys) {
	if (typeof keys === 'string') keys = [keys];
	if (!Array.isArray(keys)) throw new TypeError('Expected key or array of keys');
	let ret = await ens_resolve(provider, input);
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
	addresses = addresses.map(get_addr_type_from_input); // throws
	let ret = await ens_resolve(provider, input);
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
	let ret = await ens_resolve(provider, input);
	let {node, resolver} = ret;
	if (!is_null_hex(resolver)) {
		const SIG = 'bc1c58d1'; // contenthash(bytes32)
		let v = (await eth_call(provider, resolver, ABIEncoder.method(SIG).number(node))).memory();
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
	let ret = await ens_resolve(provider, input);
	let {node, resolver} = ret;
	if (!is_null_hex(resolver)) {
		const SIG = 'c8690233'; // pubkey(bytes32)
		let dec = await eth_call(provider, resolver, ABIEncoder.method(SIG).number(node));
		ret.pubkey = {x: dec.uint256(), y: dec.uint256()};
	}
	return ret;
}

function format_addr_type(i) {
	return '0x' + i.toString(16).padStart(4, '0');
}

// see: test/build-address-types.js
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
function get_addr_type_from_input(x) {
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
			name = format_addr_type(x);
		}
		return [name, x];
	} else {
		throw new TypeError('Expected address type or name');
	}
}

async function call_registry_resolver(provider, node) {
	const SIG = '0178b8bf'; // resolver(bytes32)
	try {
		return (await eth_call(provider, ENS_REGISTRY, ABIEncoder.method(SIG).number(node))).addr();
	} catch (cause) {
		throw new Error('Invalid response from registry', {cause});
	}
}

// this effectively is the same thing as:
// call_resolver_addr_for_type(node, 60)
async function call_resolver_addr(provider, resolver, node) {
	const SIG = '3b3b57de'; // addr(bytes32)
	try {
		return (await eth_call(provider, resolver, ABIEncoder.method(SIG).number(node))).addr();
	} catch (cause) {
		throw new Error('Invalid response from resolver for addr', {cause});
	}
}

async function call_resolver_text(provider, resolver, node, key) {
	const SIG = '59d1d43c'; // text(bytes32,string)
	try {
		return (await eth_call(provider, resolver, ABIEncoder.method(SIG).number(node).string(key))).string();
	} catch (cause) {
		throw new Error(`Invalid response from resolver for text: ${key}`, {cause});
	}
}

async function call_resolver_addr_for_type(provider, resolver, node, type) {
	const SIG = 'f1cb7e06'; // addr(bytes32,uint256);
	try {
		return (await eth_call(provider, resolver, ABIEncoder.method(SIG).number(node).number(type))).memory();
	} catch (cause) {
		throw new Error(`Invalid response from resolver for addr of type: ${format_addr_type(type)}`, {cause});
	}
}

export { ABIDecoder, ABIEncoder, ADDR_TYPES, FetchProvider, NULL_ADDRESS, Uint256, WebSocketProvider, base58_from_bytes, bytes_from_base58$1 as bytes_from_base58, bytes_from_digits_or_null, bytes_from_hex, bytes_from_utf8, checksum_address, compare_arrays, ens_addr_record, ens_avatar, ens_contenthash_record, ens_name_for_address, ens_normalize, ens_pubkey_record, ens_resolve, ens_text_record, ens_tokenize, eth_call, hash_from_label, hex_from_bytes, is_checksum_address, is_multihash, is_null_hex, is_valid_address, keccak, left_truncate_bytes, lookup_address, node_from_ens_name, parse_avatar, parse_bytes_from_digits, retry, set_bytes_to_unsigned, sha3, shake, unsigned_from_bytes, utf8_from_bytes };
