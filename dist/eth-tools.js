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
	if (s.startsWith('0x')) s = s.slice(2); // optional prefix
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
	let n = a.length;
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
		return checksum_address(s) === s;
	} catch (ignored) {
		// undefined lets you differentiate !checksum from !address
	}
}

function is_null_hex(s) {
	return /^(0x)?[0]+$/i.test(s);
}

function is_multihash(s) {
	try {
		let v = bytes_from_base58(s);
		return v.length >= 2 && v.length == 2 + v[1];
	} catch (ignored) {
		return false;
	}
}

function fix_multihash_uri(s) {
	if (is_multihash(s)) { // just a hash
		return `ipfs://${s}`;
	}
	let match;
	if (match = s.match(/^ipfs\:\/\/ipfs\/(.*)$/i)) { // fix "ipfs://ipfs/.."
		return `ipfs://${match[1]}`;
	}
	/*
	let match;
	if ((match = s.match(/\/ipfs\/([1-9a-zA-Z]{32,})(\/?.*)$/)) && is_multihash(match[1])) {
		s = `ipfs://${match[1]}${match[2]}`;
	}
	*/
	return s;
}

class Uint256 {	
	static wrap(x) { // tries to avoid a copy
		if (x instanceof Uint256) {
			return x;
		} else if (x instanceof Uint8Array) {
			return new this(left_truncate_bytes(v, 32, false));
		} else if (Number.isSafeInteger(x)) {
			return this.from_number(x);
		} else if (typeof x === 'string') {
			return this.from_str(x);	
		} else {
			throw new TypeError(`not Uint256-like: ${x}`);
		}
	}
	static zero() {
		return new this(new Uint8Array(32));
	}
	static from_number(i) {
		return this.zero().set_number(i);
	}
	static from_bytes(v) { // this copies
		return new this(left_truncate_bytes(v, 32));
	}	
	static from_str(s) { // this works like parseInt
		return s.startsWith('0x') ? this.from_hex(s) : this.from_dec(s);
	}
	static from_hex(s) {
		return this.from_bytes(bytes_from_hex(s));
	}
	static from_dec(s) {
		if (!/^[0-9]+$/.test(s)) throw new TypeError(`expected decimal digits: ${s}`);
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
	// this should not be used directly
	// warning: this does not copy!
	constructor(v) {
		if (!(v instanceof Uint8Array)) throw new TypeError('expected bytes');
		if (v.length != 32) throw new TypeError('expected 32 bytes');
		this.bytes = v;
	}
	clone() {
		return new this.constructor(this.bytes.slice());
	}
	compare(x) {
		return compare_arrays(this.bytes, this.constructor.wrap(x).bytes); // throws
	}
	set_number(i) {	 
		set_bytes_to_number(this.bytes, i); // throws
		return this;
	}
	add(x) {
		let other = this.constructor.wrap(x).bytes; // throws
		let {bytes} = this;
		let carry = 0;
		for (let i = 31; i >= 0; i--) {
			let sum = bytes[i] + other[i] + carry;
			bytes[i] = sum;
			carry = sum >> 8;
		}
		return this;
	}
	not() {
		this.bytes.forEach((x, i, v) => v[i] = ~x);
		return this;
	}
	get number() {
		let {bytes} = this;
		if (bytes[0] == 255) { // safe because 256 - 8 > 53
			return -(1 + unsigned_from_bytes(bytes.map(x => ~x)));
		} else {
			return unsigned_from_bytes(bytes);
		}
	}
	get unsigned() { return unsigned_from_bytes(this.bytes); }
	get hex() { return '0x' + hex_from_bytes(this.bytes); }
	get dec() { return this.digit_str(10); }	
	digit_str(radix, lookup = '0123456789abcdefghjiklmnopqrstuvwxyz') {
		if (radix > lookup.length) throw new RangeError(`radix larger than lookup: ${x}`);
		return this.digits(radix).map(x => lookup[x]).join('');
	}
	digits(radix) {
		if (radix < 2) throw new RangeError(`radix must be 2 or more: ${radix}`);
		let digits = [0];
		for (let x of this.bytes) {
			for (let i = 0; i < digits.length; ++i) {
				let xx = (digits[i] << 8) | x;
				digits[i] = xx % radix;
				x = (xx / radix) | 0;
			}
			while (x > 0) {
				digits.push(x % radix);
				x = (x / radix) | 0;
			}
		}
		return digits.reverse();
	}
	toJSON() {
		return this.hex;
	}
	toString() {
		return `Uint256(${this.hex})`;
	}
}

// (Uint8Array) -> Number
function unsigned_from_bytes(v) {
	if (v.length > 7) {  // 53 bits => 7 bytes, so everything else must be 0
		let n = v.length - 7;
		for (let i = 0; i < n; i++) if (v[i] > 0) throw new RangeError('overflow');
		v = v.subarray(n);
	}
	let n = 0;
	for (let i of v) n = (n * 256) + i; // cannot use shifts since 32-bit
	if (!Number.isSafeInteger(n)) throw new RangeError('overflow');
	return n;
}

// (Uint8Array, number)
// cannot use bitwise due to 32-bit truncation
function set_bytes_to_number(v, i) {
	if (!Number.isSafeInteger(i)) throw new RangeError(`expected integer: ${i}`);	
	if (i < 0) {
		i = -(i+1);
		for (let pos = v.length - 1; pos >= 0; pos--) {
			v[pos] = ~(i & 0xFF);
			i = Math.floor(i / 256); 
		}
	} else {
		for (let pos = v.length - 1; pos >= 0; pos--) {
			v[pos] = (i & 0xFF);
			i = Math.floor(i / 256); 
		}
	}
}

// return exactly n-bytes
// this always returns a copy
function left_truncate_bytes(v, n, copy_when_same = true) {
	let {length} = v;
	if (length == n) return copy_when_same ? v.slice() : v;
	if (length > n) return v.slice(n - length); // truncate
	let copy = new Uint8Array(n);
	copy.set(v, n - length); // zero pad
	return copy;
}

class ABIDecoder {
	static from_hex(x) { return new this(bytes_from_hex(x)); }
	constructor(buf) {
		this.buf = buf;
		this.pos = 0;
	}
	get remaining() { return this.buf.length - this.pos; }
	read_bytes(n) {  // THIS DOES NOT COPY
		let {pos, buf} = this;
		let end = pos + n;
		if (end > buf.length) throw new RangeError('buffer overflow');
		let v = buf.subarray(pos, end);
		this.pos = end;
		return v;
	}
	read_memory() { // THIS DOES NOT COPY
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
	read_byte() {
		let {pos, buf} = this;
		if (pos >= buf.length) throw new RangeError('buffer overflow');
		this.pos = pos + 1;
		return buf[pos];
	}
	// these all effectively copy 
	bytes(n) { return this.read_bytes(n).slice(); }
	boolean() { return this.number() > 0; }	
	number(n = 32) { return unsigned_from_bytes(this.read_bytes(n)); }
	uint256() { return new Uint256(this.bytes(32)); } 
	string() { return utf8_from_bytes(this.read_memory()); }	
	memory() { return this.read_memory().slice(); }
	addr(checksum = true) {
		if (this.read_bytes(12).some(x => x > 0)) throw new TypeError('invalid address: expected zero');
		let v = this.read_bytes(20);
		let addr = hex_from_bytes(v);
		return checksum ? checksum_address(addr) : `0x${addr}`; 
	}
	//https://github.com/multiformats/unsigned-varint
	uvarint() { 
		let acc = 0;
		let scale = 1;
		const MASK = 0x7F;
		while (true) {
			let next = this.read_byte();
			acc += (next & 0x7F) * scale;
			if (next <= MASK) break;
			if (scale > 0x400000000000) throw new RangeException('overflow'); // Ceiling[Number.MAX_SAFE_INTEGER/128]
			scale *= 128;
		}
		return acc;
	}
}

function bytes4_from_method(x) {
	if (x.includes('(')) {
		return keccak().update(x).bytes.subarray(0, 4);
	} else {
		try {
			let v = x instanceof Uint8Array ? x : bytes_from_hex(x);
			if (v.length != 4) throw new Error('expected 4 bytes');
			return v;
		} catch (err) {
			throw new Error(`method ${x} should be a signature or 8-char hex`);
		}
	}
}

class ABIEncoder {
	static method(method) {
		// method signature doesn't contribute to offset
		return new ABIEncoder(4).add_bytes(bytes4_from_method(method)); 
	}
	constructor(offset = 0, capacity = 256) { //, packed = false) {
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
		if (!Number.isSafeInteger(n) || n < 1) throw new TypeError('expected positive size');
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
			set_bytes_to_number(this.alloc(n), i);
		}
		return this; // chainable
	}
	string(s) { return this.memory(bytes_from_utf8(s)); } // chainable
	memory(v) {
		let {pos} = this; // remember offset
		this.alloc(32); // reserve spot
		let tail = new Uint8Array((v.length + 63) & ~31); // len + bytes + 0* [padded]
		set_bytes_to_number(tail.subarray(0, 32), v.length);
		tail.set(v, 32);
		this.tails.push([pos, tail]);
		return this; // chainable
	}
	addr(s) {
		let v = bytes_from_hex(s); // throws
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

// returns provider chain id
async function chain_id_from_provider(provider) {
	return parseInt(await provider.request({method: 'eth_chainId'}));
}

// returns string regarding provider construction
async function source_from_provider(provider) {
	let source = provider.source?.();
	if (source) return source;
	if (provider.isMetaMask) return 'MetaMask';
	return 'Unknown';
}

function parse_chain_id(x) {
	if (typeof x === 'string') x = parseInt(x);
	if (!Number.isSafeInteger(x)) throw new TypeError(`expected chain: ${x}`);
	return x;
}

class Providers {
	static from_map(map) {
		if (typeof map !== 'object') throw new TypeError('expected object');
		let p = new Providers();
		for (let [k, v] of Object.entries(map)) {
			p.add_static(k, v);
		}
		return p;
	}
	constructor({cooldown = 30000} = {}) {
		this.queue = [];
		this.cooldown = cooldown;
	}
	add_static(chain_id, provider) {
		chain_id = parse_chain_id(chain_id);
		if (!this.queue.some(x => x.provider === provider)) { // only add once
			this.queue.push({chain_id, provider}); // low priority
		}
		return this; // chainable
	}
	add_dynamic(provider) {
		if (!this.queue.some(x => x.provider === provider)) { // only add once
			let rec = {provider, chain_id: null}; // unknown
			provider.on('connect', ({chainId}) => { 
				rec.chain_id = parseInt(chainId);
			});
			provider.on('chainChanged', chainId => {
				rec.chain_id = parseInt(chainId);
			});
			this.queue.unshift(rec); // high priority
		}
		return this; // chainable
	}
	disconnect() {
		for (let {provider} of this.queue) {
			provider.disconnect?.();
		}
	}
	async find_provider(chain_id, required = false, dynamic = true) {
		if (chain_id !== undefined && !Number.isSafeInteger(chain_id)) {
			throw new TypeError(`expected chain_id integer: ${chain_id}`);
		}
		if (dynamic) {
			await Promise.all(this.queue.filter(x => x.chain_id === null).map(async rec => {
				try {
					rec.chain_id = await chain_id_from_provider(rec.provider);
				} catch (err) {
					rec.chain_id = false;
					rec.cooldown = setTimeout(() => {
						rec.chainId = null;
					}, this.cooldown);
				}
			}));
		}
		let rec = this.queue.find(rec => rec.chain_id === chain_id);
		if (!rec && required) throw new Error(`No provider for chain ${chain_id}`);
		return rec?.provider;
	}
	view(chain_id) {
		chain_id = parse_chain_id(chain_id);
		let get_provider = async (...a) => {
			return this.find_provider(chain_id, ...a);
		};
		return new Proxy(this, {
			get: (target, prop) => {
				switch (prop) {
					case 'isProviderView': return true;
					case 'get_provider': return get_provider;
					default: return target[prop];
				}
			}
		});
	}
}

// detect-provider is way too useless to require as a dependancy 
// https://github.com/MetaMask/detect-provider/blob/main/src/index.ts
async function determine_window_provider({fix = true, timeout = 5000} = {}) {
	return new Promise((ful, rej) => {
		let timer, handler;
		const EVENT = 'ethereum#initialized';
		if (check()) return;
		timer = setTimeout(() => {
			globalThis?.removeEventListener(EVENT, handler);
			check() || rej(new Error(`No window.ethereum`));
		}, timeout|0);
		handler = () => {
			clearTimeout(timer);		
			globalThis?.removeEventListener(EVENT, handler);
			check() || rej(new Error('jebaited'));
		};
		globalThis?.addEventListener(EVENT, handler);
		function check() {
			let e = globalThis.ethereum;
			if (e) {
				ful(fix ? retry(e) : e);
				return true;
			}
		}
	});
}

// return true if the request() error is due to bug
// this seems to be an geth bug (infura, cloudflare, metamask)
// related to not knowing the chain id
function is_header_bug(err) {
	return err.code === -32000 && err.message === 'header not found';
}

// fix the bug above
function retry(provider, {retry = 2, delay = 1000} = {}) {
	if (typeof retry !== 'number' || retry < 1) throw new TypeError('expected retry > 0');
	if (typeof delay !== 'number' || delay < 0) throw new TypeError('expected delay >= 0');
	if (!provider) return;
	async function request(obj) {
		try {
			return await provider.request(obj);
		} catch (err) {
			if (!is_header_bug(err)) throw err;
			// make a new request that isn't dangerous
			// until we run out of tries or it succeeds
			let n = retry;
			while (true) {
				try {
					await provider.request({method: 'eth_chainId'});
					break;
				} catch (retry_err) {
					if (!is_header_bug(retry_err) && --n == 0) throw err;
				}
			}
			// then issue the request again
			return provider.request(obj);
		}
	}
	return new Proxy(provider, {
		get: function(obj, prop) {
			return prop === 'request' ? request : obj[prop];
		}
	});
}

// https://eips.ethereum.org/EIPS/eip-1193
// The Provider MUST implement the following event handling methods:
// * on
// * removeListener
// These methods MUST be implemented per the Node.js EventEmitter API.
// * https://nodejs.org/api/events.html
//
class EventEmitter {
	constructor() {
		this.__events = {};
	}
	// Synchronously calls each of the listeners registered for the event named eventName, 
	// in the order they were registered, passing the supplied arguments to each.
	// Returns: <boolean>
	// Returns true if the event had listeners, false otherwise.
	emit(event, ...args) {
		let bucket = this.__events[event];
		if (!bucket) return false;
		for (let listener of bucket) listener(...args);
		return true;		
	}
	// Adds the listener function to the end of the listeners array for the event named eventName. 
	// No checks are made to see if the listener has already been added. 
	// Multiple calls passing the same combination of eventName and listener 
	// will result in the listener being added, and called, multiple times.
	// Returns: <EventEmitter>
	on(event, listener) {
		let bucket = this.__events[event];
		if (!bucket) this.__events[event] = bucket = [];
		bucket.push(listener);
		return this;
	}
	// Removes the specified listener from the listener array for the event named eventName.
	// removeListener() will remove, at most, one instance of a listener from the listener array
	// Returns: <EventEmitter>
	removeListener(event, listener) {
		let bucket = this.__events[event];
		if (bucket) {
			let i = bucket.indexOf(listener);
			if (i >= 0) {
				bucket.splice(i, 1);
				if (bucket.length == 0) {
					delete this.__events[event];
				}
			}
		}
		return this;
	}
}

class WebSocketProvider extends EventEmitter {
	constructor({url, WebSocket: ws_api, request_timeout = 30000, idle_timeout = 60000}) {
		if (typeof url !== 'string') throw new TypeError('expected url');
		if (!ws_api) ws_api = globalThis.WebSocket;
		if (!ws_api) throw new Error('unknown WebSocket implementation');
		super();
		this.url = url;
		this._ws_api = ws_api;
		this._request_timeout = request_timeout;
		this._idle_timeout = idle_timeout;
		this._idle_timer = undefined;
		this._ws = undefined;
		this._terminate = undefined;
		this._reqs = undefined;
		this._subs = new Set();
		this._id = undefined;
		this._chain_id = undefined;
	}
	source() {
		return this.url;
	}
	// idle timeout is disabled while subscribed
	get idle_timeout() { return this._idle_timeout; }
	set idle_timeout(t) {
		this.idle_timeout = t|0;
		this._restart_idle();
	}
	disconnect() {
		this._terminate?.(new Error('Forced disconnect'));
	}
	_restart_idle() {
		clearTimeout(this._idle_timer);
		if (this._idle_timeout > 0 && (this._subs.size == 0 && Object.keys(this._reqs).length == 0)) {
			const {_terminate} = this; // snapshot
			this._idle_timer = setTimeout(() => {
				_terminate(new Error('Idle timeout'));
			}, this._idle_timeout);
		}
	}
	async request(obj) {
		if (typeof obj !== 'object') throw new TypeError('expected object');
		let {method, params} = obj;
		if (typeof method !== 'string') throw new Error(`expected method`);
		if (params && !Array.isArray(params)) throw new Error('expected params array');
		await this.ensure_connected();
		switch (method) {
			case 'eth_chainId': return this._chain_id; // avoid rpc
			case 'eth_subscribe': return this._request(obj).then(ret => {
				this._subs.add(ret);
				clearTimeout(this._idle_timer);
				return ret;
			});
			case 'eth_unsubscribe': return this._request(obj).then(ret => {
				this._subs.delete(params[0]);
				this._restart_idle();
				return ret;
			});
			default: return this._request(obj);
		}
	}
	// private:
	// assumes ws is connected
	// does not intercept method
	_request(obj) {
		const id = ++this._id; 
		const {_reqs, _ws, _request_timeout: t} = this; // snapshot
		clearTimeout(this._idle_timer);
		return new Promise((ful, rej) => {
			let timer = t > 0 ? setTimeout(() => {
				delete _reqs[id];
				this._restart_idle();
				rej(new Error('Timeout'));
			}, t) : undefined;
			_reqs[id] = {timer, ful, rej};
			_ws.send(JSON.stringify({jsonrpc: '2.0', id, ...obj}));
		});
	}
	async ensure_connected() {
		let {_ws} = this;
		if (Array.isArray(_ws)) { // currently connecting
			return new Promise((ful, rej) => {
				_ws.push({ful, rej});
			});
		} else if (_ws) { // already connected
			return;
		}
		const queue = this._ws = []; // change state
		const ws = new this._ws_api(this.url); 
		//console.log('Connecting...');
		try {  
			await new Promise((ful, rej) => {
				this._terminate = rej;
				let timer = setTimeout(() => rej(new Error('Timeout')), this._request_timeout);
				ws.addEventListener('close', rej);
				ws.addEventListener('error', rej);
				ws.addEventListener('open', () => {
					ws.removeEventListener('error', rej); 
					ws.removeEventListener('close', rej);
					clearTimeout(timer);
					ful();
				});
			});
		} catch (err) {
			ws.close();
			this._ws = undefined; // reset state
			this._terminate = undefined;
			for (let {rej} of queue) rej(err);
			this.emit('connect-error', err);
			throw err;
		}
		//console.log('Handshaking...');
		this._ws = ws; // change state
		this._id = 0;
		let reqs = this._reqs = {};
		// setup error handlers
		let close_handler;
		let error_handler = this._terminate = (err) => {
			ws.removeEventListener('close', close_handler);
			ws.removeEventListener('error', error_handler);
			ws.close();
			this._ws = undefined; // reset state
			this._terminate = undefined;
			this._reqs = undefined;
			this._id = undefined;
			this._chain_id = undefined;
			this._subs.clear();
			clearTimeout(this._idle_timer);
			for (let {rej} of Object.values(reqs)) rej(err);
			this.emit('disconnect', err);
		};
		close_handler = () => error_handler(new Error('Unexpected close'));
		ws.addEventListener('close', close_handler);
		ws.addEventListener('error', error_handler);
		ws.addEventListener('message', ({data}) => {
			let json = JSON.parse(data); // throws
			let {id} = json;
			if (id === undefined) {
				let {method, params: {subscription, result}} = json;
				this.emit('message', {type: method, data: {subscription, result}});
			} else {
				let request = reqs[id];	
				if (!request) return;
				delete reqs[json.id];
				clearTimeout(request.timer);
				this._restart_idle();
				let {result, error} = json;
				if (result) return request.ful(result);
				let err = new Error(error?.message ?? 'Unknown Error');
				if ('code' in error) err.code = error.code;
				request.rej(err);
			}
		});
		this._chain_id = await this._request({method: 'eth_chainId'});
		// MUST specify the integer ID of the connected chain as a hexadecimal string, per the eth_chainId Ethereum RPC method.
		this.emit('connect', {chainId: this._chain_id});
		//console.log('Connected');
		// handle waiters
		for (let {ful} of queue) ful();
	}
}

class FetchProvider extends EventEmitter {
	constructor({url, fetch: fetch_api, source, request_timeout = 30000, idle_timeout = 60000}) {
		if (typeof url !== 'string') throw new TypeError('expected url');
		if (!fetch_api) {
			let fetch = globalThis.fetch;
			if (!fetch) throw new TypeError(`unable to find fetch()`);
			fetch_api = fetch.bind(globalThis);
		}
		super();
		this.url = url;	
		this._fetch_api = fetch_api;
		this._id = 0;
		this._chain_id = undefined;
		this._request_timeout = request_timeout|0;
		this._idle_timeout = idle_timeout|0;
		this._idle_timer = undefined;
		this._source = source;
	}
	source() {
		return this._source ?? this.url;
	}
	async request(obj) {
		if (typeof obj !== 'object') throw new TypeError('expected object');
		if (!this._idle_timer) {
			let retry = 2;
			let retry_delay = 1000;
			while (true) {
				try {
					//await this._request({method: 'web3_clientVersion'});
					this._chain_id = await this._request({method: 'eth_chainId'});					
					break;
				} catch (err) {
					if (retry > 0 && is_header_bug(err)) { 
						await new Promise(ful => setTimeout(ful, retry_delay));
						retry--;
						continue;					
					}
					this.emit('connect-error', err);
					throw err;
				}
			}
			this.emit('connect', {chainId: this._chain_id});
			this._restart_idle();
		}
		switch (obj.method) {
			case 'eth_chainId': return this._chain_id; // fast
			case 'eth_subscribe': 
			case 'eth_unsubscribe': throw new Error(`${obj.method} not supported by FetchProvider`);
		}
		try {
			let ret = await this._request(obj);
			this._restart_idle();
			return ret;
		} catch (err) {
			this._terminate(err);
			throw err;
		}
	}
	_restart_idle() {
		clearTimeout(this._idle_timer);			
		this._idle_timer = this._idle_timeout > 0 ? setTimeout(() => {
			this._terminate(new Error('Idle timeout'));
		}, this._idle_timeout) : true;		
	}
	disconnect() {
		if (!this._idle_timer) return;
		this._terminate(new Error('Forced disconnect'));
	}
	_terminate(err) {
		this.emit('disconnect', err);
		clearTimeout(this._idle_timer);
		this._idle_timer = undefined;
		this._chain_id = undefined;
	}
	_fetch(obj, ...a) {
		return this._fetch_api(this.url, {
			method: 'POST',
			body: JSON.stringify({...obj, jsonrpc: '2.0', id: ++this._id}),
			cache: 'no-store',
			...a
		});
	}
	async _request(obj) {
		let res;
		if (this._request_timeout > 0) {
			let aborter = new AbortController();
			let timer = setTimeout(() => aborter.abort(), this._request_timeout);
			try {
				res = await this._fetch(obj, {signal: aborter.signal});
			} finally {
				clearTimeout(timer);
			}
		} else {
			res = await this._fetch(obj);
		}
		if (res.status !== 200) {
			throw new Error(`Fetch failed: ${res.status}`);
		}
		let json;
		try {
			json = await res.json();
		} catch (cause) {
			throw new Error('Invalid provider response: expected json', {cause});
		}
		let {error} = json;
		if (!error) return json.result;
		let err = new Error(error.message ?? 'unknown error');
		err.code = error.code;
		throw err;
	}
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
		let hex = await provider.request({method: 'eth_call', params:[tx, tag]});
		return ABIDecoder.from_hex(hex);
	} catch (err) {
		if (err.code == -32000 && err.message === 'execution reverted') {
			err.reverted = true;
		}
		throw err;
	}
}

async function supports_interface(provider, contract, sig) {
	const SIG = '01ffc9a7'; // supportsInterface(bytes4)
	return (await eth_call(provider, contract, ABIEncoder.method(SIG).bytes(bytes4_from_method(sig)))).boolean();
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

// accepts anything that keccak can digest
// returns Uint256
function labelhash(label) {
	return new Uint256(keccak().update(label).bytes);
}

// expects a string
// warning: this does not normalize
// https://eips.ethereum.org/EIPS/eip-137#name-syntax
// returns Uint256
function namehash(name) {
	if (typeof name !== 'string') throw new TypeError('expected string');
	let buf = new Uint8Array(64); 
	if (name.length > 0) {
		for (let label of name.split('.').reverse()) {
			buf.set(labelhash(label).bytes, 32);
			buf.set(keccak().update(buf).bytes, 0);
		}
	}
	return new Uint256(buf.slice(0, 32));
}

// https://docs.ens.domains/ens-deployments
const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';

class ENS {
	constructor({provider, providers, ens_normalize, registry = ENS_REGISTRY}) {
		if (!provider) throw new Error(`expected provider`);
		this.provider = provider;
		if (provider.isProviderView) {
			this.providers = provider;
		} else {
			if (!providers) {
				let p = new Providers();
				p.add_dynamic(provider);
				this.providers = p;
			} else if (providers instanceof Providers) {
				this.providers = providers;
			} else {
				throw new Error(`invalid providers`);
			}
		}
		this.ens_normalize = ens_normalize;
		this.registry = registry;
		this.normalizer = undefined;
		this.eth = undefined;
	}
	normalize(name) {
		return this.ens_normalize?.(name) ?? name;
	}
	async get_provider() {
		let p = this.provider;
		return p.isProviderView ? p.get_provider() : p;
	}
	async get_resolver(node) {
		const SIG = '0178b8bf'; // resolver(bytes32)
		return (await eth_call(
			await this.get_provider(), 
			this.registry, 
			ABIEncoder.method(SIG).number(node)
		)).addr();
	}
	async resolve(input, {is_address, throws = false} = {}) {
		if (is_address === undefined) is_address = is_valid_address(input);
		let name = new ENSName(this, input, is_address);
		try {
			await name.resolve_input();
		} catch (err) {
			if (throws) throw err;
		}
		return name;
	}
	// warning: does not normalize!
	async is_dot_eth_available(label) {
		if (!this.eth) this.eth = await this.resolve('eth', {throws: true});
		const SIG = '96e494e8'; // available(uint256)
		return (await eth_call(
			await this.get_provider(), 
			await this.eth.get_address(), 
			ABIEncoder.method(SIG).number(labelhash(label))
		)).boolean();
	}
}

class ENSName {
	constructor(ens, input, is_address) {
		this.ens = ens;
		this.input = input;
		this._is_address = is_address;
	}
	toJSON() {
		return this.name;
	}
	assert_input_error() {
		if (this._error) {
			// throw again on reuse
			throw new Error(this._error);
		}
	}
	assert_valid_resolver() {
		this.assert_input_error();
		if (!this.resolver) {
			throw new Error(`Null resolver`);
		}
	}
	async resolve_input() {
		this._error = undefined;
		this.name = undefined;
		this.node = undefined;
		this.primary = undefined;
		this.owner = undefined;
		this.address = undefined;
		this._display = undefined;
		this.avatar = undefined;
		this.pubkey = undefined;
		this.content = undefined;
		this.resolver = undefined;
		this.resolved = undefined;
		this.text = {};
		this.addr = {};
		if (this._is_address) {
			try {
				this.address = checksum_address(this.input);
			} catch (err) {
				throw new Error(this._error = `Invalid address: ${err.message}`);
			}
			let primary;
			try {
				primary = await this.get_primary();
			} catch (err) {
				this._error = err.message;
				throw err;
			}
			if (!primary) {
				throw new Error(this._error = `No name for ${this.input}`);
			}
			try {
				this.name = this.ens.normalize(primary);
			} catch (cause) {
				throw new Error(this._error = `Primary name is invalid: ${primary}`, {cause});
			} 
			// note: we cant save this primary since the names primary might be different
		} else {
			try {
				this.name = this.ens.normalize(this.input);
			} catch (cause) {
				throw new Error(this._error = `Input name is invalid: ${this.input}`, {cause});
			}
		}
		this.node = namehash(this.name);
		try {
			let resolver = await this.ens.get_resolver(this.node);
			if (!is_null_hex(resolver)) {
				this.resolver = resolver;
			}
		} catch (cause) {
			throw new Error(this._error = `Unable to determine resolver`, {cause});
		}
		this.resolved = new Date();
		return this;
	}
	async get_address() {
		if (this.address) return this.address;
		this.assert_valid_resolver();
		try {
			const SIG = '3b3b57de'; // addr(bytes32)
			return this.address = (await eth_call(
				await this.ens.get_provider(), 
				this.resolver, 
				ABIEncoder.method(SIG).number(this.node)
			)).addr();
		} catch (cause) {
			throw new Error(`Read address failed: ${cause.message}`, {cause});
		}
	}
	async get_owner() {
		if (this.owner) return this.owner;
		this.assert_input_error();
		try {
			const SIG = '02571be3'; // owner(bytes32)
			return this.owner = (await eth_call(
				await this.ens.get_provider(), 
				this.ens.registry, 
				ABIEncoder.method(SIG).number(this.node)
			)).addr();
		} catch (cause) {
			throw new Error(`Read owner failed: ${cause.message}`, {cause});
		}
	}
	async get_primary() {
		if (this.primary !== undefined) return this.primary;		
		this.assert_input_error();
		let address = await this.get_address(true);
		// https://eips.ethereum.org/EIPS/eip-181
		let rev_node = namehash(`${address.slice(2).toLowerCase()}.addr.reverse`); 
		let rev_resolver = await this.ens.get_resolver(rev_node);
		if (is_null_hex(rev_resolver)) {			
			this.primary = null; 
		} else {
			try {
				const SIG = '691f3431'; // name(bytes)
				this.primary = (await eth_call(
					await this.ens.get_provider(), 
					rev_resolver, 
					ABIEncoder.method(SIG).number(rev_node)
				)).string();
				// this could be empty string
			} catch (cause) {
				throw new Error(`Lookup primary failed: ${cause.message}`, {cause});
			}
		}
		return this.primary;
	}
	// returns input error
	get input_error() {
		return this._error;
	}
	is_input_address() {
		return this._is_address;
	}
	is_input_norm() {
		return !this._is_address && this.input === this.name;
	}
	validate_name(name) {
		this.assert_input_error();
		let norm;
		try {
			norm = this.ens.normalize(name);
		} catch (cause) {
			throw new Error(`${name} name is invalid: ${cause.message}`, {cause});
		}
		if (norm !== this.name) {
			throw new Error(`${name || '(empty-string)'} does not match ${this.name}`);
		}
		return name;
	}
	async is_input_display() {
		if (this._is_address) return false;
		let display;
		if (this.resolver) {
			display = await this.get_text('display');
		}
		try {
			if (!display) {
				// if display name is not set
				// display is the norm name
				return this.input === this.name; 
			}
			if (this.input === display) {
				// if display matches the input
				this.validate_name(display); 
				return true;
			}
		} catch (err) {
		}
		return false;
	}
	async get_display_name() {
		if (this._display) return this._display;
		let display = await this.get_text('display');
		let name = this.name; 
		try {
			name = this.validate_name(display);
		} catch (err) {
		}
		return this._display = name;
	}
	async get_avatar() {
		if (this.avatar) return this.avatar;
		return this.avatar = await parse_avatar(
			await this.get_text('avatar'), // throws
			this.ens.providers,
			await this.get_address()
		);
	}
	// https://eips.ethereum.org/EIPS/eip-634
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/TextResolver.sol
	//async get_text
	async get_text(key) { return this.get_texts([key]).then(x => x[key]); }
	async get_texts(keys, output) {
		if (!Array.isArray(keys)) throw new TypeError('expected array');
		this.assert_valid_resolver();
		let provider = await this.ens.get_provider();
		await Promise.all(keys.flatMap(key => (key in this.text) ? [] : (async () => {
			const SIG = '59d1d43c'; // text(bytes32,string)
			try {
				this.text[key] = (await eth_call(
					provider, 
					this.resolver, 
					ABIEncoder.method(SIG).number(this.node).string(key)
				)).string();
			} catch (cause) {
				delete this.text[key];
				throw new Error(`Error reading text ${key}: ${cause.message}`, {cause});
			}
		})()));
		if (!output) return this.text;
		for (let k of keys) output[k] = this.text[k];
		return output;
	}
	// https://eips.ethereum.org/EIPS/eip-2304
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/AddrResolver.sol
	async get_addr(addr) { return this.get_addrs([addr]).then(x => x[addr]); }
	async get_addrs(addrs, output, named = true) {
		if (!Array.isArray(addrs)) throw new TypeError('expected array');
		this.assert_valid_resolver();
		addrs = addrs.map(get_addr_type_from_input); // throws
		let provider = await this.ens.get_provider();
		await Promise.all(addrs.flatMap(([name, type]) => (name in this.addr) ? [] : (async () => {
			try {
				const SIG = 'f1cb7e06'; // addr(bytes32,uint256);
				let addr = (await eth_call(
					provider, 
					this.resolver, 
					ABIEncoder.method(SIG).number(this.node).number(type)
				)).memory();
				this.addr[type] = addr;
			} catch (cause) {
				delete this.addr[type];
				throw new Error(`Error reading addr ${name}: ${cause.message}`, {cause});
			}
		})()));
		if (output) {
			for (let [name, type] of addrs) {
				output[named ? name : type] = this.addr[type];
			}
			return output; // return subset by name
		} else if (named) {
			return Object.fromEntries(Object.entries(this.addr).map(([k, v]) => {
				let [name] = get_addr_type_from_input(parseInt(k));
				return [name, v];
			})); // return all by name
		} else {
			return this.addr; // return everything by id
		}
	}
	// https://github.com/ethereum/EIPs/pull/619
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/PubkeyResolver.sol
	async get_pubkey() {
		this.assert_valid_resolver();
		if (this.pubkey) return this.pubkey;
		if (is_null_hex(this.resolver)) return this.pubkey = {};		
		try {
			const SIG = 'c8690233'; // pubkey(bytes32)
			let dec = await eth_call(
				await this.ens.get_provider(),
				this.resolver, 
				ABIEncoder.method(SIG).number(this.node)
			);
			return this.pubkey = {x: dec.uint256(), y: dec.uint256()};
		} catch (cause) {
			throw new Error(`Error reading pubkey: ${cause.message}`, {cause});
		}
	}
	// https://eips.ethereum.org/EIPS/eip-1577
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/ContentHashResolver.sol
	async get_content() {
		this.assert_valid_resolver();
		if (this.content) return this.content;
		try {
			const SIG = 'bc1c58d1'; // contenthash(bytes32)
			let hash = (await eth_call(
				await this.ens.get_provider(),
				this.resolver, 
				ABIEncoder.method(SIG).number(this.node)
			)).memory();
			let content = {};			
			if (hash.length > 0) {
				content.hash = hash;
				// https://github.com/multiformats/multicodec
				let dec = new ABIDecoder(hash);
				if (dec.uvarint() == 0xE3) { // ipfs
					if (dec.read_byte() == 0x01 && dec.read_byte() == 0x70) { // check version and content-type
						content.url = `ipfs://${base58_from_bytes(dec.read_bytes(dec.remaining))}`;
					}
				}
			}
			return this.content = content;
		} catch (cause) {
			throw new Error(`Error reading content: ${cause.message}`, {cause});
		}
	}

}

// https://medium.com/the-ethereum-name-service/step-by-step-guide-to-setting-an-nft-as-your-ens-profile-avatar-3562d39567fc
// https://medium.com/the-ethereum-name-service/major-refresh-of-nft-images-metadata-for-ens-names-963090b21b23
// https://github.com/ensdomains/ens-metadata-service
// note: the argument order here is non-traditional
async function parse_avatar(avatar, provider, address) {
	if (typeof avatar !== 'string') throw new Error('Invalid avatar: expected string');
	if (avatar.length == 0) return {type: 'null'}; 
	if (avatar.includes('://') || avatar.startsWith('data:')) return {type: 'url', url: avatar};
	let parts = avatar.split('/');
	let part0 = parts[0];
	if (part0.startsWith('eip155:')) { // nft format  
		if (parts.length < 2) return {type: 'invalid', error: 'expected contract'};
		if (parts.length < 3) return {type: 'invalid', error: 'expected token'};
		let chain_id = parseInt(part0.slice(part0.indexOf(':') + 1));
		if (!(chain_id > 0)) return {type: 'invalid', error: 'expected chain id'};
		let part1 = parts[1];
		if (part1.startsWith('erc721:')) {
			// https://eips.ethereum.org/EIPS/eip-721
			let contract = part1.slice(part1.indexOf(':') + 1);
			if (!is_valid_address(contract)) return {type: 'invalid', error: 'expected contract address'};
			contract = checksum_address(contract);
			let token;
			try {
				token = Uint256.from_str(parts[2]);
			} catch (err) {
				return {type: 'invalid', error: 'expected uint256 token'};
			}
			let ret = {type: 'nft', interface: 'erc721', contract, token, chain_id};
			if (provider instanceof Providers) {
				provider = await provider?.find_provider(chain_id);
			}
			if (provider) {
				try {
					const SIG_tokenURI = 'c87b56dd'; // tokenURI(uint256)
					const SIG_ownerOf  = '6352211e'; // ownerOf(uint256)
					let [owner, meta_uri] = await Promise.all([
						eth_call(provider, contract, ABIEncoder.method(SIG_ownerOf).number(token)).then(x => x.addr()),
						eth_call(provider, contract, ABIEncoder.method(SIG_tokenURI).number(token)).then(x => x.string())
					]);
					ret.owner = owner;
					ret.meta_uri = meta_uri;
					if (address) {
						ret.owned = address.toUpperCase() === owner.toUpperCase() ? 1 : 0; // is_same_address?
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
			contract = checksum_address(contract);
			let token;
			try {
				token = Uint256.from_str(parts[2]);
			} catch (err) {
				return {type: 'invalid', error: 'expected uint256 token'};
			}
			let ret = {type: 'nft', interface: 'erc1155', contract, token, chain_id};
			if (provider instanceof Providers) {
				provider = await provider?.find_provider(chain_id);
			}
			if (provider) {
				try {
					const SIG_uri       = '0e89341c'; // uri(uint256)
					const SIG_balanceOf = '00fdd58e'; // balanceOf(address,uint256)
					let [balance, meta_uri] = await Promise.all([
						!address ? -1 : eth_call(provider, contract, ABIEncoder.method(SIG_balanceOf).addr(address).number(token)).then(x => x.number()),
						eth_call(provider, contract, ABIEncoder.method(SIG_uri).number(token)).then(x => x.string())
					]);
					// The string format of the substituted hexadecimal ID MUST be lowercase alphanumeric: [0-9a-f] with no 0x prefix.
					ret.meta_uri = meta_uri.replace('{id}', token.hex.slice(2)); 
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

function format_addr_type(i) {
	return '0x' + i.toString(16).padStart(4, '0');
}

// see: test/build-address-types.js
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
// returns [name:string, coinType: integer]
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

class NFT {
	constructor(provider, address, {strict = true, cache = true} = {}) {
		this.provider = provider;
		this.address = checksum_address(address); // throws
		this.type = undefined;
		this.type_error = undefined;
		this.strict = strict; // assumes 721 if not 1155
		this.queue = [];
		if (cache) {
			this.token_uris = {};
		}
	}
	async get_provider() {
		let p = this.provider;
		return p.isProviderView ? p.get_provider() : p;
	}
	async get_type() {
		let {queue} = this;
		if (!queue) {
			if (this.type_error) throw new Error(`Type resolution failed`, {cause: this.type_error});
			return this.type;
		}
		if (queue.length == 0) {
			try {
				let type;
				if (await supports_interface(await this.get_provider(), this.address, 'd9b67a26')) {
					type = 'ERC-1155';
				} else if (!this.strict || await supports_interface(await this.get_provider(), this.address, '80ac58cd')) {
					type = 'ERC-721';
				} else {
					type = 'Unknown';
				}
				this.type = type;
				this.queue = undefined;
				queue.forEach(x => x.ful());
				return type;
			} catch (err) {
				this.type_error = err;
				this.queue = undefined;
				queue.forEach(x => x.rej(err));
				throw err;
			}
		} else {
			return new Promise((ful, rej) => {
				queue.push({ful, rej});
			});
		}
	} 
	async get_token_uri(x) {
		let token = Uint256.wrap(x); // throws
		let {hex} = token;
		let {token_uris} = this;
		let uri = token_uris?.[hex]; // lookup cache
		if (!uri) {
			switch (await this.get_type()) {
				case 'ERC-721': {
					// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-721.md
					const SIG = 'c87b56dd'; // tokenURI(uint256)
					uri = (await eth_call(
						await this.get_provider(),
						this.address, 
						ABIEncoder.method(SIG).add_hex(hex)
					)).string();
					break;
				}
				case 'ERC-1155': {
					// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1155.md
					const SIG = '0e89341c';	// uri(uint256)
					uri = (await eth_call(
						await this.get_provider(), 
						this.address, 
						ABIEncoder.method(SIG).add_hex(hex)
					)).string();
					uri = uri.replace('{id}', hex.slice(2)); // 1155 standard (lowercase, no 0x)
					break;
				}
				default: throw new Error(`unable to query ${x} from ${this.address}`);
			}
			uri = fix_multihash_uri(uri);
			if (token_uris) token_uris[hex] = uri; // cache
		}
		return uri;
	}
}

export { ABIDecoder, ABIEncoder, ADDR_TYPES, ENS, ENSName, FetchProvider, NFT, Providers, Uint256, WebSocketProvider, base58_from_bytes, bytes4_from_method, bytes_from_base58$1 as bytes_from_base58, bytes_from_hex, bytes_from_utf8, chain_id_from_provider, checksum_address, compare_arrays, determine_window_provider, eth_call, fix_multihash_uri, hex_from_bytes, is_checksum_address, is_header_bug, is_multihash, is_null_hex, is_valid_address, keccak, labelhash, left_truncate_bytes, namehash, parse_avatar, retry, set_bytes_to_number, sha3, shake, source_from_provider, supports_interface, unsigned_from_bytes, utf8_from_bytes };
