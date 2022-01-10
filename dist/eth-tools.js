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
function bytes_from_hex$1(s) {
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

function promise_object_setter(obj, key, promise) {
	obj[key] = promise;
	return promise.then(ret => {
		obj[key] = ret;
		return ret;
	}).catch(err => {
		delete obj[key];
		throw err;
	});
}

function data_uri_from_json(json) {
	return 'data:application/json;base64,' + btoa(JSON.stringify(json));
}

function is_null_hex(s) {
	return /^(0x)?[0]+$/i.test(s); // should this be 0+?
}

// replace ipfs:// with default https://ipfs.io
function replace_ipfs_protocol(s) {
	return s.replace(/^ipfs:\/\//i, 'https://dweb.link/ipfs/');
}

const NULL_ADDRESS = '0x0000000000000000000000000000000000000000';

// accepts address as string (0x-prefix is optional) 
// returns 0x-prefixed checksummed address 
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
function standardize_address(s, checksum = true) {
	if (typeof s !== 'string') throw new TypeError('expected string');
	if (s.startsWith('0x')) s = s.slice(2);
	let lower = s.toLowerCase();
	if (!/^[a-f0-9]{40}$/.test(lower)) throw new TypeError('expected 40-char hex');
	let ret = lower;
	if (checksum && !/^[0-9]+$/.test(ret)) { 
		let hash = keccak().update(lower).hex;
		ret = [...lower].map((x, i) => hash.charCodeAt(i) >= 56 ? x.toUpperCase() : x).join('');
		// dont enforce checksum on full lower/upper case
		if (s !== ret && s !== lower && s !== lower.toLowerCase()) {
			throw new Error(`checksum failed: ${s}`);
		}
	}
	return `0x${ret}`;
}

function is_valid_address(s) {
	return /^(0x)?[a-f0-9]{40}$/i.test(s);
}

function is_checksum_address(s) {
	try {
		return standardize_address(s) === s;
	} catch (ignored) {
		// undefined lets you differentiate !checksum from !address
	}
}

function short_address(s) {
	s = standardize_address(s);
	return s.slice(0, 6) + '..' + s.slice(-4);
}

function index_mask_from_bit(i) { 
	let index = i < 0 ? ~i : 255 - i;
	if (index < 0 || index >= 256) throw new TypeError(`invalid bit index: ${i}`);
	return [index >> 3, 0x80 >> (index & 7)];
}

class Uint256 {	
	static wrap(x) { // tries to avoid a copy
		if (x instanceof Uint256) {
			return x;
		} else if (x instanceof Uint8Array) {
			return new this(left_truncate_bytes(x, 32, false));
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
		return this.from_bytes(bytes_from_hex$1(s));
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
		return this; // chainable
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
		return this; // chainable
	}
	apply_bytewise_binary_op(fn, x) {
		let other = this.constructor.wrap(x).bytes; // throws
		this.bytes.forEach((x, i, v) => v[i] = fn(x, other[i]));
		return this; // chainable
	}
	bytewise_fill(x) {
		this.bytes.fill(x);
		return this; // chainable
	}
	or(x)  { return this.apply_bytewise_binary_op((a, b) => a | b, x); } // chainable
	and(x) { return this.apply_bytewise_binary_op((a, b) => a & b, x); } // chainable
	xor(x) { return this.apply_bytewise_binary_op((a, b) => a ^ b, x); } // chainable
	not() {
		this.bytes.forEach((x, i, v) => v[i] = ~x);
		return this;
	}
	set_bit(i, truthy = true) {
		let [index, mask] = index_mask_from_bit(i);
		if (truthy) {
			this.bytes[index] |= mask;
		} else {
			this.bytes[index] &= ~mask;
		}
		return this; // chainable
	}
	flip_bit(i) {
		let [index, mask] = index_mask_from_bit(i);
		this.bytes[index] ^= mask;
		return this; // chainable
	}
	test_bit(i) {
		let [index, mask] = index_mask_from_bit(i);
		return (this.bytes[index] & mask) > 0;
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
	get min_hex() { return '0x' + this.digit_str(16) } 
	get bin() { return '0b' + this.digit_str(2); }
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
		return this.min_hex;
	}
	toString() {
		return `Uint256(${this.min_hex})`;
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
	static from_hex(x) { return new this(bytes_from_hex$1(x)); }
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
	peek_byte(offset = 0) {		
		let {pos, buf} = this;
		pos += offset;
		if (!(pos >= 0 && pos < buf.length)) throw new RangeError(`invalid offset: ${offset}`);
		return buf[pos];
	}
	read_byte() {
		let {pos, buf} = this;
		if (pos >= buf.length) throw new RangeError('buffer overflow');
		this.pos = pos + 1;
		return buf[pos];
	}
	read_addr_bytes() {
		if (this.read_bytes(12).some(x => x > 0)) throw new TypeError('invalid address: expected zero');
		return this.read_bytes(20);
	}
	// these all effectively copy 
	bytes(n) { return this.read_bytes(n).slice(); }
	boolean() { return this.number() > 0; }	
	number(n = 32) { return unsigned_from_bytes(this.read_bytes(n)); }
	uint256() { return new Uint256(this.bytes(32)); } 
	string() { return utf8_from_bytes(this.read_memory()); }	
	memory() { return this.read_memory().slice(); }
	addr(checksum = true) {
		let addr = hex_from_bytes(this.read_addr_bytes());
		return checksum ? standardize_address(addr) : `0x${addr}`; 
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

const METHOD_CACHE = {};

function hex_from_method(x) {
	return /^0x[0-9a-fA-F]{8}$/.test(x) ? x : hex_from_bytes(bytes4_from_method(x));
}
function bytes4_from_method(x) {
	if (typeof x === 'string' && x.includes('(')) {
		let v = METHOD_CACHE[x];
		if (!v) {
			METHOD_CACHE[x] = v = keccak().update(x).bytes.subarray(0, 4);
		}
		return v.slice();
	}
	try {
		let v = x instanceof Uint8Array ? x : bytes_from_hex$1(x);
		if (v.length != 4) throw new Error('expected 4 bytes');
		return v;
	} catch (err) {
		throw new Error(`method ${x} should be a signature or 8-char hex`);
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
	bytes_hex(s) { return this.bytes(bytes_from_hex$1(s)); }
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
		let v = bytes_from_hex$1(s); // throws
		if (v.length != 20) throw new TypeError('expected address');
		this.alloc(32).set(v, 12);
		return this; // chainable
	}
	// these are dangerous
	add_hex(s) { return this.add_bytes(bytes_from_hex$1(s)); } // throws
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

class Coder {
	bytes_from_str(s) {
		if (typeof s !== 'string') throw new TypeError('expected string');
		return this.bytes(s);
	}
	str_from_bytes(v) {
		if (Array.isArray(v)) v = Uint8Array.from(v);
		if (!(v instanceof Uint8Array)) throw new TypeError('expected bytes');
		return this.str(v);
	}
	// overriden by subclasses
	bytes() { throw new TypeError('bug: not implemented'); }
	str() { throw new TypeError('bug: not implemented'); }
}

class MapStringCoder extends Coder {
	constructor(coder, fn) {
		super();
		this.coder = coder;
		this.fn = fn;
	}
	bytes(s) {
		return this.coder.bytes(this.fn(s, true));
	}
	str(v) {
		return this.fn(this.coder.str(v), false);
	}
}

class MapBytesCoder extends Coder {
	constructor(coder, fn) {
		super();
		this.coder = coder;
		this.fn = fn;
	}
	bytes(s) {
		return this.fn(this.coder.bytes(s, true));
	}
	str(v) {
		return this.coder.str(this.fn(v, false));
	}
}

class BaseCoder extends Coder {
	constructor(lookup) {
		super();
		let v = [...lookup];
		if (v.length !== lookup.length) throw new TypeError(`expected UTF16`);
		this.lookup = lookup;
		this.map = Object.fromEntries(v.map((x, i) => [x, i]));
	}
	parse(s) {
		let i = this.map[s];
		if (i === undefined) throw new TypeError(`invalid digit ${s}`);
		return i;
	}
	format(v) {
		return v.reduce((s, x) => s + this.lookup[x], '');
	}
}

// https://github.com/Chia-Network/chia-blockchain/blob/af0d6385b238c91bff4fec1a9e9c0f6158fbf896/chia/util/bech32m.py#L85
function convert_bits(v, src_bits, dst_bits, pad) {
	if (!Array.isArray(v) && !ArrayBuffer.isView(v)) throw new TypeError('expected array');
	if (!Number.isSafeInteger(src_bits) || src_bits < 1 || src_bits > 32) throw new TypeError('invalid from bits');
	if (!Number.isSafeInteger(dst_bits) || dst_bits < 1 || dst_bits > 32) throw new TypeError('invalid to bits');
	let acc = 0;
	let bits = 0;
	let ret = [];
	let mask = (1 << dst_bits) - 1;
	for (let x of v) {
		if (x < 0 || (x >> src_bits) !== 0) throw new Error('invalid digit');
		acc = (acc << src_bits) | x;
		bits += src_bits;
		while (bits >= dst_bits) {
			bits -= dst_bits;
			ret.push((acc >> bits) & mask);
		}
	}
	if (pad) {
		if (bits > 0) {
			ret.push((acc << (dst_bits - bits)) & mask);
		}
	} else if (bits >= src_bits || ((acc << (dst_bits - bits)) & mask)) {
		throw new Error('malformed');
	}
	return Uint8Array.from(ret);
}

class Prefix0 extends BaseCoder {
	bytes(s) {
		let {lookup} = this;
		let base = lookup.length;
		let n = s.length;
		let v = new Uint8Array(n);
		let pos = 0;
		for (let c of s) {
			let carry = this.parse(c);
			for (let i = 0; i < pos; i++) {
				carry += v[i] * base;
				v[i] = carry;
				carry >>= 8;
			}
			while (carry > 0) {
				v[pos++] = carry;
				carry >>= 8;
			}
		}
		for (let i = 0; i < n && s[i] === lookup[0]; i++) pos++;
		return v.subarray(0, pos).reverse();
	}
	str(v) {
		let base = this.lookup.length;
		let u = [];
		for (let x of v) {
			for (let i = 0; i < u.length; ++i) {
				let xx = (u[i] << 8) | x;
				u[i] = xx % base;
				x = (xx / base)|0;
			}
			while (x > 0) {
				u.push(x % base);
				x = (x / base)|0;
			}
		}	
		for (let i = 0; i < v.length && v[i] == 0; i++) u.push(0);
		return this.format(u.reverse());
	}
}

class RFC4648 extends BaseCoder {
	constructor(lookup, w) {
		super(lookup);
		this.w = w;
	}
	bytes(s, pad) {
		let {w} = this;
		let n = s.length;
		let pos = 0;
		let carry = 0;
		let width = 0;
		// remove padding
		while (pad && n > 0 && s[n-1] == '=') --n;
		let v = new Uint8Array((n * w) >> 3);		
		for (let i = 0; i < n; i++) {
			carry = (carry << w) | this.parse(s[i]);
			width += w;
			if (width >= 8) {
				v[pos++] = (carry >> (width -= 8)) & 0xFF;
			}
		}
		// the bits afterwards should be 0
		if ((carry << (8 - width)) & 0xFF) throw new Error('wtf');
		return v;
	}
	str(v, pad) {
		let {w, lookup} = this;
		let mask = (1 << w) - 1;
		let carry = 0;
		let width = 0;
		let s = '';
		let n = v.length;
		for (let i = 0; i < n; i++) {
			carry = (carry << 8) | v[i];
			width += 8;
			while (width >= w) {
				s += lookup[(carry >> (width -= w)) & mask];
			}
		}
		if (width) { // left align the remaining bits
			s += lookup[(carry << (w - width)) & mask];
		}
		while (pad && (s.length * w) & 7) s += '=';
		return s;
	}
}

const Base58BTC = new Prefix0('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');

// the choice of bases in multibase spec are shit
// why are there strings that aren't valid bases???
// why isn't this just encoded as an integer???

/*
export const BASE64_JS = {
	bytes_from_str(s) {
		return Uint8Array.from(atob(s), x => x.charCodeAt(0));
	},
	str_from_bytes(v) {
		return btoa(String.fromCharCode(...v));
	}
};
*/

// https://www.rfc-editor.org/rfc/rfc4648.html#section-4 
const ALPHA = 'abcdefghijklmnopqrstuvwxyz';
const RADIX = '0123456789' + ALPHA;
const Base64 = new RFC4648(ALPHA.toUpperCase() + ALPHA + RADIX.slice(0, 10) + '+=', 6);
// https://www.rfc-editor.org/rfc/rfc4648.html#section-5
const Base64URL = new RFC4648(ALPHA.toUpperCase() + ALPHA + RADIX.slice(0, 10) + '-_', 6);
// https://github.com/multiformats/multibase/blob/master/rfcs/Base36.md
const Base36 = new Prefix0(RADIX);
// https://www.rfc-editor.org/rfc/rfc4648.html#section-7
const Base32Hex = new RFC4648(RADIX.slice(0, 32), 5);
// https://www.rfc-editor.org/rfc/rfc4648.html#section-6
const Base32 = new RFC4648('abcdefghijklmnopqrstuvwxyz234567', 5);
// https://www.rfc-editor.org/rfc/rfc4648.html#section-8
const Base16 = new RFC4648(RADIX.slice(0, 16), 4);
// https://github.com/multiformats/multibase/blob/master/rfcs/Base10.md
const Base10 = new Prefix0(RADIX.slice(0, 10)); 
// https://github.com/multiformats/multibase/blob/master/rfcs/Base8.md
const Base8 = new RFC4648(RADIX.slice(0, 8), 3);
// https://github.com/multiformats/multibase/blob/master/rfcs/Base2.md
const Base2 = new RFC4648(RADIX.slice(0, 2), 1);

function bind(base, ...a) {
	return {
		decode: s => base.bytes(s, ...a), // we already know it's a string
		encode: v => base.str_from_bytes(v, ...a)
	};
}

// https://github.com/multiformats/multibase#multibase-table  
const MULTIBASES = {
	'0': {...bind(Base2), name: 'base2'},
	'7': {...bind(Base8), name: 'base8'},
	'9': {...bind(Base10), name: 'base10'},
	'f': {...bind(Base16), case: false, name: 'base16'},
	'F': {...bind(Base16), case: true, name: 'base16upper'},
	'v': {...bind(Base32Hex), case: false, name: 'base32hex'},
	'V': {...bind(Base32Hex), case: true, name: 'base32hexupper'},
	't': {...bind(Base32Hex, true), case: false, name: 'base32hexpad'},
	'T': {...bind(Base32Hex, true), case: true, name: 'base32hexpadupper'},
	'b': {...bind(Base32), case: false,name: 'base32'},
	'B': {...bind(Base32), case: true, name: 'base32upper'},
	'c': {...bind(Base32, true), case: false,name: 'base32pad'},
	'C': {...bind(Base32, true), case: true, name: 'base32padupper'},
	// h
	'k': {...bind(Base36), case: false,name: 'base36'},
	'K': {...bind(Base36), case: true, name: 'base36upper'},
	'z': {...bind(Base58BTC), name: 'base58btc'},
	// ZBase58BTC
	'm': {...bind(Base64), name: 'base64'},
	'M': {...bind(Base64, true), name: 'base64pad'},
	'u': {...bind(Base64URL), name: 'base64url'},
	'U': {...bind(Base64URL, true), name: 'base64urlpad'},
	// p
	'1': {...bind(Base58BTC), name: 'base58btc-Identity'},
	'Q': {...bind(Base58BTC), name: 'base58btc-CIDv0'},
};
for (let [k, v] of Object.entries(MULTIBASES)) {
	v.prefix = k;
	MULTIBASES[v.name] = v;
}

function decode_multibase(s, prefix) {
	if (typeof s !== 'string') throw new TypeError('expected string');
	if (!prefix) { 
		prefix = s[0];
		s = s.slice(1);
	}
	let mb = MULTIBASES[prefix];
	if (!mb) throw new Error(`Unknown multibase: ${prefix}`);	
	if (mb.case !== undefined) s = s.toLowerCase();
	return mb.decode(s);
}

function encode_multibase(prefix, v, prefixed = true) {
	let mb = MULTIBASES[prefix];
	if (!mb) throw new Error(`Unknown multibase: ${prefix}`);
	let s = mb.encode(v);
	if (mb.case) s = s.toUpperCase();
	if (prefixed) s = mb.prefix + s; 
	return s;
}

//https://github.com/multiformats/unsigned-varint

const MAX_SCALE = (() => {
	let max = 1;
	while (true) {
		let next = max * 0x80;
		if (!Number.isSafeInteger(next)) break;
		max = next;
	}
	return max;
})();

function assert_uvarint(i) {	
	if (!Number.isSafeInteger(i) || i < 0) {
		throw new TypeError(`expected uvarint: ${i}`);
	}
}

// returns number of bytes to encode the int
function sizeof_uvarint(i) {
	assert_uvarint(i);
	let len = 1;
	for (; i >= 0x80; len++) {
		i = Math.floor(i / 0x80);
	}
	return len;
}

// reads a uvarint from Uint8Array 
// returns [result, subarray]
// where subarray sliced off what was consumed
function read_uvarint(v, pos = 0) {
	if (!ArrayBuffer.isView(v)) {
		throw new TypeError(`expected ArrayBufferView`);
	}
	let i = 0;
	let x = 1;
	while (true) {
		if (pos >= v.length) throw new RangeError(`buffer overflow`);
		let next = v[pos++];
		i += (next & 0x7F) * x;
		if ((next & 0x80) == 0) break;
		if (x == MAX_SCALE) throw new RangeError('uvarint overflow');
		x *= 0x80;
	}
	return [i, v.subarray(pos)];
}

// write a uvarint of i into Uint8Array at pos
// returns new position
function write_uvarint(v, i, pos = 0) {
	if (!Array.isArray(v) && !ArrayBuffer.isView(v)) {
		throw new TypeError(`expected ArrayLike`);
	}
	assert_uvarint(i);
	while (true) {
		if (pos >= v.length) throw new RangeError(`buffer overflow`);
		if (i < 0x80) break;
		v[pos++] = (i & 0x7F) | 0x80;
		i = Math.floor(i / 0x80);
	}
	v[pos++] = i;	
	return pos;
}

// https://github.com/multiformats/multihash
// sha1 = 0x11
// sha256 = 0x12

class Multihash {
	static from_str(s) {
		return this.from_bytes(decode_multibase(s));
	}
	static from_bytes(v) {
		let code, size;
		[code, v] = read_uvarint(v);
		[size, v] = read_uvarint(v);
		if (v.length !== size) throw new Error(`expected ${size}, got ${v.length} bytes`)
		return new this(code, v.slice());
	}
	constructor(code, hash) {
		this.code = code;
		this.hash = hash;
	}
	get length() {
		return sizeof_uvarint(this.code) + sizeof_uvarint(this.hash.length) + this.hash.length;
	}
	get bytes() {
		let v = new Uint8Array(this.length);
		this.write_bytes(v, 0);
		return v;
	}
	write_bytes(v, pos = 0) {
		pos = write_uvarint(v, this.code, pos);
		pos = write_uvarint(v, this.hash.length, pos);
		v.set(this.hash, pos);
		return pos;
	}
	toJSON() {
		return {code: this.code, hash: this.hash};
	}
}

// https://github.com/multiformats/cid/blob/master/original-rfc.md
// https://github.com/multiformats/cid#cidv1

class CID {
	static from_str(s) {
		if (typeof s !== 'string') throw new TypeError('expected string');
		if (s.length == 46 && s.startsWith('Qm')) {
			return this.from_bytes(Base58BTC.bytes_from_str(s));
		} else {
			let v = decode_multibase(s);
			if (v[0] == 0x12) throw new Error(`CIDv0 cannot be multibase: ${s}`);
			return this.from_bytes(v);
		}
	}
	static from_bytes(v) {
		if (!(v instanceof Uint8Array)) throw new TypeError(`expected Uint8Array`);
		try {
			if (v.length == 34 && v[0] == 0x12 && v[1] == 0x20) {
				return new CIDv0(Multihash.from_bytes(v));
			}
			let version;
			[version, v] = read_uvarint(v);
			switch (version) {
				case 1: {
					let codec;
					[codec, v] = read_uvarint(v);
					return new CIDv1(codec, Multihash.from_bytes(v));
				}
				default: throw new Error(`unsupported version: ${version}`);
			}
		} catch (cause) {
			throw new Error(`Malformed CID: ${cause}`, {cause});
		}
	}
	toJSON() {
		return {
			version: this.version,
			codec: this.codec,
			hash: this.hash
		};
	}
}

class CIDv0 extends CID {
	constructor(hash) {
		super();
		this.hash = hash;
	}
	get version() { return 0; }
	get codec() { return 0x70; }
	get length() {
		return this.hash.bytes.length;
	}
	get bytes() {
		return this.hash.bytes;
	}
	upgrade_v0() {
		return new CIDv1(this.codec, this.hash);
	}
	toString(base) {
		const BASE = 'Q';
		if (base !== undefined && base !== BASE) throw new TypeError('expected base Q');
		return encode_multibase(BASE, this.bytes, false);
	}
}

class CIDv1 extends CID {
	constructor(codec, hash) {
		super();
		this.codec = codec;
		this.hash = hash;
	}
	get version() { return 1; }
	get length() {
		return sizeof_uvarint(this.version) + sizeof_uvarint(this.codec) + this.hash.length;
	}
	get bytes() {
		let v = new Uint8Array(this.length);
		let pos = 0;
		pos = write_uvarint(v, this.version, pos);
		pos = write_uvarint(v, this.codec, pos);
		this.hash.write_bytes(v, pos);
		return v;
	}
	upgrade_v0() {
		return this;
	}
	toString(base) {
		if (base === undefined) {
			switch (this.codec) {
				case 0x72: base = 'k'; break; // libp2p-key
				default: base = 'b';
			}
		}
		return encode_multibase(base, this.bytes, true);
	}
}

// https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

const BECH32 = new BaseCoder('qpzry9x8gf2tvdw0s3jn54khce6mua7l', 5);
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const SEP = '1';

function polymod(v, check = 1) {
	for (let x of v) {
		let digit = check >> 25;
		check = (check & 0x1FFFFFF) << 5 ^ x;
		for (let i = 0; i < 5; i++) {
			if ((digit >> i) & 1) {
				check ^= GEN[i];
			}
		}
	}
	return check;
}

function hrp_expand(s) {
	let n = s.length;
	let v = Array(n);
	v.push(0);
	for (let i = 0; i < n; i++) {
		let c = s.charCodeAt(i);
		if (c < 33 || c > 126) throw new Error(`invalid hrp character: ${c}`);
		v[i] = c >> 5;
		v.push(c & 31);
	}
	return v;
}

class Bech32Coder extends Coder {
	constructor(type, hrp) {
		Bech32.assert_hrp(hrp);
		super();
		this.type = type;
		this.hrp = hrp;
	}
	bytes(s) {
		let bech = Bech32.from_str(s);
		if (bech.type != this.type) throw new Error('expected ')
		if (bech.hrp !== this.hrp) throw new Error('invalid hrp');
		return Bech32.bytes_from_digits(bech.digits);
	}
	str(v) {
		return new Bech32(this.type, this.hrp, Bech32.digits_from_bytes(v)).toString();
	}
}

class Bech32 {
	static TYPE_1 = 1;
	static TYPE_M = 0x2bc830a3;
	static assert_type(type) {
		switch (type) {
			case this.TYPE_1:
			case this.TYPE_M: break;
			default: throw new TypeError(`unknown bech32 type: ${type}`);
		}
	}
	static assert_hrp(hrp) {
		if (typeof hrp !== 'string' || !hrp || hrp !== hrp.toLowerCase()) {
			throw new TypeError(`expected lower-case hrp`);
		}
	}
	static bytes_from_digits(v) {
		return convert_bits(v, 5, 8, false);
	}
	static digits_from_bytes(v) {
		return convert_bits(v, 8, 5, true);
	}
	static from_str(s) {
		if (typeof s !== 'string') throw new TypeError('expected string');
		try {
			if (s.length > 90) throw new Error('too long');
			let lower = s.toLowerCase();
			if (s !== lower && s !== s.toUpperCase()) throw new Error('mixed case');
			let pos = lower.lastIndexOf(SEP);
			if (pos < 1) throw new Error('expected hrp');
			if (lower.length - (pos+1) < 6) throw new Error('expected checksum');
			let hrp = lower.slice(0, pos);
			let v = Uint8Array.from([...lower.slice(pos + 1)].map(x => BECH32.parse(x)));
			return new this(polymod(v, polymod(hrp_expand(hrp))), hrp, v.slice(0, -6));
		} catch (cause) {
			throw new Error(`Invalid Bech32: ${cause.message}`, {cause});
		}
	}
	constructor(type, hrp, digits) {
		this.constructor.assert_type(type);
		this.constructor.assert_hrp(hrp);
		if (!(digits instanceof Uint8Array)) throw new TypeError('expected Uint8Array');
		this.type = type;
		this.hrp = hrp;
		this.digits = digits; // base-32
	} 
	toString() {
		let {hrp, digits} = this;
		let v = [0,0,0,0,0,0];
		let check = polymod(v, polymod(digits, polymod(hrp_expand(hrp)))) ^ this.type;
		for (let i = 0; i < v.length; i++) {
			v[i] = (check >> 5 * (5 - i)) & 31;
		}
		return this.hrp + SEP + BECH32.format(digits) + BECH32.format(v);
	}
}

const VERSION_OFFSET = 0x50;
const VERSION_MAX = 0x10;

class SegwitCoder extends Coder {
	constructor(hrp) {
		Bech32.assert_hrp(hrp);
		super();
		this.hrp = hrp;
	}
	str(v) {
		return Segwit.from_bytes(this.hrp, v).toString();
	}
	bytes(s) {
		let segwit = Segwit.from_str(s);
		if (segwit.hrp !== this.hrp) throw new Error('invalid hrp');
		return segwit.bytes;
	}
}

class Segwit {
	static from_bech32(bech) {
		if (!(bech instanceof Bech32)) throw new TypeError('expected bech32');
		if (bech.digits.length < 1) throw new Error('no digits');
		let version = bech.digits[0];
		if (version > VERSION_MAX) throw new Error(`invalid version: ${version}`);
		let v = Bech32.bytes_from_digits(bech.digits.slice(1));
		if (version == 0) {
			if (v.length != 20 && v.length != 32) throw new Error('invalid length');
			if (bech.type !== Bech32.TYPE_1) throw new Error('expected Bech32');
		} else {
			if (bech.type !== Bech32.TYPE_M) throw new Error('expected Bech32m');
		}
		return new this(bech.hrp, version, v);
	}
	static from_str(s) { 
		try {
			return this.from_bech32(Bech32.from_str(s)); 
		} catch (cause) {
			throw new Error(`Invalid segwit string: ${cause.message}`, {cause});
		}
	}
	static from_bytes(hrp, v) {
		if (!(v instanceof Uint8Array)) throw new TypeError('expected bytes');
		Bech32.assert_hrp(hrp);
		try {
			let version = v[0];
			if (version > VERSION_OFFSET) version -= VERSION_OFFSET;
			if (version > VERSION_MAX) throw new Error(`invalid version: ${version}`);
			if (v.length !== v[1] + 2) throw new Error(`invalid length`);
			return new this(hrp, version, v.slice(2));
		} catch (cause) {
			throw new Error(`Invalid segwit bytes: ${cause.message}`, {cause});
		}
	}
	constructor(hrp, version, program) {
		this.hrp = hrp;
		this.version = version;
		this.program = program;
	}
	get bytes() {
		let {version, program} = this;
		let v = new Uint8Array(2 + program.length);
		v[0] = version > 0 ? version + VERSION_OFFSET : version;
		v[1] = program.length;
		v.set(program, 2);
		return v;
	}
	get bech32() {
		let {hrp, version, program} = this;
		let u = Bech32.digits_from_bytes(program);
		let v = new Uint8Array(1 + u.length);
		v[0] = version;
		v.set(u, 1);
		return new Bech32(version == 0 ? Bech32.TYPE_1 : Bech32.TYPE_M, hrp, v);
	}
	toString() {
		return this.bech32.toString();
	}
}

function sha256() { return new SHA256(); }

class SHA256 {
	constructor() {
		this.words = Array(64);
		this.block = undefined;
		this.index = 0;
		this.wrote = 0;
		this.state = Int32Array.of(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);
	}
	update(v) {
		if (!(v instanceof Uint8Array)) {
			if (v instanceof ArrayBuffer) { 
				v = new Uint8Array(v);
			} else if (Array.isArray(v)) { 
				v = Uint8Array.from(v);
			} else if (typeof v === 'string') {
				let s;
				try {
					s = unescape(encodeURIComponent(v));
				} catch (cause) {
					throw new Error('malformed utf8', {cause});
				}
				let n = s.length;
				v = new Uint8Array(n);
				for (let i = 0; i < n; i++) {
					v[i] = s.charCodeAt(i);
				}
			} else {
				throw new TypeError('expected bytes');
			}
		}
		let {block, index, wrote} = this;
		if (wrote < 0) throw new Error('already finalized');
		let n = v.length;
		this.wrote = wrote + n;
		while (true) {		
			let w = 64 - index;
			if (n < w) break;
			if (index == 0) {
				this._update(v.subarray(0, w));
			} else {
				block.set(v.subarray(0, w), index);
				this._update(block);
			}
			v = v.subarray(w);
			n -= w;
			index = 0;
		}
		if (n > 0) {
			if (!block) this.block = block = new Uint8Array(64);
			block.set(v, index);
			index += n;
		}
		this.index = index;
		return this;
	}
	get hex() { return [...this.bytes].map(x => x.toString(16).padStart(2, '0')).join(''); }
	get bytes() {
		if (this.wrote >= 0) {
			let {block, index, wrote} = this;
			if (!block) block = new Uint8Array(64);
			block[index] = 0x80;
			block.fill(0, index + 1);
			if (index >= 56) { // 64-8
				this._update(block);
				block.fill(0);
			}
			wrote *= 8; // bits
			let U = 0x100000000;
			if (wrote >= U) {
				let upper = (wrote / U)|0;
				block[56] = upper >> 24;
				block[57] = upper >> 16;
				block[58] = upper >>  8;
				block[59] = upper;
			}
			block[60] = wrote >> 24;
			block[61] = wrote >> 16;
			block[62] = wrote >>  8;
			block[63] = wrote;
			this._update(block);
			this.wrote = -1; // mark as finalized
		}
		let v = new Uint8Array(32);
		let {state} = this;
		let pos = 0;
		for (let x of state) {
			v[pos++] = x >> 24;
			v[pos++] = x >> 16;
			v[pos++] = x >> 8;
			v[pos++] = x;
		}
		return v;
		//return new Uint8Array(this.state.buffer.slice());
	}
	_update(block) {
		let {state, words} = this;
		for (let i = 0; i < 64; i += 4) {
			words[i>>2] = (block[i] << 24) | (block[i+1] << 16) | (block[i+2] << 8) | block[i+3];
		}
		for (let i = 16; i < 64; i++) {
			words[i] = (gamma1(words[i - 2]) + words[i - 7] + gamma0(words[i - 15]) + words[i - 16]) | 0;
		}
		let [a, b, c, d, e, f, g, h] = state;
		for (let i = 0; i < 64; i++) {
			let T1 = (h + sigma1(e) + ch(e, f, g) + K[i] + words[i]) | 0;
			let T2 = (sigma0(a) + maj(a, b, c)) | 0;
			h = g;
			g = f;
			f = e;
			e = (d + T1) | 0;
			d = c;
			c = b;
			b = a;
			a = (T1 + T2) | 0;
		}
		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
		state[4] += e;
		state[5] += f;
		state[6] += g;
		state[7] += h; 
	}
}
 
function ch (x, y, z) {
	return z ^ (x & (y ^ z))
}
function maj (x, y, z) {
	return (x & y) | (z & (x | y))
}
function sigma0 (x) {
	return (x >>> 2 | x << 30) ^ (x >>> 13 | x << 19) ^ (x >>> 22 | x << 10)
}
function sigma1 (x) {
	return (x >>> 6 | x << 26) ^ (x >>> 11 | x << 21) ^ (x >>> 25 | x << 7)
}
function gamma0 (x) {
	return (x >>> 7 | x << 25) ^ (x >>> 18 | x << 14) ^ (x >>> 3)
}
function gamma1 (x) {
	return (x >>> 17 | x << 15) ^ (x >>> 19 | x << 13) ^ (x >>> 10)
}
const K = [
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
];

// https://en.bitcoin.it/wiki/Base58Check_encoding

function checksum(v) { 
	v = sha256().update(v).bytes;
	v = sha256().update(v).bytes;
	return v.slice(0, 4); 
}

class Base58Check extends Coder {
	bytes(s) {
		let v = Base58BTC.bytes_from_str(s);
		if (v.length < 4) throw new Error('missing checksum');
		let u = v.slice(0, -4);
		if (!checksum(u).every((x, i) => x == v[u.length+i])) throw new Error('invalid checksum');
		return u;
	}
	str(v) {
		return Base58BTC.str_from_bytes([...v, ...checksum(Uint8Array.from(v))])
	}
}

const X$1 = new Base58Check();

function standardize_chain_id(x) {	
	let id;
	if (typeof x === 'string') {
		id = parseInt(x);
	} else if (typeof x === 'number') {
		id = x;
	}  
	if (!Number.isSafeInteger(id)) {
		throw new TypeError(`Invalid chain: ${x}`);
	}
	return `0x${id.toString(16)}`;
}

class Chain {
	constructor(id) {
		this._id = id;
		this.data = undefined;
	}
	get id() {
		return this._id;
	}
	get name() {
		return this.data?.name ?? `Chain(${this.id})`;
	}
	explorer_address_uri(s) {
		return this.data?.explore_address.replace('{}', s);
	}
	explorer_tx_uri(s) {
		return this.data?.explore_tx.replace('{}', s);
	}
	toJSON() {
		return this.id;
	}
	toString() {
		return `Chain(${this.id})`;
	}
}

const CHAIN_CACHE = {};

function find_chain(chain_like, required = false) {
	if (chain_like instanceof Chain) return chain_like;
	let chain_id = standardize_chain_id(chain_like);
	let chain = CHAIN_CACHE[chain_id];
	if (!chain && required) throw new Error(`Unknown chain: ${chain_id}`);
	return chain;
}

function defined_chains() {
	return Object.values(CHAIN_CACHE);
}

// always returns a chain
function ensure_chain(chain_like) {
	if (chain_like instanceof Chain) return chain_like;
	let chain_id = standardize_chain_id(chain_like);
	let chain = CHAIN_CACHE[chain_id];
	if (!chain) {
		chain = CHAIN_CACHE[chain_id] = new Chain(chain_id);
	}
	return chain;
}

function explore_uris(base) {
	return {
		explore_base: base,
		explore_address: `${base}/address/{}`,
		explore_tx: `${base}/tx/{}`,
	};
}

// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md

ensure_chain(1).data = {
	name: 'Mainnet', 
	...explore_uris('https://etherscan.io'),
	//public_rpcs: ['https://cloudflare-eth.com']
};

ensure_chain(3).data = {
	name: 'Ropsten', 
	...explore_uris('https://ropsten.etherscan.io'), 
	testnet: true
};

ensure_chain(4).data = {
	name: 'Rinkeby', 
	...explore_uris('https://rinkeby.etherscan.io'), 
	testnet: true
};

ensure_chain(5).data = {
	name: 'Goerli', 
	...explore_uris('https://goerli.etherscan.io'), 
	testnet: true
};

ensure_chain(43).data = {
	name: 'Kovan', 
	...explore_uris('https://kovan.etherscan.io'), 
	testnet: true
};

ensure_chain(137).data = {
	name: 'Matic',
	...explore_uris('https://polygonscan.com'),
	//public_rpcs: ['https://rpc-mainnet.matic.network']
};

ensure_chain(43114).data = {
	name: 'Avax C-chain',
	...explore_uris('https://snowtrace.io'),
	//public_rpcs: ['https://api.avax.network/ext/bc/C/rpc']
};

// return true if the request() error is due to bug
// this seems to be an geth bug (infura, cloudflare, metamask)
// related to not knowing the chain id
function is_header_bug(err) {
	return err.code === -32000 && err.message === 'header not found';
}

const RETRY_TIMES = 3;
const RETRY_DELAY = 500;

async function retry_request(request_fn, arg) {
	let n = RETRY_TIMES;
	while (true) {
		try {
			return await request_fn(arg);
		} catch (err) {
			if (!is_header_bug(err) || !(n-- > 0)) throw err;
			await new Promise(ful => setTimeout(ful, RETRY_DELAY));
		}
	}
}

// detect-provider is way too useless to require as a dependancy 
// https://github.com/MetaMask/detect-provider/blob/main/src/index.ts
async function determine_window_provider({smart = true, timeout = 3000} = {}) {
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
				ful(smart ? make_smart(e) : e);
				return true;
			}
		}
	});
}

function make_smart(provider) {
	if (provider.isSmartProvider) return provider; // already smart!
	if (typeof provider.request !== 'function') throw new TypeError(`expected provider`);
	const source = provider.isMetaMask ? 'MetaMask' : 'Unknown Provider';
	let chain_id;
	provider.on('connect', ({chainId}) => { 
		chain_id = chainId;
	});
	provider.on('chainChanged', chainId => {
		chain_id = chainId; 
	});
	provider.on('disconnect', () => {
		chain_id = undefined;
	});
	async function request(obj) {
		if (obj.method === 'eth_chainId' && chain_id) {
			return chain_id; // fast
		}
		return retry_request(provider.request.bind(provider), obj);
	}
	async function req(method, ...params) {
		return request({method, params});
	}
	return new Proxy(provider, {
		get: function(obj, prop) {		
			switch (prop) {
				case 'req': return req;
				case 'request': return request;
				case 'chain_id': return chain_id;
				case 'source': return source;
				case 'isSmartProvider': return true;
				case 'disconnect': return obj[prop] ?? (() => {});
				default: return obj[prop];
			}	
		}
	});
}

// https://eips.ethereum.org/EIPS/eip-1193
// https://eips.ethereum.org/EIPS/eip-695 (eth_chainId)
// https://eips.ethereum.org/EIPS/eip-1474 (errors)

class Providers {
	/*
	static wrap(provider) {
		if (provider instanceof this) return provider;
		let p = new this();
		p.add_dynamic(provider);
		return p;
	}
	static from_map(map) {
		if (typeof map !== 'object') throw new TypeError('expected object');
		let p = new Providers();
		for (let [k, v] of Object.entries(map)) {
			p.add_static(k, v);
		}
		return p;
	}
	*/
	constructor() {
		this.queue = [];
	}
	/*
	add_public(chain_like) {
		let chain = find_chain(chain_like);
		if (!chain) throw new Error(`Chain ${chain_like} is not defined`);
		let v = chain?.data.public_rpcs;
		if (!Array.isArray(v) || v.length == 0) throw new Error(`${chain} has no public RPCs`);
		return this.add_static(chain, v[Math.random() * v.length|0]);
	}*/
	add_static(chain_like, provider) {
		let chain = ensure_chain(chain_like);
		provider = make_smart(provider);
		if (!this.queue.some(x => x.provider === provider)) { // only add once
			this.queue.push({chain, provider}); // low priority
		}
		return this; // chainable
	}
	add_dynamic(provider) {
		provider = make_smart(provider);
		if (!this.queue.some(x => x.provider === provider)) { // only add once
			this.queue.unshift({provider}); // high priority
		}
		return this; // chainable
	}
	available_providers() {
		return this.queue.map(({chain, provider}) => {
			if (chain == undefined) {
				chain = find_chain(provider.chain_id);
			}
			if (chain) return [chain, provider];
		}).filter(x => x);
	}
	disconnect() {
		for (let {provider} of this.queue) {
			provider.disconnect?.();
		}
	}
	async find_provider(chain_like, required) {
		let chain = find_chain(chain_like, required);
		if (chain) {
			for (let {provider, chain: other} of this.queue) {
				if (other === undefined) {
					other = find_chain(await provider.request({method: 'eth_chainId'})); // this is fast
				}
				if (chain === other) {
					return provider;
				}
			}
		}
		if (required) {
			throw new Error(`No provider for chain ${chain}`);
		}
	}
	view(chain_like) {
		let chain = ensure_chain(chain_like);
		let get_provider = async required => {
			return this.find_provider(chain, required);
		};
		return new Proxy(this, {
			get: (target, prop) => {
				switch (prop) {
					case 'isProviderView': return true;
					case 'chain': return chain;
					case 'get_provider': return get_provider;
					default: return target[prop];
				}
			}
		});
	}
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

class BaseProvider extends EventEmitter {
	get isSmartProvider() {
		return true;
	}
	async req(method, ...params) { 
		return this.request({method, params: [...params]}); 
	}
}

class WebSocketProvider extends BaseProvider {
	constructor({url, WebSocket: ws_api, source, request_timeout = 30000, idle_timeout = 60000}) {
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
		this._source = source;
	}
	get source() {
		return this._source ?? this.url;
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
				// TODO add ping/pong
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

class FetchProvider extends BaseProvider {
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
	get source() { return this._source ?? this.url; }
	async request(obj) {
		if (typeof obj !== 'object') throw new TypeError('expected object');
		let request_fn = this._request_once.bind(this);
		if (!this._idle_timer) {			
			try {
				this._chain_id = await retry_request(request_fn, {method: 'eth_chainId'});
			} catch (err) {
				this.emit('connect-error', err);
				throw err;
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
			let ret = await retry_request(request_fn, obj);
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
	async _request_once(obj) {
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
// https://eips.ethereum.org/EIPS/eip-165
async function supports_interface(provider, contract, method) {
	return eth_call(provider, contract, ABIEncoder.method('supportsInterface(bytes4)').bytes(bytes4_from_method(method))).then(dec => {
		return dec.boolean();
	}).catch(err => {
		if (err.code === -32000) return false; // TODO: implement proper fallback
		throw err;
	});
}

const TYPES = {};
const NAMES = {};

function define_ens_addr(addr) {
	if (!(addr instanceof ENSAddr)) throw new TypeError('expected ENSAddr');
	let {type, name} = addr;
	let prev = TYPES[type] ?? NAMES[name];
	if (prev) throw new TypeError(`${prev} already defined`);
	TYPES[type] = NAMES[name] = addr;
}

function find_ens_addr(x) {
	if (x instanceof ENSAddr) {
		return x;
	} else if (typeof x === 'string') {
		return NAMES[x];
	} else if (is_valid_type(x)) {
		return TYPES[x];
	} 
}

function coerce_ens_addr_type(x) {
	let addr = find_ens_addr(x);
	if (addr) return addr.type;
	if (is_valid_type(x)) return x;
}

function is_valid_type(x) {
	return Number.isSafeInteger(x);
}

class ENSAddr {
	constructor(type, name) {
		if (!is_valid_type(type)) throw new TypeError('type must be integer');
		if (typeof name !== 'string') throw new TypeError('name must be string');
		this.type = type;
		this.name = name;
	}
	str_from_bytes(v) {
		if (!(v instanceof Uint8Array)) throw new TypeError('expected bytes');
		let s = this.str(v);
		if (typeof s !== 'string') throw new Error('invalid format');
		return s;
	}
	bytes_from_str(s) {
		if (typeof s !== 'string') throw new TypeError('expected string');
		let v = this.bytes(s);
		if (!(v instanceof Uint8Array)) throw new Error('unknown format');
		return v;
	}
	toString() {
		return this.name;
	}
	str() { throw new TypeError('missing implementation'); }
	bytes() { throw new TypeError('missing implementation'); }
}

// multiple coders are supported as long as they dont throw
class ENSAddrCoder extends ENSAddr {
	constructor(type, name, ...coders) {
		super(type, name);
		this.coders = coders;
	}
	bytes(s) {
		for (let x of this.coders) {
			let ret = x.bytes(s);
			if (ret) return ret;
		}
	}
	str(v) {
		for (let x of this.coders) {
			let ret = x.str(v);
			if (ret) return ret;
		}
	}
}

// accepts anything that keccak can digest
// returns Uint256
function labelhash(label) {
	return new Uint256(keccak().update(label).bytes);
}

// a.b => [a, b]
function labels_from_name(name) {
	return name.split('.');
}

// expects a string
// warning: this does not normalize
// https://eips.ethereum.org/EIPS/eip-137#name-syntax
// returns Uint256
function namehash(name) {
	if (typeof name !== 'string') throw new TypeError('expected string');
	let buf = new Uint8Array(64); 
	if (name.length > 0) {
		for (let label of labels_from_name(name).reverse()) {
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
		this._dot_eth_contract = undefined;
		this._resolvers = {};
	}
	normalize(name) {
		return this.ens_normalize?.(name) ?? name;
	}
	labelhash(label) {
		if (typeof label === 'string') {
			return labelhash(this.normalize(label));
		} else if (label instanceof Uint256) {
			return label;
		} else {
			throw new TypeError(`expected string or Uint256`);
		}
	}
	owner(address) {
		try {
			return new ENSOwner(this, standardize_address(address));
		} catch (cause) {
			let err = new Error(`Invalid address ${address}: ${cause.message}`, {cause});
			err.isInvalid = true;
			err.address = address;
			throw err;
		}		
	}
	async get_provider() {
		let p = this.provider;
		return p.isProviderView ? p.get_provider() : p;
	}
	async call_registry(...args) {
		return eth_call(await this.get_provider(), this.registry, ...args);
	}
	async get_resolver(node) {
		return this.call_registry(ABIEncoder.method('resolver(bytes32)').number(node)).then(dec => {
			return dec.addr();
		}).then(address => {
			if (is_null_hex(address)) return; // no resolver
			let resolver = this._resolvers[address];
			if (!resolver) {
				resolver = this._resolvers[address] = new ENSResolver(this, address);
			}
			return resolver;
		});
	}
	async resolve(s) {
		let name;
		try {
			name = this.normalize(s);
		} catch (cause) {
			let err = new Error(`Name is invalid: ${cause.message}`, {cause});
			err.isInvalid = true;
			err.name = s;
			throw err;
		}
		let node = namehash(name);
		let resolver;
		try {
			resolver = await this.get_resolver(node);
		} catch (cause) {
			let err = new Error(`Unable to determine resolver: ${cause.message}`, {cause});
			err.input = s;
			err.name = name;
			err.node = node;
			throw err;
		}
		return new ENSName(this, s, name, node, resolver);
	}
	// https://eips.ethereum.org/EIPS/eip-181
	// warning: this does not normalize!
	async primary_from_address(address) {
		try {
			address = standardize_address(address, false);
		} catch (cause) {
			let err = new TypeError(`Invalid address ${address}: ${cause.message}`, {cause});
			err.input = address;
			throw err;
		}
		let rev_node = namehash(`${address.slice(2).toLowerCase()}.addr.reverse`); 
		let rev_resolver = await this.get_resolver(rev_node);
		if (!rev_resolver) return; // not set
		try {
			return (await eth_call(
				await this.get_provider(), 
				rev_resolver.address, 
				ABIEncoder.method('name(bytes32)').number(rev_node)
			)).string(); // this can be empty string
		} catch (cause) {
			throw new Error(`Read primary failed: ${cause.message}`, {cause});
		}
	}
	async get_eth_contract() {
		if (this._dot_eth_contract !== undefined) return this._dot_eth_contract;
		return promise_object_setter(this, '_dot_eth_contract', this.resolve('eth').then(name => name.get_owner()).then(x => x.address));
	}
	async is_dot_eth_available(label) {
		return (await eth_call(
			await this.get_provider(), 
			await this.get_eth_contract(),
			ABIEncoder.method('available(uint256)').number(this.labelhash(label))
		)).boolean();
	}
	async get_dot_eth_owner(label) {
		try {
			return this.owner((await eth_call(
				await this.get_provider(), 
				await this.get_eth_contract(),
				ABIEncoder.method('ownerOf(uint256)').number(this.labelhash(label))
			)).addr());
		} catch (err) {
			if (err.reverted) return; // available?
			throw err;
		}
	}
}

class ENSResolver {
	constructor(ens, address) {
		this.ens = ens;
		this.address = address;
		//
		this._interfaces = {};
	}
	async supports_interface(method) {
		let key = hex_from_method(method);
		let value = this._interfaces[key];
		if (value !== undefined) return value;
		return promise_object_setter(this._interfaces, key, this.ens.get_provider().then(p => {
			return supports_interface(p, this.address, method);
		}));
	}
	toJSON() {
		return this.address;
	}
}

class ENSOwner {
	constructor(ens, address) {
		this.ens = ens;
		this.address = address;
		//
		this._primary = undefined;
	}
	toJSON() {
		return this.address;
	}
	async get_primary_name() {
		if (this._primary !== undefined) return this._primary;
		return promise_object_setter(this, '_primary', this.ens.primary_from_address(this.address));
	}
	async resolve() {
		let name = await this.get_primary_name();
		if (name === null) throw new Error(`No name for address: ${address}`);
		if (!name) throw new Error(`Primary not set for address: ${address}`);
		return this.ens.resolve(name);
	}
}

class ENSName {
	constructor(ens, input, name, node, resolver) {
		this.ens = ens;
		this.input = input;
		this.name = name;
		this.node = node;
		this.resolver = resolver; // could be undefined
		this.resolved = new Date();
		//
		this._owner = undefined;
		this._address = undefined;
		this._display = undefined;
		this._avatar = undefined;
		this._pubkey = undefined;
		this._content = undefined;
		this._text = {};
		this._addr = {};
	}
	get labels() {
		return labels_from_name(this);
	}
	toJSON() {
		return this.name;
	}
	assert_valid_resolver() {
		if (!this.resolver) {
			throw new Error(`No resolver`);
		}
	}
	async call_resolver(...args) {
		this.assert_valid_resolver();
		return eth_call(await this.ens.get_provider(), this.resolver.address, ...args);
	}
	async get_address() {
		if (this._address !== undefined) return this._address;
		this.assert_valid_resolver();
		return promise_object_setter(this, '_address', (async () => {
			// https://eips.ethereum.org/EIPS/eip-2304	
			const METHOD = 'addr(bytes32,uint256)';
			const METHOD_OLD = 'addr(bytes32)';
			let p;
			if (await this.resolver.supports_interface(METHOD)) {
				p = this.get_addr_bytes(60);
			} else if (await this.resolver.supports_interface(METHOD_OLD)) {
				p = this.call_resolver(ABIEncoder.method(METHOD_OLD).number(this.node)).then(dec => {
					return dec.read_addr_bytes(); 
				});
			} else {
				throw new Error(`Resolver does not support addr`);
			}
			let v = await p;
			if (v.length == 0) return NULL_ADDRESS;
			if (v.length != 20) throw new Error(`Invalid ETH Address: expected 20 bytes`);
			return standardize_address(hex_from_bytes(v));
		})());
	}
	async get_owner() {
		if (this._owner !== undefined) return this._owner;
		return promise_object_setter(this, '_owner', this.ens.call_registry(ABIEncoder.method('owner(bytes32)').number(this.node)).then(dec => {
			return new ENSOwner(this.ens, dec.addr());
		}).catch(cause => {
			throw new Error(`Read owner failed: ${cause.message}`, {cause});
		}));
	}
	async get_owner_address() { return (await this.get_owner()).address; }
	async get_owner_primary_name() { return (await this.get_owner()).get_primary_name(); }	
	async is_owner_primary_name() {
		// this is not an exact match
		return this.is_equivalent_name(await this.get_owner_primary_name());
	}
	is_input_normalized() {
		return this.input === this.name;
	}
	is_equivalent_name(name) {
		try {
			this.assert_equivalent_name(name);
			return true;
		} catch (err) {
			return false;
		}
	}
	assert_equivalent_name(name) {
		if (name === this.name) return;
		if (!name) throw new Error(`Name is empty`);
		let norm;
		try {
			norm = this.ens.normalize(name);
		} catch (cause) {
			throw new Error(`Name "${name}" is invalid: ${cause.message}`, {cause});
		}
		if (norm !== this.name) {
			throw new Error(`${name} does not match ${this.name}`);
		}
	}
	async is_input_display() {
		let display;
		if (this.resolver) {
			display = await this.get_text('display');
		}
		if (!display) {
			// if display name is not set
			// display is the norm name
			return this.input === this.name; 
		}
		return this.input === display && this.is_equivalent_name(display);
	}
	// this uses norm name if display name isn't set or invalid
	async get_display_name() {
		if (this._display !== undefined) return this._display;
		return promise_object_setter(this, '_display', this.get_text('display').then(display => {
			return this.is_equivalent_name(display) ? display : this.name
		}));
	}
	async get_avatar() {
		if (this._avatar !== undefined) return this._avatar;
		return promise_object_setter(this, '_avatar', parse_avatar(
			await this.get_text('avatar'), // throws
			this.ens.providers,
			await this.get_address()
		));
	}
	// https://eips.ethereum.org/EIPS/eip-634
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/TextResolver.sol
	async get_text(key) { 
		if (typeof key !== 'string') throw new TypeError(`expected string`);
		let value = this._text[key];
		if (value !== undefined) return value;
		this.assert_valid_resolver();
		return promise_object_setter(this._text, key, (async () => {
			// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-634.md
			const METHOD = 'text(bytes32,string)';
			if (!await this.resolver.supports_interface(METHOD)) {
				throw new Error(`Resolver does not support text`);
			}
			try {
				let dec = await this.call_resolver(ABIEncoder.method(METHOD).number(this.node).string(key));
				return dec.string();
			} catch (cause) {
				throw new Error(`Error reading text ${key}: ${cause.message}`, {cause});
			}
		})());
	}
	async get_texts(keys) {
		if (keys === undefined) {
			keys = Object.keys(this._text); // all known keys
		} else if (!Array.isArray(keys)) {
			throw new TypeError('expected array');
		}
		let values = await Promise.all(keys.map(key => this.get_text(key)));
		return Object.fromEntries(keys.map((key, i) => [key, values[i]]));
	}
	// https://eips.ethereum.org/EIPS/eip-2304
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/AddrResolver.sol
	// addrs are stored by type
	async get_addr(x) {
		let addr = find_ens_addr(x);
		if (!addr) throw new Error(`Unknown address type: ${x}`);
		return addr.str_from_bytes(await this.get_addr_bytes(addr.type));
	}
	async get_addr_bytes(x) {
		let type = coerce_ens_addr_type(x);
		if (type === undefined) throw new Error(`Unknown address type: ${x}`);
		let value = this._addr[type];
		if (value !== undefined) return value;
		this.assert_valid_resolver();
		return promise_object_setter(this._addr, type, (async () => {
			const METHOD = 'addr(bytes32,uint256)';
			if (!await this.resolver.supports_interface(METHOD)) {
				throw new Error(`Resolver does not support addr`);
			}
			try {
				let dec = await this.call_resolver(ABIEncoder.method(METHOD).number(this.node).number(type));
				return dec.memory();
			} catch(cause) {
				throw new Error(`Error reading addr type ${type}: ${cause.message}`, {cause});
			}
		})());
	}
	async get_addrs(types) {
		if (types === undefined) {
			types = Object.keys(this._addr).map(x => parseInt(x));
		} else if (Array.isArray(types)) {
			types = types.map(coerce_ens_addr_type).filter(x => x !== undefined);
		} else {
			throw new TypeError('expected array');
		} 
		types = [...new Set(types)];
		let values = await Promise.all(types.map(type => this.get_addr_bytes(type)));
		return types.map((type, i) => {
			let bytes = values[i];
			let addr = find_ens_addr(type);
			let ret = {type, bytes};
			if (addr) {
				ret.name = addr.name;
				if (bytes.length > 0) {
					try {
						ret.addr = addr.str_from_bytes(bytes);
					} catch (err) {
						ret.error = err;
					}
				}
			}
			return ret;
		});
	}
	// https://github.com/ethereum/EIPs/pull/619
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/PubkeyResolver.sol
	async get_pubkey() {
		if (this._pubkey !== undefined) return this._pubkey;
		this.assert_valid_resolver();
		return promise_object_setter(this, '_pubkey', (async () => {
			try {
				let dec = await this.call_resolver(ABIEncoder.method('pubkey(bytes32)').number(this.node));
				return {x: dec.uint256(), y: dec.uint256()};
			} catch(cause) {
				throw new Error(`Error reading pubkey: ${cause.message}`, {cause});
			}
		})());
	}
	// https://eips.ethereum.org/EIPS/eip-1577
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/ContentHashResolver.sol
	async get_content() {
		if (this._content !== undefined) return this._content;
		this.assert_valid_resolver();
		return promise_object_setter(this, '_content', (async () => {
			let hash;
			try {
				let dec = await this.call_resolver(ABIEncoder.method('contenthash(bytes32)').number(this.node));
				hash = dec.memory();
			} catch (cause) {
				throw new Error(`Error reading content: ${cause.message}`, {cause});
			}
			if (hash.length == 0) return {};
			let content = parse_content(hash);
			content.hash = hash;
			return content;
		})());
	}
}

// https://eips.ethereum.org/EIPS/eip-1577
function parse_content(v) {
	let protocol;
	[protocol, v] = read_uvarint(v);
	switch (protocol) {
		case 0xE3: {
			let ret = {type: 'ipfs', protocol};
			try {
				let cid = CID.from_bytes(v);
				ret.cid = cid;
				ret.url = `ipfs://${cid.toString()}`;				
			} catch (err) {
				ret.error = err;
			}
			return ret;
		}		case 0xE5: {
			let ret = {type: 'ipns', protocol};
			try {
				let cid = CID.from_bytes(v);
				if (cid.version !== 1) {
					throw new Error('invalid CID version');
				}
				if (cid.hash.code !== 0) { // identity
					throw new Error('expected identity hash');
				}				
				ret.cid = cid;
				ret.url = `ipns://${cid}`;
			} catch (err) {
				ret.error = err;
			} 
			return ret;
		}
		default: return {type: 'unknown', protocol};
	}	
}

const AVATAR_TYPE_INVALID = 'invalid';

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
		if (parts.length < 2) return {type: AVATAR_TYPE_INVALID, error: 'expected contract'};
		if (parts.length < 3) return {type: AVATAR_TYPE_INVALID, error: 'expected token'};
		let chain_id;
		try {
			chain_id = standardize_chain_id(part0.slice(part0.indexOf(':') + 1));
		} catch (err) {
			return {type: AVATAR_TYPE_INVALID, error: err.message};
		}
		let part1 = parts[1];
		if (part1.startsWith('erc721:')) {
			// https://eips.ethereum.org/EIPS/eip-721
			let contract = part1.slice(part1.indexOf(':') + 1);
			try {
				contract = standardize_address(contract);
			} catch (err) {
				return {type: AVATAR_TYPE_INVALID, error: `Invalid contract address: ${err.message}`};
			}
			let token;
			try {
				token = Uint256.from_str(parts[2]);
			} catch (err) {
				return {type: AVATAR_TYPE_INVALID, error: `Invalid token: ${err.message}`};
			}
			let ret = {type: 'nft', interface: 'erc721', contract, token, chain_id};
			if (provider instanceof Providers) {
				provider = await provider?.find_provider(chain_id);
			}
			if (provider) {
				try {
					let [owner, meta_uri] = await Promise.all([
						eth_call(provider, contract, ABIEncoder.method('ownerOf(uint256)').number(token)).then(x => x.addr()),
						eth_call(provider, contract, ABIEncoder.method('tokenURI(uint256)').number(token)).then(x => x.string())
					]);
					ret.owner = owner;
					ret.meta_uri = meta_uri;
					if (typeof address === 'string') {
						ret.owned = address.toUpperCase() === owner.toUpperCase() ? 1 : 0; // is_same_address?
					}
				} catch (err) {
					return {type: AVATAR_TYPE_INVALID, error: `invalid response from contract`};
				}
			}
			return ret;
		} else if (part1.startsWith('erc1155:')) {
			// https://eips.ethereum.org/EIPS/eip-1155
			let contract = part1.slice(part1.indexOf(':') + 1);
			try {
				contract = standardize_address(contract);
			} catch (err) {
				return {type: AVATAR_TYPE_INVALID, error: `Invalid contract address: ${err.message}`};
			}
			let token;
			try {
				token = Uint256.from_str(parts[2]);
			} catch (err) {
				return {type: AVATAR_TYPE_INVALID, error: `Invalid token: ${err.message}`};
			}
			let ret = {type: 'nft', interface: 'erc1155', contract, token, chain_id};
			if (provider instanceof Providers) {
				provider = await provider?.find_provider(chain_id);
			}
			if (provider) {
				try {
					let [balance, meta_uri] = await Promise.all([
						is_valid_address(address) 
							? eth_call(provider, contract, ABIEncoder.method('balanceOf(address,uint256)').addr(address).number(token)).then(dec => dec.number())
							: -1,
						eth_call(provider, contract, ABIEncoder.method('uri(uint256)').number(token)).then(dec => dec.string())
					]);
					// The string format of the substituted hexadecimal ID MUST be lowercase alphanumeric: [0-9a-f] with no 0x prefix.
					ret.meta_uri = meta_uri.replace('{id}', token.hex.slice(2)); 
					if (balance >= 0) {
						ret.owned = balance;
					}
				} catch (err) {
					return {type: AVATAR_TYPE_INVALID, error: `invalid response from contract`};
				}
			}
			return ret;
		} else {
			return {type: AVATAR_TYPE_INVALID, error: `unsupported contract interface: ${part1}`};
		}		
	}
	return {type: 'unknown'};
}


function format_addr_type(type, include_type = false) {
	let pos = Object.values(ADDR_TYPES).indexOf(type);
	if (pos >= 0) { // the type has a name
		let s = Object.keys(ADDR_TYPES)[pos];
		if (include_type) s = `${s}<${type}>`;
		return s;
	} else { // the type doesn't have an known name
		return '0x' + x.toString(16).padStart(4, '0');
	}
}

class BTCCoder extends Coder {
	constructor(p2pkh, p2sh) {
		super();
		this.p2pkh = p2pkh;
		this.p2sh = p2sh;
	}
	str(v)  {
		let n = v.length;
		// P2PKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
		if (n >= 4 && v[0] == 0x76 &&  v[1] == 0xA9 && v[2] == n - 5 && v[n-2] == 0x88 && v[n-1] == 0xAC) {
			return X$1.str_from_bytes([...this.p2pkh[0], ...v.slice(3, -2)]);
		// P2SH: OP_HASH160 <scriptHash> OP_EQUAL
		} else if (n >= 3 && v[0] == 0xA9 && v[1] == n - 2 && v[n-1] == 0x76) {
			return X$1.str_from_bytes([...this.p2sh[0], ...v.slice(2)]);
		}
	}
	bytes(s) {
		let v = X$1.bytes_from_str(s);
		let n = 20; // sizeof HASH160
		for (let u of this.p2pkh) {
			if (v.length - u.length == n && compare_arrays(u, v.slice(0, u.length)) == 0) {
				return Uint8Array.from([0x76, 0xA9, n, ...v.slice(-n), 0x88, 0xAC]);
			}
		}
		for (let u of this.p2sh) {
			if (v.length - u.length == n && compare_arrays(u, v.slice(0, u.length)) == 0) {
				return Uint8Array.from([0xA9, n, ...v.slice(-n), 0x76]);
			}
		}
	}
}

class HexCoder extends Coder {
	str(v) {
		return standardize_address(hex_from_bytes(v));
	}
	bytes(s) {
		return bytes_from_hex(standardize_address(s))
	}
}

const X = new HexCoder();

// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
// https://github.com/ensdomains/address-encoder/blob/master/src/index.ts

define_ens_addr(new ENSAddrCoder(0, 'BTC', new BTCCoder([[0x00]], [[0x05]]), new SegwitCoder('bc')));
define_ens_addr(new ENSAddrCoder(2, 'LTC', new BTCCoder([[0x30]], [[0x32], [0x05]]), new SegwitCoder('ltc')));
define_ens_addr(new ENSAddrCoder(3, 'DOGE', new BTCCoder([[0x1E]], [[0x16]])));
define_ens_addr(new ENSAddrCoder(4, 'RDD', new BTCCoder([[0x3D]], [[0x05]])));
define_ens_addr(new ENSAddrCoder(5, 'DASH', new BTCCoder([[0x4C]], [[0x10]])));
define_ens_addr(new ENSAddrCoder(6, 'PPC', new BTCCoder([[0x37]], [[0x75]])));
define_ens_addr(new ENSAddrCoder(7, 'NMC', X$1));
define_ens_addr(new ENSAddrCoder(14, 'VIA', new BTCCoder([[0x47]], [[0x21]])));
// define_ens_addr(17, 'GRS') groestlcoinChain('grs', [[0x24]], [[0x05]]),
define_ens_addr(new ENSAddrCoder(20, 'DGB', new BTCCoder([[0x1e]], [[0x3f]]), new SegwitCoder('dgb')));
define_ens_addr(new ENSAddrCoder(22, 'MONA', new BTCCoder([[0x32]], [[0x37], [0x05]]), new SegwitCoder('mona')));
define_ens_addr(new ENSAddrCoder(42, 'DCR', Base58BTC));
define_ens_addr(new ENSAddrCoder(43, 'XEM', new MapStringCoder(Base32, s => s.toUpperCase())));
define_ens_addr(new ENSAddrCoder(55, 'AIB', new BTCCoder([[0x17]], [[0x05]])));
define_ens_addr(new ENSAddrCoder(57, 'SYS', new BTCCoder([[0x3f]], [[0x05]]), new SegwitCoder('sys')));
define_ens_addr(new ENSAddrCoder(56, 'BSC', X));
define_ens_addr(new ENSAddrCoder(60, 'ETH', X));
define_ens_addr(new ENSAddrCoder(61, 'ETC', X));
// define_ens_addr(74, 'ICX') icxAddressEncoder, icxAddressDecoder),
define_ens_addr(new ENSAddrCoder(77, 'XVG', new BTCCoder([[0x1E]], [[0x21]])));
define_ens_addr(new ENSAddrCoder(105, 'STRAT', new BTCCoder([[0x3F]], [[0x7D]])));
define_ens_addr(new ENSAddrCoder(111, 'ARK', new MapBytesCoder(X$1, v => {
	if (v[0] != 23) throw new Error('invalid address');
	return v;
})));
define_ens_addr(new ENSAddrCoder(118, 'ATOM', new Bech32Coder(Bech32.TYPE_1, 'cosmos')));
define_ens_addr(new ENSAddrCoder(119, 'ZIL', new Bech32Coder(Bech32.TYPE_1, 'zil')));
define_ens_addr(new ENSAddrCoder(120, 'EGLD', new Bech32Coder(Bech32.TYPE_1, 'erd')));
define_ens_addr(new ENSAddrCoder(121, 'ZEN', new MapStringCoder(X$1, s => {
	if (!/^(zn|t1|zs|t3|zc)/.test(s)) throw new Error('invalid address');
	return s;
})));
//getConfig('XMR', 128, xmrAddressEncoder, xmrAddressDecoder),
define_ens_addr(new ENSAddrCoder(133, 'ZEC', new BTCCoder([[0x1c, 0xb8]], [[0x1c, 0xbd]])), new SegwitCoder('zs'));
//   getConfig('LSK', 134, liskAddressEncoder, liskAddressDecoder),
//   eosioChain('STEEM', 135, 'STM'),
define_ens_addr(new ENSAddrCoder(136, 'FIRO', new BTCCoder([[0x52]], [[0x07]])));
define_ens_addr(new ENSAddrCoder(137, 'MATIC', X));
define_ens_addr(new ENSAddrCoder(141, 'KMD', new BTCCoder([[0x3C]], [[0x55]])));
//getConfig('XRP', 144, data => xrpCodec.encodeChecked(data), data => xrpCodec.decodeChecked(data)),
//getConfig('BCH', 145, encodeCashAddr, decodeBitcoinCash),
//getConfig('XLM', 148, strEncoder, strDecoder),
define_ens_addr(new ENSAddrCoder(153, 'BTM', new SegwitCoder('bm')));
define_ens_addr(new ENSAddrCoder(156, 'BTG', new BTCCoder([[0x26]], [[0x17]]), new SegwitCoder('btg')));
//  getConfig('NANO', 165, nanoAddressEncoder, nanoAddressDecoder),
define_ens_addr(new ENSAddrCoder(175, 'RVN', new BTCCoder([[0x3c]], [[0x7a]])));
define_ens_addr(new ENSAddrCoder(178, 'POA', X));
define_ens_addr(new ENSAddrCoder(192, 'LCC', new BTCCoder([[0x1c]], [[0x32], [0x05]]), new SegwitCoder('lcc')));
//   eosioChain('EOS', 194, 'EOS'),
define_ens_addr(new ENSAddrCoder(195, 'TRX', X$1));
//getConfig('BCN', 204, bcnAddressEncoder, bcnAddressDecoder),
//eosioChain('FIO', 235, 'FIO'),
//getConfig('BSV', 236, bsvAddresEncoder, bsvAddressDecoder),
define_ens_addr(new ENSAddrCoder(239, 'NEO', X$1));
//  getConfig('NIM', 242, nimqEncoder, nimqDecoder),
define_ens_addr(new ENSAddrCoder(246, 'EWT', X));
//   getConfig('ALGO', 283, algoEncode, algoDecode),
define_ens_addr(new ENSAddrCoder(291, 'IOST', Base58BTC));
define_ens_addr(new ENSAddrCoder(301, 'DIVI', new BTCCoder([[0x1e]], [[0xd]])));
define_ens_addr(new ENSAddrCoder(304, 'IOTX', new Bech32Coder(Bech32.TYPE_1, 'io')));
//  eosioChain('BTS', 308, 'BTS'),
define_ens_addr(new ENSAddrCoder(309, 'CKB', new Bech32Coder(Bech32.TYPE_1, 'ckb')));
define_ens_addr(new ENSAddrCoder(330, 'LUNA', new Bech32Coder(Bech32.TYPE_1, 'terra')));
// getConfig('DOT', 354, dotAddrEncoder, ksmAddrDecoder),
// getConfig('VSYS', 360, vsysAddressEncoder, vsysAddressDecoder),
// eosioChain('ABBC', 367, 'ABBC'),
// getConfig('NEAR', 397, encodeNearAddr, decodeNearAddr),
// getConfig('ETN', 415, etnAddressEncoder, etnAddressDecoder),
// getConfig('AION', 425, aionEncoder, aionDecoder),
// getConfig('KSM', 434, ksmAddrEncoder, ksmAddrDecoder),
// getConfig('AE', 457, aeAddressEncoder, aeAddressDecoder),
define_ens_addr(new ENSAddrCoder(459, 'KAVA', new Bech32Coder(Bech32.TYPE_1, 'kava')));
//getConfig('FIL', 461, filAddrEncoder, filAddrDecoder),
//getConfig('AR', 472, arAddressEncoder, arAddressDecoder),
define_ens_addr(new ENSAddrCoder(489, 'CCA', new BTCCoder([[0x0b]], [[0x05]])));
define_ens_addr(new ENSAddrCoder(500, 'THETA', X));
define_ens_addr(new ENSAddrCoder(501, 'SOL', Base58BTC));
// getConfig('XHV', 535, xmrAddressEncoder, xmrAddressDecoder),
// getConfig('FLOW', 539, flowEncode, flowDecode),
define_ens_addr(new ENSAddrCoder(566, 'IRIS', new Bech32Coder(Bech32.TYPE_1, 'griiaan')));
define_ens_addr(new ENSAddrCoder(568, 'LRG', new BTCCoder([[0x1e]], [[0x0d]])));
// getConfig('SERO', 569, seroAddressEncoder, seroAddressDecoder),
// getConfig('BDX', 570, xmrAddressEncoder, xmrAddressDecoder),
define_ens_addr(new ENSAddrCoder(571, 'CCXX', new BTCCoder([[0x89]], [[0x4b], [0x05]]), new SegwitCoder('ccx')));
define_ens_addr(new ENSAddrCoder(573, 'SRM', Base58BTC));
define_ens_addr(new ENSAddrCoder(574, 'VLX', Base58BTC));
define_ens_addr(new ENSAddrCoder(576, 'BPS', new BTCCoder([[0x00]], [[0x05]])));
define_ens_addr(new ENSAddrCoder(589, 'TFUEL', X));
define_ens_addr(new ENSAddrCoder(592, 'GRIN', new Bech32Coder(Bech32.TYPE_1, 'grin')));
define_ens_addr(new ENSAddrCoder(614, 'OPT', X));
define_ens_addr(new ENSAddrCoder(700, 'XDAI', X));
define_ens_addr(new ENSAddrCoder(703, 'VET', X));
define_ens_addr(new ENSAddrCoder(714, 'BNB', new Bech32Coder(Bech32.TYPE_1, 'bnb')));
define_ens_addr(new ENSAddrCoder(820, 'CLO', X));
//eosioChain('HIVE', 825, 'STM'),
define_ens_addr(new ENSAddrCoder(889, 'TOMO', X));
//getConfig('HNT', 904, hntAddresEncoder, hntAddressDecoder),
define_ens_addr(new ENSAddrCoder(931, 'RUNE', new Bech32Coder(Bech32.TYPE_1, 'thor')));
define_ens_addr(new ENSAddrCoder(999, 'BCD', new BTCCoder([[0x00]], [[0x05]]), new SegwitCoder('bcd')));
define_ens_addr(new ENSAddrCoder(1001, 'TT', X));
define_ens_addr(new ENSAddrCoder(1007, 'FTM', X));
define_ens_addr(new ENSAddrCoder(1023, 'ONE', new Bech32Coder(Bech32.TYPE_1, 'one')));
//{ coinType: 1729, decoder: tezosAddressDecoder,encoder: tezosAddressEncoder,name: 'XTZ',},
//getConfig('ONT', 1024, ontAddrEncoder, ontAddrDecoder),
//  cardanoChain('ADA', 1815, 'addr'),
//getConfig('SC', 1991, siaAddressEncoder, siaAddressDecoder),
//getConfig('QTUM', 2301, bs58Encode, bs58Decode),
//eosioChain('GXC', 2303, 'GXC'),
//getConfig('ELA', 2305, bs58EncodeNoCheck, bs58DecodeNoCheck),
//getConfig('NAS', 2718, nasAddressEncoder, nasAddressDecoder),
//coinType: 3030,decoder: hederaAddressDecoder,encoder: hederaAddressEncoder, name: 'HBAR',
//iotaBech32Chain('IOTA', 4218, 'iota'),
//getConfig('HNS', 5353, hnsAddressEncoder, hnsAddressDecoder),
//getConfig('STX', 5757, c32checkEncode, c32checkDecode),
define_ens_addr(new ENSAddrCoder(6060, 'GO', X));
define_ens_addr(new ENSAddrCoder(8444, 'XCH', new Bech32Coder(Bech32.TYPE_M, 'xch')));
//  getConfig('NULS', 8964, nulsAddressEncoder, nulsAddressDecoder),
define_ens_addr(new ENSAddrCoder(9000, 'AVAX', new Bech32Coder(Bech32.TYPE_1, 'avax')));
define_ens_addr(new ENSAddrCoder(9797, 'NRG', X));
//getConfig('ARDR', 16754, ardrAddressEncoder, ardrAddressDecoder),
//zcashChain('ZEL', 19167, 'za', [[0x1c, 0xb8]], [[0x1c, 0xbd]]),
define_ens_addr(new ENSAddrCoder(42161, 'ARB1', X));
define_ens_addr(new ENSAddrCoder(52752, 'CELO', X));
//bitcoinBase58Chain('WICC', 99999, [[0x49]], [[0x33]]),
//getConfig('WAN', 5718350, wanChecksummedHexEncoder, wanChecksummedHexDecoder),
//getConfig('WAVES', 5741564, bs58EncodeNoCheck, wavesAddressDecoder),

const TYPE_721 = 'ERC-721';
const TYPE_1155 = 'ERC-1155';
// legacy support
const TYPE_CRYPTO_PUNK = 'CryptoPunks';
const TYPE_UNKNOWN = 'Unknown';


class NFT {
	constructor(provider, address, {strict = true, cache = true} = {}) {
		this.provider = provider;
		this.address = standardize_address(address); // throws
		this.strict = strict; // assumes 721 if not 1155
		this._type = undefined;
		this._name = undefined;
		this._supply = undefined;
		if (cache) {
			this.token_uris = {};
		}
	}
	async call(...args) {
		return eth_call(await this.get_provider(), this.address, ...args);
	}
	async supports(method) {
		return supports_interface(await this.get_provider(), this.address, method);
	}
	async get_provider() {
		let p = this.provider;
		return p.isProviderView ? p.get_provider() : p;
	}
	async get_type() {
		if (this._type !== undefined) return this._type;
		if (this.address === '0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB') {
			return this._type = TYPE_CRYPTO_PUNK;
		}
		return promise_object_setter(this, '_type', (async () => {
			if (await this.supports('d9b67a26')) {
				// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1155.md
				return TYPE_1155;
			} else if (!this.strict || await this.supports('80ac58cd')) {
				// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-721.md
				return TYPE_721;
			} else if (await this.supports('d31b620d')) { 
				/*console.log([
					'name()', 
					'symbol()', 
					'totalSupply()', 
					'balanceOf(address)', 
					'ownerOf(uint256)', 
					'approve(address,uint256)', 
					'safeTransferFrom(address,address,uint256)'
				].reduce((a, x) => a.xor(keccak().update(x).bytes), Uint256.zero()).hex.slice(0, 10));*/
				return TYPE_721;
			} else {
				return TYPE_UNKNOWN;
			}
		})());
	} 
	async _uri_from_token(token) {
		switch (await this.get_type()) {
			case TYPE_CRYPTO_PUNK: {
				let {dec} = token;			
				return data_uri_from_json({
					name: `CryptoPunk #${dec}`,
					image: `https://www.larvalabs.com/public/images/cryptopunks/punk${dec}.png`,
					external_url:  `https://www.larvalabs.com/cryptopunks/details/${dec}`
				});
			}
			case TYPE_721: {
				return this.call(ABIEncoder.method('tokenURI(uint256)').number(token)).then(x => x.string()).then(s => {
					return fix_multihash_uri(s.trim());
				});
			}
			case TYPE_1155: {
				return this.call(ABIEncoder.method('uri(uint256)').number(token)).then(x => x.string()).then(s => {
					// 1155 standard (lowercase, no 0x)
					return fix_multihash_uri(s.replace('{id}', token.hex.slice(2)).trim());
				});
			}
			default: throw new Error(`unable to query ${token} from ${this.address}`);
		}
	}
	async get_token_uri(x) {
		let token = Uint256.wrap(x); // throws
		let cache = this.token_uris;
		if (!cache) return this._uri_from_token(token); // no cache
		let key = token.hex;
		let value = cache[key];
		if (value !== undefined) return value;
		return promise_object_setter(cache, key, this._uri_from_token(token));
	}
	async get_name() {
		if (this._name !== undefined) return this._name;
		return promise_object_setter(this, '_name', (async () => {
			switch (await this.get_type()) {
				case TYPE_CRYPTO_PUNK:
				case TYPE_721: {
					try {
						let dec = await this.call(ABIEncoder.method('name()'));
						return dec.string();
					} catch (cause) {
						throw new Error(`Error reading name: ${cause.message}`, {cause});
					}
				}
				default: return ''; // unknown?
			}
		})());
	}
	async get_supply() {
		if (this._supply !== undefined) this._supply;
		return promise_object_setter(this, '_supply', (async () => {
			switch (await this.get_type()) {
				case TYPE_CRYPTO_PUNK:
				case TYPE_721: {
					try {
						let dec = await this.call(ABIEncoder.method('totalSupply()'));
						return dec.number();
					} catch (cause) {
						if (err.reverted) return NaN; // not ERC721Enumerable 
						throw new Error(`Error reading supply: ${cause.message}`, {cause});
					}
				}
				default: return NaN;
			}
		})());
	}
}

function fix_multihash_uri(s) {
	try {
		Multihash.from_str(s);
		return `ipfs://${s}`;
	} catch (ignored) {
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

export { ABIDecoder, ABIEncoder, Base10, Base16, Base2, Base32, Base32Hex, Base36, Base58BTC, X$1 as Base58Check, Base64, Base64URL, Base8, Bech32, Bech32Coder, CID, CIDv0, CIDv1, Chain, ENS, ENSAddr, ENSAddrCoder, ENSName, ENSOwner, ENSResolver, FetchProvider, NFT, NULL_ADDRESS, Providers, Segwit, SegwitCoder, Uint256, WebSocketProvider, assert_uvarint, bytes4_from_method, bytes_from_hex$1 as bytes_from_hex, bytes_from_utf8, coerce_ens_addr_type, compare_arrays, data_uri_from_json, decode_multibase, define_ens_addr, defined_chains, determine_window_provider, encode_multibase, ensure_chain, eth_call, find_chain, find_ens_addr, fix_multihash_uri, format_addr_type, hex_from_bytes, hex_from_method, is_checksum_address, is_null_hex, is_valid_address, keccak, labelhash, labels_from_name, left_truncate_bytes, make_smart, namehash, parse_avatar, parse_content, promise_object_setter, read_uvarint, replace_ipfs_protocol, set_bytes_to_number, sha256, sha3, shake, short_address, sizeof_uvarint, standardize_address, standardize_chain_id, supports_interface, unsigned_from_bytes, utf8_from_bytes, write_uvarint };
