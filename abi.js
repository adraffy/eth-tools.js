import {bytes_from_str, bytes_from_hex, hex_from_bytes, keccak, str_from_bytes} from '@adraffy/keccak';
import {checksum_address} from './utils.js';

export function number_from_abi(x) {
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

export class ABIDecoder {
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

export class ABIEncoder {
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