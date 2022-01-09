import {sizeof_uvarint, read_uvarint, write_uvarint} from './uvarint.js';
import {decode_multibase} from './multibase.js';

// https://github.com/multiformats/multihash
// sha1 = 0x11
// sha256 = 0x12

export class Multihash {
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