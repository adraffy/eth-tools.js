import {sizeof_uvarint, read_uvarint, write_uvarint} from './uvarint.js';
import {decode_multibase, encode_multibase, Base58BTC} from './multibase.js';
import {Multihash} from './multihash.js';

// https://github.com/multiformats/cid/blob/master/original-rfc.md
// https://github.com/multiformats/cid#cidv1

export class CID {
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

export class CIDv0 extends CID {
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

export class CIDv1 extends CID {
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
