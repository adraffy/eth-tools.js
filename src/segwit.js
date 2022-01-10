import {Coder} from './base-coders.js';
import {Bech32} from './bech32.js';

const VERSION_OFFSET = 0x50;
const VERSION_MAX = 0x10;

export class SegwitCoder extends Coder {
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

export class Segwit {
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