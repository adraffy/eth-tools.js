import {Coder, BaseCoder, convert_bits} from './base-coders.js';

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

export class Bech32Coder extends Coder {
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

export class Bech32 {
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