import {Lookup} from './base-coders.js';

// https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

const BECH32 = new Lookup('qpzry9x8gf2tvdw0s3jn54khce6mua7l', 5);
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

export class Bech32 {
	static from_str(s) {
		if (typeof s !== 'string') throw new TypeError('expected string');
		try {
			if (s.length > 90) throw new Error('too long');
			let lower = s.toLowerCase();
			if (s !== lower && s !== s.toUpperCase()) throw new Error('mixed case');
			let pos = lower.lastIndexOf(SEP);
			if (pos < 1) throw new Error('expected hrp');
			if (lower.length - pos - 1 < 6) throw new Error('expected checksum');
			let hrp = lower.slice(0, pos);
			let v = [...lower.slice(pos + 1)].map(x => BECH32.parse(x));
			switch (polymod(v, polymod(hrp_expand(hrp)))) {
				case this.CONST: return new this(hrp, v.slice(0, -6));
				case Bech32m.CONST: return new Bech32m(hrp, v.slice(0, -6));
				default: throw new Error(`invalid checksum`);
			}
		} catch (cause) {
			throw new Error(`Invalid Bech32: ${cause.message}`, {cause});
		}
	}
	static CONST = 1;
	constructor(hrp, digits) {
		this.hrp = hrp;
		this.digits = digits; // base-32
	} 
	toString() {
		let {hrp, digits} = this;
		let v = [0,0,0,0,0,0];
		let check = polymod(v, polymod(digits, polymod(hrp_expand(hrp)))) ^ this.constructor.CONST;
		for (let i = 0; i < v.length; i++) {
			v[i] = (check >> 5 * (5 - i)) & 31;
		}
		return this.hrp.toLowerCase() + SEP + BECH32.format(digits) + BECH32.format(v);
	}
}

export class Bech32m extends Bech32 {
	static CONST = 0x2bc830a3;
	get is_m() { return true; }
}