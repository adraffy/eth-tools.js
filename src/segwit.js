import {Bech32, Bech32m} from './bech32.js';

export class Segwit {
	static decode(s) {
		let bech = Bech32.from_str(s);
		if (bech.digits.length < 1) throw new Error('no digits');
		let version = bech.digits[0];
		if (version > 16) throw new Error(`invalid version: ${version}`);
		let v = convertbits(bech.digits.slice(1), 5, 8, false);
		if (version == 0) {
			if (v.length != 20 && v.length != 32) throw new Error('invalid length');
			if (bech.is_m) throw new Error('expected Bech32');
		} else {
			if (!bech.is_m) throw new Error('expected Bech32m');
		}
		return new this(bech.hrp, version, v);
	}
	constructor(hrp, version, program) {
		this.hrp = hrp;
		this.version = version;
		this.program = program;
	}
	get bech32() {
		let {hrp, version, program} = this;
		let v = convertbits([version, ...program], 8, 5, true);
		return version == 0 ? new Bech32(hrp, v) : new Bech32m(hrp, v);
	}
	toString() {
		return this.bech32.toString();
	}
}

function convertbits (data, frombits, tobits, pad) {
	var acc = 0;
	var bits = 0;
	var ret = [];
	var maxv = (1 << tobits) - 1;
	for (var p = 0; p < data.length; ++p) {
	  var value = data[p];
	  if (value < 0 || (value >> frombits) !== 0) {
		return null;
	  }
	  acc = (acc << frombits) | value;
	  bits += frombits;
	  while (bits >= tobits) {
		bits -= tobits;
		ret.push((acc >> bits) & maxv);
	  }
	}
	if (pad) {
	  if (bits > 0) {
		ret.push((acc << (tobits - bits)) & maxv);
	  }
	} else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
	  return null;
	}
	return ret;
  }

