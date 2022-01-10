import {Coder} from './base-coders.js';
import {compare_arrays} from './utils.js';
import {Base58Check} from './base58check.js';

export class BTCCoder extends Coder {
	constructor(p2pkh, p2sh) {
		super();
		this.p2pkh = p2pkh;
		this.p2sh = p2sh;
	}
	str(v)  {
		let n = v.length;
		// P2PKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
		if (n >= 4 && v[0] == 0x76 &&  v[1] == 0xA9 && v[2] == n - 5 && v[n-2] == 0x88 && v[n-1] == 0xAC) {
			return Base58Check.str_from_bytes([...this.p2pkh[0], ...v.slice(3, -2)]);
		// P2SH: OP_HASH160 <scriptHash> OP_EQUAL
		} else if (n >= 3 && v[0] == 0xA9 && v[1] == n - 2 && v[n-1] == 0x76) {
			return Base58Check.str_from_bytes([...this.p2sh[0], ...v.slice(2)]);
		}
	}
	bytes(s) {
		let v = Base58Check.bytes_from_str(s);
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