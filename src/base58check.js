
import {sha256} from './sha256.js';
import {Coder} from './base-coders.js';
import {Base58BTC} from './base58.js';

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

const X = new Base58Check();
export {X as Base58Check};
