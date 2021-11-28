import {keccak, hex_from_bytes} from '@adraffy/keccak';

// expects a string
// returns 64-char hex-string, no 0x-prefix
// https://eips.ethereum.org/EIPS/eip-137#name-syntax
export function namehash(name) {
	if (typeof name !== 'string') throw new TypeError('Expected string');
	let buf = new Uint8Array(64); 
	if (name.length > 0) {
		for (let label of name.split('.').reverse()) {
			buf.set(keccak().update(label).bytes, 32);
			buf.set(keccak().update(buf).bytes, 0);
		}
	}
	return hex_from_bytes(buf.subarray(0, 32));
}

// accepts address as string (0x-prefix is optional) 
// returns 0x-prefixed checksummed address 
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
export function checksum_address(s) {
	if (typeof s !== 'string') throw new TypeError('expected string');
	if (s.startsWith('0x')) s = s.slice(2);
	s = s.toLowerCase();
	if (!/^[a-f0-9]{40}$/.test(s)) throw new TypeError('expected 40-char hex');
	let hash = keccak().update(s).hex;
	return '0x' + [...s].map((x, i) => hash.charCodeAt(i) >= 56 ? x.toUpperCase() : x).join('');
}

export function is_valid_address(s) {
	return /^(0x)?[a-f0-9]{40}$/i.test(s);
}

export function is_null_address(s) {
	return /^(0x)?[0]{40}$/i.test(s);
}

/*
export function method_signature(x) {
	if (typeof x === 'string') {	
		return keccak().update(x).hex.slice(0, 8);
	} else {
		throw new TypeError('unknown input');
	}
}
*/
			