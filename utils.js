import {keccak, hex_from_bytes, bytes_from_hex, bytes_from_str} from '@adraffy/keccak';

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

export function is_null_hex(s) {
	return /^(0x)?[0]+$/i.test(s);
}

const BASE_58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; // removed: "IOl0+/"

// https://tools.ietf.org/id/draft-msporny-base58-01.html
export function base58_from_bytes(v) {
	let digits = [];
	let zero = 0;
	for (let x of v) {
		if (digits.length == 0 && x == 0) {
			zero++;
			continue;
		}
		for (let i = 0; i < digits.length; ++i) {
			let xx = (digits[i] << 8) | x
			digits[i] = xx % 58;
			x = (xx / 58) | 0;
		}
		while (x > 0) {
			digits.push(x % 58);
			x = (x / 58) | 0
		}
	}
	for (; zero > 0; zero--) digits.push(0);
	return String.fromCharCode(...digits.reverse().map(x => BASE_58.charCodeAt(x)));
}