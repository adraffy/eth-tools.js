import {keccak} from '@adraffy/keccak';

// accepts address as string (0x-prefix is optional) 
// returns 0x-prefixed checksummed address 
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
export function standardize_address(s, checksum = true) {
	if (typeof s !== 'string') throw new TypeError('expected string');
	if (s.startsWith('0x')) s = s.slice(2);
	s = s.toLowerCase();
	if (!/^[a-f0-9]{40}$/.test(s)) throw new TypeError('expected 40-char hex');
	if (checksum) {
		let hash = keccak().update(s).hex;
		s = [...s].map((x, i) => hash.charCodeAt(i) >= 56 ? x.toUpperCase() : x).join('');
	}
	return `0x${s}`;
}

export function is_valid_address(s) {
	return /^(0x)?[a-f0-9]{40}$/i.test(s);
}

export function is_checksum_address(s) {
	try {
		return standardize_address(s) === s;
	} catch (ignored) {
		// undefined lets you differentiate !checksum from !address
	}
}

export function short_address(s) {
	s = standardize_address(s);
	return s.slice(0, 6) + '..' + s.slice(-4);
}