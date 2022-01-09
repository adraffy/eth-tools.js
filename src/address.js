import {keccak} from '@adraffy/keccak';

export const NULL_ADDRESS = '0x0000000000000000000000000000000000000000';

// accepts address as string (0x-prefix is optional) 
// returns 0x-prefixed checksummed address 
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
export function standardize_address(s, checksum = true) {
	if (typeof s !== 'string') throw new TypeError('expected string');
	if (s.startsWith('0x')) s = s.slice(2);
	let lower = s.toLowerCase();
	if (!/^[a-f0-9]{40}$/.test(lower)) throw new TypeError('expected 40-char hex');
	let ret = lower;
	if (checksum && !/^[0-9]+$/.test(ret)) { 
		let hash = keccak().update(lower).hex;
		ret = [...lower].map((x, i) => hash.charCodeAt(i) >= 56 ? x.toUpperCase() : x).join('');
		// dont enforce checksum on full lower/upper case
		if (s !== ret && s !== lower && s !== lower.toLowerCase()) {
			throw new Error(`checksum failed: ${s}`);
		}
	}
	return `0x${ret}`;
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