import {keccak} from '@adraffy/keccak';

export function compare_arrays(a, b) {
	let n = a.length;
	let c = n - b.length;
	for (let i = 0; c == 0 && i < n; i++) c = a[i] - b[i];
	return c;
}

// returns promises mirror the initial promise
// callback is fired once with (value, err)
export function promise_queue(promise, callback) {
	let queue = [];	
	promise.then(ret => {
		callback?.(ret);
		for (let x of queue) x.ful(ret);
	}).catch(err => {
		callback?.(null, err);
		for (let x of queue) x.rej(err);
	});
	return () => new Promise((ful, rej) => {
		queue.push({ful, rej});
	});
}

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

export function is_null_hex(s) {
	return /^(0x)?[0]+$/i.test(s); // should this be 0+
}

export function is_multihash(s) {
	try {
		let v = bytes_from_base58(s);
		return v.length >= 2 && v.length == 2 + v[1];
	} catch (ignored) {
		return false;
	}
}

export function fix_multihash_uri(s) {
	if (is_multihash(s)) { // just a hash
		return `ipfs://${s}`;
	}
	let match;
	if (match = s.match(/^ipfs\:\/\/ipfs\/(.*)$/i)) { // fix "ipfs://ipfs/.."
		return `ipfs://${match[1]}`;
	}
	/*
	let match;
	if ((match = s.match(/\/ipfs\/([1-9a-zA-Z]{32,})(\/?.*)$/)) && is_multihash(match[1])) {
		s = `ipfs://${match[1]}${match[2]}`;
	}
	*/
	return s;
}
