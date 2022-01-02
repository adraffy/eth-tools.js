import {bytes_from_base58} from './base58.js';
import {ABIDecoder} from './abi.js';

// https://github.com/multiformats/multihash
// sha1 = 0x11
// sha256 = 0x12

export function is_multihash(s) {
	// FIX: this is assuming base58
	// TODO: split this into a parser
	try {
		let dec = new ABIDecoder(bytes_from_base58(s));
		let type = dec.uvarint();
		let size = dec.uvarint();
		return dec.remaining === size;
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

// should this be here?
// replace ipfs:// with default https://ipfs.io
export function replace_ipfs_protocol(s) {
	return s.replace(/^ipfs:\/\//i, 'https://ipfs.io/ipfs/');
}