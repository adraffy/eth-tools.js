import {Prefix0, RFC4648} from './base-coders.js';
import {Base58BTC} from './base58.js';

// the choice of bases in multibase spec are shit
// why are there strings that aren't valid bases???
// why isn't this just encoded as an integer???

/*
export const BASE64_JS = {
	bytes_from_str(s) {
		return Uint8Array.from(atob(s), x => x.charCodeAt(0));
	},
	str_from_bytes(v) {
		return btoa(String.fromCharCode(...v));
	}
};
*/

// https://www.rfc-editor.org/rfc/rfc4648.html#section-4 
const ALPHA = 'abcdefghijklmnopqrstuvwxyz';
const RADIX = '0123456789' + ALPHA;
export const Base64 = new RFC4648(ALPHA.toUpperCase() + ALPHA + RADIX.slice(0, 10) + '+=', 6);
// https://www.rfc-editor.org/rfc/rfc4648.html#section-5
export const Base64URL = new RFC4648(ALPHA.toUpperCase() + ALPHA + RADIX.slice(0, 10) + '-_', 6);
// https://tools.ietf.org/id/draft-msporny-base58-03.html 
export {Base58BTC};
// https://github.com/multiformats/multibase/blob/master/rfcs/Base36.md
export const Base36 = new Prefix0(RADIX);
// https://www.rfc-editor.org/rfc/rfc4648.html#section-7
export const Base32Hex = new RFC4648(RADIX.slice(0, 32), 5);
// https://www.rfc-editor.org/rfc/rfc4648.html#section-6
export const Base32 = new RFC4648('abcdefghijklmnopqrstuvwxyz234567', 5);
// https://www.rfc-editor.org/rfc/rfc4648.html#section-8
export const Base16 = new RFC4648(RADIX.slice(0, 16), 4);
// https://github.com/multiformats/multibase/blob/master/rfcs/Base10.md
export const Base10 = new Prefix0(RADIX.slice(0, 10)); 
// https://github.com/multiformats/multibase/blob/master/rfcs/Base8.md
export const Base8 = new RFC4648(RADIX.slice(0, 8), 3);
// https://github.com/multiformats/multibase/blob/master/rfcs/Base2.md
export const Base2 = new RFC4648(RADIX.slice(0, 2), 1);

function bind(base, ...a) {
	return {
		decode: s => base.bytes(s, ...a), // we already know it's a string
		encode: v => base.str_from_bytes(v, ...a)
	};
}

// https://github.com/multiformats/multibase#multibase-table  
const MULTIBASES = {
	'0': {...bind(Base2), name: 'base2'},
	'7': {...bind(Base8), name: 'base8'},
	'9': {...bind(Base10), name: 'base10'},
	'f': {...bind(Base16), case: false, name: 'base16'},
	'F': {...bind(Base16), case: true, name: 'base16upper'},
	'v': {...bind(Base32Hex), case: false, name: 'base32hex'},
	'V': {...bind(Base32Hex), case: true, name: 'base32hexupper'},
	't': {...bind(Base32Hex, true), case: false, name: 'base32hexpad'},
	'T': {...bind(Base32Hex, true), case: true, name: 'base32hexpadupper'},
	'b': {...bind(Base32), case: false,name: 'base32'},
	'B': {...bind(Base32), case: true, name: 'base32upper'},
	'c': {...bind(Base32, true), case: false,name: 'base32pad'},
	'C': {...bind(Base32, true), case: true, name: 'base32padupper'},
	// h
	'k': {...bind(Base36), case: false,name: 'base36'},
	'K': {...bind(Base36), case: true, name: 'base36upper'},
	'z': {...bind(Base58BTC), name: 'base58btc'},
	// ZBase58BTC
	'm': {...bind(Base64), name: 'base64'},
	'M': {...bind(Base64, true), name: 'base64pad'},
	'u': {...bind(Base64URL), name: 'base64url'},
	'U': {...bind(Base64URL, true), name: 'base64urlpad'},
	// p
	'1': {...bind(Base58BTC), name: 'base58btc-Identity'},
	'Q': {...bind(Base58BTC), name: 'base58btc-CIDv0'},
};
for (let [k, v] of Object.entries(MULTIBASES)) {
	v.prefix = k;
	MULTIBASES[v.name] = v;
}

export function decode_multibase(s, prefix) {
	if (typeof s !== 'string') throw new TypeError('expected string');
	if (!prefix) { 
		prefix = s[0];
		s = s.slice(1);
	}
	let mb = MULTIBASES[prefix];
	if (!mb) throw new Error(`Unknown multibase: ${prefix}`);	
	if (mb.case !== undefined) s = s.toLowerCase();
	return mb.decode(s);
}

export function encode_multibase(prefix, v, prefixed = true) {
	let mb = MULTIBASES[prefix];
	if (!mb) throw new Error(`Unknown multibase: ${prefix}`);
	let s = mb.encode(v);
	if (mb.case) s = s.toUpperCase();
	if (prefixed) s = mb.prefix + s; 
	return s;
}