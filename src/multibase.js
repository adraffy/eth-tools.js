import {Prefix0, RFC4648} from './base-coders.js';

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
export const BASE64 = new RFC4648(ALPHA.toUpperCase() + ALPHA + RADIX.slice(0, 10) + '+=', 6);
// https://www.rfc-editor.org/rfc/rfc4648.html#section-5
export const BASE64_URL = new RFC4648(ALPHA.toUpperCase() + ALPHA + RADIX.slice(0, 10) + '-_', 6);
// https://tools.ietf.org/id/draft-msporny-base58-03.html 
export const BASE58_BTC = new Prefix0('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
// https://github.com/multiformats/multibase/blob/master/rfcs/Base36.md
export const BASE36 = new Prefix0(RADIX);
// https://www.rfc-editor.org/rfc/rfc4648.html#section-7
export const BASE32_HEX = new RFC4648(RADIX.slice(0, 32), 5);
// https://www.rfc-editor.org/rfc/rfc4648.html#section-6
export const BASE32 = new RFC4648('abcdefghijklmnopqrstuvwxyz234567', 5);
// https://www.rfc-editor.org/rfc/rfc4648.html#section-8
export const BASE16 = new RFC4648(RADIX.slice(0, 16), 4);
// https://github.com/multiformats/multibase/blob/master/rfcs/Base10.md
export const BASE10 = new Prefix0(RADIX.slice(0, 10)); 
// https://github.com/multiformats/multibase/blob/master/rfcs/Base8.md
export const BASE8 = new RFC4648(RADIX.slice(0, 8), 3);
// https://github.com/multiformats/multibase/blob/master/rfcs/Base2.md
export const BASE2 = new RFC4648(RADIX.slice(0, 2), 1);

function bind(base, ...a) {
	return {
		decode: s => base.bytes_from_str(s, ...a),
		encode: v => base.str_from_bytes(v, ...a)
	};
}

// https://github.com/multiformats/multibase#multibase-table  
const MULTIBASES = {
	'0': {...bind(BASE2), name: 'base2'},
	'7': {...bind(BASE8), name: 'base8'},
	'9': {...bind(BASE10), name: 'base10'},
	'f': {...bind(BASE16), case: false, name: 'base16'},
	'F': {...bind(BASE16), case: true, name: 'base16upper'},
	'v': {...bind(BASE32_HEX), case: false, name: 'base32hex'},
	'V': {...bind(BASE32_HEX), case: true, name: 'base32hexupper'},
	't': {...bind(BASE32_HEX, true), case: false, name: 'base32hexpad'},
	'T': {...bind(BASE32_HEX, true), case: true, name: 'base32hexpadupper'},
	'b': {...bind(BASE32), case: false,name: 'base32'},
	'B': {...bind(BASE32), case: true, name: 'base32upper'},
	'c': {...bind(BASE32, true), case: false,name: 'base32pad'},
	'C': {...bind(BASE32, true), case: true, name: 'base32padupper'},
	// h
	'k': {...bind(BASE36), case: false,name: 'base36'},
	'K': {...bind(BASE36), case: true, name: 'base36upper'},
	'z': {...bind(BASE58_BTC), name: 'base58btc'},
	// Z
	'm': {...bind(BASE64), name: 'base64'},
	'M': {...bind(BASE64, true), name: 'base64pad'},
	'u': {...bind(BASE64_URL), name: 'base64url'},
	'U': {...bind(BASE64_URL, true), name: 'base64urlpad'},
	// p
	'1': {...bind(BASE58_BTC), name: 'base58btc-Identity'},
	'Q': {...bind(BASE58_BTC), name: 'base58btc-CIDv0'},
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
	if (!mb) throw new Error(`Unknown multihash: ${prefix}`);	
	if (mb.case !== undefined) s = s.toLowerCase();
	return mb.decode(s);
}

export function encode_multibase(prefix, v, prefixed = true) {
	let mb = MULTIBASES[prefix];
	if (!mb) throw new Error(`Unknown multibase: ${prefix}`);
	let s = mb.encode(v);
	if (mb.upper) s = s.toUpperCase();
	if (prefixed) s = mb.prefix + s; 
	return s;
}