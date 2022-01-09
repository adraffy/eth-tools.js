import {
	BASE58_BTC,
	bytes_from_utf8, 
	bytes_from_hex,
	hex_from_bytes
} from '../index.js';

let KNOWN = [
	[bytes_from_utf8('Hello World!'), '2NEpo7TZRRrLZSi2U'],
	[bytes_from_utf8('The quick brown fox jumps over the lazy dog.'), 'USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z'],
	[bytes_from_hex('0x0000287fb4cd'), '11233QC4']
];

for (let [input, expect] of KNOWN) {
	let result = BASE58_BTC.str_from_bytes(input);
	if (result !== expect) {
		console.log({result, expect})
		throw new Error('wtf');
	}
	let v = BASE58_BTC.bytes_from_str(expect);
	if (hex_from_bytes(v) !== hex_from_bytes(input)) {
		console.log([v, input]);
		throw new Error('wtf');
	}
}

console.log('OK');
