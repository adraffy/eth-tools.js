import {
	base58_from_bytes, bytes_from_base58, 
	bytes_from_utf8, 
	bytes_from_hex, hex_from_bytes
} from '../index.js';

let KNOWN = [
	[bytes_from_utf8('Hello World!'), '2NEpo7TZRRrLZSi2U'],
	[bytes_from_utf8('The quick brown fox jumps over the lazy dog.'), 'USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z'],
	[bytes_from_hex('0x0000287fb4cd'), '11233QC4']
];

for (let [input, output] of KNOWN) {
	if (base58_from_bytes(input) !== output) {
		throw new Error('wtf');
	}
	if (hex_from_bytes(bytes_from_base58(output)) !== hex_from_bytes(input)) {
		console.log([bytes_from_base58(output), input]);
		throw new Error('wtf');
	}
}
