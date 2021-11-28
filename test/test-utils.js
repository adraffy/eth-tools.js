import {bytes_from_str} from '@adraffy/keccak';
import {checksum_address, base58_from_bytes, is_null_hex} from '../utils.js';

let ADDRESSES = [
	['0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359', '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359']
];

for (let [input, address0] of ADDRESSES) {
	let address = checksum_address(input);
	if (address !== address0) {
		console.log({input, address, address0});
		throw new Error(`mismatch: ${input}`);
	}
}

if (!is_null_hex('0x00000000000000000000000000000000')) throw new Error('wtf');

let BASE_58 = [
	['Hello World!', '2NEpo7TZRRrLZSi2U'],
	['The quick brown fox jumps over the lazy dog.', 'USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z'],
];

for (let [input, output] of BASE_58) {
	if (base58_from_bytes(bytes_from_str(input)) !== output) {
		throw new Error('wtf');
	}
}


console.log('OK');