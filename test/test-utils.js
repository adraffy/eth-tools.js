import {checksum_address} from '../utils.js';

let known = [
	['0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359', '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359']
];

for (let [input, address0] of known) {
	let address = checksum_address(input);
	if (address !== address0) {
		console.log({input, address, address0});
		throw new Error(`mismatch: ${input}`);
	}
}

console.log('OK');