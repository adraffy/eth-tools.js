import {checksum_address, is_checksum_address, is_null_hex} from '../utils.js';

let ADDRESSES = [
	'0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
	'0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e',
	'0xaB528d626EC275E3faD363fF1393A41F581c5897'
];

for (let a0 of ADDRESSES) {
	let a1 = checksum_address(a0.toLowerCase());
	if (a0 !== a1) {
		console.log({a0, a1});
		throw new Error(`wtf`);
	}
}

if (!is_null_hex('0x00000000000000000000000000000000')) throw new Error('wtf');
if (!is_null_hex('0x0')) throw new Error('wtf');
if (!is_null_hex('0')) throw new Error('wtf');

console.log('OK');

console.log(is_checksum_address('0x51050ec063d393217B436747617aD1C2285Aeeee'));