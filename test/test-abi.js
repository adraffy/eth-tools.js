import {hex_from_bytes} from '@adraffy/keccak';
import {ABIEncoder, ABIDecoder, Uint256, parse_bytes_from_digits, left_truncate_bytes} from '../abi.js';
import {compare_arrays} from '../utils.js';
import {random_bytes} from './utils.js';

let s = 'Hello 💩';
let a = '0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41';
let i = 1234;
let u = Uint256.from_hex('0x1234');

let enc = new ABIEncoder();
enc.string(s);
enc.addr(a);
enc.number(i);
enc.number(u);
console.log(enc.build_hex());

let dec = ABIDecoder.from_hex(enc.build_hex());
if (s !== dec.string()) throw new Error('wtf');
if (a !== dec.addr()) throw new Error('wtf');
if (i !== dec.number()) throw new Error('wtf');
if (u.compare(dec.uint256()) != 0) throw new Error('wtf');

console.log(ABIEncoder.method('text(bytes32,string)').number(0).string('avatar').build_hex());

if (ABIDecoder.from_hex('E301').uvarint() !== 227) throw new Error('wtf');

for (let i = 0; i < 1000; i++) {
	let v0 = random_bytes(6);
	let hex = '0x' + hex_from_bytes(v0);
	let dec = parseInt(hex).toString();
	let v1 = left_truncate_bytes(parse_bytes_from_digits(dec), v0.length);
	let v2 = left_truncate_bytes(parse_bytes_from_digits(hex), v0.length);
	if (compare_arrays(v0, v1) != 0) throw new Error('wtf parse dec');
	if (compare_arrays(v0, v2) != 0) throw new Error('wtf parse hex');
}

for (let i = 0; i < 10000; i++) {
	let u0 = Uint256.from_bytes(random_bytes(Math.random() * 32|0));	
	let u1 = Uint256.from_hex(u0.hex);
	let u2 = Uint256.from_dec(u1.dec);
	if (u0.compare(u2) != 0) {
		console.log({u0, u1, u2});
		throw new Error('wtf');
	}
}

for (let i = 0; i < 10000; i++) {
	let n0 = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);
	u.set_number(n0);
	let n1 = u.number;
	if (n0 != n1) {
		console.log({i, n0, n1, u});
		throw new Error('wtf');
	}
}