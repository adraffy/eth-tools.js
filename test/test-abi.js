import {ABIEncoder, ABIDecoder} from '../abi.js';

let s = 'Hello 💩';
let a = '0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41';
let i = 1234;
let n = 1152921504606846976n;

let enc = new ABIEncoder();
enc.string(s);
enc.addr(a);
enc.number(i);
enc.big(n);
console.log(enc.build_hex());

function assert_equal(a, b) {
	if (a !== b) throw new Error(`wtf ${a} != ${b}`);
	return a;
}

let dec = ABIDecoder.from_hex(enc.build_hex());
console.log(assert_equal(s, dec.string()));
console.log(assert_equal(a, dec.addr()));
console.log(assert_equal(i, dec.number()));
console.log(assert_equal(n, dec.big()));

console.log(ABIEncoder.method('text(bytes32,string)').number(0).string('avatar').build_hex());

assert_equal(ABIDecoder.from_hex("e301").uvarint(), 227);