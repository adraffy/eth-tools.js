import {ABIEncoder, ABIDecoder, Uint256} from '../index.js';

let s = 'Hello 💩';
let a = '0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41';
let i = 1234;
let u = Uint256.from_hex('0x1234');
u = Uint256.from_bytes([1, 2]);

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