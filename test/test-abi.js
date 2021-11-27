import {ABIEncoder, ABIDecoder} from '../abi.js';

let enc = new ABIEncoder();
enc.string('hello');
enc.addr('0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41');
enc.number(3);
console.log(enc.hex_encoded);

let dec = ABIDecoder.from_hex(enc.hex_encoded);
console.log(dec.string());
console.log(dec.addr());
console.log(dec.number());