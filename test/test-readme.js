import {ENS} from '../index.js';
import {WS as provider} from './nodejs-provider.js';
//let provider = ...; // see above
import {ens_normalize} from '@adraffy/ens-normalize'; // recommended
let ens = new ENS({provider, ens_normalize});

let name = await ens.resolve('bRAntly.eth');

console.log(await name.get_address());
// "0x983110309620D911731Ac0932219af06091b6744"
console.log(await name.get_primary());
// "brantly.eth"
console.log((await name.get_content()).hash);
// UintArray(...)
console.log(await name.get_text('com.twitter'));
// {"com.twitter": "brantlymillegan"}
console.log(await name.get_addrs(['BTC', 'XCH']));
// {"BTC": ..., "XCH": ...}
console.log(await ens.is_dot_eth_available('brantly'));
// false
console.log((await ens.resolve('0x983110309620D911731Ac0932219af06091b6744')).name);
// "brantly.eth"

// 

import {ABIEncoder, Uint256} from '../index.js';

let enc = ABIEncoder.method('func(string,bytes32'); // or hashed signature
enc.string('hello');
enc.number(1234);
enc.number(Uint256.from_number(1234));
enc.addr('0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41');

console.log(enc.build());     // Uint8Array
console.log(enc.build_hex()); // hex-string (0x-prefixed)

//

import {ABIDecoder} from '../index.js';

let dec = ABIDecoder.from_hex(enc.build_hex());
dec.read_bytes(4); // skip signature
console.log(dec.string());  // read a string
console.log(dec.number());  // read u256 as number, throws if too big
console.log(dec.uint256()); // read u256
console.log(dec.addr());    // read 40-char hex-string (0x-prefixed w/checksum)

//

import {checksum_address, is_valid_address, is_checksum_address} from '../index.js';

let a = '0xb8c2c29ee19d8307cb7255e1cd9cbde883a267d5';
let b = checksum_address(a);
console.log(b); 
// "0xb8c2C29ee19D8307cb7255e1Cd9CbDE883A267d5"
console.log(a.toLowerCase() === b.toLowerCase());
// true
console.log([is_valid_address(a), is_checksum_address(b)]);
// [true, true]
console.log([is_checksum_address(a), is_checksum_address(b)]);
// [false, true]