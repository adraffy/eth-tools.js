import {ens_avatar, lookup_address, ens_name_for_address} from'../eth-tools.js';
import provider from './nodejs-provider.js';

console.log(await ens_avatar(provider, 'bRAntly.eth'));
// {resolver, address, avatar, type, contract, token, ...}

console.log(await lookup_address(provider, 'bRAntly.eth'));
// "0x983110309620D911731Ac0932219af06091b6744"

console.log(await ens_name_for_address(provider, '0x983110309620D911731Ac0932219af06091b6744'));
// "brantly.eth"


//

import {ABIEncoder, Uint256} from'../eth-tools.js';

let enc = ABIEncoder.method('func(string,bytes32'); // or hashed signature
enc.string('hello');
enc.number(1234);
enc.number(Uint256.from_number(1234));
enc.addr('0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41');

console.log(enc.build());     // Uint8Array
console.log(enc.build_hex()); // hex-string (0x-prefixed)

//

import {ABIDecoder} from '../eth-tools.js';

let dec = ABIDecoder.from_hex(enc.build_hex());
dec.read(4); // skip signature
console.log(dec.string());  // read a string
console.log(dec.number());  // read u256 as number, throws if too big
console.log(dec.uint256()); // read u256
console.log(dec.addr());    // read 40-char hex-string (0x-prefixed w/checksum)

//

import {checksum_address} from '../eth-tools.js';

console.log(checksum_address('b8c2c29ee19d8307cb7255e1cd9cbde883a267d5')); 
// returns "0xb8c2C29ee19D8307cb7255e1Cd9CbDE883A267d5"
