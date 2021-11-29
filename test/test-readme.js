import {keccak, sha3} from '../eth-tools.js';

console.log(keccak().update('abc').hex);      // keccak-256 hash, hex-string, no prefix
console.log(sha3(384).update([1,2,3]).bytes); // sha-384, Uint8Array

// and a few utilities:
import {bytes_from_hex, bytes_from_str, hex_from_bytes, str_from_bytes} from '../eth-tools.js';

console.log(bytes_from_hex('0x01'));    // UintArray(1)[1]  (0x-prefix is optional)
console.log(bytes_from_str('abc'));     // UintArray(3)[97, 98, 99]
console.log(hex_from_bytes([1,2,3,4])); // "01020304" (no 0x-prefix)
console.log(str_from_bytes([97]));      // "A", throws if invalid utf8

//

import {ens_normalize} from '../eth-tools.js';

let normalized = ens_normalize('🚴‍♂️.eth'); // throws if error

//

import {ABIEncoder} from'../eth-tools.js';

let enc = ABIEncoder.method('func(string,bytes32'); // or hashed signature
enc.string('hello');
enc.number(1234);
enc.big(1152921504606846976n);
enc.addr('0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41');

console.log(enc.build());     // Uint8Array
console.log(enc.build_hex()); // hex-string (0x-prefixed)

//

import {ABIDecoder} from '../eth-tools.js';

let dec = ABIDecoder.from_hex(enc.build_hex());
dec.read(4); // skip signature
console.log(dec.string()); // read a string
console.log(dec.number()); // read u256 as number, throws if too big
console.log(dec.big());    // read u256 as BigInt
console.log(dec.addr());   // read 40-char hex-string (0x-prefixed w/checksum)

//

import {ens_address_from_name, ens_name_from_address, ens_avatar} from '../eth-tools.js';
import provider from './nodejs-provider.js'; 

 // normalize a name
 console.log(ens_normalize('niCK.eth')); 
 // returns "nick.eth"
 
 // resolve an unnormalized name
 console.log(await ens_address_from_name(provider, 'nIcK.eth')); // throws if error
 // returns {name, name0, namehash, resolver, address}
 
 // reverse an address to a name
 console.log(await ens_name_from_address(provider, '0xb8c2C29ee19D8307cb7255e1Cd9CbDE883A267d5')); // throws if error, 0x-prefix is optional
 // returns {address, namehash, resolver, name}
 
 // lookup an avatar by unnormalized name or address
 console.log(await ens_avatar(provider, 'niCk.eTh')); // throws if error
 // returns {type, name, address, avatar, contract, token, meta_uri, is_owner}
 // type can be: ['null, 'url', 'erc1155', 'erc721', 'unknown']

//

import {checksum_address} from '../eth-tools.js';

console.log(checksum_address('b8c2c29ee19d8307cb7255e1cd9cbde883a267d5')); 
// returns "0xb8c2C29ee19D8307cb7255e1Cd9CbDE883A267d5"
