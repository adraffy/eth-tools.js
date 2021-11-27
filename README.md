# eth-provider.js
Tiny ES6 ABIDecoder, ABIEncoder, and Infura Ethereum WS Provider.

## ABIDecoder
```Javascript
import {ABIDecoder} from '@adraffy/eth-provider';

let dec = ABIDecoder.from_hex('...')
let s = dec.string(); // read a string
let i = dec.number(); // read u256 as number, throws if too big
let n = dec.bigint(); // read u256 as BigInt
let a = dec.addr();   // read address (0x-prefixed hex-string w/checksum)
```

## ABIEncoder
```Javascript
import {ABIDecoder} from '@adraffy/eth-provider';

let enc = new ABIDecoder();
enc.string('hello');
enc.number(1234);
enc.bigint(1152921504606846976n);
enc.addr('0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e');

let v = enc.build(); // Uint8Array
let s = enc.build_hex(); // 0x-prefixed hex-string
```