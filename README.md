# eth-provider.js
Tiny ES6 ABIDecoder, ABIEncoder, and Infura Ethereum WS Provider.

**This is under construction, DO NOT USE!**

### ABIDecoder
```Javascript
import {ABIDecoder} from '@adraffy/eth-provider';

let dec = ABIDecoder.from_hex('...')
let s = dec.string(); // read a string
let i = dec.number(); // read u256 as number, throws if too big
let n = dec.big();    // read u256 as BigInt
let a = dec.addr();   // read address (0x-prefixed hex-string w/checksum)
```

### ABIEncoder
```Javascript
import {ABIEncoder} from '@adraffy/eth-provider';

let enc = new ABIEncoder();
enc.string('hello');
enc.number(1234);
enc.big(1152921504606846976n);
enc.addr('0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41');

let v = enc.build();     // Uint8Array
let s = enc.build_hex(); // 0x-prefixed hex-string
```

### InfuraWSProvider

```Javascript
// TODO
```