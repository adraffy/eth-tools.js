# eth-tools.js
Compact set of ES6 tools for Ethereum dapps that work in the browser.

<!-- -->

* Demo: [ENS Resolver](https://adraffy.github.io/ens-normalize.js/test/resolver.html)
* Demo: [ENS Avatar &amp; Records](https://adraffy.github.io/eth-tools.js/examples/avatar.html)
* Dependancy: [@adraffy/keccak.js](https://github.com/adraffy/keccak.js)
* Recommended: [@adraffy/ens-normalize.js](https://github.com/adraffy/ens-normalize.js)

```Javascript
import * as tools from '@adraffy/eth-tools';
// browser:
// 'https://unpkg.com/@adraffy/eth-tools@latest/dist/eth-tools.min.js'
```

## Providers
```Javascript
import {FetchProvider, WebSocketProvider, retry} from '...';

let provider = new WebSocketProvider({url: 'ws://...', /*WebSocket*/}); 
// pass it a WebSocket implementation for nodejs

let provider = new FetchProvider({url: 'https://cloudflare-eth.com', /*fetch*/}); 
// pass it a fetch implementation for nodejs

// fix "header not found" bug
// works with any provider
let provider = retry(window.ethereum); 
```

## ENS
```Javascript
import {ENS} from '...';
let provider = ...; // see above
import {ens_normalize} from '@adraffy/ens-normalize.js'; // recommended
let ens = new ENS({provider, ens_normalize});

let name = await ens.resolve('bRAntly.eth');

console.log(await name.get_address());
// "0x983110309620D911731Ac0932219af06091b6744"
console.log(await name.get_primary());
// "brantly.eth"
console.log((await name.get_content()).hash);
console.log(await name.get_text('com.twitter'));
// {"com.twitter": "brantlymillegan"}
console.log(await name.get_addr(['BTC', 'XCH']));
// {"BTC": ..., "XCH": ...}
console.log(await ens.is_dot_eth_available('brantly'));
// false
console.log((await ens.resolve('0x983110309620D911731Ac0932219af06091b6744')).name);
// "brantly.eth"
```
## ABI
```Javascript
import {ABIEncoder, ABIDecoder, Uint256} from '...';

let enc = ABIEncoder.method('func(string,bytes32'); // or hashed signature
enc.string('hello');
enc.number(1234);
enc.number(Uint256.from_number(1234));
enc.addr('0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41');
console.log(enc.build());     // Uint8Array
console.log(enc.build_hex()); // hex-string (0x-prefixed)

let dec = ABIDecoder.from_hex(enc.build_hex());
dec.read_bytes(4); // skip signature
console.log(dec.string());  // read a string
console.log(dec.number());  // read u256 as number, throws if too big
console.log(dec.uint256()); // read u256
console.log(dec.addr());    // read 40-char hex-string (0x-prefixed w/checksum)
```

## Utils

```Javascript
import {checksum_address, is_valid_address, is_checksum_address} from '...';

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

```