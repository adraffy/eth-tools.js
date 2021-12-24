# eth-tools.js
Compact set of ES6 tools for Ethereum dapps that work in the browser.

* `dist/eth-tools.js` contains everything.
* `dist/eth-abi.js` contains everything except ENS support.

<!-- -->

* Demo: [ENS Resolver](https://adraffy.github.io/ens-normalize.js/test/resolver.html)
* Demo: [ENS Avatar &amp; Records](https://raffy.antistupid.com/eth/ens-records.html)
* Subproject: [@adraffy/keccak.js](https://github.com/adraffy/keccak.js)
* Subproject: [@adraffy/ens-normalize.js](https://github.com/adraffy/ens-normalize.js)

```Javascript
import * as tools from '@adraffy/eth-tools';
// browser:
//  all tools: 'https://unpkg.com/@adraffy/eth-tools@latest/dist/eth-tools.min.js'
//    w/o ENS: 'https://unpkg.com/@adraffy/eth-tools@latest/dist/eth-abi.min.js'
```

## Providers
```Javascript
import {FetchProvider, WebSocketProvider, retry};

let provider = new FetchProvider({url: 'https://cloudflare-eth.com', /*fetch*/}); 
// pass it a fetch() implementation for nodejs

let provider = new WebSocketProvider({url: 'ws://...'}, /*WebSocket*/); 
// pass it a WebSocket implementation for nodejs

// fix "header not found" bug
// works with any provider
let provider = retry(window.ethereum); 
```


## ENS
```Javascript
import {ens_avatar, lookup_address, ens_name_for_address};
let provider = ...; // see above

console.log(await ens_avatar(provider, 'bRAntly.eth'));
// {resolver, address, avatar, type, contract, token, ...}

console.log(await lookup_address(provider, 'bRAntly.eth'));
// "0x983110309620D911731Ac0932219af06091b6744"

console.log(await ens_name_for_address(provider, '0x983110309620D911731Ac0932219af06091b6744'));
// "brantly.eth"
```
## ABI
```Javascript
import {ABIEncoder, ABIDecoder, Uint256};

let enc = ABIEncoder.method('func(string,bytes32'); // or hashed signature
enc.string('hello');
enc.number(1234);
enc.number(Uint256.from_number(1234));
enc.addr('0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41');
console.log(enc.build());     // Uint8Array
console.log(enc.build_hex()); // hex-string (0x-prefixed)

let dec = ABIDecoder.from_hex(enc.build_hex());
dec.read(4); // skip signature
console.log(dec.string());  // read a string
console.log(dec.number());  // read u256 as number, throws if too big
console.log(dec.uint256()); // read u256
console.log(dec.addr());    // read 40-char hex-string (0x-prefixed w/checksum)
```

## Utils

```Javascript
import {checksum_address};

console.log(checksum_address('b8c2c29ee19d8307cb7255e1cd9cbde883a267d5')); 
// "0xb8c2C29ee19D8307cb7255e1Cd9CbDE883A267d5"
```