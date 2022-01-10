import {ens_addr_decode} from '../src/ens-addr.js';


console.log(ens_addr_decode('BTC', Uint8Array.from([
    0,  20, 144,  16,  88, 127,
  131, 100, 185, 100, 252, 170,
  112, 104, 114,  22, 181,  59,
  210, 203, 215, 152
])));