/*
import {ENS} from '../index.js';
import {WS as provider} from './nodejs-provider.js';
import {ens_normalize} from '@adraffy/ens-normalize';

let ens = new ENS({provider, ens_normalize});

let name = await ens.resolve('NIck.eth');
console.log(await name.get());

//console.log(await ens.resolve('brantly.eth').then(x => x.get_addrs(['BTC'])));

console.log(await ens.resolve('poo'));

console.log(await ens.resolve('adrafFy.eth').then(x => x.get_display()));

provider.disconnect();
*/

import {ENS, keccak, is_multihash, Uint256} from '../index.js';
import {WS as provider} from './nodejs-provider.js';

let ens = new ENS({provider});

//console.log((await ens.get_dot_eth_owner('raffy')).address);

let name = await ens.resolve('raffy.eth');
console.log(name);

console.log(await name.get_addr(3));
console.log(await name.get_addr(60));
console.log(await name.get_address());
console.log(await name.get_owner());

console.log(await name.get_text('display'));
console.log(await name.get_texts(['com.twitter']));
console.log(await name.get_texts());

console.log(await ens.get_dot_eth_owner('raffy'));


console.log(is_multihash('QmRwgn6qNPwzdDJfpPuSeq2Qjodi6z3n5QmdKk82fUJb1Y'));