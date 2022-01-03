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

import {providers} from './nodejs-provider.js';

console.log(await (await providers.find_provider(1)).request({method: 'web3_clientVersion'}));
console.log(await (await providers.find_provider(137)).request({method: 'web3_clientVersion'}));

console.log(providers.view(1).chain);