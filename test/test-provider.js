import provider from './nodejs-provider.js';
import {retry} from '../retry-provider.js';

console.log(await provider.request({method: 'web3_clientVersion'}));

let better = retry(provider);
console.log(await better.request({method: 'web3_clientVersion'}));
