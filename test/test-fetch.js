import {FETCH as provider} from './nodejs-provider.js';
import {chain_id_from_provider} from '../index.js';

console.log(provider.source());

provider.on('connect', (chainId) => {
	console.log(`connected: ${chainId}`);
});
provider.on('disconnect', err => {
	console.log(`disconnected: ${err}`);
});

console.log(await chain_id_from_provider(provider));

console.log(await provider.request({method: 'web3_clientVersion'}));

provider.disconnect();

