import {FETCH as provider} from './nodejs-provider.js';

console.log(provider.source);

if (!provider.isSmartProvider) throw new Error('wtf');

provider.on('connect', ({chainId}) => {
	console.log(`connected: ${chainId}`);
});
provider.on('disconnect', err => {
	console.log(`disconnected: ${err}`);
});

console.log(await provider.request({method: 'eth_chainId'}));

console.log(await provider.request({method: 'web3_clientVersion'}));

provider.disconnect();

