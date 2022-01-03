import {WS as provider} from './nodejs-provider.js';

console.log(provider.source);

if (!provider.isSmartProvider) throw new Error('wtf');

provider.on('connect', ({chainId}) => {
	console.log(`connected: ${chainId}`);
});
provider.on('disconnect', err => {
	console.log(`disconnected: ${err}`);
});

console.log(await provider.request({method: 'eth_chainId'}));
provider.disconnect();
console.log(`Should be disconnected`);
console.log(await provider.request({method: 'eth_chainId'}));
console.log(`Should be reconnected`);

await provider.request({method: 'eth_subscribe', params: ['newHeads']}).then(sub => new Promise((ful, rej) => {
	console.log(`Subscribed: ${sub}`);
	let handler = (data) => {
		console.log(data);
		provider.removeListener('message', handler);
		provider.request({method: 'eth_unsubscribe', params: [sub]}).then(() => {
			console.log(`Unsubscribed: ${sub}`);
			ful()
		}).catch(rej);
	}
	provider.on('message', handler);
	console.log('waiting for head...');
}));
console.log('Should disconnect soon');

