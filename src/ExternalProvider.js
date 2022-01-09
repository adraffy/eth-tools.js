import {retry_request} from './retry.js';

// detect-provider is way too useless to require as a dependancy 
// https://github.com/MetaMask/detect-provider/blob/main/src/index.ts
export async function determine_window_provider({smart = true, timeout = 3000} = {}) {
	return new Promise((ful, rej) => {
		let timer, handler;
		const EVENT = 'ethereum#initialized';
		if (check()) return;
		timer = setTimeout(() => {
			globalThis?.removeEventListener(EVENT, handler);
			check() || rej(new Error(`No window.ethereum`));
		}, timeout|0);
		handler = () => {
			clearTimeout(timer);		
			globalThis?.removeEventListener(EVENT, handler);
			check() || rej(new Error('jebaited'));
		};
		globalThis?.addEventListener(EVENT, handler);
		function check() {
			let e = globalThis.ethereum;
			if (e) {
				ful(smart ? make_smart(e) : e);
				return true;
			}
		}
	});
}

export function make_smart(provider) {
	if (provider.isSmartProvider) return provider; // already smart!
	if (typeof provider.request !== 'function') throw new TypeError(`expected provider`);
	const source = provider.isMetaMask ? 'MetaMask' : 'Unknown Provider';
	let chain_id;
	provider.on('connect', ({chainId}) => { 
		chain_id = chainId;
	});
	provider.on('chainChanged', chainId => {
		chain_id = chainId; 
	});
	provider.on('disconnect', () => {
		chain_id = undefined;
	});
	async function request(obj) {
		if (obj.method === 'eth_chainId' && chain_id) {
			return chain_id; // fast
		}
		return retry_request(provider.request.bind(provider), obj);
	}
	async function req(method, ...params) {
		return request({method, params});
	}
	return new Proxy(provider, {
		get: function(obj, prop) {		
			switch (prop) {
				case 'req': return req;
				case 'request': return request;
				case 'chain_id': return chain_id;
				case 'source': return source;
				case 'isSmartProvider': return true;
				case 'disconnect': return obj[prop] ?? (() => {});
				default: return obj[prop];
			}	
		}
	});
}