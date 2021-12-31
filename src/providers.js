
// returns provider chain id
export async function chain_id_from_provider(provider) {
	return parseInt(await provider.request({method: 'eth_chainId'}));
}

// returns string regarding provider construction
export async function source_from_provider(provider) {
	let source = provider.source?.();
	if (source) return source;
	if (provider.isMetaMask) return 'MetaMask';
	return 'Unknown';
}

function parse_chain_id(x) {
	if (typeof x === 'string') x = parseInt(x);
	if (!Number.isSafeInteger(x)) throw new TypeError(`expected chain: ${x}`);
	return x;
}

export class Providers {
	static from_map(map) {
		if (typeof map !== 'object') throw new TypeError('expected object');
		let p = new Providers();
		for (let [k, v] of Object.entries(map)) {
			p.add_static(k, v);
		}
		return p;
	}
	constructor({cooldown = 30000} = {}) {
		this.queue = [];
		this.cooldown = cooldown;
	}
	add_static(chain_id, provider) {
		chain_id = parse_chain_id(chain_id);
		if (!this.queue.some(x => x.provider === provider)) {
			this.queue.push({chain_id, provider}); // low priority
		}
		return this; // chainable
	}
	add_dynamic(provider) {
		if (!this.queue.some(x => x.provider === provider)) {
			let rec = {provider, chain_id: null}; // unknown
			provider.on('connect', ({chainId}) => { 
				rec.chain_id = parseInt(chainId);
			});
			provider.on('chainChanged', chainId => {
				rec.chain_id = parseInt(chainId);
			});
			this.queue.unshift(rec); // high priority
		}
		return this; // chainable
	}
	disconnect() {
		for (let {provider} of this.queue) {
			provider.disconnect?.();
		}
	}
	async find_provider(chain_id, required = false, dynamic = true) {
		if (chain_id !== undefined && !Number.isSafeInteger(chain_id)) {
			throw new TypeError(`expected chain_id integer: ${chain_id}`);
		}
		if (dynamic) {
			await Promise.all(this.queue.filter(x => x.chain_id === null).map(async rec => {
				try {
					rec.chain_id = await chain_id_from_provider(rec.provider);
				} catch (err) {
					rec.chain_id = false;
					rec.cooldown = setTimeout(() => {
						rec.chainId = null;
					}, this.cooldown);
				}
			}));
		}
		let rec = this.queue.find(rec => rec.chain_id === chain_id);
		if (!rec && required) throw new Error(`No provider for chain ${chain_id}`);
		return rec?.provider;
	}
	view(chain_id) {
		chain_id = parse_chain_id(chain_id);
		let get_provider = async (...a) => {
			return this.find_provider(chain_id, ...a);
		};
		return new Proxy(this, {
			get: (target, prop) => {
				switch (prop) {
					case 'isProviderView': return true;
					case 'get_provider': return get_provider;
					default: return target[prop];
				}
			}
		});
	}
}

// detect-provider is way too useless to require as a dependancy 
// https://github.com/MetaMask/detect-provider/blob/main/src/index.ts
export async function determine_window_provider({fix = true, timeout = 5000} = {}) {
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
				ful(fix ? retry(e) : e);
				return true;
			}
		}
	});
}

// return true if the request() error is due to bug
// this seems to be an geth bug (infura, cloudflare, metamask)
// related to not knowing the chain id
export function is_header_bug(err) {
	return err.code === -32000 && err.message === 'header not found';
}

// fix the bug above
export function retry(provider, {retry = 2, delay = 1000} = {}) {
	if (typeof retry !== 'number' || retry < 1) throw new TypeError('expected retry > 0');
	if (typeof delay !== 'number' || delay < 0) throw new TypeError('expected delay >= 0');
	if (!provider) return;
	async function request(obj) {
		try {
			return await provider.request(obj);
		} catch (err) {
			if (!is_header_bug(err)) throw err;
			// make a new request that isn't dangerous
			// until we run out of tries or it succeeds
			let n = retry;
			while (true) {
				try {
					await provider.request({method: 'eth_chainId'});
					break;
				} catch (retry_err) {
					if (!is_header_bug(retry_err) && --n == 0) throw err;
				}
			}
			// then issue the request again
			return provider.request(obj);
		}
	}
	return new Proxy(provider, {
		get: function(obj, prop) {
			return prop === 'request' ? request : obj[prop];
		}
	});
}