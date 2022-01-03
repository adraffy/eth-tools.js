import {find_chain, ensure_chain} from './chains.js';
import {make_smart} from './ExternalProvider.js';

// https://eips.ethereum.org/EIPS/eip-1193
// https://eips.ethereum.org/EIPS/eip-695 (eth_chainId)
// https://eips.ethereum.org/EIPS/eip-1474 (errors)

export class Providers {
	/*
	static wrap(provider) {
		if (provider instanceof this) return provider;
		let p = new this();
		p.add_dynamic(provider);
		return p;
	}
	static from_map(map) {
		if (typeof map !== 'object') throw new TypeError('expected object');
		let p = new Providers();
		for (let [k, v] of Object.entries(map)) {
			p.add_static(k, v);
		}
		return p;
	}
	*/
	constructor() {
		this.queue = [];
	}
	/*
	add_public(chain_like) {
		let chain = find_chain(chain_like);
		if (!chain) throw new Error(`Chain ${chain_like} is not defined`);
		let v = chain?.data.public_rpcs;
		if (!Array.isArray(v) || v.length == 0) throw new Error(`${chain} has no public RPCs`);
		return this.add_static(chain, v[Math.random() * v.length|0]);
	}*/
	add_static(chain_like, provider) {
		let chain = ensure_chain(chain_like);
		provider = make_smart(provider);
		if (!this.queue.some(x => x.provider === provider)) { // only add once
			this.queue.push({chain, provider}); // low priority
		}
		return this; // chainable
	}
	add_dynamic(provider) {
		provider = make_smart(provider);
		if (!this.queue.some(x => x.provider === provider)) { // only add once
			this.queue.unshift({provider}); // high priority
		}
		return this; // chainable
	}
	available_providers() {
		return this.queue.map(({chain, provider}) => {
			if (chain == undefined) {
				chain = find_chain(provider.chain_id);
			}
			if (chain) return [chain, provider];
		}).filter(x => x);
	}
	disconnect() {
		for (let {provider} of this.queue) {
			provider.disconnect?.();
		}
	}
	async find_provider(chain_like, required) {
		let chain = find_chain(chain_like, required);
		if (chain) {
			for (let {provider, chain: other} of this.queue) {
				if (other === undefined) {
					other = find_chain(await provider.request({method: 'eth_chainId'})); // this is fast
				}
				if (chain === other) {
					return provider;
				}
			}
		}
		if (required) {
			throw new Error(`No provider for chain ${chain}`);
		}
	}
	view(chain_like) {
		let chain = ensure_chain(chain_like);
		let get_provider = async required => {
			return this.find_provider(chain, required);
		};
		return new Proxy(this, {
			get: (target, prop) => {
				switch (prop) {
					case 'isProviderView': return true;
					case 'chain': return chain;
					case 'get_provider': return get_provider;
					default: return target[prop];
				}
			}
		});
	}
}
