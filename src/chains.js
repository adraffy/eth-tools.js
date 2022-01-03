
export function standardize_chain_id(x) {	
	let id;
	if (typeof x === 'string') {
		id = parseInt(x);
	} else if (typeof x === 'number') {
		id = x;
	}  
	if (!Number.isSafeInteger(id)) {
		throw new TypeError(`Invalid chain: ${x}`);
	}
	return `0x${id.toString(16)}`;
}

export class Chain {
	constructor(id) {
		this._id = id;
		this.data = undefined;
	}
	get id() {
		return this._id;
	}
	get name() {
		return this.data?.name ?? `Chain(${this.id})`;
	}
	explorer_address_uri(s) {
		return this.data?.explore_address.replace('{}', s);
	}
	explorer_tx_uri(s) {
		return this.data?.explore_tx.replace('{}', s);
	}
	toJSON() {
		return this.id;
	}
	toString() {
		return `Chain(${this.id})`;
	}
}

const CHAIN_CACHE = {};

export function find_chain(chain_like, required = false) {
	if (chain_like instanceof Chain) return chain_like;
	let chain_id = standardize_chain_id(chain_like);
	let chain = CHAIN_CACHE[chain_id];
	if (!chain && required) throw new Error(`Unknown chain: ${chain_id}`);
	return chain;
}

export function defined_chains() {
	return Object.values(CHAIN_CACHE);
}

// always returns a chain
export function ensure_chain(chain_like) {
	if (chain_like instanceof Chain) return chain_like;
	let chain_id = standardize_chain_id(chain_like);
	let chain = CHAIN_CACHE[chain_id];
	if (!chain) {
		chain = CHAIN_CACHE[chain_id] = new Chain(chain_id);
	}
	return chain;
}

function explore_uris(base) {
	return {
		explore_base: base,
		explore_address: `${base}/address/{}`,
		explore_tx: `${base}/tx/{}`,
	};
}

// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md

ensure_chain(1).data = {
	name: 'Mainnet', 
	...explore_uris('https://etherscan.io'),
	//public_rpcs: ['https://cloudflare-eth.com']
};

ensure_chain(3).data = {
	name: 'Ropsten', 
	...explore_uris('https://ropsten.etherscan.io'), 
	testnet: true
};

ensure_chain(4).data = {
	name: 'Rinkeby', 
	...explore_uris('https://rinkeby.etherscan.io'), 
	testnet: true
};

ensure_chain(5).data = {
	name: 'Goerli', 
	...explore_uris('https://goerli.etherscan.io'), 
	testnet: true
};

ensure_chain(43).data = {
	name: 'Kovan', 
	...explore_uris('https://kovan.etherscan.io'), 
	testnet: true
};

ensure_chain(137).data = {
	name: 'Matic',
	...explore_uris('https://polygonscan.com'),
	//public_rpcs: ['https://rpc-mainnet.matic.network']
};

ensure_chain(43114).data = {
	name: 'Avax C-chain',
	...explore_uris('https://snowtrace.io'),
	//public_rpcs: ['https://api.avax.network/ext/bc/C/rpc']
};
