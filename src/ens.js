import {hex_from_bytes, keccak} from '@adraffy/keccak';
import {ABIDecoder, ABIEncoder, Uint256, hex_from_method} from './abi.js';
import {eth_call, supports_interface} from './eth.js';
import {is_null_hex, promise_queue} from './utils.js';
import {standardize_address, is_valid_address, NULL_ADDRESS} from './address.js';
import {base58_from_bytes} from './base58.js';
import {Providers} from './providers.js';
import {standardize_chain_id} from './chains.js';
import ADDR_TYPES from './ens-address-types.js';

// accepts anything that keccak can digest
// returns Uint256
export function labelhash(label) {
	return new Uint256(keccak().update(label).bytes);
}

// a.b => [a, b]
export function labels_from_name(name) {
	return name.split('.');
}

// expects a string
// warning: this does not normalize
// https://eips.ethereum.org/EIPS/eip-137#name-syntax
// returns Uint256
export function namehash(name) {
	if (typeof name !== 'string') throw new TypeError('expected string');
	let buf = new Uint8Array(64); 
	if (name.length > 0) {
		for (let label of labels_from_name(name).reverse()) {
			buf.set(labelhash(label).bytes, 32);
			buf.set(keccak().update(buf).bytes, 0);
		}
	}
	return new Uint256(buf.slice(0, 32));
}

// https://docs.ens.domains/ens-deployments
const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';

export class ENS {
	constructor({provider, providers, ens_normalize, registry = ENS_REGISTRY}) {
		if (!provider) throw new Error(`expected provider`);
		this.provider = provider;
		if (provider.isProviderView) {
			this.providers = provider;
		} else {
			if (!providers) {
				let p = new Providers();
				p.add_dynamic(provider);
				this.providers = p;
			} else if (providers instanceof Providers) {
				this.providers = providers;
			} else {
				throw new Error(`invalid providers`);
			}
		}
		this.ens_normalize = ens_normalize;
		this.registry = registry;
		this.normalizer = undefined;
		this._dot_eth_contract = undefined;
		this._resolvers = {};
	}
	normalize(name) {
		return this.ens_normalize?.(name) ?? name;
	}
	labelhash(label) {
		if (typeof label === 'string') {
			return labelhash(this.normalize(label));
		} else if (label instanceof Uint256) {
			return label;
		} else {
			throw new TypeError(`expected string or Uint256`);
		}
	}
	owner(address) {
		try {
			return new ENSOwner(this, standardize_address(address));
		} catch (cause) {
			let err = new Error(`Invalid address ${address}: ${cause.message}`, {cause});
			err.isInvalid = true;
			err.address = address;
			throw err;
		}		
	}
	async get_provider() {
		let p = this.provider;
		return p.isProviderView ? p.get_provider() : p;
	}
	async call_registry(...args) {
		return eth_call(await this.get_provider(), this.registry, ...args);
	}
	async get_resolver(node) {
		return this.call_registry(ABIEncoder.method('resolver(bytes32)').number(node)).then(dec => {
			return dec.addr();
		}).then(address => {
			if (is_null_hex(address)) return; // no resolver
			let resolver = this._resolvers[address];
			if (!resolver) {
				resolver = this._resolvers[address] = new ENSResolver(this, address);
			}
			return resolver;
		});
	}
	async resolve(s) {
		let name;
		try {
			name = this.normalize(s);
		} catch (cause) {
			let err = new Error(`Name is invalid: ${cause.message}`, {cause});
			err.isInvalid = true;
			err.name = s;
			throw err;
		}
		let node = namehash(name);
		let resolver;
		try {
			resolver = await this.get_resolver(node);
		} catch (cause) {
			let err = new Error(`Unable to determine resolver: ${cause.message}`, {cause})
			err.input = s;
			err.name = name;
			err.node = node;
			throw err;
		}
		return new ENSName(this, s, name, node, resolver);
	}
	// https://eips.ethereum.org/EIPS/eip-181
	// warning: this does not normalize!
	async primary_from_address(address) {
		try {
			address = standardize_address(address, false);
		} catch (cause) {
			let err = new TypeError(`Invalid address ${address}: ${cause.message}`, {cause});
			err.input = address;
			throw err;
		}
		let rev_node = namehash(`${address.slice(2).toLowerCase()}.addr.reverse`); 
		let rev_resolver = await this.get_resolver(rev_node);
		if (!rev_resolver) return; // not set
		try {
			return (await eth_call(
				await this.get_provider(), 
				rev_resolver.address, 
				ABIEncoder.method('name(bytes32)').number(rev_node)
			)).string(); // this can be empty string
		} catch (cause) {
			throw new Error(`Read primary failed: ${cause.message}`, {cause});
		}
	}
	async get_eth_contract() {
		let temp = this._dot_eth_contract;
		if (typeof temp === 'string') return temp;
		if (!temp) {
			temp = this._dot_eth_contract = promise_queue(
				this.resolve('eth').then(name => name.get_owner()).then(x => x.address),
				address => this._dot_eth_contract = address
			);
		}
		return temp();
	}
	async is_dot_eth_available(label) {
		return (await eth_call(
			await this.get_provider(), 
			await this.get_eth_contract(),
			ABIEncoder.method('available(uint256)').number(this.labelhash(label))
		)).boolean();
	}
	async get_dot_eth_owner(label) {
		try {
			return this.owner((await eth_call(
				await this.get_provider(), 
				await this.get_eth_contract(),
				ABIEncoder.method('ownerOf(uint256)').number(this.labelhash(label))
			)).addr());
		} catch (err) {
			if (err.reverted) return; // available?
			throw err;
		}
	}
}

export class ENSResolver {
	constructor(ens, address) {
		this.ens = ens;
		this.address = address;
		//
		this._interfaces = {};
	}
	async supports_interface(method) {
		let key = hex_from_method(method);
		let temp = this._interfaces[key];
		if (typeof temp === 'boolean') return temp;
		if (!temp) {
			temp = this._interfaces = promise_queue(
				supports_interface(await this.ens.get_provider(), this.address, method),
				b => this._interfaces[key] = b
			);
		}
		return temp();
	}
	toJSON() {
		return this.address;
	}
}

export class ENSOwner {
	constructor(ens, address) {
		this.ens = ens;
		this.address = address;
		//
		this._primary = undefined;
	}
	toJSON() {
		return this.address;
	}
	async get_primary_name() {
		let temp = this._primary;
		if (typeof temp === 'string' || temp === null) return temp;
		if (!temp) {
			temp = this._primary = promise_queue(
				this.ens.primary_from_address(this.address),
				address => this._primary = address
			);
		}
		return temp();
	}
	async resolve() {
		let name = await this.get_primary_name();
		if (name === null) throw new Error(`No name for address: ${address}`);
		if (!name) throw new Error(`Primary not set for address: ${address}`);
		return this.ens.resolve(name);
	}
}

export class ENSName {
	constructor(ens, input, name, node, resolver) {
		this.ens = ens;
		this.input = input;
		this.name = name;
		this.node = node;
		this.resolver = resolver; // could be undefined
		this.resolved = new Date();
		//
		this._owner = undefined;
		this._address = undefined;
		this._display = undefined;
		this._avatar = undefined;
		this._pubkey = undefined;
		this._content = undefined;
		this._text = {};
		this._addr = {};
	}
	get labels() {
		return labels_from_name(this);
	}
	toJSON() {
		return this.name;
	}
	assert_valid_resolver() {
		if (!this.resolver) {
			throw new Error(`No resolver`);
		}
	}
	async call_resolver(...args) {
		this.assert_valid_resolver();
		return eth_call(await this.ens.get_provider(), this.resolver.address, ...args);
	}
	async get_address() {
		let temp = this._address;
		if (typeof temp === 'string') return temp;
		if (!temp) {
			this.assert_valid_resolver();
			// https://eips.ethereum.org/EIPS/eip-2304	
			const METHOD = 'addr(bytes32,uint256)';
			const METHOD_OLD = 'addr(bytes32)';
			let p;
			if (await this.resolver.supports_interface(METHOD)) {
				p = this.get_addr(60);
			} else if (await this.resolver.supports_interface(METHOD_OLD)) {
				p = this.call_resolver(ABIEncoder.method(METHOD_OLD).number(this.node)).then(dec => {
					return dec.read_addr_bytes(); 
				});
			} else {
				throw new Error(`Resolver does not support addr`);
			}
			temp = this._address = promise_queue(p.then(v => {
				if (v.length == 0) return NULL_ADDRESS;
				if (v.length != 20) throw new Error(`Invalid ETH Address: expected 20 bytes`);
				return standardize_address(hex_from_bytes(v));
			}), s => this._address = s);
		}
		return temp();
	}
	async get_owner() {
		let temp = this._owner;
		if (temp instanceof ENSOwner) return temp;
		if (!temp) {
			temp = this._owner = promise_queue(
				this.ens.call_registry(ABIEncoder.method('owner(bytes32)').number(this.node)).then(dec => {
					return new ENSOwner(this.ens, dec.addr());
				}).catch(cause => {
					throw new Error(`Read owner failed: ${cause.message}`, {cause});
				}),
				owner => this._owner = owner
			);
		}
		return temp();
	}
	async get_owner_address() { return (await this.get_owner()).address; }
	async get_owner_primary_name() { return (await this.get_owner()).get_primary_name(); }	
	async is_owner_primary_name() {
		// this is not an exact match
		return this.is_equivalent_name(await this.get_owner_primary_name());
	}
	is_input_normalized() {
		return this.input === this.name;
	}
	is_equivalent_name(name) {
		try {
			this.assert_equivalent_name(name);
			return true;
		} catch (err) {
			return false;
		}
	}
	assert_equivalent_name(name) {
		if (name === this.name) return;
		if (!name) throw new Error(`Name is empty`);
		let norm;
		try {
			norm = this.ens.normalize(name);
		} catch (cause) {
			throw new Error(`Name "${name}" is invalid: ${cause.message}`, {cause});
		}
		if (norm !== this.name) {
			throw new Error(`${name} does not match ${this.name}`);
		}
	}
	async is_input_display() {
		let display;
		if (this.resolver) {
			display = await this.get_text('display');
		}
		if (!display) {
			// if display name is not set
			// display is the norm name
			return this.input === this.name; 
		}
		return this.input === display && this.is_equivalent_name(display);
	}
	// this uses norm name if display name isn't set or invalid
	async get_display_name() {
		if (this._display) return this._display;
		let display = await this.get_text('display');
		return this._display = this.is_equivalent_name(display) ? display : this.name;
	}
	async get_avatar() {
		if (this._avatar) return this._avatar;
		return this._avatar = await parse_avatar(
			await this.get_text('avatar'), // throws
			this.ens.providers,
			await this.get_address()
		);
	}
	// https://eips.ethereum.org/EIPS/eip-634
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/TextResolver.sol
	async get_text(key) { 
		if (typeof key !== 'string') throw new TypeError(`expected string`);
		let temp = this._text[key];
		if (typeof temp === 'string') return temp;
		if (!temp) {
			this.assert_valid_resolver();
			// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-634.md
			const METHOD = 'text(bytes32,string)';
			if (!await this.resolver.supports_interface(METHOD)) {
				throw new Error(`Resolver does not support text`);
			}
			temp = this._text[key] = promise_queue(
				this.call_resolver(ABIEncoder.method(METHOD).number(this.node).string(key)).then(x => {
					return x.string();
				}).catch(cause => {
					throw new Error(`Error reading text ${key}: ${cause.message}`, {cause});
				}),
				s => {
					if (typeof s === 'string') {
						this._text[key] = s;
					} else {
						delete this._text[key];
					}
				}
			);
		}
		return temp();
	}
	async get_texts(keys) {
		if (keys === undefined) {
			keys = Object.keys(this._text); // all known keys
		} else if (!Array.isArray(keys)) {
			throw new TypeError('expected array');
		}
		let values = await Promise.all(keys.map(key => this.get_text(key)));
		return Object.fromEntries(keys.map((key, i) => [key, values[i]]));
	}
	// https://eips.ethereum.org/EIPS/eip-2304
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/AddrResolver.sol
	// addrs are stored by type
	async get_addr(addr) { 
		let type = parse_addr_type(addr);
		let temp = this._addr[type];
		if (temp instanceof Uint8Array) return temp;
		if (!temp) {
			this.assert_valid_resolver();
			const METHOD = 'addr(bytes32,uint256)';
			if (!await this.resolver.supports_interface(METHOD)) {
				throw new Error(`Resolver does not support text`);
			}
			temp = this._addr[type] = promise_queue(
				this.call_resolver(ABIEncoder.method(METHOD).number(this.node).number(type)).then(dec => {
					return dec.memory();
				}).catch(cause => {
					throw new Error(`Error reading addr ${format_addr_type(type, true)}: ${cause.message}`, {cause});
				}),
				v => {
					if (v instanceof Uint8Array) {
						this._addr[type] = v;
					} else {
						delete this._addr[type];
					}
				}
			);
		}
		return temp();
	}
	async get_addrs(addrs, named = true) {
		let types;
		if (addrs === undefined) {
			types = Object.keys(this._addr); // all known addrs
		} else if (Array.isArray(addrs)) {
			types = addrs.map(parse_addr_type); // throws
		} else {
			throw new TypeError('expected array');
		} 
		let values = await Promise.all(types.map(type => this.get_addr(type)));
		return Object.fromEntries(types.map((type, i) => [named ? format_addr_type(type) : type, values[i]]));
	}
	// https://github.com/ethereum/EIPs/pull/619
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/PubkeyResolver.sol
	async get_pubkey() {
		let temp = this._pubkey;
		if (typeof temp === 'object') return temp;
		if (!temp) {
			this.assert_valid_resolver();
			temp = this._pubkey = promise_queue(
				this.call_resolver(ABIEncoder.method('pubkey(bytes32)').number(this.node)).then(dec => {
					return {x: dec.uint256(), y: dec.uint256()};
				}).catch(cause => {
					throw new Error(`Error reading pubkey: ${cause.message}`, {cause});
				}),
				pubkey => this._pubkey = pubkey
			);
		}
		return temp();
	}
	// https://eips.ethereum.org/EIPS/eip-1577
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/ContentHashResolver.sol
	async get_content() {
		let temp = this._content;
		if (typeof temp === 'object') return temp;
		if (!temp) {
			this.assert_valid_resolver();
			temp = this._content = promise_queue(
				this.call_resolver(ABIEncoder.method('contenthash(bytes32)').number(this.node)).then(dec => {
					return dec.memory();
				}).then(hash => {
					let content = {};
					if (hash.length > 0) {
						content.hash = hash;
						try {
							// https://github.com/multiformats/multicodec
							let dec = new ABIDecoder(hash);
							let protocol = dec.uvarint();
							let cid_version = dec.uvarint();
							let content_type = dec.uvarint();
							// TODO: this needs fixed
							// either remove or use CID dependancy
							if (protocol == 0xE3 && cid_version == 0x1 && content_type == 0x70) {
								content.url = `ipfs://${base58_from_bytes(dec.read_bytes(dec.remaining))}`;
							}
						} catch (ignored) {							
						}
					}
					return content;
				}).catch(cause => {
					throw new Error(`Error reading content: ${cause.message}`, {cause});
				}),
				content => this._content = content
			);
		}
		return temp();
	}
}

const AVATAR_TYPE_INVALID = 'invalid';

// https://medium.com/the-ethereum-name-service/step-by-step-guide-to-setting-an-nft-as-your-ens-profile-avatar-3562d39567fc
// https://medium.com/the-ethereum-name-service/major-refresh-of-nft-images-metadata-for-ens-names-963090b21b23
// https://github.com/ensdomains/ens-metadata-service
// note: the argument order here is non-traditional
export async function parse_avatar(avatar, provider, address) {
	if (typeof avatar !== 'string') throw new Error('Invalid avatar: expected string');
	if (avatar.length == 0) return {type: 'null'}; 
	if (avatar.includes('://') || avatar.startsWith('data:')) return {type: 'url', url: avatar};
	let parts = avatar.split('/');
	let part0 = parts[0];
	if (part0.startsWith('eip155:')) { // nft format  
		if (parts.length < 2) return {type: AVATAR_TYPE_INVALID, error: 'expected contract'};
		if (parts.length < 3) return {type: AVATAR_TYPE_INVALID, error: 'expected token'};
		let chain_id;
		try {
			chain_id = standardize_chain_id(part0.slice(part0.indexOf(':') + 1));
		} catch (err) {
			return {type: AVATAR_TYPE_INVALID, error: err.message};
		}
		let part1 = parts[1];
		if (part1.startsWith('erc721:')) {
			// https://eips.ethereum.org/EIPS/eip-721
			let contract = part1.slice(part1.indexOf(':') + 1);
			try {
				contract = standardize_address(contract);
			} catch (err) {
				return {type: AVATAR_TYPE_INVALID, error: `Invalid contract address: ${err.message}`};
			}
			let token;
			try {
				token = Uint256.from_str(parts[2]);
			} catch (err) {
				return {type: AVATAR_TYPE_INVALID, error: `Invalid token: ${err.message}`};
			}
			let ret = {type: 'nft', interface: 'erc721', contract, token, chain_id};
			if (provider instanceof Providers) {
				provider = await provider?.find_provider(chain_id);
			}
			if (provider) {
				try {
					let [owner, meta_uri] = await Promise.all([
						eth_call(provider, contract, ABIEncoder.method('ownerOf(uint256)').number(token)).then(x => x.addr()),
						eth_call(provider, contract, ABIEncoder.method('tokenURI(uint256)').number(token)).then(x => x.string())
					]);
					ret.owner = owner;
					ret.meta_uri = meta_uri;
					if (typeof address === 'string') {
						ret.owned = address.toUpperCase() === owner.toUpperCase() ? 1 : 0; // is_same_address?
					}
				} catch (err) {
					return {type: AVATAR_TYPE_INVALID, error: `invalid response from contract`};
				}
			}
			return ret;
		} else if (part1.startsWith('erc1155:')) {
			// https://eips.ethereum.org/EIPS/eip-1155
			let contract = part1.slice(part1.indexOf(':') + 1);
			try {
				contract = standardize_address(contract);
			} catch (err) {
				return {type: AVATAR_TYPE_INVALID, error: `Invalid contract address: ${err.message}`};
			}
			let token;
			try {
				token = Uint256.from_str(parts[2]);
			} catch (err) {
				return {type: AVATAR_TYPE_INVALID, error: `Invalid token: ${err.message}`};
			}
			let ret = {type: 'nft', interface: 'erc1155', contract, token, chain_id};
			if (provider instanceof Providers) {
				provider = await provider?.find_provider(chain_id);
			}
			if (provider) {
				try {
					let [balance, meta_uri] = await Promise.all([
						is_valid_address(address) 
							? eth_call(provider, contract, ABIEncoder.method('balanceOf(address,uint256)').addr(address).number(token)).then(x => x.number())
							: -1,
						eth_call(provider, contract, ABIEncoder.method('uri(uint256)').number(token)).then(x => x.string())
					]);
					// The string format of the substituted hexadecimal ID MUST be lowercase alphanumeric: [0-9a-f] with no 0x prefix.
					ret.meta_uri = meta_uri.replace('{id}', token.hex.slice(2)); 
					if (balance >= 0) {
						ret.owned = balance;
					}
				} catch (err) {
					return {type: AVATAR_TYPE_INVALID, error: `invalid response from contract`};
				}
			}
			return ret;
		} else {
			return {type: AVATAR_TYPE_INVALID, error: `unsupported contract interface: ${part1}`};
		}		
	}
	return {type: 'unknown'};
}

export {ADDR_TYPES}; // mutable?

export function format_addr_type(type, include_type = false) {
	let pos = Object.values(ADDR_TYPES).indexOf(type);
	let name;
	if (pos >= 0) { // the type has a name
		let s = Object.keys(ADDR_TYPES)[pos];
		if (include_type) s = `${s}<${type}>`;
		return s;
	} else { // the type doesn't have an known name
		return '0x' + x.toString(16).padStart(4, '0');
	}
}

// see: test/build-address-types.js
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
export function parse_addr_type(x) {
	if (typeof x === 'string') {
		let type = ADDR_TYPES[x];
		if (typeof type !== 'number') throw new Error(`Unknown address type for name: ${x}`);
		return type;
	} else if (Number.isSafeInteger(x)) {		
		return x;
	} else {
		throw new TypeError(`Invalid address type: ${x}`);
	}
}