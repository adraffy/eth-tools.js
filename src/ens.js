import {keccak} from '@adraffy/keccak';
import {ABIDecoder, ABIEncoder, Uint256} from './abi.js';
import {eth_call} from './eth.js';
import {checksum_address, is_null_hex, is_valid_address} from './utils.js';
import {base58_from_bytes} from './base58.js';
import {Providers} from './providers.js';
import ADDR_TYPES from './ens-address-types.js';

export {ADDR_TYPES}; // note: this is mutable

// accepts anything that keccak can digest
// returns Uint256
export function labelhash(label) {
	return new Uint256(keccak().update(label).bytes);
}

// expects a string
// warning: this does not normalize
// https://eips.ethereum.org/EIPS/eip-137#name-syntax
// returns Uint256
export function namehash(name) {
	if (typeof name !== 'string') throw new TypeError('expected string');
	let buf = new Uint8Array(64); 
	if (name.length > 0) {
		for (let label of name.split('.').reverse()) {
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
		this.eth = undefined;
	}
	normalize(name) {
		return this.ens_normalize?.(name) ?? name;
	}
	async get_provider() {
		let p = this.provider;
		return p.isProviderView ? p.get_provider() : p;
	}
	async get_resolver(node) {
		const SIG = '0178b8bf'; // resolver(bytes32)
		return (await eth_call(
			await this.get_provider(), 
			this.registry, 
			ABIEncoder.method(SIG).number(node)
		)).addr();
	}
	async resolve(input, {is_address, throws = false} = {}) {
		if (is_address === undefined) is_address = is_valid_address(input);
		let name = new ENSName(this, input, is_address);
		try {
			await name.resolve_input();
		} catch (err) {
			if (throws) throw err;
		}
		return name;
	}
	// warning: does not normalize!
	async is_dot_eth_available(label) {
		if (!this.eth) this.eth = await this.resolve('eth', {throws: true});
		const SIG = '96e494e8'; // available(uint256)
		return (await eth_call(
			await this.get_provider(), 
			await this.eth.get_address(), 
			ABIEncoder.method(SIG).number(labelhash(label))
		)).boolean();
	}
}

export class ENSName {
	constructor(ens, input, is_address) {
		this.ens = ens;
		this.input = input;
		this._is_address = is_address;
	}
	toJSON() {
		return this.name;
	}
	assert_input_error() {
		if (this._error) {
			// throw again on reuse
			throw new Error(this._error);
		}
	}
	assert_valid_resolver() {
		this.assert_input_error();
		if (!this.resolver) {
			throw new Error(`Null resolver`);
		}
	}
	async resolve_input() {
		this._error = undefined;
		this.name = undefined;
		this.node = undefined;
		this.primary = undefined;
		this.owner = undefined;
		this.address = undefined;
		this._display = undefined;
		this.avatar = undefined;
		this.pubkey = undefined;
		this.content = undefined;
		this.resolver = undefined;
		this.resolved = undefined;
		this.text = {};
		this.addr = {};
		if (this._is_address) {
			try {
				this.address = checksum_address(this.input);
			} catch (err) {
				throw new Error(this._error = `Invalid address: ${err.message}`);
			}
			let primary;
			try {
				primary = await this.get_primary();
			} catch (err) {
				this._error = err.message;
				throw err;
			}
			if (!primary) {
				throw new Error(this._error = `No name for ${this.input}`);
			}
			try {
				this.name = this.ens.normalize(primary);
			} catch (cause) {
				throw new Error(this._error = `Primary name is invalid: ${primary}`, {cause});
			} 
			// note: we cant save this primary since the names primary might be different
		} else {
			try {
				this.name = this.ens.normalize(this.input);
			} catch (cause) {
				throw new Error(this._error = `Input name is invalid: ${this.input}`, {cause});
			}
		}
		this.node = namehash(this.name);
		try {
			let resolver = await this.ens.get_resolver(this.node);
			if (!is_null_hex(resolver)) {
				this.resolver = resolver;
			}
		} catch (cause) {
			throw new Error(this._error = `Unable to determine resolver`, {cause});
		}
		this.resolved = new Date();
		return this;
	}
	async get_address() {
		if (this.address) return this.address;
		this.assert_valid_resolver();
		try {
			const SIG = '3b3b57de'; // addr(bytes32)
			return this.address = (await eth_call(
				await this.ens.get_provider(), 
				this.resolver, 
				ABIEncoder.method(SIG).number(this.node)
			)).addr();
		} catch (cause) {
			throw new Error(`Read address failed: ${cause.message}`, {cause});
		}
	}
	async get_owner() {
		if (this.owner) return this.owner;
		this.assert_input_error();
		try {
			const SIG = '02571be3'; // owner(bytes32)
			return this.owner = (await eth_call(
				await this.ens.get_provider(), 
				this.ens.registry, 
				ABIEncoder.method(SIG).number(this.node)
			)).addr();
		} catch (cause) {
			throw new Error(`Read owner failed: ${cause.message}`, {cause});
		}
	}
	async get_primary() {
		if (this.primary !== undefined) return this.primary;		
		this.assert_input_error();
		let address = await this.get_address(true);
		// https://eips.ethereum.org/EIPS/eip-181
		let rev_node = namehash(`${address.slice(2).toLowerCase()}.addr.reverse`); 
		let rev_resolver = await this.ens.get_resolver(rev_node);
		if (is_null_hex(rev_resolver)) {			
			this.primary = null; 
		} else {
			try {
				const SIG = '691f3431'; // name(bytes)
				this.primary = (await eth_call(
					await this.ens.get_provider(), 
					rev_resolver, 
					ABIEncoder.method(SIG).number(rev_node)
				)).string();
				// this could be empty string
			} catch (cause) {
				throw new Error(`Lookup primary failed: ${cause.message}`, {cause});
			}
		}
		return this.primary;
	}
	// returns input error
	get input_error() {
		return this._error;
	}
	is_input_address() {
		return this._is_address;
	}
	is_input_norm() {
		return !this._is_address && this.input === this.name;
	}
	validate_name(name) {
		this.assert_input_error();
		let norm;
		try {
			norm = this.ens.normalize(name);
		} catch (cause) {
			throw new Error(`${name} name is invalid: ${cause.message}`, {cause});
		}
		if (norm !== this.name) {
			throw new Error(`${name || '(empty-string)'} does not match ${this.name}`);
		}
		return name;
	}
	async is_input_display() {
		if (this._is_address) return false;
		let display;
		if (this.resolver) {
			display = await this.get_text('display');
		}
		try {
			if (!display) {
				// if display name is not set
				// display is the norm name
				return this.input === this.name; 
			}
			if (this.input === display) {
				// if display matches the input
				this.validate_name(display); 
				return true;
			}
		} catch (err) {
		}
		return false;
	}
	async get_display_name() {
		if (this._display) return this._display;
		let display = await this.get_text('display');
		let name = this.name; 
		try {
			name = this.validate_name(display);
		} catch (err) {
		}
		return this._display = name;
	}
	async get_avatar() {
		if (this.avatar) return this.avatar;
		return this.avatar = await parse_avatar(
			await this.get_text('avatar'), // throws
			this.ens.providers,
			await this.get_address()
		);
	}
	// https://eips.ethereum.org/EIPS/eip-634
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/TextResolver.sol
	//async get_text
	async get_text(key) { return this.get_texts([key]).then(x => x[key]); }
	async get_texts(keys, output) {
		if (!Array.isArray(keys)) throw new TypeError('expected array');
		this.assert_valid_resolver();
		let provider = await this.ens.get_provider();
		await Promise.all(keys.flatMap(key => (key in this.text) ? [] : (async () => {
			const SIG = '59d1d43c'; // text(bytes32,string)
			try {
				this.text[key] = (await eth_call(
					provider, 
					this.resolver, 
					ABIEncoder.method(SIG).number(this.node).string(key)
				)).string();
			} catch (cause) {
				delete this.text[key];
				throw new Error(`Error reading text ${key}: ${cause.message}`, {cause});
			}
		})()));
		if (!output) return this.text;
		for (let k of keys) output[k] = this.text[k];
		return output;
	}
	// https://eips.ethereum.org/EIPS/eip-2304
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/AddrResolver.sol
	async get_addr(addr) { return this.get_addrs([addr]).then(x => x[addr]); }
	async get_addrs(addrs, output, named = true) {
		if (!Array.isArray(addrs)) throw new TypeError('expected array');
		this.assert_valid_resolver();
		addrs = addrs.map(get_addr_type_from_input); // throws
		let provider = await this.ens.get_provider();
		await Promise.all(addrs.flatMap(([name, type]) => (name in this.addr) ? [] : (async () => {
			try {
				const SIG = 'f1cb7e06'; // addr(bytes32,uint256);
				let addr = (await eth_call(
					provider, 
					this.resolver, 
					ABIEncoder.method(SIG).number(this.node).number(type)
				)).memory();
				this.addr[type] = addr;
			} catch (cause) {
				delete this.addr[type];
				throw new Error(`Error reading addr ${name}: ${cause.message}`, {cause});
			}
		})()));
		if (output) {
			for (let [name, type] of addrs) {
				output[named ? name : type] = this.addr[type];
			}
			return output; // return subset by name
		} else if (named) {
			return Object.fromEntries(Object.entries(this.addr).map(([k, v]) => {
				let [name] = get_addr_type_from_input(parseInt(k));
				return [name, v];
			})); // return all by name
		} else {
			return this.addr; // return everything by id
		}
	}
	// https://github.com/ethereum/EIPs/pull/619
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/PubkeyResolver.sol
	async get_pubkey() {
		this.assert_valid_resolver();
		if (this.pubkey) return this.pubkey;
		if (is_null_hex(this.resolver)) return this.pubkey = {};		
		try {
			const SIG = 'c8690233'; // pubkey(bytes32)
			let dec = await eth_call(
				await this.ens.get_provider(),
				this.resolver, 
				ABIEncoder.method(SIG).number(this.node)
			);
			return this.pubkey = {x: dec.uint256(), y: dec.uint256()};
		} catch (cause) {
			throw new Error(`Error reading pubkey: ${cause.message}`, {cause});
		}
	}
	// https://eips.ethereum.org/EIPS/eip-1577
	// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/ContentHashResolver.sol
	async get_content() {
		this.assert_valid_resolver();
		if (this.content) return this.content;
		try {
			const SIG = 'bc1c58d1'; // contenthash(bytes32)
			let hash = (await eth_call(
				await this.ens.get_provider(),
				this.resolver, 
				ABIEncoder.method(SIG).number(this.node)
			)).memory();
			let content = {};			
			if (hash.length > 0) {
				content.hash = hash;
				// https://github.com/multiformats/multicodec
				let dec = new ABIDecoder(hash);
				if (dec.uvarint() == 0xE3) { // ipfs
					if (dec.read_byte() == 0x01 && dec.read_byte() == 0x70) { // check version and content-type
						content.url = `ipfs://${base58_from_bytes(dec.read_bytes(dec.remaining))}`;
					}
				}
			}
			return this.content = content;
		} catch (cause) {
			throw new Error(`Error reading content: ${cause.message}`, {cause});
		}
	}

}

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
		if (parts.length < 2) return {type: 'invalid', error: 'expected contract'};
		if (parts.length < 3) return {type: 'invalid', error: 'expected token'};
		let chain_id = parseInt(part0.slice(part0.indexOf(':') + 1));
		if (!(chain_id > 0)) return {type: 'invalid', error: 'expected chain id'};
		let part1 = parts[1];
		if (part1.startsWith('erc721:')) {
			// https://eips.ethereum.org/EIPS/eip-721
			let contract = part1.slice(part1.indexOf(':') + 1);
			if (!is_valid_address(contract)) return {type: 'invalid', error: 'expected contract address'};
			contract = checksum_address(contract);
			let token;
			try {
				token = Uint256.from_str(parts[2]);
			} catch (err) {
				return {type: 'invalid', error: 'expected uint256 token'};
			}
			let ret = {type: 'nft', interface: 'erc721', contract, token, chain_id};
			if (provider instanceof Providers) {
				provider = await provider?.find_provider(chain_id);
			}
			if (provider) {
				try {
					const SIG_tokenURI = 'c87b56dd'; // tokenURI(uint256)
					const SIG_ownerOf  = '6352211e'; // ownerOf(uint256)
					let [owner, meta_uri] = await Promise.all([
						eth_call(provider, contract, ABIEncoder.method(SIG_ownerOf).number(token)).then(x => x.addr()),
						eth_call(provider, contract, ABIEncoder.method(SIG_tokenURI).number(token)).then(x => x.string())
					]);
					ret.owner = owner;
					ret.meta_uri = meta_uri;
					if (address) {
						ret.owned = address.toUpperCase() === owner.toUpperCase() ? 1 : 0; // is_same_address?
					}
				} catch (err) {
					return {type: 'invalid', error: `invalid response from contract`};
				}
			}
			return ret;
		} else if (part1.startsWith('erc1155:')) {
			// https://eips.ethereum.org/EIPS/eip-1155
			let contract = part1.slice(part1.indexOf(':') + 1);
			if (!is_valid_address(contract)) return  {type: 'invalid', error: 'invalid contract address'};
			contract = checksum_address(contract);
			let token;
			try {
				token = Uint256.from_str(parts[2]);
			} catch (err) {
				return {type: 'invalid', error: 'expected uint256 token'};
			}
			let ret = {type: 'nft', interface: 'erc1155', contract, token, chain_id};
			if (provider instanceof Providers) {
				provider = await provider?.find_provider(chain_id);
			}
			if (provider) {
				try {
					const SIG_uri       = '0e89341c'; // uri(uint256)
					const SIG_balanceOf = '00fdd58e'; // balanceOf(address,uint256)
					let [balance, meta_uri] = await Promise.all([
						!address ? -1 : eth_call(provider, contract, ABIEncoder.method(SIG_balanceOf).addr(address).number(token)).then(x => x.number()),
						eth_call(provider, contract, ABIEncoder.method(SIG_uri).number(token)).then(x => x.string())
					]);
					// The string format of the substituted hexadecimal ID MUST be lowercase alphanumeric: [0-9a-f] with no 0x prefix.
					ret.meta_uri = meta_uri.replace('{id}', token.hex.slice(2)); 
					if (address) {
						ret.owned = balance;
					}
				} catch (err) {
					return {type: 'invalid', error: `invalid response from contract`};
				}
			}
			return ret;
		} else {
			return {type: 'invalid', error: `unsupported contract interface: ${part1}`};
		}		
	}
	return {type: 'unknown'};
}

function format_addr_type(i) {
	return '0x' + i.toString(16).padStart(4, '0');
}

// see: test/build-address-types.js
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
// returns [name:string, coinType: integer]
function get_addr_type_from_input(x) {
	if (typeof x === 'string') {
		let type = ADDR_TYPES[x];
		if (typeof type !== 'number') throw new Error(`Unknown address type for name: ${x}`);
		return [x, type];
	} else if (typeof x === 'number') {		
		let pos = Object.values(ADDR_TYPES).indexOf(x);
		let name;
		if (pos >= 0) {
			name = Object.keys(ADDR_TYPES)[pos];
		} else {
			name = format_addr_type(x);
		}
		return [name, x];
	} else {
		throw new TypeError('Expected address type or name');
	}
}
