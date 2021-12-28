import {keccak, hex_from_bytes} from '@adraffy/keccak';
import {eth_call, ABIDecoder, ABIEncoder, Uint256} from './abi.js';
import {is_null_hex, is_valid_address} from './utils.js';
import {base58_from_bytes} from './base58.js';
import ADDR_TYPES from './ens-address-types.js';

export {ADDR_TYPES}; // note: this is mutable

let dot_eth;

// set the normalizer transformation
// default is passthru
let normalizer;
export function set_normalizer(fn) {
	normalizer = fn;
}

// accepts anything that keccak can digest
// returns Uint256
export function labelhash(label) {
	return new Uint256(keccak().update(label).bytes);
}

// expects a string
// warning: this does not normalize
// https://eips.ethereum.org/EIPS/eip-137#name-syntax
// returns Uint256
export function node_from_ens_name(name) {
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
const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'; // ens registry contract on mainnet
const RESOLVED = Symbol('ENSResolved');

// turn a name/address/object into {node, resolver, ...}
// ens_resolve(node)
// ens_resolve({node})
// ens_resolve({name})
// ens_resolve(name)
// ens_resolve(address)
export async function ens_resolve(provider, input) {
	if (input instanceof Uint256) { // node
		return {
			resolver: await call_registry_resolver(provider, input),
			[RESOLVED]: new Date(),
			node: input
		};
	}
	if (typeof input === 'object') { // previously resolved object? 
		if (RESOLVED in input) { // trusted
			return input; 
		} else if (input.node instanceof Uint256) { // use the provided node
			return ens_resolve(provider, input.node);
		} else if (typeof input.name === 'string') { // use the provided name as-is
			let {name} = input;
			let ret = await ens_resolve(provider, node_from_ens_name(name));
			ret.name = name; // keep the name
			return ret;
		} else {
			input = input.address; // fall through
		}
	}
	if (typeof input === 'string') { // unnormalized-name or address
		input = input.trim();
		if (input.length > 0) {
			if (is_valid_address(input)) {
				input = await ens_name_for_address(provider, input);
				if (!input) throw new Error(`No primary for address`);
				// we cant remember this address because
				// the primary can be set to any name
			}
			if (normalizer) input = normalizer(input);
			return ens_resolve(provider, {name: input});
		}
	}
	throw new TypeError('Expected name or address');
}

// this lookups up an address for name
// it also stores the result into the record
// returns checksummed-address as string
export async function lookup_address(provider, input) {
	let ret = await ens_resolve(provider, input);
	let {resolver, node, address} = ret;
	if (is_null_hex(resolver)) return; // no resolver
	if (address) return address; // already looked up
	const SIG = '3b3b57de'; // addr(bytes32)
	// this effectively is the same thing as:
	// call_resolver_addr_for_type(node, 60
	return ret.address = (await eth_call(provider, resolver, ABIEncoder.method(SIG).number(node))).addr();
}

export async function lookup_owner(provider, input) {
	let ret = await ens_resolve(provider, input);
	let {node, owner} = ret;
	if (owner) return owner; // already looked up
	const SIG = '02571be3'; // owner(bytes32)
	return ret.owner = (await eth_call(provider, ENS_REGISTRY, ABIEncoder.method(SIG).number(node))).addr();
}

// warning: this does not normalize
// returns boolean
export async function is_dot_eth_available(provider, label) {
	if (!dot_eth || (Date.now() - dot_eth[RESOLVED] > 3600000)) { // 1 hour
		dot_eth = await ens_resolve(provider, {name: 'eth'});
		await lookup_address(provider, dot_eth);
		console.log(dot_eth);
	}
	const SIG = '96e494e8'; // available(uint256)
	return (await eth_call(provider, dot_eth.address, ABIEncoder.method(SIG).number(labelhash(label)))).boolean();
}

// https://eips.ethereum.org/EIPS/eip-181
// warning: this doesn't have to be normalized
// returns string
export async function ens_name_for_address(provider, address) {
	let rev_node = node_from_ens_name(`${address.slice(2).toLowerCase()}.addr.reverse`); 
	let rev_resolver = await call_registry_resolver(provider, rev_node);
	if (is_null_hex(rev_resolver)) return;
	const SIG = '691f3431'; // name(bytes)
	return (await eth_call(provider, rev_resolver, ABIEncoder.method(SIG).number(rev_node))).string();
}

// https://medium.com/the-ethereum-name-service/step-by-step-guide-to-setting-an-nft-as-your-ens-profile-avatar-3562d39567fc
// https://medium.com/the-ethereum-name-service/major-refresh-of-nft-images-metadata-for-ens-names-963090b21b23
// https://github.com/ensdomains/ens-metadata-service
export async function ens_avatar(provider, input) {
	let ret = await ens_resolve(provider, input);
	let {node, resolver} = ret;
	if (is_null_hex(resolver)) return {type: 'none', ...ret};
	await lookup_address(provider, ret);
	ret.avatar = await call_resolver_text(provider, resolver, node, 'avatar');
	return {...ret, ...await parse_avatar(ret.avatar, provider, ret.address)};
}

// note: the argument order here is non-traditional
export async function parse_avatar(avatar, provider = null, address = false) {
	if (typeof avatar !== 'string') throw new Error('Invalid avatar: expected string');
	if (avatar.length == 0) return {type: 'null'}; 
	if (avatar.includes('://') || avatar.startsWith('data:')) return {type: 'url'};
	let parts = avatar.split('/');
	let part0 = parts[0];
	if (part0.startsWith('eip155:')) { // nft format  
		if (parts.length < 2) return {type: 'invalid', error: 'expected contract'};
		if (parts.length < 3) return {type: 'invalid', error: 'expected token'};
		let chain = parseInt(part0.slice(part0.indexOf(':') + 1));
		if (!(chain > 0)) return {type: 'invalid', error: 'expected chain id'};
		let part1 = parts[1];
		if (part1.startsWith('erc721:')) {
			// https://eips.ethereum.org/EIPS/eip-721
			let contract = part1.slice(part1.indexOf(':') + 1);
			if (!is_valid_address(contract)) return  {type: 'invalid', error: 'expected contract address'};
			let token;
			try {
				token = Uint256.from_str(parts[2]);
			} catch (err) {
				return {type: 'invalid', error: 'expected uint256 token'};
			}
			let ret = {type: 'nft', interface: 'erc721', contract, token, chain};
			if (provider && parseInt(provider.chainId) === chain) {
				const SIG_tokenURI = 'c87b56dd'; // tokenURI(uint256)
				const SIG_ownerOf  = '6352211e'; // ownerOf(uint256)
				try {
					let [owner, meta_uri] = await Promise.all([
						eth_call(provider, contract, ABIEncoder.method(SIG_ownerOf).number(token)).then(x => x.addr()),
						eth_call(provider, contract, ABIEncoder.method(SIG_tokenURI).number(token)).then(x => x.string())
					]);
					ret.owner = owner;
					ret.meta_uri = meta_uri;
					if (address) {
						ret.owned = address === owner ? 1 : 0;
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
			let token;
			try {
				token = Uint256.from_str(parts[2]);
			} catch (err) {
				return {type: 'invalid', error: 'expected uint256 token'};
			}
			let ret = {type: 'nft', interface: 'erc1155', contract, token, chain};
			if (provider && parseInt(provider.chainId) === chain) {
				const SIG_uri       = '0e89341c'; // uri(uint256)
				const SIG_balanceOf = '00fdd58e'; // balanceOf(address,uint256)
				try {
					let [balance, meta_uri] = await Promise.all([
						!address ? -1 : eth_call(provider, contract, ABIEncoder.method(SIG_balanceOf).addr(address).number(token)).then(x => x.number()),
						eth_call(provider, contract, ABIEncoder.method(SIG_uri).number(token)).then(x => x.string())
					]);
					// The string format of the substituted hexadecimal ID MUST be lowercase alphanumeric: [0-9a-f] with no 0x prefix.
					ret.meta_uri = meta_uri.replace('{id}', hex_from_bytes(token.bytes)); 
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

// https://eips.ethereum.org/EIPS/eip-634
// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/TextResolver.sol
export async function ens_text_record(provider, input, keys) {
	if (typeof keys === 'string') keys = [keys];
	if (!Array.isArray(keys)) throw new TypeError('Expected key or array of keys');
	let ret = await ens_resolve(provider, input);
	let {node, resolver} = ret;
	if (!is_null_hex(resolver)) {
		let values = await Promise.all(keys.map(x => call_resolver_text(provider, resolver, node, x)));
		ret.text = Object.fromEntries(keys.map((k, i) => [k, values[i]]));
	}
	return ret;
}

// https://eips.ethereum.org/EIPS/eip-2304
// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/AddrResolver.sol
export async function ens_addr_record(provider, input, addresses) {
	if (!Array.isArray(addresses)) addresses = [addresses];
	addresses = addresses.map(get_addr_type_from_input); // throws
	let ret = await ens_resolve(provider, input);
	let {node, resolver} = ret;
	if (!is_null_hex(resolver)) {
		let values = await Promise.all(addresses.map(([_, type]) => call_resolver_addr_for_type(provider, resolver, node, type)));
		ret.addr = Object.fromEntries(addresses.map(([name, _], i) => [name, values[i]]));
	}
	return ret;
}

// https://eips.ethereum.org/EIPS/eip-1577
// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/ContentHashResolver.sol
export async function ens_contenthash_record(provider, input) {
	let ret = await ens_resolve(provider, input);
	let {node, resolver} = ret;
	if (!is_null_hex(resolver)) {
		const SIG = 'bc1c58d1'; // contenthash(bytes32)
		let v = (await eth_call(provider, resolver, ABIEncoder.method(SIG).number(node))).memory();
		if (v.length > 0) {
			ret.contenthash = v;
			// https://github.com/multiformats/multicodec
			let dec = new ABIDecoder(v);
			if (dec.uvarint() == 0xE3) { // ipfs
				if (dec.read_byte() == 0x01 && dec.read_byte() == 0x70) { // check version and content-type
					ret.contenthash_url = `ipfs://${base58_from_bytes(dec.read(dec.remaining))}`;
				}
			}
		}
	}
	return ret;
}

// https://github.com/ethereum/EIPs/pull/619
// https://github.com/ensdomains/resolvers/blob/master/contracts/profiles/PubkeyResolver.sol
export async function ens_pubkey_record(provider, input) {
	let ret = await ens_resolve(provider, input);
	let {node, resolver} = ret;
	if (!is_null_hex(resolver)) {
		const SIG = 'c8690233'; // pubkey(bytes32)
		let dec = await eth_call(provider, resolver, ABIEncoder.method(SIG).number(node));
		ret.pubkey = {x: dec.uint256(), y: dec.uint256()};
	}
	return ret;
}

function format_addr_type(i) {
	return '0x' + i.toString(16).padStart(4, '0');
}

// see: test/build-address-types.js
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
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

async function call_registry_resolver(provider, node) {
	const SIG = '0178b8bf'; // resolver(bytes32)
	try {
		return (await eth_call(provider, ENS_REGISTRY, ABIEncoder.method(SIG).number(node))).addr();
	} catch (cause) {
		throw new Error('Invalid response from registry', {cause});
	}
}


async function call_resolver_text(provider, resolver, node, key) {
	const SIG = '59d1d43c'; // text(bytes32,string)
	try {
		return (await eth_call(provider, resolver, ABIEncoder.method(SIG).number(node).string(key))).string();
	} catch (cause) {
		throw new Error(`Invalid response from resolver for text: ${key}`, {cause});
	}
}

async function call_resolver_addr_for_type(provider, resolver, node, type) {
	const SIG = 'f1cb7e06'; // addr(bytes32,uint256);
	try {
		return (await eth_call(provider, resolver, ABIEncoder.method(SIG).number(node).number(type))).memory();
	} catch (cause) {
		throw new Error(`Invalid response from resolver for addr of type: ${format_addr_type(type)}`, {cause});
	}
}