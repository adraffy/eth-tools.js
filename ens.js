import {ens_normalize} from '@adraffy/ens-normalize';
import {eth_call, ABIDecoder, ABIEncoder} from './abi.js';
import {namehash as ens_node_from_name, checksum_address, is_null_hex} from './utils.js';
import {base58_from_bytes} from './base58.js';
import ADDR_TYPES from './ens-address-types.js';

export {ADDR_TYPES}; // note: this is mutable

// https://eips.ethereum.org/EIPS/eip-137#name-syntax
// warning: this does not normalize
export {ens_node_from_name};

/*
export function ens_labelhash(s) {
	return keccak().update(s).hex;
}
*/

// https://docs.ens.domains/ens-deployments
const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'; // ens registry contract on mainnet
const RESOLVED = Symbol('ENSResolved');

function resolved_value() {
	return new Date();
}

export async function ens_address_from_node(provider, node) {
	let resolver = await call_registry_resolver(provider, node);
	let address = false; // TODO: decide this placeholder value
	if (!is_null_hex(resolver)) {
		address = await call_resolver_addr(provider, resolver, node);
	}
	return {node, resolver, address};
}

// https://eips.ethereum.org/EIPS/eip-137
export async function ens_address_from_name(provider, name0, ...a) {	
	let name = ens_normalize(name0, ...a); // throws 
	let node = ens_node_from_name(name);
	return {name0, name, ...await ens_address_from_node(provider, node), [RESOLVED]: resolved_value()};
}

// https://eips.ethereum.org/EIPS/eip-181
export async function ens_name_from_address(provider, address) {
	address = checksum_address(address); // throws
	let node = ens_node_from_name(`${address.slice(2).toLowerCase()}.addr.reverse`); 
	let resolver = await call_registry_resolver(provider, node);
	let ret = {node, resolver, address, [RESOLVED]: resolved_value()};
	if (!is_null_hex(resolver)) {
		const SIG = '691f3431'; // name(bytes)
		ret.name = (await eth_call(provider, resolver, ABIEncoder.method(SIG).add_hex(node))).string();
	}
	return ret;
}

// https://medium.com/the-ethereum-name-service/step-by-step-guide-to-setting-an-nft-as-your-ens-profile-avatar-3562d39567fc
// https://medium.com/the-ethereum-name-service/major-refresh-of-nft-images-metadata-for-ens-names-963090b21b23
// https://github.com/ensdomains/ens-metadata-service
export async function ens_avatar(provider, input) {
	let ret = await resolve_name_from_input(provider, input);
	let {node, resolver, address} = ret;
	if (is_null_hex(resolver)) return {type: 'none', ...ret};
	if (!address) ret.address = await call_resolver_addr(provider, resolver, node);
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
			let contract = part1.slice(part1.indexOf(':') + 1);
			let token = parts[2];
			let token_big = BigInt(token);
			let ret = {type: 'nft', interface: 'erc721', contract, token};
			if (provider && parseInt(provider.chainId) === chain) {
				const SIG_tokenURI = 'c87b56dd'; // tokenURI(uint256)
				const SIG_ownerOf  = '6352211e'; // ownerOf(uint256)
				let [owner, meta_uri] = await Promise.all([
					eth_call(provider, contract, ABIEncoder.method(SIG_ownerOf).big(token_big)).then(x => x.addr()),
					eth_call(provider, contract, ABIEncoder.method(SIG_tokenURI).big(token_big)).then(x => x.string())
				]);
				ret.owner = owner;
				ret.meta_uri = meta_uri;
				if (address) {
					ret.is_owner = address === owner;
				}
			}
			return ret;
		} else if (part1.startsWith('erc1155:')) {
			let contract = part1.slice(part1.indexOf(':') + 1);
			let token = parts[2];
			let token_hex = BigInt(token).toString(16).padStart(64, '0'); // no 0x
			let ret = {type: 'nft', interface: 'erc1155', contract, token};
			if (provider && parseInt(provider.chainId) === chain) {
				const SIG_tokenURI  = '0e89341c'; // uri(uint256)
				const SIG_balanceOf = '00fdd58e'; // balanceOf(address,uint256)
				let [balance, meta_uri] = await Promise.all([
					!address ? -1 : eth_call(provider, contract, ABIEncoder.method(SIG_balanceOf).addr(address).add_hex(token_hex)).then(x => x.number()),
					eth_call(provider, contract, ABIEncoder.method(SIG_tokenURI).add_hex(token_hex)).then(x => x.string())
				]);
				ret.meta_uri = meta_uri.replace(/{id}/, token_hex); // 1155 standard
				if (address) {
					ret.owned = balance;				
					ret.is_owner = balance > 0;
				}
			}
			return {type: 'nft', interface: 'erc1155', chain, contract, token, meta_uri, is_owner: balance > 0};
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
	let ret = await resolve_name_from_input(provider, input);
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
	let ret = await resolve_name_from_input(provider, input);
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
	let ret = await resolve_name_from_input(provider, input);
	let {node, resolver} = ret;
	if (!is_null_hex(resolver)) {
		const SIG = 'bc1c58d1'; // contenthash(bytes32)
		let v = (await eth_call(provider, resolver, ABIEncoder.method(SIG).add_hex(node))).memory();
		if (v.length > 0) {
			ret.contenthash = v;
			// https://github.com/multiformats/multicodec
			let dec = new ABIDecoder(v);
			if (dec.uvarint() == 0xE3) { // ipfs
				if (dec.byte() == 0x01 && dec.byte() == 0x70) { // check version and content-type
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
	let ret = await resolve_name_from_input(provider, input);
	let {node, resolver} = ret;
	if (!is_null_hex(resolver)) {
		const SIG = 'c8690233'; // pubkey(bytes32)
		let dec = await eth_call(provider, resolver, ABIEncoder.method(SIG).add_hex(node));
		ret.pubkey = {x: dec.big(), y: dec.big()};
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

// turn a name/address/object into {name, node, resolver}
async function resolve_name_from_input(provider, input) {
	if (typeof input === 'object') { // previously resolved object? 
		if (RESOLVED in input) return input; // trusted
		input = input.name ?? input.address; // fallback
	}
	if (typeof input === 'string') { // name or address
		input = input.trim();
		if (input.length > 0) {
			let ret;
			try { 
				// assume input is address
				// throws immediately if not
				ret = await ens_name_from_address(provider, input); 
			} catch (ignored) {
				// assume input is name
				// FIXME: no way to choose disallowed behavior 
				ret = {name: ens_normalize(input)}; // throws
			}
			let {name} = ret;
			if (!name) {
				// this only happens if input was address
				// and we couldn't determine a name
				throw new Error(`No name for address`);
			}
			let node = ens_node_from_name(name);
			let resolver = await call_registry_resolver(provider, node);
			return {...ret, node, resolver, [RESOLVED]: resolved_value()};
		}
	}
	throw new TypeError('Expected name or address');
}

async function call_registry_resolver(provider, node) {
	const SIG = '0178b8bf'; // resolver(bytes32)
	try {
		return (await eth_call(provider, ENS_REGISTRY, ABIEncoder.method(SIG).add_hex(node))).addr();
	} catch (cause) {
		throw new Error('Invalid response from registry', {cause});
	}
}

// this effectively is the same thing as:
// call_resolver_addr_for_type(node, 60)
async function call_resolver_addr(provider, resolver, node) {
	const SIG = '3b3b57de'; // addr(bytes32)
	try {
		return (await eth_call(provider, resolver, ABIEncoder.method(SIG).add_hex(node))).addr();
	} catch (cause) {
		throw new Error('Invalid response from resolver for addr', {cause});
	}
}

async function call_resolver_text(provider, resolver, node, key) {
	const SIG = '59d1d43c'; // text(bytes32,string)
	try {
		return (await eth_call(provider, resolver, ABIEncoder.method(SIG).add_hex(node).string(key))).string();
	} catch (cause) {
		throw new Error(`Invalid response from resolver for text: ${key}`, {cause});
	}
}

async function call_resolver_addr_for_type(provider, resolver, node, type) {
	const SIG = 'f1cb7e06'; // addr(bytes32,uint256);
	try {
		return (await eth_call(provider, resolver, ABIEncoder.method(SIG).add_hex(node).number(type))).memory();
	} catch (cause) {
		throw new Error(`Invalid response from resolver for addr of type: ${format_addr_type(type)}`, {cause});
	}
}