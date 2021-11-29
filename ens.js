import {ens_normalize} from '@adraffy/ens-normalize';
import {ABIDecoder, ABIEncoder} from './abi.js';
import {namehash as ens_node_from_name, checksum_address, is_null_hex, base58_from_bytes} from './utils.js';
import ADDR_TYPES from './ens-address-types.js';

export {ADDR_TYPES}; // note: this is mutable

// https://eips.ethereum.org/EIPS/eip-137#name-syntax
// warning: this does not normalize
export {ens_node_from_name};

// https://docs.ens.domains/ens-deployments
const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'; // ens registry contract on mainnet
const RESOLVED = Symbol('ENSResolved');

function resolved_value() {
	return new Date();
}

export async function ens_address_from_node(provider, node) {
	let resolver = await call_registry_resolver(provider, node);
	let address = false;
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
		ret.name = ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).add_hex(node))).string();
	}
	return ret;
}

// https://medium.com/the-ethereum-name-service/step-by-step-guide-to-setting-an-nft-as-your-ens-profile-avatar-3562d39567fc
export async function ens_avatar(provider, input) {
	let ret = await resolve_name_from_input(provider, input);
	let {node, resolver, address} = ret;
	if (is_null_hex(resolver)) return {type: 'none', ...ret};
	if (!address) ret.address = address = await call_resolver_addr(provider, resolver, node);
	let avatar = await call_resolver_text(provider, resolver, node, 'avatar');
	if (avatar.length == 0) return {type: 'null', ...ret}; 
	ret.avatar = avatar;
	if (avatar.includes('://') || avatar.startsWith('data:')) return {type: 'url', ...ret};
	// parse inline format
	let parts = avatar.split('/');
	let part0 = parts[0];
	if (part0.startsWith('eip155:')) {
		if (parts.length < 2) throw new Error('Invalid avatar format: expected type');
		let chain = parseInt(part0.slice(part0.indexOf(':') + 1));
		if (chain != 1) throw new Error('Avatar not on mainnet');
		let part1 = parts[1];
		if (part1.startsWith('erc721:')) {
			if (parts.length < 3) throw new Error('Invalid avatar format: expected token');
			let contract = part1.slice(part1.indexOf(':') + 1);
			let token = parts[2];
			let token_big = BigInt(token);
			const SIG_tokenURI = 'c87b56dd'; // tokenURI(uint256)
			const SIG_ownerOf  = '6352211e'; // ownerOf(uint256)
			let [owner, meta_uri] = await Promise.all([
				call(provider, contract, ABIEncoder.method(SIG_ownerOf).big(token_big)),
				call(provider, contract, ABIEncoder.method(SIG_tokenURI).big(token_big))
			]);
			owner = ABIDecoder.from_hex(owner).addr();
			meta_uri = ABIDecoder.from_hex(meta_uri).string();
			return {type: 'erc721', ...ret, contract, token, meta_uri, is_owner: address === owner};
		} else if (part1.startsWith('erc1155:')) {
			if (parts.length < 3) throw new Error('Invalid avatar format: expected token');
			let contract = part1.slice(part1.indexOf(':') + 1);
			let token = parts[2];
			let hex_token = BigInt(token).toString(16).padStart(64, '0'); // no 0x
			const SIG_tokenURI  = '0e89341c'; // uri(uint256)
			const SIG_balanceOf = '00fdd58e'; // balanceOf(address,uint256)
			let [balance, meta_uri] = await Promise.all([
				call(provider, contract, ABIEncoder.method(SIG_balanceOf).addr(address).add_hex(hex_token)),
				call(provider, contract, ABIEncoder.method(SIG_tokenURI).add_hex(hex_token))
			]);
			balance = ABIDecoder.from_hex(balance).number();
			meta_uri = ABIDecoder.from_hex(meta_uri).string().replace(/{id}/, hex_token); // 1155 standard
			return {type: 'erc1155', ...ret, contract, token, meta_uri, is_owner: balance > 0};
		} 			
	}
	return {type: 'unknown', ...ret};	
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
	addresses = addresses.map(resolve_addr_type_from_input); // throws
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
		let v =ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).add_hex(node))).memory();
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
		let dec = ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).add_hex(node)));
		ret.pubkey = {x: dec.read(32), y: dec.read(32)};
	}
	return ret;
}

// see: test/build-address-types.js
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
function resolve_addr_type_from_input(x) {
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
			name = '0x' + x.toString(16).padStart(4, '0');
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
				ret = await ens_name_from_address(provider, input); // assume address, will throw if not
			} catch (ignored) {		
				ret = {name: ens_normalize(input)}; // assume name, throws
			}
			let {name} = ret;
			if (!name) throw new Error(`No name for address`);
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
		return ABIDecoder.from_hex(await call(provider, ENS_REGISTRY, ABIEncoder.method(SIG).add_hex(node))).addr();
	} catch (cause) {
		throw new Error('Invalid response from registry', {cause});
	}
}

async function call_resolver_addr(provider, resolver, node) {
	const SIG = '3b3b57de'; // addr(bytes32)
	try {
		return ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).add_hex(node))).addr();
	} catch (cause) {
		throw new Error('Invalid response from resolver for addr', {cause});
	}
}

async function call_resolver_text(provider, resolver, node, key) {
	const SIG = '59d1d43c'; // text(bytes32,string)
	try {
		return ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).add_hex(node).string(key))).string();
	} catch (cause) {
		throw new Error(`Invalid response from resolver for text: ${key}`, {cause});
	}
}

async function call_resolver_addr_for_type(provider, resolver, node, type) {
	const SIG = 'f1cb7e06'; // addr(bytes32,uint256);
	try {
		return ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).add_hex(node).number(type))).memory();
	} catch (cause) {
		throw new Error(`Invalid response from resolver for addr of type: 0x${type.toString(16).padStart(4, '0')}`, {cause});
	}
}

function call(provider, to, enc) {
	if (typeof provider === 'object') {
		if (provider.request) {
			provider = provider.request.bind(provider); 
		} else if (provider.sendAsync) { // support boomer tech
			provider = provider.sendAsync.bind(provider);
		} // what else?
	}
	if (typeof provider !== 'function') throw new TypeError('unknown provider');
	return provider({method: 'eth_call', params:[{to, data: enc.build_hex()}, 'latest']});
}