import {hex_from_bytes, keccak} from '@adraffy/keccak';
import {ens_normalize} from '@adraffy/ens-normalize';
import {ABIDecoder, ABIEncoder} from './abi.js';
import {namehash, checksum_address, is_null_address} from './utils.js';

export {ens_normalize};

// https://eips.ethereum.org/EIPS/eip-137#name-syntax
// warning: this does not normalize
export const ens_node_from_name = namehash;

// https://docs.ens.domains/ens-deployments
const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'; // ens registry contract on mainnet

// https://eips.ethereum.org/EIPS/eip-137
export async function ens_address_from_name(provider, name0) {	
	let name = ens_normalize(name0); // throws
	let node = ens_node_from_name(name);
	let resolver = await call_resolver(provider, node);
	let address = false;
	if (!is_null_address(resolver)) {
		address = await call_resolver_addr(provider, resolver, node);
	}
	return {name, name0, node, resolver, address};
}

// https://eips.ethereum.org/EIPS/eip-181
export async function ens_name_from_address(provider, address) {
	address = checksum_address(address); // throws
	let node = ens_node_from_name(`${address.slice(2).toLowerCase()}.addr.reverse`); 
	let resolver = await call_resolver(provider, node);
	let name = false;
	if (!is_null_address(resolver)) {			
		const SIG = '691f3431'; // name(bytes)
		name = ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).hex(node))).string();
	}
	return {address, node, resolver, name};
}

// https://medium.com/the-ethereum-name-service/step-by-step-guide-to-setting-an-nft-as-your-ens-profile-avatar-3562d39567fc
export async function ens_avatar(provider, input) {
	let name, address = false;
	try {
		// if the name is actually an address, reverse it
		// this will bail immediately if not an address
		({name, address} = await ens_name_from_address(provider, input)); 
	} catch (ignored) {		
		name = ens_normalize(input); // throws
	}
	if (name === false) throw new Error(`No name for address`);
	let node = ens_node_from_name(name);
	let resolver = await call_resolver(provider, node);
	if (is_null_address(resolver)) {
		return {type: 'none', name};
	}
	if (!address) {
		address = await call_resolver_addr(provider, resolver, node);
	}
	let avatar = await call_resolver_text(provider, resolver, node, 'avatar');
	if (avatar.length == 0) { 
		return {type: 'null', name, address};
	}
	if (avatar.includes('://') || avatar.startsWith('data:')) {
		return {type: 'url', name, address, avatar};
	}
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
			meta_uri = ABIDecoder.from_hex(meta).string();
			return {type: 'erc721', name, address, avatar, contract: contract, token, meta_uri, is_owner: address === owner};
		} else if (part1.startsWith('erc1155:')) {
			if (parts.length < 3) throw new Error('Invalid avatar format: expected token');
			let contract = part1.slice(part1.indexOf(':') + 1);
			let token = parts[2];
			let hex_token = '0x' + BigInt(token).toString(16).padStart(64, '0');
			const SIG_tokenURI  = '0e89341c'; // uri(uint256)
			const SIG_balanceOf = '00fdd58e'; // balanceOf(address,uint256)
			let [balance, meta_uri] = await Promise.all([
				call(provider, contract, ABIEncoder.method(SIG_balanceOf).addr(address).hex(hex_token)),
				call(provider, contract, ABIEncoder.method(SIG_tokenURI).hex(hex_token))
			]);
			balance = ABIDecoder.from_hex(balance).number();
			meta_uri = ABIDecoder.from_hex(meta_uri).string().replace(/{id}/, hex_token); // 1155 standard
			return {type: 'erc1155', name, address, avatar, contract: contract, token, meta_uri, is_owner: balance > 0};
		} 			
	}
	return {type: 'unknown', name, address, avatar};	
}

async function call_resolver(provider, node) {
	const SIG = '0178b8bf'; // resolver(bytes32)
	try {
		return ABIDecoder.from_hex(await call(provider, ENS_REGISTRY, ABIEncoder.method(SIG).hex(node))).addr();
	} catch (err) {
		throw wrap_error('Invalid response from registry', err);
	}
}

async function call_resolver_addr(provider, resolver, node) {
	const SIG = '3b3b57de'; // addr(bytes32)
	try {
		return ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).hex(node))).addr();
	} catch (err) {
		throw wrap_error('Invalid response from resolver for addr()', err)
	}
}

async function call_resolver_text(provider, resolver, node, key) {
	const SIG = '59d1d43c'; // text(bytes32,string)
	try {
		return ABIDecoder.from_hex(await call(provider, resolver, ABIEncoder.method(SIG).hex(node).string(key))).string();
	} catch (err) {
		throw wrap_error(`Invalid response from resolver for text(${key})`, err);
	}
}

function call(provider, to, enc) {
	if (typeof provider === 'object') {
		if (provider.request) {
			provider = provider.request.bind(provider); 
		} else if (provider.sendAsync) {
			provider = provider.sendAsync.bind(provider);
		} // what else?
	}
	if (typeof provider !== 'function') throw new TypeError('unknown provider');
	return provider({method: 'eth_call', params:[{to, data: enc.build_hex()}, 'latest']});
}

function wrap_error(s, err) {
	let wrap = new Error(s);
	wrap.reason = err;
	return wrap;
}