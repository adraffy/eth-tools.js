import {
	ens_resolve,
	node_from_ens_name,
	lookup_address,
	ens_name_for_address,
	ens_avatar,
	ens_text_record,
	ens_addr_record,
	ens_contenthash_record,
	ens_pubkey_record,
	parse_avatar,
	is_dot_eth_available,
	lookup_owner
} from '../ens.js';
import provider from './nodejs-provider.js';

console.log(await is_dot_eth_available(provider, 'raffy'));
console.log(await lookup_owner(provider, 'raffy.eth'));

let name = 'brantly.eth';

console.log(node_from_ens_name(name).toString());
console.log(await ens_resolve(provider, node_from_ens_name(name)));

let resolved = await ens_resolve(provider, name);
console.log(resolved);

console.log(await lookup_address(provider, resolved));

console.log(resolved);
console.log(await ens_name_for_address(provider, resolved.address));

let {avatar} = await ens_avatar(provider, name); // by name
console.log(avatar);
console.log(await ens_avatar(provider, resolved));

console.log(await ens_text_record(provider, resolved.address, ['email', 'url', 'avatar']));

console.log(await ens_addr_record(provider, name, ['BTC', 2, 'ETH', 'XLM']));

console.log(await ens_contenthash_record(provider, resolved));

console.log(await ens_pubkey_record(provider, resolved));

console.log(await parse_avatar(avatar));
console.log(await parse_avatar(avatar, provider));
console.log(JSON.stringify(await parse_avatar(avatar, provider, avatar.account)));

console.log(await lookup_owner(provider, 'brantly.eth'));