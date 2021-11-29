import {ens_address_from_name, ens_avatar, ens_name_from_address,
	ens_text_record, ens_addr_record, ens_contenthash_record,
	ens_pubkey_record, ens_node_from_name, ens_address_from_node, parse_avatar} from '../ens.js';
import provider from './nodejs-provider.js';

let name = 'bRaNTly.eth';

console.log(await ens_address_from_node(provider, ens_node_from_name(name)));

let resolved = await ens_address_from_name(provider, name);
console.log(resolved);

let reversed = await ens_name_from_address(provider, resolved.address);
console.log(reversed);

let avatar = await ens_avatar(provider, reversed.address); // by addr
console.log(avatar);
//console.log(await ens_avatar(provider, name)); // by name
//console.log(await ens_avatar(provider, resolved)); // by previous

console.log(await ens_text_record(provider, resolved, ['email', 'url', 'avatar']));

console.log(await ens_addr_record(provider, resolved, ['BTC', 2, 'ETH', 'XLM']));

console.log(await ens_contenthash_record(provider, resolved));

console.log(await ens_pubkey_record(provider, resolved));

console.log(await parse_avatar(avatar.avatar));
console.log(await parse_avatar(avatar.avatar, provider));
console.log(await parse_avatar(avatar.avatar, provider, avatar.account));