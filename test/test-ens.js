import {ens_address_from_name, ens_avatar, ens_name_from_address} from '../ens.js';
import provider from './cloudflare.js';

let name = 'nIcK.eth';

let resolved = await ens_address_from_name(provider, 'nIcK.eth');
console.log(resolved);

let reversed = await ens_name_from_address(provider, resolved.address);
console.log(reversed);

let avatar = await ens_avatar(provider, reversed.address); // by addr
console.log(avatar);
console.log(await ens_avatar(provider, name)); // by name