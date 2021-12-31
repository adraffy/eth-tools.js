import {ENS, parse_avatar, namehash, labelhash} from '../index.js';
import {WS as provider} from './nodejs-provider.js';
import {ens_normalize} from '@adraffy/ens-normalize';

console.log(labelhash('eth'));
console.log(namehash('eth'));

let ens = new ENS({provider, ens_normalize});

console.log(await ens.is_dot_eth_available('brantly'));

let name = await ens.resolve('bRantly.eth');
console.log(name);

console.log(await name.get_address());
console.log(await name.get_primary());
console.log(await name.get_avatar());
console.log(await name.get_owner());

console.log(await name.get_texts(['name', 'email', 'com.twitter']));
console.log(await name.get_addrs(['BTC', 'XLM']));
console.log(await name.get_addrs(['BTC', 'XLM'], undefined, false));
console.log(await name.get_content());
console.log(await name.get_pubkey());

console.log(await ens.resolve(name.address));

console.log(await parse_avatar(await name.get_text('avatar')));

console.log(await ens.resolve(await name.get_address()));

provider.disconnect();