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
console.log(await name.get_avatar());
console.log(await name.get_owner());

console.log(await name.get_texts(['name', 'email', 'com.twitter']));
console.log(await name.get_addrs(['BTC', 'ETH', 'XLM']));
console.log(await name.get_addrs([0], {}));
console.log(await name.get_content());
console.log(await name.get_pubkey());

console.log(await parse_avatar(await name.get_text('avatar')));

let addr = '0x983110309620D911731Ac0932219af06091b6744'.toLowerCase();

console.log(await ens.primary_from_address(addr));

let owner = ens.owner(addr);
console.log(owner.address);
console.log(await owner.get_primary_name());
console.log(await owner.resolve());

provider.disconnect();