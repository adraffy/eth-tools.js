import {ENS} from '../index.js';
import {ens_normalize} from '@adraffy/ens-normalize';
import {WS as provider} from './nodejs-provider.js';

let ens = new ENS({provider, ens_normalize});

async function dump(input) {
	let name = await ens.resolve(input);
	await Promise.all([
		name.get_address(),
		name.get_display(),
		name.get_primary(),
		name.get_owner(),
		name.get_avatar(),
		name.get_pubkey(),
		name.get_content(),
		name.get_texts(['name', 'email', 'com.twitter']),
		name.get_addrs(['BTC', 2, 'ETH', 'XLM'])
	]);
	return name;
}

console.log(await dump('nIck.eth'));