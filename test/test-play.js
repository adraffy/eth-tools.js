/*
import {ENS} from '../index.js';
import {WS as provider} from './nodejs-provider.js';
import {ens_normalize} from '@adraffy/ens-normalize';

let ens = new ENS({provider, ens_normalize});

let name = await ens.resolve('NIck.eth');
console.log(await name.get());

//console.log(await ens.resolve('brantly.eth').then(x => x.get_addrs(['BTC'])));

console.log(await ens.resolve('poo'));

console.log(await ens.resolve('adrafFy.eth').then(x => x.get_display()));

provider.disconnect();
*/


//import {FetchProvider, ENS, NFT} from '../dist/eth-tools.min.js';
//import {ens_normalize} from '../../ens-normalize.js/dist/ens-normalize.min.js'; 
//import {FETCH as provider} from './nodejs-provider.js';

/*
import {Providers, FetchProvider, WebSocketProvider,
	determine_window_provider, ENS, NFT} from '../dist/eth-tools.min.js';
import {ens_normalize} from '../../ens-normalize.js/dist/ens-normalize.min.js'; 
let providers = new Providers()
	.add_static(1, new WebSocketProvider({url: 'ws://192.168.77.10:8546'}))
	.add_static(43114, new FetchProvider({url: 'https://api.avax.network/ext/bc/C/rpc'}));
determine_window_provider().then(p => {
	providers.add_dynamic(p);
}).catch(() => {}); 
let mainnet = providers.view(1);
let ens = new ENS({provider: mainnet, ens_normalize});
let name = await ens.resolve('rAFFy.eth');
console.log(await name.get_text('com.twitter'));
// "adraffy"
console.log(await name.get_address());
// "0x51050ec063d393217B436747617aD1C2285Aeeee"
let nfs = new NFT(mainnet, '0xdc8bed466ee117ebff8ee84896d6acd42170d4bb');
console.log(await nfs.get_type());
// "ERC-721"
console.log(await nfs.get_token_uri(1));
// "ipfs://QmSSperMye5DrJbC2w9dxFXv9GWWLdfqDs9VtiG64FQDkq/1"

*/


import {ENS, find_ens_addr} from '../index.js';
import {WS as provider} from './nodejs-provider.js';




let ens = new ENS({provider});

/*




console.log(await ens.resolve('name').then(x => x.get_text('com.twitter')))

console.log((await ens.get_dot_eth_owner('raffy')).address);

let name = await ens.resolve('raffy.eth');
console.log(name);

console.log(await name.get_addr(3));
console.log(await name.get_addr(60));
console.log(await name.get_address());
console.log(await name.get_owner());

console.log(await name.get_text('display'));
console.log(await name.get_texts(['com.twitter']));
console.log(await name.get_texts());

console.log(await ens.get_dot_eth_owner('raffy'));

let name = await ens.resolve('zadok7.eth');

//console.log(name.resolver);

//console.log(await name.resolver.supports_text());


//console.log(await name.get_avatar('avatar'));
console.log(await name.get_content());


console.log([
	'name()', 
	'symbol()', 
	'totalSupply()', 
	'balanceOf(address)', 
	'ownerOf(uint256)', 
	'approve(address,uint256)', 
	'safeTransferFrom(address,address,uint256)'
].reduce((a, x) => a.xor(keccak().update(x).bytes), Uint256.zero()).hex.slice(0, 10));
*/

//console.log(is_multihash('QmRwgn6qNPwzdDJfpPuSeq2Qjodi6z3n5QmdKk82fUJb1Y'));

//console.log(await provider.req('eth_getCode', '0x51050ec063d393217B436747617aD1C2285Aeeee', 'latest'));
//console.log(await provider.req('eth_getCode', '0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85', 'latest'));



let name = await ens.resolve('brantly.eth');
for (let key of [
	'ETH', 'TRX', 'XEM', 'EOS', 'RSK', 
	'XLM', 'ATOM', 'DASH', 'BNB', 'BCH', 
	'XRP', 'ETC', 'DOGE', 'LTC', 'BTC']) {
	try {
		console.log(key, await name.get_addr(key));
	} catch (err) {
		console.log(key, err.message);
	}
}

console.log(await name.get_addrs([ "BTC", 2, "XLM", "XCH" ]));
