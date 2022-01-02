import {NFT} from '../index.js';
import {WS as provider} from './nodejs-provider.js';
import fetch from 'node-fetch';


let nfs = new NFT(provider, '0xdc8bed466ee117ebff8ee84896d6acd42170d4bb');
let pat = new NFT(provider, '0xddf0aef52d9b3c2dc63ec120828a761a28103ba0');
let bun = new NFT(provider, '0x6f13d82d5d501b2eebb94a34bbf8bfdf20440079');
let cp = new NFT(provider, '0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB');

console.log(await nfs.get_type());
console.log(await pat.get_type());

console.log(await nfs.get_token_uri(1));

try {
	console.log(await bun.get_token_uri(9000));
} catch (err) {
	console.error(err);
}

console.log(await cp.get_token_uri(0));

let wtf = new NFT(provider, '0x2A46f2fFD99e19a89476E2f62270e0a35bBf0756');

console.log(await wtf.get_type());