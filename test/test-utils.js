import {
	standardize_address, 
	is_checksum_address, 
	is_valid_address,
	is_null_hex,
	promise_object_setter,
	data_uri_from_json
} from '../index.js';
import fetch from 'node-fetch';

let ADDRESSES = [
	'0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
	'0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e',
	'0xaB528d626EC275E3faD363fF1393A41F581c5897'
];

for (let a0 of ADDRESSES) {
	let a1 = standardize_address(a0.toLowerCase());
	if (a0 !== a1) {
		console.log({a0, a1});
		throw new Error(`wtf`);
	}
}

if (!is_null_hex('0x00000000000000000000000000000000')) throw new Error('wtf');
if (!is_null_hex('0x0')) throw new Error('wtf');
if (!is_null_hex('0')) throw new Error('wtf');

console.log('OK');

console.log(is_checksum_address(ADDRESSES[0]));
console.log(is_valid_address(ADDRESSES[0].toLowerCase()));

console.log(await fetch(data_uri_from_json({a: 1})).then(x => x.json()));

/*
let f = promise_object_setter(new Promise(ful => setTimeout(() => {
	console.log('once');
	ful('a')
}, 1000)));
console.log(await Promise.all([f(), f()]));

await promise_queue(
	new Promise(ful => setTimeout(() => {
		console.log('again');
		ful('a')
	}, 1000)),
	() => f = null
)();
if (f !== null) throw Error(`not null`);

f = promise_queue(
	Promise.reject('wtf'),
	(ok, err) => console.log({ok, err})
);
let threw;
try {
	await f();
} catch (err) {
	threw = true;
}
if (!threw) throw new Error(`didn't throw`);

await promise_queue(Promise.resolve(true), () => { throw new Error('wtf'); });


Promise.resolve(1).then(() => { throw 1 }, err => {
	console.log('a');
}).catch(() => {
	console.log('b');
});
*/