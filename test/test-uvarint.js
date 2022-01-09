import {read_uvarint, sizeof_uvarint, write_uvarint} from '../index.js';

let v = new Uint8Array(32);
for (let i = 0; i < 10000; i++) {
	let n0 = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);
	let len = write_uvarint(v, n0);
	if (len !== sizeof_uvarint(n0)) throw new Error('wtf');
	let [n1] = read_uvarint(v);
	if (n0 !== n1) throw new Error('wtf');
}

console.log('OK');