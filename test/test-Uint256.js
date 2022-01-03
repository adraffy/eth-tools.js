import {Uint256} from '../index.js';
import {random_bytes, random_safe_unsigned, random_safe_integer} from './utils.js';

const N = 100000;

console.log(Uint256.from_number(0).min_hex);
console.log(Uint256.from_number(255).digits(2));
console.log(Uint256.from_number(343).digits(7));

for (let i = 0; i < N; i++) {
	let u0 = Uint256.from_bytes(random_bytes(Math.random() * 32|0));	
	let u1 = Uint256.from_hex(u0.hex);
	let u2 = Uint256.from_dec(u1.dec);
	if (u0.compare(u2) != 0) {
		console.log({u0, u1, u2});
		throw new Error('wtf dec/hex');
	}
}

for (let i = 0; i < N; i++) {
	let n0 = random_safe_unsigned();
	let u = Uint256.from_number(n0);
	let n1 = u.unsigned;
	if (n0 != n1) {
		console.log({i, n0, n1, u});
		throw new Error('wtf unsigned');
	}
}

for (let i = 0; i < N; i++) {
	let n0 = random_safe_integer();
	let u = Uint256.from_number(n0);
	let n1 = u.number;
	if (n0 != n1) {
		console.log({i, n0, n1, u});
		throw new Error('wtf signed');
	}
}

for (let i = 0; i < N; i++) {
	let a = Math.floor(random_safe_unsigned() / 2);
	let b = Math.floor(random_safe_unsigned() / 2);
	let u = Uint256.from_number(a).add(b);
	let c = a + b;
    let d = u.number;
	if (c != d) {
		console.log({a, b, c, d, u});
		throw new Error('wtf add');
	}
}