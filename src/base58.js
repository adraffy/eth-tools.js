// https://tools.ietf.org/id/draft-msporny-base58-03.html

// removed: "IOl0+/"
const BASE_58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; 

export function base58_from_bytes(v) {
	let digits = [];
	let zero = 0;
	for (let x of v) {
		if (digits.length == 0 && x == 0) {
			zero++;
			continue;
		}
		for (let i = 0; i < digits.length; ++i) {
			let xx = (digits[i] << 8) | x
			digits[i] = xx % 58;
			x = (xx / 58) | 0;
		}
		while (x > 0) {
			digits.push(x % 58);
			x = (x / 58) | 0
		}
	}
	for (; zero > 0; zero--) digits.push(0);
	return String.fromCharCode(...digits.reverse().map(x => BASE_58.charCodeAt(x)));
}

export function bytes_from_base58(s) {
	if (typeof s !== 'string') throw new TypeError('expected string');
	let v = new Uint8Array(s.length);
	let zeros = 0;
	let n = 0;
	for (let c of s) {
		let carry = BASE_58.indexOf(c);
		if (carry < 0) throw new TypeError('expected base58 string');
		if (n == 0) {
			if (carry == 0) {
				zeros++;
				continue;
			} else {
				n = 1;
			}
		}
		for (let i = 0; i < n; i++) {
			carry += v[i] * 58;
			v[i] = carry;
			carry >>= 8;
		}
		while (carry > 0) {
			v[n++] = carry;
			carry >>= 8;
		}
	}
	n += zeros;
	for (let a = 0, b = n - 1; a < b; a++, b--) {
		let temp = v[a];
		v[a] = v[b];
		v[b] = temp;
	}
	return v.subarray(0, n);
}