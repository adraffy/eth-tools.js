export function random_bytes(n) {	
	let v = new Uint8Array(n);
	for (let i = 0; i < n; i++) {
		v[i] = (Math.random() * 256)|0; 
	}
	return v;
}

export function random_choice(v) {
	return v[Math.random() * v.length|0];
}

export function random_safe_unsigned() {
	return Math.floor(Math.random() * (1 + Number.MAX_SAFE_INTEGER)); // [0, max]
}

export function random_safe_integer() {
	let r = 2 * Math.random();
	return r > 1 ? Math.floor(Number.MIN_SAFE_INTEGER * (r - 1)) // [min, -1]
	             : Math.floor(Number.MAX_SAFE_INTEGER * r);      // [0, max]
}