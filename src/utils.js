export function compare_arrays(a, b) {
	let n = a.length;
	let c = n - b.length;
	for (let i = 0; c == 0 && i < n; i++) c = a[i] - b[i];
	return c;
}

export function promise_object_setter(obj, key, promise) {
	obj[key] = promise;
	return promise.then(ret => {
		obj[key] = ret;
		return ret;
	}).catch(err => {
		delete obj[key];
		throw err;
	});
}

export function data_uri_from_json(json) {
	return 'data:application/json;base64,' + btoa(JSON.stringify(json));
}

export function is_null_hex(s) {
	return /^(0x)?[0]+$/i.test(s); // should this be 0+?
}

// replace ipfs:// with default https://ipfs.io
export function replace_ipfs_protocol(s) {
	return s.replace(/^ipfs:\/\//i, 'https://dweb.link/ipfs/');
}