export function compare_arrays(a, b) {
	let n = a.length;
	let c = n - b.length;
	for (let i = 0; c == 0 && i < n; i++) c = a[i] - b[i];
	return c;
}

// returns promises mirror the initial promise
// callback is fired once with (value, err)

export function promise_queue(promise, callback) {
	let queue = [];	
	promise.then(ret => {
		for (let x of queue) x.ful(ret); 
		let cb = callback;
		if (cb) {
			callback = queue; // mark used
			cb(ret); // could throw
		}
	}).catch(err => {
		if (callback === queue) throw err; // success callback threw
		for (let x of queue) x.rej(err);
		callback?.(null, err); // could throw
	}).catch(err => {		
		console.error('Uncaught callback exception: ', err);
	});
	return () => new Promise((ful, rej) => {
		queue.push({ful, rej});
	});
}

export function data_uri_from_json(json) {
	return 'data:application/json;base64,' + btoa(JSON.stringify(json));
}

export function is_null_hex(s) {
	return /^(0x)?[0]+$/i.test(s); // should this be 0+?
}
