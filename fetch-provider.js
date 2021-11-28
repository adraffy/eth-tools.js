export class FetchProvider {
	constructor(url, fetch_api) {
		if (!fetch_api) fetch_api = globalThis.fetch.bind(globalThis); 
		if (typeof fetch_api !== 'function') throw new TypeError('fetch api should be a function');
		if (typeof url !== 'string') throw new TypeError('expected url');
		this.fetch_api = fetch_api;
		this.url = url;	
		this.id = 0;
		this.retry_max = 2;
		this.retry_ms = 2000;
	}
	async request(obj, attempt = 0) {
		if (typeof obj !== 'object') throw new TypeError('expected object');
		let res = await this.fetch_api(this.url, {
			method: 'POST',
			body: JSON.stringify({...obj, jsonrpc: '2.0', id: ++this.id})
		});
		if (res.status !== 200) throw new Error(`provider error: ${res.status}`);
		let json;
		try {
			json = await res.json();
		} catch (err) {
			throw new Error('expected json');
		}
		let {error} = json;
		if (error) { // assume object?		
			if (error.code === -32000 && attempt < this.retry_max) {
				// "header not found" bug?
				await new Promise(ful => setTimeout(ful, this.retry_ms));
				return this.request(obj, attempt + 1);
			}
			let err = new Error(error.message ?? 'unknown rpc error');
			err.code = error.code;
			throw err;
		}
		return json.result;
	}
}