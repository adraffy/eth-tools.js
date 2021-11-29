// minimal window.ethereum provider
// https://docs.metamask.io/guide/ethereum-provider.html
export class FetchProvider {
	constructor({url, chain_id = 1, fetch: fetch_api}) {
		if (typeof url !== 'string') throw new TypeError('expected url');
		if (!fetch_api) fetch_api = globalThis.fetch.bind(globalThis); 
		if (typeof fetch_api !== 'function') throw new TypeError('fetch should be a function');
		this.url = url;	
		this.fetch_api = fetch_api;
		this.chain_id = chain_id;
		this.id = 0;
	}
	get chainId() { return this.chain_id; }
	async request(obj) {
		if (typeof obj !== 'object') throw new TypeError('expected object');
		let res = await this.fetch_api(this.url, {
			method: 'POST',
			body: JSON.stringify({...obj, jsonrpc: '2.0', id: ++this.id})
		});
		if (res.status !== 200) throw new Error(`provider fetch error: ${res.status}`);
		let json;
		try {
			json = await res.json();
		} catch (cause) {
			throw new Error('expected json', {cause});
		}
		let {error} = json;
		if (error) {
			let err = new Error(error.message ?? 'unknown error');
			err.code = error.code;
			throw err;
		}
		return json.result;
	}
}