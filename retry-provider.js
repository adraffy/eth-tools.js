export function retry(provider, retry = 2, delay = 1000) {
	if (typeof retry !== 'number' || retry < 1) throw new TypeError('expected retry > 0');
	if (typeof delay !== 'number' || delay < 0) throw new TypeError('expected delay >= 0');
	async function unfucked(args) {
		let n = 0;
		while (true) {
			try {
				return await provider.request(args);
			} catch (err) {
				if (error.code === -32000 && n++ < retry) { 
					// "header not found"
					// this seems to be an geth bug (infura, cloudflare, metamask)
					await new Promise(ful => setTimeout(ful, delay));
					continue;
				}
				throw err;
			}
		}
	}
	return new Proxy(provider, {
		get: function(obj, prop) {
			return prop === 'request' ? unfucked : obj[prop];
		}
	});
}