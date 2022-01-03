// return true if the request() error is due to bug
// this seems to be an geth bug (infura, cloudflare, metamask)
// related to not knowing the chain id
function is_header_bug(err) {
	return err.code === -32000 && err.message === 'header not found';
}

const RETRY_TIMES = 3;
const RETRY_DELAY = 500;

export async function retry_request(request_fn, arg) {
	let n = RETRY_TIMES;
	while (true) {
		try {
			return await request_fn(arg);
		} catch (err) {
			if (!is_header_bug(err) || !(n-- > 0)) throw err;
			await new Promise(ful => setTimeout(ful, RETRY_DELAY));
		}
	}
}