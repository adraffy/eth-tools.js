import {ABIEncoder, ABIDecoder, bytes4_from_method} from './abi.js';

// convenience for making an eth_call
// return an ABIDecoder
// https://eth.wiki/json-rpc/API#eth_call
// https://www.jsonrpc.org/specification
// https://docs.soliditylang.org/en/latest/abi-spec.html
export async function eth_call(provider, tx, enc = null, tag = 'latest') {
	if (typeof provider !== 'object') throw new TypeError('expected provider');
	if (typeof tx === 'string') tx = {to: tx};
	if (enc instanceof ABIEncoder) tx.data = enc.build_hex();
	try {
		let hex = await provider.request({method: 'eth_call', params:[tx, tag]});
		return ABIDecoder.from_hex(hex);
	} catch (err) {
		if (err.code == -32000 && err.message === 'execution reverted') {
			err.reverted = true;
		}
		throw err;
	}
}

export async function supports_interface(provider, contract, sig) {
	const SIG = '01ffc9a7' // supportsInterface(bytes4)
	return (await eth_call(provider, contract, ABIEncoder.method(SIG).bytes(bytes4_from_method(sig)))).boolean();
}