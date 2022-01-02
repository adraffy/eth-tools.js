import {ABIEncoder, Uint256} from './abi.js';
import {eth_call, supports_interface} from './eth.js';
import {promise_queue, data_uri_from_json} from './utils.js';
import {standardize_address} from './address.js';
import {fix_multihash_uri} from './multihash.js';

const TYPE_721 = 'ERC-721';
const TYPE_1155 = 'ERC-1155';
// legacy support
const TYPE_CRYPTO_PUNK = 'CryptoPunks';
const TYPE_UNKNOWN = 'Unknown';


export class NFT {
	constructor(provider, address, {strict = true, cache = true} = {}) {
		this.provider = provider;
		this.address = standardize_address(address); // throws
		this._type = undefined;
		this.type_error = undefined;
		this.strict = strict; // assumes 721 if not 1155
		if (cache) {
			this.token_uris = {};
		}
	}
	async get_provider() {
		let p = this.provider;
		return p.isProviderView ? p.get_provider() : p;
	}
	async get_type() {
		let temp = this._type;
		if (typeof temp === 'string') return temp;
		if (!temp) {
			if (this.address === '0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB') {
				return this._type = TYPE_CRYPTO_PUNK;
			}
			this._type = temp = promise_queue((async () => {
					if (await supports_interface(await this.get_provider(), this.address, 'd9b67a26')) {
						return TYPE_1155;
					} else if (!this.strict || await supports_interface(await this.get_provider(), this.address, '80ac58cd')) {
						return TYPE_721;
					} else if (await supports_interface(await this.get_provider(), this.address, 'd31b620d')) {
						return TYPE_721;
					} else {
						return TYPE_UNKNOWN;
					}
				})(), 
				type => this._type = type
			);
		}
		return temp();
	} 
	async _uri_from_token(token) {
		switch (await this.get_type()) {
			case TYPE_CRYPTO_PUNK: {
				let {dec} = token;			
				return data_uri_from_json({
					name: `CryptoPunk #${dec}`,
					image: `https://www.larvalabs.com/public/images/cryptopunks/punk${dec}.png`,
					external_url:  `https://www.larvalabs.com/cryptopunks/details/${dec}`
				});
			}
			case TYPE_721: {
				// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-721.md
				return eth_call(
					await this.get_provider(),
					this.address, 
					ABIEncoder.method('tokenURI(uint256)').number(token)
				).then(x => x.string()).then(s => {
					return fix_multihash_uri(s.trim());
				});
			}
			case TYPE_1155: {
				// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1155.md
				return eth_call(
					await this.get_provider(), 
					this.address, 
					ABIEncoder.method('uri(uint256)').number(token)
				).then(x => x.string()).then(s => {
					// 1155 standard (lowercase, no 0x)
					return fix_multihash_uri(s.replace('{id}', token.hex.slice(2)).trim());
				});
			}
			default: throw new Error(`unable to query ${token} from ${this.address}`);
		}
	}
	async get_token_uri(x) {
		let token = Uint256.wrap(x); // throws
		let cache = this.token_uris;
		if (!cache) return this._uri_from_token(token); // no cache
		let key = token.hex;
		let temp = cache[key];
		if (typeof temp === 'string') return temp;
		if (!temp) {
			cache[key] = temp = promise_queue(
				this._uri_from_token(token),
				uri => {
					if (typeof uri === 'string') {
						cache[key] = uri;
					} else {
						delete cache[key];
					}
				}
			);
		}
		return temp();
	}
}