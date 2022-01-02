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
		this.strict = strict; // assumes 721 if not 1155
		this._type = undefined;
		this._name = undefined;
		this._supply = undefined;
		if (cache) {
			this.token_uris = {};
		}
	}
	async call(...args) {
		return eth_call(await this.get_provider(), this.address, ...args);
	}
	async supports(method) {
		return supports_interface(await this.get_provider(), this.address, method);
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
					if (await this.supports('d9b67a26')) {
						// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1155.md
						return TYPE_1155;
					} else if (!this.strict || await this.supports('80ac58cd')) {
						// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-721.md
						return TYPE_721;
					} else if (await this.supports('d31b620d')) { 
						/*console.log([
							'name()', 
							'symbol()', 
							'totalSupply()', 
							'balanceOf(address)', 
							'ownerOf(uint256)', 
							'approve(address,uint256)', 
							'safeTransferFrom(address,address,uint256)'
						].reduce((a, x) => a.xor(keccak().update(x).bytes), Uint256.zero()).hex.slice(0, 10));*/
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
				return this.call(ABIEncoder.method('tokenURI(uint256)').number(token)).then(x => x.string()).then(s => {
					return fix_multihash_uri(s.trim());
				});
			}
			case TYPE_1155: {
				return this.call(ABIEncoder.method('uri(uint256)').number(token)).then(x => x.string()).then(s => {
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
	async get_name() {
		let temp = this._name;
		if (typeof temp === 'string') return temp;
		if (!temp) {
			switch (await this.get_type()) {
				case TYPE_CRYPTO_PUNK:
				case TYPE_721: {
					this._name = temp = promise_queue(
						this.call(ABIEncoder.method('name()')).then(x => x.string()),
						name => this._name = name
					);
					break;
				}
			}
		}
		return temp();
	}
	async get_supply() {
		let temp = this._supply;
		if (typeof temp === 'number') return temp;
		if (!temp) {
			switch (await this.get_type()) {
				case TYPE_CRYPTO_PUNK:
				case TYPE_721: {
					this._supply = temp = promise_queue(
						this.call(ABIEncoder.method('totalSupply()')).then(x => x.number()).catch(err => {
							if (err.reverted) return NaN; // not ERC721Enumerable 
							throw err;
						}),
						n => this._supply = n
					);
					break;
				}				
				default: {
					// unknown supply
					return this._supply = NaN;
				}
			}
		}
		return temp();
	}
	/*
	async get_balance(token, owner) {
		// this could cache

	}
	async _get_balance(token, owner) {

	}
	*/
}