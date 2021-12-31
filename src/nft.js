import {ABIEncoder, Uint256} from './abi.js';
import {eth_call, supports_interface} from './eth.js';
import {checksum_address, fix_multihash_uri} from './utils.js';

export class NFT {
	constructor(provider, address, {strict = true, cache = true} = {}) {
		this.provider = provider;
		this.address = checksum_address(address); // throws
		this.type = undefined;
		this.type_error = undefined;
		this.strict = strict; // assumes 721 if not 1155
		this.queue = [];
		if (cache) {
			this.token_uris = {};
		}
	}
	async get_provider() {
		let p = this.provider;
		return p.isProviderView ? p.get_provider() : p;
	}
	async get_type() {
		let {queue} = this;
		if (!queue) {
			if (this.type_error) throw new Error(`Type resolution failed`, {cause: this.type_error});
			return this.type;
		}
		if (queue.length == 0) {
			try {
				let type;
				if (await supports_interface(await this.get_provider(), this.address, 'd9b67a26')) {
					type = 'ERC-1155';
				} else if (!this.strict || await supports_interface(await this.get_provider(), this.address, '80ac58cd')) {
					type = 'ERC-721';
				} else {
					type = 'Unknown';
				}
				this.type = type;
				this.queue = undefined;
				queue.forEach(x => x.ful());
				return type;
			} catch (err) {
				this.type_error = err;
				this.queue = undefined;
				queue.forEach(x => x.rej(err));
				throw err;
			}
		} else {
			return new Promise((ful, rej) => {
				queue.push({ful, rej});
			});
		}
	} 
	async get_token_uri(x) {
		let token = Uint256.wrap(x); // throws
		let {hex} = token;
		let {token_uris} = this;
		let uri = token_uris?.[hex]; // lookup cache
		if (!uri) {
			switch (await this.get_type()) {
				case 'ERC-721': {
					// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-721.md
					const SIG = 'c87b56dd'; // tokenURI(uint256)
					uri = (await eth_call(
						await this.get_provider(),
						this.address, 
						ABIEncoder.method(SIG).add_hex(hex)
					)).string();
					break;
				}
				case 'ERC-1155': {
					// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1155.md
					const SIG = '0e89341c';	// uri(uint256)
					uri = (await eth_call(
						await this.get_provider(), 
						this.address, 
						ABIEncoder.method(SIG).add_hex(hex)
					)).string();
					uri = uri.replace('{id}', hex.slice(2)); // 1155 standard (lowercase, no 0x)
					break;
				}
				default: throw new Error(`unable to query ${x} from ${this.address}`);
			}
			uri = fix_multihash_uri(uri);
			if (token_uris) token_uris[hex] = uri; // cache
		}
		return uri;
	}
}