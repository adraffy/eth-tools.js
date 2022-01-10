import {hex_from_bytes} from '@adraffy/keccak';
import {standardize_address} from './address.js';
import {Coder} from './base-coders.js';

export const NULL_ADDRESS = '0x0000000000000000000000000000000000000000';

class HexCoder extends Coder {
	str(v) {
		return standardize_address(hex_from_bytes(v));
	}
	bytes(s) {
		return bytes_from_hex(standardize_address(s))
	}
}

const X = new HexCoder();
export {X as HexCoder};
