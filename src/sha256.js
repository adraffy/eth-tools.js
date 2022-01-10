
export function sha256() { return new SHA256(); }

class SHA256 {
	constructor() {
		this.words = Array(64);
		this.block = undefined;
		this.index = 0;
		this.wrote = 0;
		this.state = Int32Array.of(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);
	}
	update(v) {
		if (!(v instanceof Uint8Array)) {
			if (v instanceof ArrayBuffer) { 
				v = new Uint8Array(v);
			} else if (Array.isArray(v)) { 
				v = Uint8Array.from(v);
			} else if (typeof v === 'string') {
				let s;
				try {
					s = unescape(encodeURIComponent(v));
				} catch (cause) {
					throw new Error('malformed utf8', {cause});
				}
				let n = s.length;
				v = new Uint8Array(n);
				for (let i = 0; i < n; i++) {
					v[i] = s.charCodeAt(i);
				}
			} else {
				throw new TypeError('expected bytes');
			}
		}
		let {block, index, wrote} = this;
		if (wrote < 0) throw new Error('already finalized');
		let n = v.length;
		this.wrote = wrote + n;
		while (true) {		
			let w = 64 - index;
			if (n < w) break;
			if (index == 0) {
				this._update(v.subarray(0, w));
			} else {
				block.set(v.subarray(0, w), index);
				this._update(block);
			}
			v = v.subarray(w);
			n -= w;
			index = 0;
		}
		if (n > 0) {
			if (!block) this.block = block = new Uint8Array(64);
			block.set(v, index);
			index += n;
		}
		this.index = index;
		return this;
	}
	get hex() { return [...this.bytes].map(x => x.toString(16).padStart(2, '0')).join(''); }
	get bytes() {
		if (this.wrote >= 0) {
			let {block, index, wrote} = this;
			if (!block) block = new Uint8Array(64);
			block[index] = 0x80;
			block.fill(0, index + 1);
			if (index >= 56) { // 64-8
				this._update(block);
				block.fill(0);
			}
			wrote *= 8; // bits
			let U = 0x100000000;
			if (wrote >= U) {
				let upper = (wrote / U)|0;
				block[56] = upper >> 24;
				block[57] = upper >> 16;
				block[58] = upper >>  8;
				block[59] = upper;
			}
			block[60] = wrote >> 24;
			block[61] = wrote >> 16;
			block[62] = wrote >>  8;
			block[63] = wrote;
			this._update(block);
			this.wrote = -1; // mark as finalized
		}
		let v = new Uint8Array(32);
		let {state} = this;
		let pos = 0;
		for (let x of state) {
			v[pos++] = x >> 24;
			v[pos++] = x >> 16;
			v[pos++] = x >> 8;
			v[pos++] = x;
		}
		return v;
		//return new Uint8Array(this.state.buffer.slice());
	}
	_update(block) {
		let {state, words} = this;
		for (let i = 0; i < 64; i += 4) {
			words[i>>2] = (block[i] << 24) | (block[i+1] << 16) | (block[i+2] << 8) | block[i+3];
		}
		for (let i = 16; i < 64; i++) {
			words[i] = (gamma1(words[i - 2]) + words[i - 7] + gamma0(words[i - 15]) + words[i - 16]) | 0;
		}
		let [a, b, c, d, e, f, g, h] = state;
		for (let i = 0; i < 64; i++) {
			let T1 = (h + sigma1(e) + ch(e, f, g) + K[i] + words[i]) | 0;
			let T2 = (sigma0(a) + maj(a, b, c)) | 0;
			h = g;
			g = f;
			f = e;
			e = (d + T1) | 0;
			d = c;
			c = b;
			b = a;
			a = (T1 + T2) | 0;
		}
		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
		state[4] += e;
		state[5] += f;
		state[6] += g;
		state[7] += h; 
	}
}
 
function ch (x, y, z) {
	return z ^ (x & (y ^ z))
}
function maj (x, y, z) {
	return (x & y) | (z & (x | y))
}
function sigma0 (x) {
	return (x >>> 2 | x << 30) ^ (x >>> 13 | x << 19) ^ (x >>> 22 | x << 10)
}
function sigma1 (x) {
	return (x >>> 6 | x << 26) ^ (x >>> 11 | x << 21) ^ (x >>> 25 | x << 7)
}
function gamma0 (x) {
	return (x >>> 7 | x << 25) ^ (x >>> 18 | x << 14) ^ (x >>> 3)
}
function gamma1 (x) {
	return (x >>> 17 | x << 15) ^ (x >>> 19 | x << 13) ^ (x >>> 10)
}
const K = [
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
];