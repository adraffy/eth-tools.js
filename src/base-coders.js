export class Coder {
	bytes_from_str(s) {
		if (typeof s !== 'string') throw new TypeError('expected string');
		return this.bytes(s);
	}
	str_from_bytes(v) {
		if (Array.isArray(v)) v = Uint8Array.from(v);
		if (!(v instanceof Uint8Array)) throw new TypeError('expected bytes');
		return this.str(v);
	}
	// overriden by subclasses
	bytes() { throw new TypeError('bug: not implemented'); }
	str() { throw new TypeError('bug: not implemented'); }
}

export class MapStringCoder extends Coder {
	constructor(coder, fn) {
		super();
		this.coder = coder;
		this.fn = fn;
	}
	bytes(s) {
		return this.coder.bytes(this.fn(s, true));
	}
	str(v) {
		return this.fn(this.coder.str(v), false);
	}
}

export class MapBytesCoder extends Coder {
	constructor(coder, fn) {
		super();
		this.coder = coder;
		this.fn = fn;
	}
	bytes(s) {
		return this.fn(this.coder.bytes(s, true));
	}
	str(v) {
		return this.coder.str(this.fn(v, false));
	}
}

export class BaseCoder extends Coder {
	constructor(lookup) {
		super();
		let v = [...lookup];
		if (v.length !== lookup.length) throw new TypeError(`expected UTF16`);
		this.lookup = lookup;
		this.map = Object.fromEntries(v.map((x, i) => [x, i]));
	}
	parse(s) {
		let i = this.map[s];
		if (i === undefined) throw new TypeError(`invalid digit ${s}`);
		return i;
	}
	format(v) {
		return v.reduce((s, x) => s + this.lookup[x], '');
	}
}

// https://github.com/Chia-Network/chia-blockchain/blob/af0d6385b238c91bff4fec1a9e9c0f6158fbf896/chia/util/bech32m.py#L85
export function convert_bits(v, src_bits, dst_bits, pad) {
	if (!Array.isArray(v) && !ArrayBuffer.isView(v)) throw new TypeError('expected array');
	if (!Number.isSafeInteger(src_bits) || src_bits < 1 || src_bits > 32) throw new TypeError('invalid from bits');
	if (!Number.isSafeInteger(dst_bits) || dst_bits < 1 || dst_bits > 32) throw new TypeError('invalid to bits');
	let acc = 0;
	let bits = 0;
	let ret = [];
	let mask = (1 << dst_bits) - 1;
	for (let x of v) {
		if (x < 0 || (x >> src_bits) !== 0) throw new Error('invalid digit');
		acc = (acc << src_bits) | x;
		bits += src_bits;
		while (bits >= dst_bits) {
			bits -= dst_bits;
			ret.push((acc >> bits) & mask);
		}
	}
	if (pad) {
		if (bits > 0) {
			ret.push((acc << (dst_bits - bits)) & mask);
		}
	} else if (bits >= src_bits || ((acc << (dst_bits - bits)) & mask)) {
		throw new Error('malformed');
	}
	return Uint8Array.from(ret);
}

export class Prefix0 extends BaseCoder {
	bytes(s) {
		let {lookup} = this;
		let base = lookup.length;
		let n = s.length;
		let v = new Uint8Array(n);
		let pos = 0;
		for (let c of s) {
			let carry = this.parse(c);
			for (let i = 0; i < pos; i++) {
				carry += v[i] * base;
				v[i] = carry;
				carry >>= 8;
			}
			while (carry > 0) {
				v[pos++] = carry;
				carry >>= 8;
			}
		}
		for (let i = 0; i < n && s[i] === lookup[0]; i++) pos++;
		return v.subarray(0, pos).reverse();
	}
	str(v) {
		let base = this.lookup.length;
		let u = [];
		for (let x of v) {
			for (let i = 0; i < u.length; ++i) {
				let xx = (u[i] << 8) | x;
				u[i] = xx % base;
				x = (xx / base)|0;
			}
			while (x > 0) {
				u.push(x % base);
				x = (x / base)|0;
			}
		}	
		for (let i = 0; i < v.length && v[i] == 0; i++) u.push(0);
		return this.format(u.reverse());
	}
}

export class RFC4648 extends BaseCoder {
	constructor(lookup, w) {
		super(lookup);
		this.w = w;
	}
	bytes(s, pad) {
		let {w} = this;
		let n = s.length;
		let pos = 0;
		let carry = 0;
		let width = 0;
		// remove padding
		while (pad && n > 0 && s[n-1] == '=') --n;
		let v = new Uint8Array((n * w) >> 3);		
		for (let i = 0; i < n; i++) {
			carry = (carry << w) | this.parse(s[i]);
			width += w;
			if (width >= 8) {
				v[pos++] = (carry >> (width -= 8)) & 0xFF;
			}
		}
		// the bits afterwards should be 0
		if ((carry << (8 - width)) & 0xFF) throw new Error('wtf');
		return v;
	}
	str(v, pad) {
		let {w, lookup} = this;
		let mask = (1 << w) - 1;
		let carry = 0;
		let width = 0;
		let s = '';
		let n = v.length;
		for (let i = 0; i < n; i++) {
			carry = (carry << 8) | v[i];
			width += 8;
			while (width >= w) {
				s += lookup[(carry >> (width -= w)) & mask];
			}
		}
		if (width) { // left align the remaining bits
			s += lookup[(carry << (w - width)) & mask];
		}
		while (pad && (s.length * w) & 7) s += '=';
		return s;
	}
}