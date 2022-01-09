export class Lookup {
	constructor(lookup) {
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
		return v.map(x => this.lookup[x]).join('');
	}
}

export class Prefix0 extends Lookup {
	bytes_from_str(s) {
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
	str_from_bytes(v) {
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

export class RFC4648 extends Lookup {
	constructor(lookup, w) {
		super(lookup);
		this.w = w;
	}
	bytes_from_str(s, pad) {
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
	str_from_bytes(v, pad) {
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