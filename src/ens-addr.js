const TYPES = {};
const NAMES = {};

export function define_ens_addr(addr) {
	if (!(addr instanceof ENSAddr)) throw new TypeError('expected ENSAddr');
	let {type, name} = addr;
	let prev = TYPES[type] ?? NAMES[name];
	if (prev) throw new TypeError(`${prev} already defined`);
	TYPES[type] = NAMES[name] = addr;
}

export function find_ens_addr(x) {
	if (x instanceof ENSAddr) {
		return x;
	} else if (typeof x === 'string') {
		return NAMES[x];
	} else if (is_valid_type(x)) {
		return TYPES[x];
	} 
}

export function coerce_ens_addr_type(x) {
	let addr = find_ens_addr(x);
	if (addr) return addr.type;
	if (is_valid_type(x)) return x;
}

function is_valid_type(x) {
	return Number.isSafeInteger(x);
}

export class ENSAddr {
	constructor(type, name) {
		if (!is_valid_type(type)) throw new TypeError('type must be integer');
		if (typeof name !== 'string') throw new TypeError('name must be string');
		this.type = type;
		this.name = name;
	}
	str_from_bytes(v) {
		if (!(v instanceof Uint8Array)) throw new TypeError('expected bytes');
		let s = this.str(v);
		if (typeof s !== 'string') throw new Error('invalid format');
		return s;
	}
	bytes_from_str(s) {
		if (typeof s !== 'string') throw new TypeError('expected string');
		let v = this.bytes(s);
		if (!(v instanceof Uint8Array)) throw new Error('unknown format');
		return v;
	}
	toString() {
		return this.name;
	}
	str() { throw new TypeError('missing implementation'); }
	bytes() { throw new TypeError('missing implementation'); }
}

// multiple coders are supported as long as they dont throw
export class ENSAddrCoder extends ENSAddr {
	constructor(type, name, ...coders) {
		super(type, name);
		this.coders = coders;
	}
	bytes(s) {
		for (let x of this.coders) {
			let ret = x.bytes(s);
			if (ret) return ret;
		}
	}
	str(v) {
		for (let x of this.coders) {
			let ret = x.str(v);
			if (ret) return ret;
		}
	}
}
