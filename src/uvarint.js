//https://github.com/multiformats/unsigned-varint

const MAX_SCALE = (() => {
	let max = 1;
	while (true) {
		let next = max * 0x80;
		if (!Number.isSafeInteger(next)) break;
		max = next;
	}
	return max;
})();

export function assert_uvarint(i) {	
	if (!Number.isSafeInteger(i) || i < 0) {
		throw new TypeError(`expected uvarint: ${i}`);
	}
}

// returns number of bytes to encode the int
export function sizeof_uvarint(i) {
	assert_uvarint(i);
	let len = 1;
	for (; i >= 0x80; len++) {
		i = Math.floor(i / 0x80);
	}
	return len;
}

// reads a uvarint from Uint8Array 
// returns [result, subarray]
// where subarray sliced off what was consumed
export function read_uvarint(v, pos = 0) {
	if (!ArrayBuffer.isView(v)) {
		throw new TypeError(`expected ArrayBufferView`);
	}
	let i = 0;
	let x = 1;
	while (true) {
		if (pos >= v.length) throw new RangeError(`buffer overflow`);
		let next = v[pos++];
		i += (next & 0x7F) * x;
		if ((next & 0x80) == 0) break;
		if (x == MAX_SCALE) throw new RangeError('uvarint overflow');
		x *= 0x80;
	}
	return [i, v.subarray(pos)];
}

// write a uvarint of i into Uint8Array at pos
// returns new position
export function write_uvarint(v, i, pos = 0) {
	if (!Array.isArray(v) && !ArrayBuffer.isView(v)) {
		throw new TypeError(`expected ArrayLike`);
	}
	assert_uvarint(i);
	while (true) {
		if (pos >= v.length) throw new RangeError(`buffer overflow`);
		if (i < 0x80) break;
		v[pos++] = (i & 0x7F) | 0x80;
		i = Math.floor(i / 0x80);
	}
	v[pos++] = i;	
	return pos;
}