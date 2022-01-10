import {sha256} from '../src/sha256.js';

[
	['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
	['raffy', 'c683d2351235cbd01b827ba91f492103f02d8173ec1e29145f9468e8e2910e75'],
	['raffy.eth', '4f08607cd23f473d862b20039109d4ad09e931d28cc5fb8b4c3d8a3d4c24406a'],
	['The quick brown fox jumps over the lazy dog', 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592'],
	['12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364',
		'67c30f8e137bc53c2ecdcff74cd6a4fe03260e4ac60e5dfb55160e266afcc5a7']
].forEach(([input, expect]) => {
	let result = sha256().update(input).hex;
	if (result !== expect) {
		console.log({input, expect, result});
		throw new Error('wtf');
	}
});

