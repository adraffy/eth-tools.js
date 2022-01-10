import {Bech32} from '../index.js';

[
	'A12UEL5L',
	'A1LQFN3A',
	'an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6',
	'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx',
	'11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8',
	'split1checkupstagehandshakeupstreamerranterredcaperredlc445v',
	'?1v759aa'
].forEach(input => {
	let bech = Bech32.from_str(input);
	if (bech.toString() !== input.toLowerCase()) {
		throw new Error('wtf');
	}
});

/*
let s = 'bc1qjqg9slurvjukfl92wp58y94480fvh4uc2pwa6n';
let bech = Bech32.from_str(s);
console.log(bech);
console.log(bech.toString());
console.log(s);
*/