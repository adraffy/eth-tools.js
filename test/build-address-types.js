import fetch from 'node-fetch';
import {writeFileSync} from 'fs';

function local_file(name) {
	return new URL(name, import.meta.url).pathname;
}

let res = await fetch('https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0044.md');
if (res.status !== 200) {
	throw new Error('wtf');
}
let text = await res.text();

let map = {};

// find coins with names
for (let line of text.split('\n')) {
	let match = line.match(/^([\d]+)\s*\|\s*(0x[0-9a-f]{8})\s*\|\s*([a-z0-9]*)\s*\|.*$/i);
	if (!match) continue;
	let [_, coin, code, name] = match;
	if (name.length == 0) continue;
	let prev = map[name];
	if (prev === false) continue; // ignored
	if (typeof prev === 'number') {
		map[name] = false;
		console.log(`conflict: ${name}`);
	}
	map[name] = parseInt(coin);
}

//console.log(map);

// remove coins name conflicts
for (let [k, v] of Object.entries(map)) {
	if (v === false) {
		delete map[k];
	}	
}

writeFileSync(local_file('../ens-address-types.js'), `export default ${JSON.stringify(map, null, 2)}`);


