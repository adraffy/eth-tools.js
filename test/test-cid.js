import {CID, decode_multibase} from '../index.js';

let cid0 = CID.from_str('QmPggfboD39JAxTdFwK6oN8L1yKnntuhT2ECv51jjq453A');
console.log(cid0);
console.log(cid0.toString());
console.log(cid0.upgrade_v0());
console.log(cid0.upgrade_v0().toString());

let cid = CID.from_str('k51qzi5uqu5dhkaa0k9g05zvmzahc17376saxq61uu48o5zzuf4zg8nitoz689');

console.log(cid);
console.log(cid.toString());
console.log(cid.toString('b'));

cid = CID.from_str('bafzaajaiaejcan3c6h4e2rdtsopjgauuytcjhqvwbxozwnbcosimbvjvzh46hfsj');

console.log(cid.toString());
console.log(decode_multibase(cid.toString('b')));
