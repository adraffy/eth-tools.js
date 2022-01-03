import {find_chain, defined_chains} from '../index.js';

console.log(find_chain(1).name);

console.log(defined_chains());

console.log(find_chain(137).explorer_address_uri('a'));