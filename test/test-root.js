import {eth_call, ABIEncoder} from '../index.js';
import provider from './nodejs-provider.js';

const ENS_ROOT = '0xaB528d626EC275E3faD363fF1393A41F581c5897';
const SIG = '3f15457f'; // ens()
console.log((await eth_call(provider, ENS_ROOT, ABIEncoder.method(SIG))).addr());