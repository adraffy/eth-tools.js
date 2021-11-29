import {FetchProvider} from '../fetch-provider.js';
import fetch from 'node-fetch';
export default new FetchProvider({url: 'https://cloudflare-eth.com', fetch});