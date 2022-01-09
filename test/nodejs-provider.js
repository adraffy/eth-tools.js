import fetch from 'node-fetch';
import WebSocket from 'ws';
import {FetchProvider, WebSocketProvider, Providers} from '../index.js';
const idle_timeout = 1000;
function no_idle_fetch(url) {
	return new FetchProvider({url, fetch, idle_timeout});
}
export const WS = new WebSocketProvider({url: 'ws://192.168.77.10:8546', WebSocket, idle_timeout});
export const FETCH = no_idle_fetch('https://cloudflare-eth.com');
export const providers = new Providers()
	.add_static(1, WS)
	.add_static(1, FETCH)
	.add_static(137, no_idle_fetch('https://polygon-rpc.com'))
	.add_static(43114, no_idle_fetch('https://api.avax.network/ext/bc/C/rpc'));