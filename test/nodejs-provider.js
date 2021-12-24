import fetch from 'node-fetch';
import {FetchProvider} from '../fetch-provider.js';
import WebSocket from 'ws';
import {WebSocketProvider} from '../ws-provider.js';
export default process.env.USER === 'raffy' 
	? new WebSocketProvider({url: 'ws://192.168.77.10:8546', WebSocket, idle_timeout: 1000})
	: new FetchProvider({url: 'https://cloudflare-eth.com', fetch});