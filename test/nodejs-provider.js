import fetch from 'node-fetch';
import WebSocket from 'ws';
import {FetchProvider, WebSocketProvider} from '../index.js';
const idle_timeout = 1000;
export const WS = new WebSocketProvider({url: 'ws://192.168.77.10:8546', WebSocket, idle_timeout});
export const FETCH = new FetchProvider({url: 'https://cloudflare-eth.com', fetch, idle_timeout});