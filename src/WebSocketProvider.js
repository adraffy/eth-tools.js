import {EventEmitter} from './EventEmitter.js';
export class WebSocketProvider extends EventEmitter {
	constructor({url, WebSocket: ws_api, request_timeout = 30000, idle_timeout = 60000}) {
		if (typeof url !== 'string') throw new TypeError('expected url');
		if (!ws_api) ws_api = globalThis.WebSocket;
		if (!ws_api) throw new Error('unknown WebSocket implementation');
		super();
		this.url = url;
		this._ws_api = ws_api;
		this._request_timeout = request_timeout;
		this._idle_timeout = idle_timeout;
		this._idle_timer = undefined;
		this._ws = undefined;
		this._terminate = undefined;
		this._reqs = undefined;
		this._subs = new Set();
		this._id = undefined;
		this._chain_id = undefined;
	}
	source() {
		return this.url;
	}
	// idle timeout is disabled while subscribed
	get idle_timeout() { return this._idle_timeout; }
	set idle_timeout(t) {
		this.idle_timeout = t|0;
		this._restart_idle();
	}
	disconnect() {
		this._terminate?.(new Error('Forced disconnect'));
	}
	_restart_idle() {
		clearTimeout(this._idle_timer);
		if (this._idle_timeout > 0 && (this._subs.size == 0 && Object.keys(this._reqs).length == 0)) {
			const {_terminate} = this; // snapshot
			this._idle_timer = setTimeout(() => {
				_terminate(new Error('Idle timeout'));
			}, this._idle_timeout);
		}
	}
	async request(obj) {
		if (typeof obj !== 'object') throw new TypeError('expected object');
		let {method, params} = obj;
		if (typeof method !== 'string') throw new Error(`expected method`);
		if (params && !Array.isArray(params)) throw new Error('expected params array');
		await this.ensure_connected();
		switch (method) {
			case 'eth_chainId': return this._chain_id; // avoid rpc
			case 'eth_subscribe': return this._request(obj).then(ret => {
				this._subs.add(ret);
				clearTimeout(this._idle_timer);
				return ret;
			});
			case 'eth_unsubscribe': return this._request(obj).then(ret => {
				this._subs.delete(params[0]);
				this._restart_idle();
				return ret;
			});
			default: return this._request(obj);
		}
	}
	// private:
	// assumes ws is connected
	// does not intercept method
	_request(obj) {
		const id = ++this._id; 
		const {_reqs, _ws, _request_timeout: t} = this; // snapshot
		clearTimeout(this._idle_timer);
		return new Promise((ful, rej) => {
			let timer = t > 0 ? setTimeout(() => {
				delete _reqs[id];
				this._restart_idle();
				rej(new Error('Timeout'));
			}, t) : undefined;
			_reqs[id] = {timer, ful, rej};
			_ws.send(JSON.stringify({jsonrpc: '2.0', id, ...obj}));
		});
	}
	async ensure_connected() {
		let {_ws} = this;
		if (Array.isArray(_ws)) { // currently connecting
			return new Promise((ful, rej) => {
				_ws.push({ful, rej});
			});
		} else if (_ws) { // already connected
			return;
		}
		const queue = this._ws = []; // change state
		const ws = new this._ws_api(this.url); 
		//console.log('Connecting...');
		try {  
			await new Promise((ful, rej) => {
				this._terminate = rej;
				let timer = setTimeout(() => rej(new Error('Timeout')), this._request_timeout);
				ws.addEventListener('close', rej);
				ws.addEventListener('error', rej);
				ws.addEventListener('open', () => {
					ws.removeEventListener('error', rej); 
					ws.removeEventListener('close', rej);
					clearTimeout(timer);
					ful();
				});
			});
		} catch (err) {
			ws.close();
			this._ws = undefined; // reset state
			this._terminate = undefined;
			for (let {rej} of queue) rej(err);
			this.emit('connect-error', err);
			throw err;
		}
		//console.log('Handshaking...');
		this._ws = ws; // change state
		this._id = 0;
		let reqs = this._reqs = {};
		// setup error handlers
		let close_handler;
		let error_handler = this._terminate = (err) => {
			ws.removeEventListener('close', close_handler);
			ws.removeEventListener('error', error_handler);
			ws.close();
			this._ws = undefined; // reset state
			this._terminate = undefined;
			this._reqs = undefined;
			this._id = undefined;
			this._chain_id = undefined;
			this._subs.clear();
			clearTimeout(this._idle_timer);
			for (let {rej} of Object.values(reqs)) rej(err);
			this.emit('disconnect', err);
		};
		close_handler = () => error_handler(new Error('Unexpected close'));
		ws.addEventListener('close', close_handler);
		ws.addEventListener('error', error_handler);
		ws.addEventListener('message', ({data}) => {
			let json = JSON.parse(data); // throws
			let {id} = json;
			if (id === undefined) {
				let {method, params: {subscription, result}} = json;
				this.emit('message', {type: method, data: {subscription, result}});
			} else {
				let request = reqs[id];	
				if (!request) return;
				delete reqs[json.id];
				clearTimeout(request.timer);
				this._restart_idle();
				let {result, error} = json;
				if (result) return request.ful(result);
				let err = new Error(error?.message ?? 'Unknown Error');
				if ('code' in error) err.code = error.code;
				request.rej(err);
			}
		});
		this._chain_id = await this._request({method: 'eth_chainId'});
		// MUST specify the integer ID of the connected chain as a hexadecimal string, per the eth_chainId Ethereum RPC method.
		this.emit('connect', {chainId: this._chain_id});
		//console.log('Connected');
		// handle waiters
		for (let {ful} of queue) ful();
	}
}