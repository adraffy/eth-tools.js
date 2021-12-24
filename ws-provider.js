export class WebSocketProvider {
	constructor({url, chain_id, WebSocket: ws_api, request_timeout = 10000, idle_timeout = 500}) {
		if (typeof url !== 'string') throw new TypeError('expected url');
		if (!ws_api) ws_api = globalThis.WebSocket;
		if (!ws_api) throw new Error('unknown WebSocket implementation');
		this.url = url;
		this.ws_api = ws_api;
		this.chain_id = chain_id;
		this.request_timeout = request_timeout;
		this.idle_timeout = idle_timeout;
		this.idle_timer = undefined;
		this.ws = undefined;
		this.reqs = undefined;
		this.id = 0;
	}
	get chainId() { return this.chain_id; }
	restart_idle() {
		if (this.idle_timeout > 0) {
			if (Object.keys(this.reqs).length == 0) {
				let {ws} = this; // snapshot
				this.idle_timer = setTimeout(() => {
					//console.log('Disconnect: idle');
					ws.close();	
				}, this.idle_timeout);
			} else {
				clearTimeout(this.idle_timer);
			}
		}
	}
	async request(obj) {
		if (typeof obj !== 'object') throw new TypeError('expected object');
		await this.connect();
		const id = ++this.id; 
		const {reqs, ws} = this; // snapshot
		this.restart_idle();
		return new Promise((ful, rej) => {
			let timer = setTimeout(() => {
				delete reqs[id];
				rej(new Error('Timeout'));
			}, this.request_timeout);
			reqs[id] = {timer, ful, rej};
			ws.send(JSON.stringify({jsonrpc: '2.0', id, ...obj}));
		});
	}
	async connect() {
		let {ws} = this;
		if (ws === undefined) {
			let queue = this.ws = []; // change state		 
			let s = new this.ws_api(this.url);
			//console.log('Connecting...');
			let timer, handler;
			try {  
				await new Promise((ful, rej) => {
					handler = () => {
						s.removeEventListener('error', rej); 
						s.removeEventListener('close', rej);
						ful();						
					};
					timer = setTimeout(() => rej(new Error('Timeout')), this.request_timeout);
					s.addEventListener('close', rej);
					s.addEventListener('error', rej);
					s.addEventListener('open', handler, {once: true});
				});
			} catch (err) {
				//console.log(`Connect error: ${err}`);
				this.ws = undefined; // reset state
				s.removeEventListener('open', handler);
				for (let {rej} of queue) rej(err);
				s.close();
				throw err;
			} finally {
				clearTimeout(timer);
			} 
			//console.log('Connected');
			this.ws = s; // connected state
			this.id = 0;
			this.reqs = {};
			// setup error handlers
			let die = (err) => {
				if (s !== this.ws) return;
				this.ws = undefined; // reset state
				for (let {rej} of Object.values(this.reqs)) rej(err);
				this.reqs = undefined;
				clearTimeout(this.idle_timer);
			};
			s.addEventListener('close', () => die(new Error('Unexpected close')));
			s.addEventListener('error', die);
			// process waiters
			for (let {ful} of queue) ful();
			// handle requests
			let {reqs} = this; // snapshot
			s.addEventListener('message', ({data}) => {
				let json = JSON.parse(data);
				let request = reqs[json.id];
				if (!request) return;
				this.restart_idle();
				delete reqs[json.id];
				clearTimeout(request.timer);
				let {result, error} = json;
				if (result) return request.ful(result);
				let err = new Error(error?.message ?? 'Unknown Error');
				if ('code' in error) err.code = error.code;
				request.rej(err);
			});
			this.restart_idle();
		} else if (Array.isArray(ws)) { // already connecting
			await new Promise((ful, rej) => {
				ws.push({ful, rej});
			});
		}
	}
}