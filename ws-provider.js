// TODO: this is still a work in progress
export function smol_provider(url, WebSocket) {
	const CONNECT_TIMEOUT = 10000;
	const REQUEST_TIMEOUT = 5000;
	let _ws, _id, _reqs;
	return async (args) => {
		if (_ws === undefined) { // disconnected state
			let queue = _ws = []; // change state		 
			let s = new WebSocket(url);
			let timer, ful, rej;
			try {  
				await new Promise((ful, rej) => {
					ful = ful;
					rej = rej;
					timer = setTimeout(() => rej(new Error('Timeout')), CONNECT_TIMEOUT);
					s.addEventListener('close', rej);
					s.addEventListener('error', rej);
					s.addEventListener('open', ful, {once: true});
				});
			} catch (err) {
				_ws = undefined; // reset state
				s.removeEventListener('open', ful);
				for (let {rej} of queue) rej(err);
				s.close();
				throw err;
			} finally {
				clearTimeout(timer);
			} 
			s.removeEventListener('error', ful);   
			s.removeEventListener('close', ful);	  
			_ws = s; // connected state
			_id = 0;
			_reqs = {};
			for (let {ful} of queue) ful();
			s.addEventListener('message', ({data}) => {
				let json = JSON.parse(data);
				let request = _reqs[json.id];
				if (!request) return;
				delete _reqs[json.id];
				clearTimeout(request.timer);
				let {result, error} = json;
				if (result) return request.ful(result);
				let err = new Error(error?.message ?? 'Unknown Error');
				if ('code' in error) err.code = error.code;
				request.rej(err);
			});
			function die(err) {
				if (s !== _ws) return;
				_ws = undefined; // reset state
				for (let {rej} of Object.values(_reqs)) rej(err);
				_reqs = undefined;
			}
			s.addEventListener('close', (e) => die(Error('Unexpected close')));
			s.addEventListener('error', die);
		} else if (Array.isArray(_ws)) { // already connecting
			await new Promimse((ful, rej) => {
				_ws.push({ful, rej});
			});
		}
		// normal operation
		let ws = _ws;
		let id = ++_id; 
		let reqs = _reqs;
		return new Promise((ful, rej) => {			  
			let timer = setTimeout(() => {
				delete reqs[id];
				rej(new Error('Timeout'));
			}, REQUEST_TIMEOUT);
			_reqs[id] = {timer, ful, rej};
			_ws.send(JSON.stringify({jsonrpc: '2.0', id, ...args}));
		});
	};
}