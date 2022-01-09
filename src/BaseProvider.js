import {EventEmitter} from './EventEmitter.js';
export class BaseProvider extends EventEmitter {
	get isSmartProvider() {
		return true;
	}
	async req(method, ...params) { 
		return this.request({method, params: [...params]}); 
	}
}