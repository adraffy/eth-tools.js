// https://eips.ethereum.org/EIPS/eip-1193
// The Provider MUST implement the following event handling methods:
// * on
// * removeListener
// These methods MUST be implemented per the Node.js EventEmitter API.
// * https://nodejs.org/api/events.html
//
export class EventEmitter {
	constructor() {
		this.__events = {};
	}
	// Synchronously calls each of the listeners registered for the event named eventName, 
	// in the order they were registered, passing the supplied arguments to each.
	// Returns: <boolean>
	// Returns true if the event had listeners, false otherwise.
	emit(event, ...args) {
		let bucket = this.__events[event];
		if (!bucket) return false;
		for (let listener of bucket) listener(...args);
		return true;		
	}
	// Adds the listener function to the end of the listeners array for the event named eventName. 
	// No checks are made to see if the listener has already been added. 
	// Multiple calls passing the same combination of eventName and listener 
	// will result in the listener being added, and called, multiple times.
	// Returns: <EventEmitter>
	on(event, listener) {
		let bucket = this.__events[event];
		if (!bucket) this.__events[event] = bucket = [];
		bucket.push(listener);
		return this;
	}
	// Removes the specified listener from the listener array for the event named eventName.
	// removeListener() will remove, at most, one instance of a listener from the listener array
	// Returns: <EventEmitter>
	removeListener(event, listener) {
		let bucket = this.__events[event];
		if (bucket) {
			let i = bucket.indexOf(listener);
			if (i >= 0) {
				bucket.splice(i, 1);
				if (bucket.length == 0) {
					delete this.__events[event];
				}
			}
		}
		return this;
	}
}
