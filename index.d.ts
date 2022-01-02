export class Uint256 {
	zero(): Uint256;
	from_str(s: string): Uint256;  
	from_hex(s: string): Uint256;
	from_dec(s: string): Uint256;
	from_bytes(v: Uint8Array): Uint256;
	from_number(i: number): Uint256;
	clone(): Uint256;
	compare(other:string|number|Uint8Array|Uint256): number;
	set_number(i: number): Uint256;
	add(other:string|number|Uint8Array|Uint256): Uint256;
	not(): Uint256;
	get number(): number;
	get unsigned(): number;
	get hex(): string;
	get dec(): string;
	digit_str(radix:number, lookup:string|object[]): string;
	digits(radix:number): number[];
	toJSON(): string;
}

export class ABIDecoder {
	from_hex(s: string): ABIDecoder;
	constructor(u: Uint8Array);
	get remaining(): number;
	read_bytes(n: number): Uint8Array;
	read_memory(): Uint8Array;
	read_byte(): number;
	bytes(n: number): Uint8Array;
	boolean(): boolean;
	number(n?: number): number;
	uint256(): Uint256;
	string(): string;
	memory(): Uint8Array;
	addr(checksum?: boolean): string;
	uvarint(): number; 
}

export class ABIEncoder {
	method(method: string|Uint8Array): ABIEncoder;
	constructor(offset?: number, capacity?: number);
	reset(): ABIEncoder;
	build_hex(): string;
	build(): Uint8Array;
	alloc(n: number): Uint8Array;
	bytes_hex(s: string): ABIEncoder;
	bytes(v: Uint8Array): ABIEncoder;
	number(i: number, n?: number): ABIEncoder;
	string(s: string): ABIEncoder;
	memory(v: Uint8Array): ABIEncoder;
	addr(s: string): ABIEncoder;
}

export function set_bytes_to_number(v: Uint8Array, i: number): void;
export function unsigned_from_bytes(v: Uint8Array): number;
export function left_truncate_bytes(v: Uint8Array): Uint8Array;

export function is_null_hex(s: string): boolean;
export function is_valid_address(s: string): boolean;
export function is_checksum_address(s: string): boolean;
export function standardize_address(s: string, checksum?: boolean): string;

export function is_multihash(s: string): boolean;
export function fix_multihash_uri(s: string): string;

type Provider = any;

declare class ProvideLike<T> {
	request(obj: object): Promise<object>;
	emit(event: string|Symbol, ...args: any[]): boolean;
	on(event: string|Symbol, listener: any): T;
	removeListener(event: string|Symbol, listener: any): T;
	disconnect(): void;
}
export class FetchProvider extends ProvideLike<FetchProvider> {
	constructor(params: {url: string, fetch?: any, request_timeout?: number, idle_timeout?: number});
}
export class WebSocketProvider extends ProvideLike<WebSocketProvider> {
	constructor(params: {url: string, WebSocket?: any, request_timeout?: number, idle_timeout?: number});
	set idle_timeout(t: number);
}

export class Providers {
	add_static(chain_id: number, provider: Provider): Providers;
	add_dynamic(provider: Provider): Providers;
	find_provider(chain_id: number, required?: boolean, dynamic?: boolean): Promise<Provider>;
	disconnect(): void;
	view(chain_id: number): ProviderView;
}

export class ProviderView extends Providers {
	get_provider(): Promise<Provider>;
}

export class ENSOwner {
	readonly ens: ENS;
	readonly address: string;
	get_primary_name(): Promise<string>;
	resolve(): Promise<ENSName>;
}

export class ENSName {
	readonly ens: ENS;
	readonly input: string;
	readonly name: string;
	readonly node: Uint256;
	readonly resolver: string;
	readonly resolved: Date;
	assert_valid_resolver(): void;
	get_address(): Promise<string>;
	get_owner(): Promise<ENSOwner>;	
	get_owner_address(): Promise<string>;
	get_owner_primary_name(): Promise<string>;
	is_owner_primary_name(): Promise<boolean>;
	is_input_normalized(): boolean;
	is_equivalent_name(name: string): boolean;
	assert_equivalent_name(name: string): void; 
	is_input_display(): Promise<boolean>;
	get_display_name(): Promise<string>;
	get_avatar(): Promise<{type: string}>;
	get_text(key: string): Promise<string>;
	get_texts(keys: string[]): Promise<Record<string,string>>;
	get_addr(addr: any): Promise<Uint8Array>;
	get_addrs(addrs: any[], named?: boolean): Promise<Record<any, Uint8Array>>;
	get_content(): Promise<{hash: Uint8Array, url?: string}>;
	get_pubkey(): Promise<{x: Uint256, y: Uint256}>;
}

type Normalizer = (name: string) => string;

export class ENS {
	constructor({
		provider: any,
		registry: string,
		ens_normalize: Normalizer
	});
	normalize(name: string): string;
	labelhash(label: string|Uint256): Uint256;
	owner(address: string): ENSOwner;
	resolve(name: string): Promise<ENSName>;
	get_resolver(node: Uint256): Promise<string>;
	primary_from_address(address: string): Promise<string>;
	is_dot_eth_available(label: string): Promise<boolean>;
	get_dot_eth_owner(label: string): Promise<ENSOwner>;
}