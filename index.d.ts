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
	method(method: string): ABIEncoder;
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
export function checksum_address(s: string): string;

export function is_multihash(s: string): boolean;
export function fix_multihash_uri(s: string): string;

type Provider = any;

declare interface ProvideLike<T> {
	request(obj: object): Promise<object>;
	emit(event: string|Symbol, ...args: any[]): boolean;
	on(event: string|Symbol, listener: any): T;
	removeListener(event: string|Symbol, listener: any): T;
	disconnect(): void;
}
export class FetchProvider implements ProvideLike<FetchProvider> {
	constructor(params: {url: string, fetch?: any, request_timeout?: number, idle_timeout?: number});
}
export class WebSocketProvider implements ProvideLike<WebSocketProvider> {
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

type Address = string;

export class ENSName {
	ens: ENS;
	get_address(): Promise<Address>;
	get_owner(): Promise<Address>;
	get_primary(): Promise<string>;
	get_avatar(): Promise<{type: string}>;
	get_display(throw_on_invalid?: boolean): Promise<string>;
	get_text(key: string): Promise<string>;
	get_texts(keys: string[], output?: object): Promise<object>;
	get_addr(addr: any): Promise<Uint8Array>;
	get_addrs(addrs: any[], output?: object): Promise<object>;
}

type Normalizer = (name: string) => string;

export class ENS {
	constructor({
		provider: any,
		registry: Address,
		ens_normalize: Normalizer
	});
	resolve(name: string): Proimse<ENSName>;
	normalize(name: string): string;
	get_resolver(node: Uint256): Promise<Address>;
	is_dot_eth_available(label: string): Promise<boolean>;
}





/*
type ENSInput = string|Uint256|{name?:string, node?:Uint256};
type CoinType = string|number;

export function set_normalizer(fn: CallableFunction): void;
export function labelhash(label: string): Uint256;
export function node_from_ens_name(name: string): Uint256;
export function ens_resolve(provider: Provider, input: ENSInput): {resolver: string, node: Uint256, name?: string};
export function lookup_address(provider: Provider, input: ENSInput): string;
export function lookup_owner(provider: Provider, input: ENSInput): string;
export function ens_name_for_address(provider: Provider, address: string): string;
export function ens_avatar(provider: Provider, input: ENSInput): string;
export function parse_avatar(avatar: string, provider?: Provider, address?: string): {type: string};
export function ens_text_record(provider: Provider, input: ENSInput, text: string|string[]): {text?: {}};
export function ens_addr_record(provider: Provider, input: ENSInput, text: CoinType|CoinType[]): {addr?: {}};
export function ens_contenthash_record(provider: Provider, input: ENSInput): {contenthash?: string, contenthash_url?: string};
export function ens_pubkey_record(provider: Provider, input: ENSInput): {pubkey?: {x: Uint256, y: Uint256}};
*/