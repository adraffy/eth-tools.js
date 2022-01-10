import {Bech32, Bech32Coder} from './bech32.js';
import {Base58Check} from './base58check.js';
import {MapStringCoder, MapBytesCoder} from './base-coders.js';
import {define_ens_addr, ENSAddrCoder} from './ens-addr.js';
import {SegwitCoder} from './segwit.js';
import {BTCCoder} from './btc-coder.js';
import {HexCoder} from './hex-coder.js';
import {Base32, Base58BTC} from './multibase.js';

// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
// https://github.com/ensdomains/address-encoder/blob/master/src/index.ts

define_ens_addr(new ENSAddrCoder(0, 'BTC', new BTCCoder([[0x00]], [[0x05]]), new SegwitCoder('bc')));
define_ens_addr(new ENSAddrCoder(2, 'LTC', new BTCCoder([[0x30]], [[0x32], [0x05]]), new SegwitCoder('ltc')));
define_ens_addr(new ENSAddrCoder(3, 'DOGE', new BTCCoder([[0x1E]], [[0x16]])));
define_ens_addr(new ENSAddrCoder(4, 'RDD', new BTCCoder([[0x3D]], [[0x05]])));
define_ens_addr(new ENSAddrCoder(5, 'DASH', new BTCCoder([[0x4C]], [[0x10]])));
define_ens_addr(new ENSAddrCoder(6, 'PPC', new BTCCoder([[0x37]], [[0x75]])));
define_ens_addr(new ENSAddrCoder(7, 'NMC', Base58Check));
define_ens_addr(new ENSAddrCoder(14, 'VIA', new BTCCoder([[0x47]], [[0x21]])));
// define_ens_addr(17, 'GRS') groestlcoinChain('grs', [[0x24]], [[0x05]]),
define_ens_addr(new ENSAddrCoder(20, 'DGB', new BTCCoder([[0x1e]], [[0x3f]]), new SegwitCoder('dgb')));
define_ens_addr(new ENSAddrCoder(22, 'MONA', new BTCCoder([[0x32]], [[0x37], [0x05]]), new SegwitCoder('mona')));
define_ens_addr(new ENSAddrCoder(42, 'DCR', Base58BTC));
define_ens_addr(new ENSAddrCoder(43, 'XEM', new MapStringCoder(Base32, s => s.toUpperCase())));
define_ens_addr(new ENSAddrCoder(55, 'AIB', new BTCCoder([[0x17]], [[0x05]])));
define_ens_addr(new ENSAddrCoder(57, 'SYS', new BTCCoder([[0x3f]], [[0x05]]), new SegwitCoder('sys')));
define_ens_addr(new ENSAddrCoder(56, 'BSC', HexCoder));
define_ens_addr(new ENSAddrCoder(60, 'ETH', HexCoder));
define_ens_addr(new ENSAddrCoder(61, 'ETC', HexCoder));
// define_ens_addr(74, 'ICX') icxAddressEncoder, icxAddressDecoder),
define_ens_addr(new ENSAddrCoder(77, 'XVG', new BTCCoder([[0x1E]], [[0x21]])));
define_ens_addr(new ENSAddrCoder(105, 'STRAT', new BTCCoder([[0x3F]], [[0x7D]])));
define_ens_addr(new ENSAddrCoder(111, 'ARK', new MapBytesCoder(Base58Check, v => {
	if (v[0] != 23) throw new Error('invalid prefix');
	return v;
})));
define_ens_addr(new ENSAddrCoder(118, 'ATOM', new Bech32Coder(Bech32.TYPE_1, 'cosmos')));
define_ens_addr(new ENSAddrCoder(119, 'ZIL', new Bech32Coder(Bech32.TYPE_1, 'zil')));
define_ens_addr(new ENSAddrCoder(120, 'EGLD', new Bech32Coder(Bech32.TYPE_1, 'erd')));
define_ens_addr(new ENSAddrCoder(121, 'ZEN', new MapStringCoder(Base58Check, s => {
	if (!/^(zn|t1|zs|t3|zc)/.test(s)) throw new Error('invalid prefix');
	return s;
})));
//getConfig('XMR', 128, xmrAddressEncoder, xmrAddressDecoder),
define_ens_addr(new ENSAddrCoder(133, 'ZEC', new BTCCoder([[0x1c, 0xb8]], [[0x1c, 0xbd]])), new SegwitCoder('zs'));
//   getConfig('LSK', 134, liskAddressEncoder, liskAddressDecoder),
//   eosioChain('STEEM', 135, 'STM'),
define_ens_addr(new ENSAddrCoder(136, 'FIRO', new BTCCoder([[0x52]], [[0x07]])));
define_ens_addr(new ENSAddrCoder(137, 'MATIC', HexCoder));
define_ens_addr(new ENSAddrCoder(141, 'KMD', new BTCCoder([[0x3C]], [[0x55]])));
//getConfig('XRP', 144, data => xrpCodec.encodeChecked(data), data => xrpCodec.decodeChecked(data)),
//getConfig('BCH', 145, encodeCashAddr, decodeBitcoinCash),
//getConfig('XLM', 148, strEncoder, strDecoder),
define_ens_addr(new ENSAddrCoder(153, 'BTM', new SegwitCoder('bm')));
define_ens_addr(new ENSAddrCoder(156, 'BTG', new BTCCoder([[0x26]], [[0x17]]), new SegwitCoder('btg')));
//  getConfig('NANO', 165, nanoAddressEncoder, nanoAddressDecoder),
define_ens_addr(new ENSAddrCoder(175, 'RVN', new BTCCoder([[0x3c]], [[0x7a]])));
define_ens_addr(new ENSAddrCoder(178, 'POA', HexCoder));
define_ens_addr(new ENSAddrCoder(192, 'LCC', new BTCCoder([[0x1c]], [[0x32], [0x05]]), new SegwitCoder('lcc')));
//   eosioChain('EOS', 194, 'EOS'),
define_ens_addr(new ENSAddrCoder(195, 'TRX', Base58Check));
//getConfig('BCN', 204, bcnAddressEncoder, bcnAddressDecoder),
//eosioChain('FIO', 235, 'FIO'),
//getConfig('BSV', 236, bsvAddresEncoder, bsvAddressDecoder),
define_ens_addr(new ENSAddrCoder(239, 'NEO', Base58Check));
//  getConfig('NIM', 242, nimqEncoder, nimqDecoder),
define_ens_addr(new ENSAddrCoder(246, 'EWT', HexCoder));
//   getConfig('ALGO', 283, algoEncode, algoDecode),
define_ens_addr(new ENSAddrCoder(291, 'IOST', Base58BTC));
define_ens_addr(new ENSAddrCoder(301, 'DIVI', new BTCCoder([[0x1e]], [[0xd]])));
define_ens_addr(new ENSAddrCoder(304, 'IOTX', new Bech32Coder(Bech32.TYPE_1, 'io')));
//  eosioChain('BTS', 308, 'BTS'),
define_ens_addr(new ENSAddrCoder(309, 'CKB', new Bech32Coder(Bech32.TYPE_1, 'ckb')));
define_ens_addr(new ENSAddrCoder(330, 'LUNA', new Bech32Coder(Bech32.TYPE_1, 'terra')));
// getConfig('DOT', 354, dotAddrEncoder, ksmAddrDecoder),
// getConfig('VSYS', 360, vsysAddressEncoder, vsysAddressDecoder),
// eosioChain('ABBC', 367, 'ABBC'),
// getConfig('NEAR', 397, encodeNearAddr, decodeNearAddr),
// getConfig('ETN', 415, etnAddressEncoder, etnAddressDecoder),
// getConfig('AION', 425, aionEncoder, aionDecoder),
// getConfig('KSM', 434, ksmAddrEncoder, ksmAddrDecoder),
// getConfig('AE', 457, aeAddressEncoder, aeAddressDecoder),
define_ens_addr(new ENSAddrCoder(459, 'KAVA', new Bech32Coder(Bech32.TYPE_1, 'kava')));
//getConfig('FIL', 461, filAddrEncoder, filAddrDecoder),
//getConfig('AR', 472, arAddressEncoder, arAddressDecoder),
define_ens_addr(new ENSAddrCoder(489, 'CCA', new BTCCoder([[0x0b]], [[0x05]])));
define_ens_addr(new ENSAddrCoder(500, 'THETA', HexCoder));
define_ens_addr(new ENSAddrCoder(501, 'SOL', Base58BTC));
// getConfig('XHV', 535, xmrAddressEncoder, xmrAddressDecoder),
// getConfig('FLOW', 539, flowEncode, flowDecode),
define_ens_addr(new ENSAddrCoder(566, 'IRIS', new Bech32Coder(Bech32.TYPE_1, 'griiaan')));
define_ens_addr(new ENSAddrCoder(568, 'LRG', new BTCCoder([[0x1e]], [[0x0d]])));
// getConfig('SERO', 569, seroAddressEncoder, seroAddressDecoder),
// getConfig('BDX', 570, xmrAddressEncoder, xmrAddressDecoder),
define_ens_addr(new ENSAddrCoder(571, 'CCXX', new BTCCoder([[0x89]], [[0x4b], [0x05]]), new SegwitCoder('ccx')))
define_ens_addr(new ENSAddrCoder(573, 'SRM', Base58BTC));
define_ens_addr(new ENSAddrCoder(574, 'VLX', Base58BTC));
define_ens_addr(new ENSAddrCoder(576, 'BPS', new BTCCoder([[0x00]], [[0x05]])));
define_ens_addr(new ENSAddrCoder(589, 'TFUEL', HexCoder));
define_ens_addr(new ENSAddrCoder(592, 'GRIN', new Bech32Coder(Bech32.TYPE_1, 'grin')));
define_ens_addr(new ENSAddrCoder(614, 'OPT', HexCoder));
define_ens_addr(new ENSAddrCoder(700, 'XDAI', HexCoder));
define_ens_addr(new ENSAddrCoder(703, 'VET', HexCoder));
define_ens_addr(new ENSAddrCoder(714, 'BNB', new Bech32Coder(Bech32.TYPE_1, 'bnb')));
define_ens_addr(new ENSAddrCoder(820, 'CLO', HexCoder));
//eosioChain('HIVE', 825, 'STM'),
define_ens_addr(new ENSAddrCoder(889, 'TOMO', HexCoder));
define_ens_addr(new ENSAddrCoder(904, 'HNT', new MapBytesCoder(Base58Check, (v, to_b) => {
	if (to_b) return Uint8Array.of(0, ...v);
	if (v[0] != 0) throw new Error('invalid prefix');
	return v.slice(1);
})));
define_ens_addr(new ENSAddrCoder(931, 'RUNE', new Bech32Coder(Bech32.TYPE_1, 'thor')));
define_ens_addr(new ENSAddrCoder(999, 'BCD', new BTCCoder([[0x00]], [[0x05]]), new SegwitCoder('bcd')))
define_ens_addr(new ENSAddrCoder(1001, 'TT', HexCoder));
define_ens_addr(new ENSAddrCoder(1007, 'FTM', HexCoder));
define_ens_addr(new ENSAddrCoder(1023, 'ONE', new Bech32Coder(Bech32.TYPE_1, 'one')));
//{ coinType: 1729, decoder: tezosAddressDecoder,encoder: tezosAddressEncoder,name: 'XTZ',},
//getConfig('ONT', 1024, ontAddrEncoder, ontAddrDecoder),
//  cardanoChain('ADA', 1815, 'addr'),
//getConfig('SC', 1991, siaAddressEncoder, siaAddressDecoder),
define_ens_addr(new ENSAddrCoder(2301, 'QTUM', Base58Check));
//eosioChain('GXC', 2303, 'GXC'),
define_ens_addr(new ENSAddrCoder(2305, 'ELA', Base58BTC));
//getConfig('NAS', 2718, nasAddressEncoder, nasAddressDecoder),
//coinType: 3030,decoder: hederaAddressDecoder,encoder: hederaAddressEncoder, name: 'HBAR',
define_ens_addr(new ENSAddrCoder(4218, 'IOTA', new MapBytesCoder(new Bech32Coder(Bech32.TYPE_1, 'iota'), (v, to_b) => {
	return to_b ? v.slice(1) : Uint8Array.of(0, ...v);
})));
//getConfig('HNS', 5353, hnsAddressEncoder, hnsAddressDecoder),
//getConfig('STX', 5757, c32checkEncode, c32checkDecode),
define_ens_addr(new ENSAddrCoder(6060, 'GO', HexCoder));
define_ens_addr(new ENSAddrCoder(8444, 'XCH', new Bech32Coder(Bech32.TYPE_M, 'xch')));
//  getConfig('NULS', 8964, nulsAddressEncoder, nulsAddressDecoder),
define_ens_addr(new ENSAddrCoder(9000, 'AVAX', new Bech32Coder(Bech32.TYPE_1, 'avax')));
define_ens_addr(new ENSAddrCoder(9797, 'NRG', HexCoder));
//getConfig('ARDR', 16754, ardrAddressEncoder, ardrAddressDecoder),
//zcashChain('ZEL', 19167, 'za', [[0x1c, 0xb8]], [[0x1c, 0xbd]]),
define_ens_addr(new ENSAddrCoder(42161, 'ARB1', HexCoder));
define_ens_addr(new ENSAddrCoder(52752, 'CELO', HexCoder));
//bitcoinBase58Chain('WICC', 99999, [[0x49]], [[0x33]]),
//getConfig('WAN', 5718350, wanChecksummedHexEncoder, wanChecksummedHexDecoder),
//getConfig('WAVES', 5741564, bs58EncodeNoCheck, wavesAddressDecoder),

