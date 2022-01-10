for (let test of [
	'abi',
	'bech32',
	'chains',
	'cid',
	'ens',
	'fetch',
	'multibase-58',
	'multibase',
	'nft',
	'providers',
	'readme',
	//'root',
	'segwit',
	'sha256',
	'Uint256',
	'utils',
	'uvarint',
	'ws',
]) {	
	console.log(`=== Test: ${test} ===`.padEnd(60, '='));	
	await import(`./test-${test}.js`);
	console.log();
}