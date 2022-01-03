for (let test of [
	'Uint256',
	'abi',
	'base58',
	'utils',
	'readme',
	'ws',
	'fetch',
	'chains',
	'providers',
	'ens',
	'nft'
]) {	
	console.log(`=== Test: ${test} ===`.padEnd(60, '='));	
	await import(`./test-${test}.js`);
	console.log();
}