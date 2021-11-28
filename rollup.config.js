import { nodeResolve } from '@rollup/plugin-node-resolve';

export default [
	{
		input: 'eth-tools.js',
		output: {file: 'dist/eth-tools.js'},
		plugins: [nodeResolve()]
	},
	{
		input: 'abi.js',
		output: {file: 'dist/eth-abi.js'},
		plugins: [nodeResolve()]
	}
];