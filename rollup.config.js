import { nodeResolve } from '@rollup/plugin-node-resolve';

export default {
	input: 'index.js',
	output: {file: 'dist/eth-provider.js'},
	plugins: [nodeResolve()]
};