import {nodeResolve} from '@rollup/plugin-node-resolve';
import {terser} from 'rollup-plugin-terser';

export default [
	{
		input: 'eth-tools.js',
		output: {
			file: 'dist/eth-tools.js'
		},
		plugins: [nodeResolve()]
	},
	{
		input: 'dist/eth-tools.js',
		output: {
			file: 'dist/eth-tools.min.js'
		},
		plugins: [terser({
			compress: {
				toplevel: true
			},
			mangle: { 
				toplevel: true
			}
		})]
	}
];