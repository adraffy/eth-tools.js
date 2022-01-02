import {nodeResolve} from '@rollup/plugin-node-resolve';
import {terser} from 'rollup-plugin-terser';

export default [
	{
		input: 'index.js',
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
	},
	{
		input: 'src/lib-browser.js',
		output: {
			file: 'dist/eth-tools-browser.min.js'
		},
		plugins: [nodeResolve(), terser({
			compress: {
				toplevel: true
			},
			mangle: { 
				toplevel: true
			}
		})]
	}
];