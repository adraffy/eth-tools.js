import {nodeResolve} from '@rollup/plugin-node-resolve';
import {terser} from 'rollup-plugin-terser';

function mini(name) {
	return {
		input: `src/lib-${name}.js`,
		output: {
			file: `dist/eth-tools-${name}.min.js`
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
}

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
	mini('browser'),
	mini('cid'),
	mini('sha256'),
	mini('ens-addr')
];