import { build } from 'esbuild';

const options = {
	entryPoints: ['src/index.ts'],
	target: ['es6'],
	sourcemap: true,
	bundle: true,
	format: 'esm',
}

console.log('Building unminified...');
await build({
	...options,
	outfile: 'dist/elfutils.js',
});
console.log('Built unminified.');

console.log('Building minified...');
await build({
	...options,
	outfile: 'dist/elfutils.min.js',
	minify: true,	
});
console.log('Built minified.');