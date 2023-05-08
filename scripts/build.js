import { context, build } from 'esbuild';

const options = {
	entryPoints: ['src/index.ts'],
	outfile: 'dist/elfutils.min.js',
	minify: true,	
	target: ['es6'],
	sourcemap: true,
	bundle: true,
	format: 'esm',
}

if(['--watch', '-w'].some(flag => process.argv.includes(flag))) {
	const ctx = await context({ ...options, plugins: [ { name: 'counter', setup(build){
		let i = 1;
		build.onStart(() => console.log('Build #' + i++))
	} } ] });
	await ctx.watch();
}else{
	await build(options);
}