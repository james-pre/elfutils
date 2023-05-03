import { build } from 'esbuild';
import * as fs from 'fs';

await build({
	entryPoints: [ './src/index.js' ],
	outfile: './dist/bundle.js',
	preservceName: true,
	bundle: true,
});