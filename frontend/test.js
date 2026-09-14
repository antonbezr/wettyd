// Bundles every *.test.ts file with esbuild (already a build-time
// dependency, so this needs nothing extra) into plain JS, then runs them
// with Node's own built-in test runner. Mirrors the C side's approach of
// keeping tests dependency-free rather than pulling in a whole framework.
import { globSync } from 'node:fs';
import { spawn } from 'node:child_process';
import * as esbuild from 'esbuild';

const root = import.meta.dirname;
const testFiles = globSync('src/**/*.test.ts', { cwd: root });

if (testFiles.length === 0) {
  console.log('no test files found');
  process.exit(0);
}

const outdir = `${root}/.test-build`;
await esbuild.build({
  entryPoints: testFiles.map((f) => `${root}/${f}`),
  outdir,
  outbase: `${root}/src`,
  bundle: true,
  platform: 'node',
  format: 'esm',
  outExtension: { '.js': '.mjs' },
  logLevel: 'info',
});

const outFiles = testFiles.map(
  (f) => `${outdir}/${f.replace(/^src\//, '').replace(/\.ts$/, '.mjs')}`,
);

const child = spawn(process.execPath, ['--test', ...outFiles], {
  stdio: 'inherit',
});
child.on('exit', (code) => process.exit(code ?? 1));
