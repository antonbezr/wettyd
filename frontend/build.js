// Builds wettyd's frontend and produces src/html.h for the C backend to
// embed, mirroring ttyd's own html/gulpfile.js pipeline (webpack -> inline
// -> gzip -> C byte array), but driven from wetty's esbuild-based client
// instead of ttyd's preact one.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import * as esbuild from 'esbuild';
import { sassPlugin } from 'esbuild-sass-plugin';
import { inlineSource } from 'inline-source';

const root = import.meta.dirname;

function assembleXtermConfigSrcdoc() {
  const dir = `${root}/src/assets/xterm_config`;
  let html = readFileSync(`${dir}/index.html`, 'utf8');
  html = html.replace(
    '<link rel="stylesheet" href="./style.css" />',
    `<style>${readFileSync(`${dir}/style.css`, 'utf8')}</style>`,
  );
  for (const file of [
    'functionality.js',
    'xterm_general_options.js',
    'xterm_color_theme.js',
    'xterm_advanced_options.js',
    'xterm_defaults.js',
  ]) {
    html = html.replace(
      `<script src="./${file}"></script>`,
      `<script>${readFileSync(`${dir}/${file}`, 'utf8')}</script>`,
    );
  }
  // Escape for embedding as a double-quoted HTML attribute value.
  return html
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;');
}

function faviconDataUri() {
  const bytes = readFileSync(`${root}/src/assets/favicon.png`);
  return `data:image/png;base64,${bytes.toString('base64')}`;
}

async function buildClient() {
  await esbuild.build({
    entryPoints: [`${root}/src/client/wetty.ts`],
    outdir: `${root}/build/client`,
    bundle: true,
    platform: 'browser',
    format: 'iife',
    minify: true,
    sourcemap: false,
    plugins: [
      sassPlugin({
        embedded: true,
        loadPaths: ['node_modules'],
        style: 'compressed',
      }),
    ],
    logLevel: 'info',
  });
}

// Reproduces ttyd/html/gulpfile.js's genHeader(): a C byte array plus the
// original (index_html_size) and gzip-compressed (index_html_len) lengths,
// consumed by ttyd's src/http.c via zlib inflate.
function genHeader(size, buf) {
  const len = buf.length;
  const lines = [];
  let line = '  ';
  for (let i = 0; i < len; i++) {
    const hex = buf[i].toString(16).padStart(2, '0');
    line += `0x${hex}`;
    const idx = i + 1;
    if (idx === len) {
      line += '\n';
    } else {
      line += idx % 12 === 0 ? ',\n  ' : ', ';
    }
  }
  lines.push(line);
  return (
    `unsigned char index_html[] = {\n${lines.join('')}};\n` +
    `unsigned int index_html_len = ${len};\n` +
    `unsigned int index_html_size = ${size};\n`
  );
}

async function main() {
  await buildClient();

  mkdirSync(`${root}/build`, { recursive: true });
  let html = readFileSync(`${root}/src/template.html`, 'utf8');
  html = html
    .replace('__FAVICON_DATA_URI__', faviconDataUri())
    .replace('__XTERM_CONFIG_SRCDOC__', assembleXtermConfigSrcdoc());
  const templatePath = `${root}/build/client/pre-inline.html`;
  writeFileSync(templatePath, html);

  const inlined = await inlineSource(templatePath, {
    compress: false,
  });
  writeFileSync(`${root}/build/index.html`, inlined);

  const originalSize = Buffer.byteLength(inlined);
  const gzipped = gzipSync(Buffer.from(inlined));
  const header = genHeader(originalSize, gzipped);
  writeFileSync(`${root}/../src/html.h`, header);

  console.log(
    `[wettyd] frontend built: ${originalSize} bytes -> ${gzipped.length} bytes gzipped -> ../src/html.h`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
