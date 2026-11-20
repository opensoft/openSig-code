// SPDX-License-Identifier: Apache-2.0
//
// T035 ui-build UB-02: no inline script or style. The built outputs carry none (checked
// here independently of the builder), the served shell's policy would block one anyway,
// and the build refuses sources that try.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { buildUi, BuildRefused } from '../../scripts/build-ui.mjs';
import { assertNoInline } from './checks.mjs';
import { ASSET_TOKEN, assertBuilt, cleanup, DOM_DIRECTIVE, rawRequest, runBuild, serveStatic, syntheticRoot, syntheticSources, tempDir } from './support.mjs';

after(cleanup);

const SPDX = '// SPDX-License-Identifier: Apache-2.0';

test('[UB-02] the built shell, scripts, styles and images carry no inline script or style, and the served policy forbids them', async () => {
  const root = syntheticRoot();
  const out = join(tempDir('out'), 'dist');
  const run = runBuild({ root, out });
  assertBuilt(run);
  assertNoInline(out, run.manifest);

  const served = await serveStatic({ distDir: out });
  try {
    const shell = await rawRequest(served.port, 'GET', '/sign');
    assert.equal(shell.status, 200);
    assert.ok(shell.body.equals(readFileSync(join(out, 'autograph', 'index.html'))), 'the checked shell is the served shell');
    const csp = shell.headers['content-security-policy'];
    assert.ok(typeof csp === 'string');
    const directives = new Map(csp.split(';').map((part) => part.trim().split(/\s+/)).map(([name, ...values]) => [name, values]));
    assert.deepEqual(directives.get('script-src'), ["'self'"], "scripts only from the server's own origin");
    assert.deepEqual(directives.get('style-src'), ["'self'"], "styles only from the server's own origin");
    assert.deepEqual(directives.get('default-src'), ["'none'"]);
    assert.deepEqual(directives.get('object-src'), ["'none'"]);
    assert.deepEqual(directives.get('base-uri'), ["'none'"]);
    assert.deepEqual(directives.get('frame-ancestors'), ["'none'"]);
    assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|unsafe-hashes|wasm-unsafe-eval|'nonce-|'sha(?:256|384|512)-|strict-dynamic|\*|https?:|data:|blob:/, 'no inline allowance, no eval, no external source');
  } finally {
    await served.close();
  }
});

test('[UB-02] the build refuses inline script, inline style, handler attributes, eval and external URLs', () => {
  const sources = syntheticSources();
  const shell = sources['src/autograph/index.html'];
  const withShell = (replace, by) => ({ 'src/autograph/index.html': shell.replace(replace, by) });
  const main = `<script type="module" src="/assets/${ASSET_TOKEN}/main.js"></script>`;
  const css = `<link rel="stylesheet" href="/assets/${ASSET_TOKEN}/review.css">`;
  const script = (body) => ({ 'src/autograph/types.ts': `${SPDX}\n${DOM_DIRECTIVE}\n${body}\n` });
  const style = (body) => ({ 'src/autograph/review.css': `/* SPDX-License-Identifier: Apache-2.0 */\n${body}\n` });
  const image = (body) => ({ 'src/autograph/icons/seal.svg': `<!-- SPDX-License-Identifier: Apache-2.0 -->\n${body}\n` });
  const svg = (inner, attributes = '') => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"${attributes}>${inner}</svg>`;
  const cases = {
    'an inline classic script': [withShell(main, `${main}\n<script>window.opened = true;</script>`), 'inline-shell'],
    'an inline module script': [withShell(main, `<script type="module">import './main.js';</script>`), 'inline-shell'],
    'a script without type="module"': [withShell(main, `<script src="/assets/${ASSET_TOKEN}/main.js"></script>`), 'inline-shell'],
    'a style element': [withShell(css, `${css}\n<style>main { color: red; }</style>`), 'inline-shell'],
    'a style attribute': [withShell('<main id="app"', '<main style="color: red" id="app"'), 'inline-shell'],
    'an event-handler attribute': [withShell('<main id="app"', '<main onclick="go()" id="app"'), 'inline-shell'],
    'a javascript: URL': [withShell('href="#app"', 'href="javascript:void(0)"'), 'inline-shell'],
    'an external script': [withShell(main, '<script type="module" src="https://cdn.example.test/x.js"></script>'), 'inline-shell'],
    'a protocol-relative stylesheet': [withShell(css, '<link rel="stylesheet" href="//cdn.example.test/x.css">'), 'inline-shell'],
    'an asset outside this build': [withShell(main, '<script type="module" src="/assets/0000000000000000000000000000000000000000000000000000000000000000/main.js"></script>'), 'inline-shell'],
    'a reference to no built asset': [withShell(main, `<script type="module" src="/assets/${ASSET_TOKEN}/missing.js"></script>`), 'inline-shell'],
    'an object element': [withShell('</main>', '</main><object data="/v1/recipient-session/document"></object>'), 'inline-shell'],
    'eval': [script("export const f = (code: string): unknown => eval(code);"), 'inline-script'],
    'new Function': [script("export const f = new Function('return 1');"), 'inline-script'],
    'an innerHTML assignment': [script("export function f(el: HTMLElement): void { el.innerHTML = '<b>x</b>'; }"), 'inline-script'],
    'a style attribute set from script': [script("export function f(el: HTMLElement): void { el.setAttribute('style', 'color: red'); }"), 'inline-script'],
    'a script element created from script': [script("export const f = (): HTMLElement => document.createElement('script');"), 'inline-script'],
    'a string timer': [script("export const f = (): number => setTimeout('go()', 1);"), 'inline-script'],
    'an @import': [style('@import url("https://fonts.example.test/x.css");'), 'inline-style'],
    'a data: url()': [style('main { background: url("data:image/svg+xml,%3Csvg%3E"); }'), 'inline-style'],
    'an external url()': [style('main { background: url(https://cdn.example.test/x.png); }'), 'inline-style'],
    'a legacy behavior property': [style('main { behavior: url(review.css); }'), 'inline-style'],
    'a legacy -ms-behavior property': [style('main{-ms-behavior:url(review.css)}'), 'inline-style'],
    'a legacy behavior property behind the star hack': [style('main { *behavior: url(review.css); }'), 'inline-style'],
    'a -moz-binding property': [style('main { -moz-binding: url(review.css); }'), 'inline-style'],
    'an SVG script': [image(svg('<script>alert(1)</script>')), 'inline-image'],
    'an SVG style element': [image(svg('<style>circle { fill: red; }</style>')), 'inline-image'],
    'an SVG style attribute': [image(svg('<circle cx="1" cy="1" r="1" style="fill: red"/>')), 'inline-image'],
    'an SVG event handler': [image(svg('<circle cx="1" cy="1" r="1"/>', ' onload="go()"')), 'inline-image'],
    'an SVG foreignObject': [image(svg('<foreignObject width="1" height="1"></foreignObject>')), 'inline-image'],
  };
  for (const [label, [overrides, code]] of Object.entries(cases)) {
    const root = syntheticRoot(overrides, 'inline');
    const out = join(tempDir('out'), 'dist');
    assert.throws(() => buildUi({ root, out }), (error) => error instanceof BuildRefused && error.code === code, `${label}: refused as ${code}`);
    assert.throws(() => readFileSync(join(out, 'build-provenance.json')), /ENOENT/, `${label}: nothing written`);
  }
});

test('[UB-02] properties that merely end in behavior are ordinary CSS: scroll-behavior and overscroll-behavior build, while the legacy behavior property is refused', () => {
  const modern = ['/* SPDX-License-Identifier: Apache-2.0 */', 'html { scroll-behavior: smooth; }', 'main{overscroll-behavior:contain;overscroll-behavior-x:none}', '.behaviorless { color: inherit; }', ''].join('\n');
  const root = syntheticRoot({ 'src/autograph/review.css': modern }, 'modern-css');
  const out = join(tempDir('out'), 'dist');
  const manifest = buildUi({ root, out });
  assert.ok(Array.isArray(manifest?.outputs) && manifest.outputs.some((output) => output.path === 'autograph/review.css'), 'the build accepts scroll-behavior and overscroll-behavior');
  assert.equal(readFileSync(join(out, 'autograph', 'review.css'), 'utf8'), modern, 'and copies the stylesheet byte for byte');
  assertNoInline(out, manifest);

  const legacy = syntheticRoot({ 'src/autograph/review.css': modern.replace('scroll-behavior: smooth', 'behavior: url(review.css)') }, 'legacy-css');
  assert.throws(() => buildUi({ root: legacy, out: join(tempDir('out'), 'dist') }), (error) => error instanceof BuildRefused && error.code === 'inline-style', 'the legacy behavior property beside them is refused');
});
