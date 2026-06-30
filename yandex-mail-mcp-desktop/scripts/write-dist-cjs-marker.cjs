// write-dist-cjs-marker.cjs -- ensure dist/ is marked CommonJS.
//
// The bundle is built --format=cjs (it uses require()). But the repo-root
// package.json (the npx-from-GitHub proxy) declares "type": "module", and the
// root `files` whitelist ships only `yandex-mail-mcp-desktop/dist/` -- NOT the
// desktop package.json that would otherwise mark this subtree CommonJS. So when
// a user runs `npx -y github:owner/repo`, Node resolves the bundle's module type
// by walking up to the root package.json, treats the CJS bundle as ESM, and
// crashes with "require is not defined in ES module scope".
//
// A package.json with {"type":"commonjs"} sitting NEXT TO the bundle wins that
// walk-up and forces CommonJS, independent of any ancestor. Run at the end of
// `npm run build` so a clean rebuild always regenerates it.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const dist = path.join(__dirname, '..', 'dist');
fs.mkdirSync(dist, { recursive: true });
fs.writeFileSync(path.join(dist, 'package.json'), '{ "type": "commonjs" }\n');
