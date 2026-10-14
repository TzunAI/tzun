#!/usr/bin/env node
// scripts/copy-build-assets.mjs
// Copy non-TypeScript runtime assets into dist/ after `tsc`.
//
// tsc only emits compiled .ts → .js; it does not copy data files. The SDK
// reads the bundled TSA root cert (freetsa-ca.pem) at runtime for RFC 3161
// timestamp verification, so it must be present in dist/ and shipped in the
// published package (see `files` in package.json: dist/src/**/*).
import fs from 'node:fs';
import path from 'node:path';

function copyRecursive(src, dst) {
  if (!fs.existsSync(src)) return;
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    fs.mkdirSync(dst, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
      copyRecursive(path.join(src, entry), path.join(dst, entry));
    }
  } else {
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.copyFileSync(src, dst);
  }
}

const ROOT = process.cwd();
const targets = [
  ['src/attestation/certs', 'dist/src/attestation/certs'],
];
for (const [src, dst] of targets) {
  copyRecursive(path.join(ROOT, src), path.join(ROOT, dst));
}
console.log('Build assets copied into dist/');
