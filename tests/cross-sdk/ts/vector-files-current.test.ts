/**
 * The vector files the record revision owns are what their generators print
 * (scripts/regenerate-vectors.ts --check): a rule changed in the engine, or a
 * file edited by hand, fails here, naming the file. Each generator also stops
 * when the engine disagrees with an answer it states from the design.
 */
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { ROOT } from './vectors';

it('every generated vector file is current', () => {
  const r = spawnSync(join(ROOT, 'node_modules', '.bin', 'tsx'), [join(ROOT, 'scripts', 'regenerate-vectors.ts'), '--check'], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  expect(r.stderr).toBe('');
  expect(r.status).toBe(0);
}, 180_000);
