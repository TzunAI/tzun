import { modelOf } from '../helpers/step-model';
// tests/ts/wrappers/no-wrap-exports.test.ts — the per-vendor wrapper files
// stay deleted, and wrappers.ts exports the named per-vendor aliases.
// IMPORTANT: the file-deletion and structural assertions are KEPT below; there
// is no "wrappers.ts does not export wrap<Vendor>" block, since those symbols
// are exported on purpose.
import { existsSync } from 'fs';
import { join } from 'path';
import * as wrappers from '../../../src/sdk/wrappers';
import { Tzun } from '../../../src/sdk/index';
import {
  wrapOpenAI, wrapAnthropic, wrapAwsBedrock, wrapGcpVertex,
  wrapAzureAI, wrapNvidiaNim, wrapHFInference,
} from '../../../src/sdk/wrappers';

const fakeOpenAI = () => ({
  chat: { completions: { create: async () => ({ model: 'gpt-4o-2024-08-06' }) } },
});

describe('per-vendor wrapper files deleted; named aliases exported', () => {
  const projectRoot = join(__dirname, '..', '..');

  // ── File-deletion assertions (kept from original file) ──────────────────
  const deletedFiles = [
    'src/sdk/wrappers-aws.ts',
    'src/sdk/wrappers-azure.ts',
    'src/sdk/wrappers-gcp.ts',
    'src/sdk/wrappers-hf.ts',
    'src/sdk/wrappers-nvidia.ts',
  ];
  it.each(deletedFiles)('%s is deleted', (path) => {
    expect(existsSync(join(projectRoot, path))).toBe(false);
  });

  // ── Structural exports still present (kept from original file) ──────────
  it('wrappers.ts exports attachClient and hookCore', () => {
    const exported = Object.keys(wrappers);
    expect(exported).toContain('attachClient');
    expect(exported).toContain('hookCore');
  });

  it('wrappers.ts does NOT export buildAiBomForCall (alias retired)', () => {
    expect(Object.keys(wrappers)).not.toContain('buildAiBomForCall');
  });

  // ── Named per-vendor wrappers ───────────────────────────────────────────
  describe('named per-vendor wrappers', () => {
    it('all seven exist and are functions', () => {
      for (const w of [wrapOpenAI, wrapAnthropic, wrapAwsBedrock, wrapGcpVertex,
                       wrapAzureAI, wrapNvidiaNim, wrapHFInference]) {
        expect(typeof w).toBe('function');
      }
    });

    it('wrapNvidiaNim pins the vendor (the shape OpenAI shares)', async () => {
      const tzun = await Tzun.init();
      // attach() on this shape duck-types to openai; the alias must force nvidia-nim.
      const wrapped = wrapNvidiaNim(fakeOpenAI(), tzun);
      const direct = tzun.attach(fakeOpenAI(), { vendor: 'nvidia-nim' });
      // capture-parity alias-vs-attach: drive both with tzun_capture and compare
      // the stored envelopes' aiBom vendor fingerprint/descriptor vendor.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (wrapped.chat.completions.create as any)({ model: 'x', tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'a', reason: 'r' } });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (direct.chat.completions.create as any)({ model: 'x', tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'a', reason: 'r' } });
      const all = await tzun.list();
      expect(all.length).toBe(2);
      const vendors = all.map(({ envelope: e }) => {
        const bom = modelOf(e.payload) as { modelDescriptor?: { vendor?: string } } | null;
        return bom?.modelDescriptor?.vendor;
      });
      // Both should produce identical vendor identities.
      expect(vendors[0]).toEqual(vendors[1]);
    });

    it('options cannot override the pinned vendor (Omit<…,"vendor"> at the type level)', async () => {
      const tzun = await Tzun.init();
      // @ts-expect-error vendor is not accepted on alias options (the alias signature)
      wrapOpenAI(fakeOpenAI(), tzun, { vendor: 'anthropic' });
    });
  });
});
