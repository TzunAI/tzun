import { resolveMode } from '../../src/sdk/mode-resolver';
import { TzunConfig } from '@tzun/engine';

describe('resolveMode', () => {
  it('returns dev when no config is provided', () => {
    expect(resolveMode({})).toBe('dev');
  });

  it('returns dev when config is undefined', () => {
    expect(resolveMode(undefined as unknown as TzunConfig)).toBe('dev');
  });

  it('returns local when mode is explicitly set to local', () => {
    expect(resolveMode({ mode: 'local' })).toBe('local');
  });

  it('returns cloud when apiKey is present and no custom URL', () => {
    expect(resolveMode({ apiKey: 'tzun_live_abc123' })).toBe('cloud');
  });

  it('returns self-hosted when apiKey and custom apiUrl are present', () => {
    expect(resolveMode({
      apiKey: 'tzun_live_abc123',
      apiUrl: 'https://tzun.internal.acme.com',
    })).toBe('self-hosted');
  });

  it('explicit mode overrides apiKey inference', () => {
    expect(resolveMode({ mode: 'local', apiKey: 'tzun_live_abc123' })).toBe('local');
  });

  it('resolves from TZUN_MODE environment variable', () => {
    const original = process.env.TZUN_MODE;
    process.env.TZUN_MODE = 'local';
    try {
      expect(resolveMode({})).toBe('local');
    } finally {
      if (original === undefined) {
        delete process.env.TZUN_MODE;
      } else {
        process.env.TZUN_MODE = original;
      }
    }
  });
});
