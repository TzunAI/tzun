import { TzunConfig, CaptureAttestation } from '@tzun/engine';
import { validateAttestationConfig } from '../../src/sdk/mode-resolver';

describe('AttestationConfig types', () => {
  it('accepts a full attestation config', () => {
    const config: TzunConfig = {
      mode: 'cloud',
      apiKey: 'tzun_live_abc123',
      attestation: {
        timestamp: {
          rfc3161Url: 'https://freetsa.org/tsr',
        },
        webauthn: {
          rpId: 'example.com',
          rpName: 'Example Corp',
        },
        require: ['webauthn'],
        deferrable: ['timestamp'],
      },
    };

    expect(config.attestation).toBeDefined();
    expect(config.attestation!.require).toContain('webauthn');
    expect(config.attestation!.deferrable).toContain('timestamp');
  });

  it('accepts an empty attestation config', () => {
    const config: TzunConfig = {
      mode: 'dev',
      attestation: {},
    };

    expect(config.attestation).toBeDefined();
    expect(config.attestation!.require).toBeUndefined();
    expect(config.attestation!.deferrable).toBeUndefined();
  });

  it('accepts attestation config with only require', () => {
    const config: TzunConfig = {
      attestation: {
        require: ['timestamp', 'webauthn'],
      },
    };

    expect(config.attestation!.require).toEqual(['timestamp', 'webauthn']);
  });

  it('CaptureAttestation only allows valid values', () => {
    const valid: CaptureAttestation[] = ['timestamp', 'webauthn'];
    expect(valid).toHaveLength(2);
    // @ts-expect-error — a capture never holds an anchor
    const anchor: CaptureAttestation = 'blockchain';
    expect(anchor).toBe('blockchain');
  });

  it('has no blockchain key, and deferrable cannot name the anchor', () => {
    const legacy: TzunConfig = {
      attestation: {
        // @ts-expect-error — anchoring is not an attestation component
        blockchain: { anchorPrivateKey: '0x' + 'ab'.repeat(32) },
      },
    };
    const deferAnchor: TzunConfig = {
      attestation: {
        // @ts-expect-error — the retry never obtains an anchor
        deferrable: ['blockchain'],
      },
    };
    expect(legacy).toBeDefined();
    expect(deferAnchor).toBeDefined();
  });

  it('has no `optional` list, and `deferrable` cannot name webauthn', () => {
    const config: TzunConfig = {
      attestation: {
        // @ts-expect-error — the list is `deferrable`
        optional: ['timestamp'],
      },
    };
    const deferWebauthn: TzunConfig = {
      attestation: {
        // @ts-expect-error — a signature is a human ceremony, never obtained later
        deferrable: ['webauthn'],
      },
    };
    expect(config).toBeDefined();
    expect(deferWebauthn).toBeDefined();
  });
});

describe('validateAttestationConfig', () => {
  const PROD_ERROR = /Production modes must obtain an RFC 3161 timestamp for every record/;
  const PRODUCTION_MODES = ['local', 'cloud', 'self-hosted'] as const;

  // dev mode — no enforcement
  it('dev mode allows require: []', () => {
    expect(() => validateAttestationConfig('dev', { require: [] })).not.toThrow();
  });

  it('dev mode allows undefined config', () => {
    expect(() => validateAttestationConfig('dev', undefined)).not.toThrow();
  });

  it('dev mode allows require: [\'timestamp\'] opt-in', () => {
    expect(() => validateAttestationConfig('dev', { require: ['timestamp'] })).not.toThrow();
  });

  it('dev mode with undefined returns require: [], deferrable: []', () => {
    const result = validateAttestationConfig('dev', undefined);
    expect(result.require).toEqual([]);
    expect(result.deferrable).toEqual([]);
  });

  describe.each(PRODUCTION_MODES)('%s mode', (mode) => {
    it('defers the timestamp when nothing is configured', () => {
      const result = validateAttestationConfig(mode, undefined);
      expect(result.require).toEqual([]);
      expect(result.deferrable).toEqual(['timestamp']);
    });

    it('defers the timestamp when require is not specified', () => {
      const result = validateAttestationConfig(mode, {});
      expect(result.require).toEqual([]);
      expect(result.deferrable).toEqual(['timestamp']);
    });

    it('keeps a required timestamp required, and does not also defer it', () => {
      const result = validateAttestationConfig(mode, { require: ['timestamp'] });
      expect(result.require).toEqual(['timestamp']);
      expect(result.deferrable).toEqual([]);
    });

    it('accepts an explicitly deferrable timestamp with an empty require', () => {
      const result = validateAttestationConfig(mode, { require: [], deferrable: ['timestamp'] });
      expect(result.require).toEqual([]);
      expect(result.deferrable).toEqual(['timestamp']);
    });

    it('adds the timestamp to a deferrable list that omits it when require is unset', () => {
      const result = validateAttestationConfig(mode, { deferrable: [] });
      expect(result.require).toEqual([]);
      expect(result.deferrable).toEqual(['timestamp']);
    });

    it('refuses require: [] — the timestamp would never be sought', () => {
      expect(() => validateAttestationConfig(mode, { require: [] })).toThrow(PROD_ERROR);
    });

    it('refuses a require that omits the timestamp when nothing defers it', () => {
      expect(() => validateAttestationConfig(mode, { require: ['webauthn'] })).toThrow(PROD_ERROR);
    });

    it('refuses a set require whose deferrable list omits the timestamp', () => {
      expect(() =>
        validateAttestationConfig(mode, { require: ['webauthn'], deferrable: [] }),
      ).toThrow(PROD_ERROR);
    });

    it('the refusal names both ways to obtain a timestamp', () => {
      expect(() => validateAttestationConfig(mode, { require: [] })).toThrow(/`attestation\.deferrable`/);
      expect(() => validateAttestationConfig(mode, { require: [] })).toThrow(/`attestation\.require`/);
    });
  });

  it("non-dev mode allows require: ['timestamp', 'webauthn']", () => {
    expect(() =>
      validateAttestationConfig('cloud', { require: ['timestamp', 'webauthn'] }),
    ).not.toThrow();
  });

  it('preserves deferrable alongside require', () => {
    const result = validateAttestationConfig('cloud', {
      require: ['webauthn'],
      deferrable: ['timestamp'],
    });
    expect(result.require).toEqual(['webauthn']);
    expect(result.deferrable).toEqual(['timestamp']);
  });

  describe('contradictions are refused in every mode', () => {
    it.each(['dev', ...PRODUCTION_MODES] as const)(
      '%s: a component both required and deferrable',
      (mode) => {
        expect(() =>
          validateAttestationConfig(mode, { require: ['timestamp'], deferrable: ['timestamp'] }),
        ).toThrow(/both `require` and `deferrable`: timestamp/);
      },
    );

    it.each(['dev', ...PRODUCTION_MODES] as const)(
      '%s: webauthn in deferrable (a signature is never obtained later)',
      (mode) => {
        expect(() =>
          validateAttestationConfig(mode, {
            deferrable: ['webauthn' as unknown as 'timestamp'],
          }),
        ).toThrow(/`attestation\.deferrable` cannot name 'webauthn'/);
      },
    );
  });
});
