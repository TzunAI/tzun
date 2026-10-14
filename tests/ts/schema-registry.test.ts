import { SchemaRegistry, canonicalSerialize } from '@tzun/engine';

describe('SchemaRegistry', () => {
  let registry: SchemaRegistry;

  beforeEach(() => {
    registry = new SchemaRegistry();
  });

  it('has v1.0 registered by default', () => {
    const schema = registry.get('v1.0');
    expect(schema).toBeDefined();
    expect(schema!.versionId).toBe('v1.0');
    expect(schema!.status).toBe('active');
  });

  it('v1.0 hashed field set matches spec: the eleven names of 0.8.0', () => {
    const schema = registry.get('v1.0');
    expect(schema!.hashedFieldSet).toEqual([
      'action', 'aiOutput', 'aiSystemId', 'capturedAt', 'contributions', 'decider', 'evidenceId', 'links', 'reason',
      'sequenceNumber', 'signoffExpectation',
    ]);
  });

  it('v1.0 serialization rules match spec', () => {
    const schema = registry.get('v1.0');
    expect(schema!.serializationRules.encoding).toBe('utf-8');
    expect(schema!.serializationRules.format).toBe('json');
    expect(schema!.serializationRules.separators).toEqual([',', ':']);
    expect(schema!.serializationRules.whitespace).toBe(false);
    expect(schema!.serializationRules.keySort).toBe('recursive-lexicographic-utf16-code-unit');
  });

  it('returns undefined for unregistered version', () => {
    expect(registry.get('v99.0')).toBeUndefined();
  });

  it('holds v1.0 alone, and no v1.1 exists', () => {
    expect(registry.list().map((v) => v.versionId)).toEqual(['v1.0']);
    expect(registry.get('v1.1')).toBeUndefined();
  });

  it('allows registering a new schema version', () => {
    registry.register({
      versionId: 'v1.2',
      hashedFieldSet: ['aiOutput', 'aiSystemId', 'capturedAt', 'evidenceId', 'action', 'reason', 'contextId'],
      serializationRules: {
        encoding: 'utf-8',
        format: 'json',
        separators: [',', ':'],
        whitespace: false,
        keySort: 'recursive-lexicographic-utf16-code-unit',
        nullHandling: 'undefined-becomes-null, explicit-null-preserved',
        numberHandling: 'no-trailing-zeros, integers-no-decimal, finite-only',
        stringHandling: 'standard-json-escaping, nfc-normalization',
        arrayHandling: 'preserve-insertion-order, elements-recursive',
      },
      createdAt: new Date().toISOString(),
      status: 'active',
    });
    expect(registry.get('v1.2')).toBeDefined();
  });

  it('throws when registering a duplicate version', () => {
    expect(() => registry.register({
      versionId: 'v1.0',
      hashedFieldSet: [],
      serializationRules: {} as any,
      createdAt: new Date().toISOString(),
      status: 'active',
    })).toThrow();
  });

  it('can deprecate a version but still retrieve it', () => {
    registry.deprecate('v1.0');
    const schema = registry.get('v1.0');
    expect(schema).toBeDefined();
    expect(schema!.status).toBe('deprecated');
  });

  it('lists all registered versions', () => {
    const versions = registry.list();
    expect(versions.length).toBeGreaterThanOrEqual(1);
    expect(versions[0].versionId).toBe('v1.0');
  });

  // The registry hands out deep copies, so a returned `hashedFieldSet` is
  // never the module-level V1_0 constant's own array. Were it shared,
  // mutating it would change the hashed field set — and therefore every
  // digest — for every SchemaRegistry in the process, present and future.
  describe('defensive copying of hashedFieldSet', () => {
    // Assert CONTENT, not length. With a shared array these tests would
    // pollute it for each other (a pop in one followed by a push in the
    // next restores the length while corrupting the contents), so a
    // length-only assertion could pass by accident.
    const CANONICAL = [
      'action', 'aiOutput', 'aiSystemId', 'capturedAt', 'contributions', 'decider',
      'evidenceId', 'links', 'reason', 'sequenceNumber', 'signoffExpectation',
    ];

    it('mutating a get() result does not affect a sibling registry', () => {
      const r1 = new SchemaRegistry();
      const r2 = new SchemaRegistry();
      r1.get('v1.0')!.hashedFieldSet.pop();
      expect(r2.get('v1.0')!.hashedFieldSet).toEqual(CANONICAL);
    });

    it('mutating a get() result does not affect a registry constructed later', () => {
      const r1 = new SchemaRegistry();
      r1.get('v1.0')!.hashedFieldSet.push('reviewer');
      // The widest blast radius: a registry that does not exist yet when the
      // mutation happens must not inherit it via V1_0.
      expect(new SchemaRegistry().get('v1.0')!.hashedFieldSet).toEqual(CANONICAL);
    });

    it('mutating a get() result does not affect the same registry on re-read', () => {
      const r = new SchemaRegistry();
      r.get('v1.0')!.hashedFieldSet.push('reviewer');
      expect(r.get('v1.0')!.hashedFieldSet).toEqual(CANONICAL);
    });

    it('mutating a list() result does not leak back into the registry', () => {
      const r = new SchemaRegistry();
      r.list()[0].hashedFieldSet.length = 0;
      expect(r.get('v1.0')!.hashedFieldSet).toEqual(CANONICAL);
    });

    it('mutating serializationRules.separators does not leak back', () => {
      const r = new SchemaRegistry();
      r.get('v1.0')!.serializationRules.separators[0] = ';';
      expect(r.get('v1.0')!.serializationRules.separators[0]).toBe(',');
    });

    it('mutating the array passed to register() does not leak into the registry', () => {
      const r = new SchemaRegistry();
      const fields = ['a', 'b'];
      const base = r.get('v1.0')!;
      r.register({ ...base, versionId: 'v9.9', hashedFieldSet: fields });
      fields.push('c');
      expect(r.get('v9.9')!.hashedFieldSet).toEqual(['a', 'b']);
    });
  });
});

/**
 * The registry's `serializationRules` is the document a third-party verifier
 * implements from, so it must name the order the serializer uses:
 * `Object.keys(obj).sort()`, i.e. UTF-16 code-unit order. Code-point order
 * (`recursive-lexicographic-unicode`) disagrees with it on exactly the shape
 * below, so an outside implementation built from that wording would report
 * honest records as tampered.
 *
 * This pins the declared rule against the observed behaviour rather than
 * against another string literal, so the two cannot drift apart.
 */
describe('declared keySort matches what canonicalSerialize actually does', () => {
  const BMP_FULLWIDTH = '！'; // U+FF01, code point 0xFF01
  const ASTRAL_EMOJI = '\u{1F600}'; // U+1F600, first UTF-16 unit 0xD83D

  it('the astral key sorts FIRST, which is UTF-16 order, not code-point order', () => {
    const text = canonicalSerialize(
      { aiOutput: { [BMP_FULLWIDTH]: 1, [ASTRAL_EMOJI]: 2 } },
      ['aiOutput'],
    );

    expect(text.indexOf(ASTRAL_EMOJI)).toBeLessThan(text.indexOf(BMP_FULLWIDTH));
    // Code-point order would have produced the opposite.
    expect(BMP_FULLWIDTH.codePointAt(0)!).toBeLessThan(ASTRAL_EMOJI.codePointAt(0)!);
  });

  it('the registry names that ordering', () => {
    const rules = new SchemaRegistry().get('v1.0')!.serializationRules;
    expect(rules.keySort).toContain('utf16');
    expect(rules.keySort).not.toContain('unicode');
  });
});
