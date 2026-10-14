import { SchemaVersion, SerializationRules } from './types/schema';

const V1_0_RULES: SerializationRules = {
  encoding: 'utf-8',
  format: 'json',
  separators: [',', ':'],
  whitespace: false,
  keySort: 'recursive-lexicographic-utf16-code-unit',
  nullHandling: 'undefined-becomes-null, explicit-null-preserved',
  numberHandling: 'no-trailing-zeros, integers-no-decimal, finite-only',
  stringHandling: 'standard-json-escaping, no-unicode-normalization',
  arrayHandling: 'preserve-insertion-order, elements-recursive',
};

/**
 * The v1.0 hashed field set: eleven names, in byte order (Record §4.1, as
 * revised in place in 0.8.0). `action` and `reason` are the decision taken
 * and the stated reason, whoever took it; `decider` says who that was;
 * `contributions` records who contributed, and is the only place a model's
 * bill of materials is recorded; `links` names the records the decision
 * relates to; `signoffExpectation` says what signature the record owes.
 *
 * Records built under an earlier set recompute to different digests: the 0.7
 * set and the set before 0.7.0 are detection constants in store-schema.ts
 * (`FIELD_SET_0_7`, `FIELD_SET_BEFORE_0_7`), never used to verify, and a store
 * holding such records is refused at open (StoreSchemaOutdatedError).
 */
export const V1_0_HASHED_FIELDS: readonly string[] = Object.freeze([
  'action', 'aiOutput', 'aiSystemId', 'capturedAt', 'contributions', 'decider', 'evidenceId', 'links', 'reason',
  'sequenceNumber', 'signoffExpectation',
]);

/** The schema version a writer builds: the only registered version. */
export const CURRENT_SCHEMA_VERSION = 'v1.0';

const V1_0: SchemaVersion = {
  versionId: 'v1.0',
  hashedFieldSet: [...V1_0_HASHED_FIELDS],
  serializationRules: V1_0_RULES,
  createdAt: '2026-03-22T00:00:00Z',
  status: 'active',
};

/**
 * Deep-copy a schema version across the registry boundary.
 *
 * A shallow `{ ...v }` copies the REFERENCE to `hashedFieldSet`, so the array
 * handed to a caller was the very array stored in the map — and, because the
 * constructor was shallow too, the module-level V1_0 constant itself. One
 * `registry.get('v1.0').hashedFieldSet.push(...)` anywhere in the process
 * therefore changed the hashed field set for every SchemaRegistry in that
 * process, including ones constructed afterwards, and so changed every digest
 * computed or verified from then on. Copying the array (and the separators
 * array inside serializationRules) at every boundary contains that.
 */
function cloneSchemaVersion(v: SchemaVersion): SchemaVersion {
  return {
    ...v,
    hashedFieldSet: [...v.hashedFieldSet],
    serializationRules: {
      ...v.serializationRules,
      separators: [...v.serializationRules.separators] as [string, string],
    },
  };
}

export class SchemaRegistry {
  private versions: Map<string, SchemaVersion> = new Map();

  constructor() {
    this.versions.set(V1_0.versionId, cloneSchemaVersion(V1_0));
  }

  get(versionId: string): SchemaVersion | undefined {
    const v = this.versions.get(versionId);
    return v ? cloneSchemaVersion(v) : undefined;
  }

  register(schema: SchemaVersion): void {
    if (this.versions.has(schema.versionId)) {
      throw new Error(
        `Schema version "${schema.versionId}" is already registered. ` +
        'Schema versions are append-only and cannot be overwritten.'
      );
    }
    this.versions.set(schema.versionId, cloneSchemaVersion(schema));
  }

  deprecate(versionId: string): void {
    const schema = this.versions.get(versionId);
    if (!schema) {
      throw new Error(`Schema version "${versionId}" not found.`);
    }
    schema.status = 'deprecated';
  }

  list(): SchemaVersion[] {
    return Array.from(this.versions.values()).map(cloneSchemaVersion);
  }
}
