/** Serialization rules for a schema version. */
export interface SerializationRules {
  encoding: 'utf-8';
  format: 'json';
  separators: [string, string];
  whitespace: boolean;
  /**
   * Key ordering. `recursive-lexicographic-utf16-code-unit` is
   * `Array.prototype.sort()` on the key strings — UTF-16 code-unit ordinal
   * comparison — applied at every level.
   *
   * The name says UTF-16 code unit because a looser name such as
   * `recursive-lexicographic-unicode` reads as Unicode CODE POINT order, and
   * the two disagree for any BMP key in U+E000..U+FFFF next to an astral key:
   * code-point order puts U+FF01 before U+1F600, UTF-16 code-unit order puts
   * U+1F600 (surrogate D83D) first. A verifier built on code-point order
   * reports honest records as tampered. The implementations — canonical.ts
   * `Object.keys(obj).sort()` and canonical.py
   * `key=lambda s: s.encode('utf-16-be')` — both sort by UTF-16 code unit.
   */
  keySort: 'recursive-lexicographic-utf16-code-unit';
  nullHandling: string;
  numberHandling: string;
  stringHandling: string;
  arrayHandling: string;
}

/** A schema version entry in the registry. */
export interface SchemaVersion {
  versionId: string;
  hashedFieldSet: string[];
  serializationRules: SerializationRules;
  createdAt: string;
  status: 'active' | 'deprecated';
}
