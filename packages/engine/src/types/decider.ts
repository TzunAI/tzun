/**
 * The decider member of a v1.0 record (Record §6): who took the
 * decision, inside the digest. Pure type definitions; the rules are in
 * `packages/engine/src/decider.ts`.
 */

/**
 * The kinds a 0.8.0 writer states. A reader abstains on any other string
 * (`unsupported_decider_kind`), so the vocabulary can grow without a grammar
 * change.
 */
export type DeciderKind = 'human' | 'agent' | 'agent-mandated' | 'policy-engine';

/**
 * `payload.decider`: an object with exactly these five members, every one
 * present, `null` where it does not apply.
 *
 * @tzun-canonical-sort utf16
 */
export interface Decider {
  kind: DeciderKind;
  /** `<scheme>:<value>`, 3 to 1,024 characters of 0x21–0x7E (schemes: acct, spiffe, jkt, desc, cmt). */
  id: string;
  /** The agent descriptor digest, `sha256:` and 64 lowercase hex; `null` for a human. */
  agent: string | null;
  /** The digest (64 lowercase hex) of the decider's credential registration record, or `null`. */
  credential: string | null;
  /** A finalized-block reference `<CAIP-2>@<block number>:0x<64 hex>`, or `null`. */
  freshness: string | null;
}

/**
 * What a capture call names as its decider. The SDK resolves it into a
 * {@link Decider}: `id` defaults to `desc:<agent>` for the agent kinds,
 * `freshness: 'auto'` (the default) takes the header follower's cached
 * finalized block, and `commit: true` replaces `id` with a `cmt:` commitment
 * whose opening the store keeps.
 */
export interface DeciderInput {
  kind: DeciderKind;
  id?: string;
  agent?: string | null;
  credential?: string | null;
  /** `'auto'`, `null`, or an explicit finalized-block reference. */
  freshness?: string | null;
  commit?: boolean;
}

/**
 * The opening of a `cmt:` identifier: the 32-byte salt as unpadded base64url
 * and the identifier it commits to. Kept outside the record.
 */
export interface DeciderOpening {
  salt: string;
  id: string;
}

/** Why a decider is refused at capture, first failure first (the engine's `deciderViolation`). */
export type DeciderViolationCode =
  | 'not_an_object'
  | 'unknown_members'
  | 'missing_members'
  | 'invalid_kind'
  | 'invalid_identifier'
  | 'scheme_not_permitted'
  | 'invalid_agent_reference'
  | 'agent_reference_required'
  | 'agent_reference_forbidden'
  | 'desc_identifier_mismatch'
  | 'invalid_credential_reference'
  | 'invalid_freshness_reference'
  | 'freshness_required'
  | 'kind_contradicts_expectation'
  | 'kind_contradicts_material'
  | 'identity_contradicts_assertion'
  | 'commitment_not_supported_by_store';

/** A decider refusal: the code, the field it names, and a message that never echoes the value. */
export interface DeciderViolation {
  code: DeciderViolationCode;
  field: string;
  message: string;
}

/** A finalized-block reference, parsed (`parseFreshnessReference`). */
export interface FreshnessReference {
  /** The CAIP-2 chain id, e.g. `eip155:1`. */
  chain: string;
  namespace: string;
  reference: string;
  blockNumber: number;
  /** `0x` and 64 lowercase hex. */
  blockHash: string;
}
