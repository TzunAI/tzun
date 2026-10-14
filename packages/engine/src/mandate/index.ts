/** The mandate rules (Record §9.6 to §9.11): every pure function, re-exported. */
export {
  P256_ORDER,
  assertionDigest,
  assertionDigestResult,
  decodeBase64Text,
  normaliseEs256Signature,
} from './assertion-digest';
export type { AssertionDigestFailure, AssertionDigestResult } from './assertion-digest';
export {
  MANDATE_DOCUMENT_MAX_BYTES,
  MANDATE_DOCUMENT_VERSION,
  MANDATE_MAX_CAPS,
  MANDATE_MAX_PREDICATES,
  MANDATE_NAME_RE,
  documentGrammarFailure,
  documentPathMembers,
  isMandateInstant,
  mandateDigest,
  mandateDocumentViolation,
  mandateRestrictionHolds,
} from './document';
export type { MandateDocumentOptions } from './document';
export {
  MANDATE_BLOCK_MAX_BYTES,
  MANDATE_EXPECTATION_KEYS,
  checkMandateExpectationMaterial,
  mandateBlockViolation,
} from './expectation';
export {
  MANDATE_AI_SYSTEM_ID,
  MANDATE_EVENT_VERSION,
  MANDATE_ISSUE_ACTION,
  MANDATE_REVOKE_ACTION,
  buildMandateEventBody,
  checkMandateIssuance,
  mandateEventBodyDigest,
  mandateEventBodyViolation,
} from './issuance';
export {
  mandateConfirmationViolation,
  mandateExpiredAt,
  mandateIssuanceInput,
  mandatePrincipalDecider,
  mandateRevocationInput,
  planMandateClaim,
  predecessorPrincipalViolation,
  revocationInstantViolation,
} from './lifecycle';
export {
  GLOB_MAX_PATTERN_LENGTH,
  PREDICATE_MAX_ARRAY_ELEMENTS,
  PREDICATE_MAX_SET,
  PREDICATE_MAX_SUBJECT_CODE_POINTS,
  PREDICATE_OPS,
  evaluatePredicate,
  globMatch,
  parseJsonPointer,
  predicateViolation,
  resolvePointer,
} from './predicate';
export type { PointerResolution } from './predicate';
export {
  checkMandateConsumption,
  checkMandateLimits,
  deciderInMandate,
  evaluateMandateConfirm,
  evaluateMandateScope,
  mandateCapValues,
  recordedModels,
} from './scope';
export {
  MANDATE_STATEMENT_VERSION,
  buildMandateStatement,
  mandateConfirmationChallenge,
  mandateStatementChallenge,
  mandateStatementDigest,
  mandateStatementViolation,
} from './statement';
