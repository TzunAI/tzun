"""Mandates (Record §9.6 to §9.11): every pure rule, re-exported.

The twin of ``packages/engine/src/mandate/``: the document ``tzun-mandate/1``
and its digest, predicates, the statement ``tzun-signoff-mandate/1`` and its
challenge, the assertion digest, the mandate form of the expectation, the
issuance check, scope, limits and consumption, event bodies and the
lifecycle. The capture API and the mandate tables are
:class:`tzun_sdk.Tzun`'s ``mandates`` namespace (``tzun_sdk.mandates_api``).
"""

from __future__ import annotations

from tzun_sdk.mandate.assertion_digest import (
    P256_ORDER,
    assertion_digest,
    assertion_digest_result,
    decode_base64_text,
    normalise_es256_signature,
)
from tzun_sdk.mandate.document import (
    MANDATE_DOCUMENT_MAX_BYTES,
    MANDATE_DOCUMENT_VERSION,
    MANDATE_MAX_CAPS,
    MANDATE_MAX_PREDICATES,
    MANDATE_NAME_RE,
    document_grammar_failure,
    document_path_members,
    is_mandate_instant,
    mandate_digest,
    mandate_document_violation,
    mandate_restriction_holds,
)
from tzun_sdk.mandate.expectation import (
    MANDATE_BLOCK_MAX_BYTES,
    MANDATE_EXPECTATION_KEYS,
    check_mandate_expectation_material,
    has_mandate_expectation_members,
    mandate_block_violation,
    mandate_expectation_member_violation,
)
from tzun_sdk.mandate.issuance import (
    MANDATE_AI_SYSTEM_ID,
    MANDATE_EVENT_VERSION,
    MANDATE_ISSUE_ACTION,
    MANDATE_REVOKE_ACTION,
    build_mandate_event_body,
    check_mandate_issuance,
    mandate_event_body_digest,
    mandate_event_body_violation,
)
from tzun_sdk.mandate.lifecycle import (
    mandate_confirmation_violation,
    mandate_expired_at,
    mandate_issuance_input,
    mandate_principal_decider,
    mandate_revocation_input,
    plan_mandate_claim,
    predecessor_principal_violation,
    revocation_instant_violation,
)
from tzun_sdk.mandate.predicate import (
    GLOB_MAX_PATTERN_LENGTH,
    PREDICATE_MAX_ARRAY_ELEMENTS,
    PREDICATE_MAX_SET,
    PREDICATE_MAX_SUBJECT_CODE_POINTS,
    PREDICATE_OPS,
    evaluate_predicate,
    glob_match,
    parse_json_pointer,
    predicate_violation,
    resolve_pointer,
)
from tzun_sdk.mandate.scope import (
    check_mandate_consumption,
    check_mandate_limits,
    decider_in_mandate,
    evaluate_mandate_confirm,
    evaluate_mandate_scope,
    mandate_cap_values,
    recorded_models,
)
from tzun_sdk.mandate.statement import (
    MANDATE_STATEMENT_VERSION,
    build_mandate_statement,
    mandate_confirmation_challenge,
    mandate_statement_challenge,
    mandate_statement_digest,
    mandate_statement_violation,
)

__all__ = (
    "GLOB_MAX_PATTERN_LENGTH",
    "MANDATE_AI_SYSTEM_ID",
    "MANDATE_BLOCK_MAX_BYTES",
    "MANDATE_DOCUMENT_MAX_BYTES",
    "MANDATE_DOCUMENT_VERSION",
    "MANDATE_EVENT_VERSION",
    "MANDATE_EXPECTATION_KEYS",
    "MANDATE_ISSUE_ACTION",
    "MANDATE_MAX_CAPS",
    "MANDATE_MAX_PREDICATES",
    "MANDATE_NAME_RE",
    "MANDATE_REVOKE_ACTION",
    "MANDATE_STATEMENT_VERSION",
    "P256_ORDER",
    "PREDICATE_MAX_ARRAY_ELEMENTS",
    "PREDICATE_MAX_SET",
    "PREDICATE_MAX_SUBJECT_CODE_POINTS",
    "PREDICATE_OPS",
    "assertion_digest",
    "assertion_digest_result",
    "build_mandate_event_body",
    "build_mandate_statement",
    "check_mandate_consumption",
    "check_mandate_expectation_material",
    "check_mandate_issuance",
    "check_mandate_limits",
    "decider_in_mandate",
    "decode_base64_text",
    "document_grammar_failure",
    "document_path_members",
    "evaluate_mandate_confirm",
    "evaluate_mandate_scope",
    "evaluate_predicate",
    "glob_match",
    "has_mandate_expectation_members",
    "is_mandate_instant",
    "mandate_block_violation",
    "mandate_cap_values",
    "mandate_confirmation_challenge",
    "mandate_confirmation_violation",
    "mandate_digest",
    "mandate_document_violation",
    "mandate_event_body_digest",
    "mandate_event_body_violation",
    "mandate_expectation_member_violation",
    "mandate_expired_at",
    "mandate_issuance_input",
    "mandate_principal_decider",
    "mandate_restriction_holds",
    "mandate_revocation_input",
    "mandate_statement_challenge",
    "mandate_statement_digest",
    "mandate_statement_violation",
    "normalise_es256_signature",
    "parse_json_pointer",
    "plan_mandate_claim",
    "predecessor_principal_violation",
    "predicate_violation",
    "recorded_models",
    "resolve_pointer",
    "revocation_instant_violation",
)
