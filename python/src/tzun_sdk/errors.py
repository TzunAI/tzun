"""Exception hierarchy for tzun-sdk.

All SDK-raised exceptions inherit from :class:`TzunError`. Catching the
base class is the recommended pattern for any code that wants to handle
all SDK errors uniformly while letting unrelated exceptions propagate.

Each subclass signals one condition, which its docstring names.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tzun_sdk.models import ChainHead


class TzunError(Exception):
    """Base class for all tzun-sdk exceptions."""


class VerificationError(TzunError):
    """Raised when an envelope fails verification — digest mismatch, chain break, etc.

    Tamper signal; not generally recoverable.
    """


class TamperDetected(TzunError):
    """Raised when the monitoring layer emits a ``TamperIncident``.

    Tamper signal; surfaces a security event for the caller to escalate.
    """


class DescriptorNotRegistered(TzunError):
    """Verifier cannot resolve a descriptor via catalog or cache.

    Recoverable: register the descriptor and retry.
    """


class WireFormatMismatch(TzunError):
    """Envelope ``schemaVersion`` does not match the SDK's supported version.

    Non-recoverable from the SDK's side — version skew between SDKs.
    """


class MissingExtraError(TzunError):
    """A code path requires an optional extra that is not installed.

    Message names the exact ``pip install`` command to fix the missing extra.
    """


class CodegenDriftError(TzunError):
    """The in-tree ``_generated/`` files do not match a fresh codegen run.

    Only raised when ``TZUN_VERIFY_CODEGEN_AT_IMPORT=1`` is set.
    """


class TsaUnavailableError(TzunError):
    """RFC 3161 TSA unreachable — network error, timeout, or open circuit."""


class WebAuthnVerificationError(TzunError):
    """WebAuthn at-rest verification failure.

    The original ``py-webauthn`` exception is chained via ``raise ... from e``.
    """


class SigstoreIdentityMismatchError(TzunError):
    """Sigstore signature identity not in the allowed-identities list."""


class AdminTokenRequiredError(TzunError):
    """Admin-gated operation invoked without a matching admin token."""


class ChainConflictError(TzunError):
    """A conditional chain append was refused because the head moved.

    :meth:`~tzun_sdk.core.Tzun.capture` reserves a sequence number and computes
    a chain link from the head it read, then hashes both into the record —
    ``sequenceNumber`` is inside the v1.0 hashed field set, so it cannot be
    assigned after the digest exists. That makes the append a compare-and-swap:
    if the head is no longer what it was when the record was built, the record
    does not belong at that position and MUST NOT be written. Writing it anyway
    is what produced two records at the same sequence, both linking to the same
    predecessor, both reported as captured — after which every verifier reports
    chain breaks on evidence nobody tampered with, and real tampering becomes
    indistinguishable from load.

    ``code`` is the same stable discriminator the TS twin
    (``packages/engine/src/errors.ts``) and the cloud error contract use:
    ``"chain_conflict"``.

    A refused append is a *transient* answer, not a broken store: the record
    was built against a head that has since moved, and the same input rebuilt
    against the head this error carries in ``actual`` will (absent further
    contention) be accepted. That is what a compare-and-swap is for, and it is
    why ``retryable`` is ``True`` — so a caller can tell "the head moved under
    me" from "the database is broken" by ``(code, retryable)`` alone.
    :meth:`~tzun_sdk.core.Tzun.capture` performs that rebuild-and-retry itself
    (bounded by ``chain_conflict_max_attempts``) and only raises this once the
    bound is exhausted.
    """

    #: Stable discriminator for callers that branch on the cause.
    code = "chain_conflict"
    #: Always ``True``: re-capturing the decision against ``actual`` is the
    #: correct response to a moved head.
    retryable = True

    def __init__(self, expected: ChainHead, actual: ChainHead) -> None:
        expected_digest = expected.digest if expected.digest else None
        actual_digest = actual.digest if actual.digest else None
        super().__init__(
            "Chain conflict: the chain head moved between building this record "
            f"and storing it. Expected head sequence {int(expected.sequence)} "
            f"digest {expected_digest if expected_digest is not None else '(none)'}, "
            f"but the store holds sequence {int(actual.sequence)} digest "
            f"{actual_digest if actual_digest is not None else '(none)'}. The "
            "record was NOT stored — its sequence number and chain link are "
            "baked into its digest and would duplicate or orphan an existing "
            "record."
        )
        #: The head the caller built its record against.
        self.expected = expected
        #: The head the store actually holds.
        self.actual = actual


class DuplicateEvidenceError(TzunError):
    """An append was refused because a record with that ``evidenceId`` already exists.

    Storage is append-only and ``evidenceId`` is the primary key of the
    evidence table in every adapter, so a second ``store()`` of an id that is
    already present can only be a replay, a retry of a write that already
    succeeded, or an attempt to rewrite history. None of those may land.
    The memory, SQLite and Postgres adapters all raise this, before the
    chain-head compare-and-swap, with the message the TypeScript adapters
    throw (``src/storage/memory.ts``): one answer to one question, never an
    overwritten record or a raw driver error such as
    ``sqlite3.IntegrityError``.

    ``code`` is the stable discriminator for callers that branch on the
    cause: ``"evidence_id_conflict"`` — the same string the cloud capture
    endpoint of the hosted service answers for this condition
    (``409 evidence_id_conflict``), so a caller that moves from a
    local adapter to :class:`~tzun_sdk.storage.http.HttpBackendAdapter`
    keeps one branch for one condition. :class:`ChainConflictError` already
    matches its wire name the same way (``chain_conflict``).
    """

    #: Stable discriminator for callers that branch on the cause. Same string
    #: the cloud capture endpoint answers for this condition (409
    #: `evidence_id_conflict`), as
    #: `ChainConflictError.code` already matches the wire `chain_conflict`.
    code = "evidence_id_conflict"

    def __init__(self, evidence_id: str) -> None:
        super().__init__(
            f'Evidence record "{evidence_id}" already exists. Storage is append-only.'
        )
        #: The id that is already present in the store.
        self.evidence_id = evidence_id


class TzunCaptureError(TzunError):
    """Raised when the cloud capture endpoint returns a non-2xx error.

    Carries the stable machine-readable ``code`` from the server response body
    (e.g. ``"verification_failed"``, ``"chain_conflict"``, ``"unauthenticated"``)
    and the HTTP ``status`` code so callers can branch on both without parsing
    the raw exception message.
    """

    def __init__(self, message: str, *, code: str, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class ModelCatalogUnsupportedError(TzunError):
    """The store keeps no model catalog: :class:`~tzun_sdk.storage.http.HttpBackendAdapter`
    against a platform that does not serve ``POST /v1/models``.

    ``hook()`` reads it as "the model cannot be recorded" (it returns ``None``
    and logs ``capture_model_not_recordable``), and ``capture()`` refuses an
    inline step descriptor with ``invalid_step_ai_bom``, as on a store that has
    no ``register_descriptor``. The TS twin is ``ModelCatalogUnsupportedError``.
    """

    code = "model_catalog_not_supported_by_store"


class InvalidSignoffExpectationError(TzunError):
    """A capture's ``signoff_expectation`` was refused before anything was built.

    The value becomes the record's hashed ``payload.signoffExpectation``
    (Record §9.1), so it is checked first, as the TS SDK checks
    ``CaptureOptions.signoffExpectation``: it is ``None`` or exactly
    ``{"policyDigest": <64 lowercase hex>}``. ``violation`` is the engine's
    ``SignoffExpectationViolation`` code; ``"session_slot_not_claimed"`` for
    the session form ``{"statementDigest", "sessionSeq"}``, which only the
    capture that claimed a sign-off session slot may write (this SDK opens no
    sign-off sessions); ``"mandate_form_not_writable"`` for the mandate form,
    which only a capture under a mandate writes, from its claim; or
    ``"expectation_with_mandate"`` for any expectation given beside
    ``mandate``. No sequence number is taken.
    """

    #: The same refusal the TS SDK reports as a ``validation_failure``.
    code = "validation_failure"

    def __init__(self, violation: str, message: str) -> None:
        super().__init__(message)
        #: Why the value was refused.
        self.violation = violation
        #: The capture argument that carried it, by its wire name.
        self.field = "signoffExpectation"


class StoreSchemaOutdatedError(TzunError):
    """The store holds records an earlier release captured under an earlier v1.0 field set.

    The v1.0 hashed field set was revised in place twice: 0.7.0 added
    ``signoffExpectation``, and 0.8.0 renamed ``humanAction``/``humanReason``
    to ``action``/``reason``, moved ``aiBom`` into ``contributions`` and added
    ``decider``, ``contributions`` and ``links`` (Record §4.1 names both earlier
    sets). A record
    of an earlier generation has a digest over the earlier set, and every
    check this release runs reads it as tampered. ``Tzun.init()`` refuses such
    a store, before it captures anything and, for SQLite and Postgres, before
    the adapter sets up its tables, recognising it by its first record
    (``record_field_set_generation``; the newest decides when the first is an
    old record that was altered). Create a new store and capture into that;
    the old one is unchanged. The twin of the engine's
    ``StoreSchemaOutdatedError``.
    """

    #: Stable discriminator, the TS error's ``code``.
    code = "store_schema_outdated"
    #: Opening the same store again is refused again: the remedy is a new store.
    retryable = False

    def __init__(self, evidence_id: str, generation: str = "before-0.7") -> None:
        release = "0.7.x" if generation == "0.7" else "a release before 0.7.0"
        super().__init__(
            f"This store was written by Tzun SDK {release} (record {evidence_id}, field set "
            f"{generation}), and this release hashes the revised v1.0 field set, so every record "
            "in it would verify as tampered. Create a new store and capture into that. The old "
            "store is unchanged."
        )
        #: The record the store was recognised by.
        self.evidence_id = evidence_id
        #: The field-set generation of that record: ``"0.7"`` or ``"before-0.7"``.
        self.generation = generation


class CaptureRefusedError(TzunError):
    """A capture refused before anything was stored.

    ``code`` is the refusal's code (``invalid_action``, ``not_a_set``,
    ``link_target_not_found``, ...), ``field`` names the member, and the
    message names the field and the rule and never echoes a value. Raised
    before any sequence number is taken. ``details`` carries what the TS
    SDK's ``FailureRecord.diagnosticMetadata`` carries beside them
    (``renamedTo``, ``movedTo``, ``step``, ``link``, ``rule``, ``findings``).
    """

    #: The member a refusal of this class is about.
    rule = "payload"

    def __init__(self, code: str, field: str, message: str, **details: object) -> None:
        super().__init__(message)
        #: The refusal's code.
        self.code = code
        #: The member it concerns.
        self.field = field
        #: Further facts about the refusal (never a refused value).
        self.details: dict[str, object] = {k: v for k, v in details.items() if v is not None}


class InvalidPayloadError(CaptureRefusedError):
    """A payload member is refused: ``action``, ``reason``, ``aiOutput``, ``aiSystemId``, size, a 0.7 name."""

    rule = "payload"


class InvalidDeciderError(CaptureRefusedError):
    """The decider is refused (Record §6): its grammar, consistency, agreement or freshness."""

    rule = "decider"


class InvalidContributionsError(CaptureRefusedError):
    """The contributions member is refused (Record §7), or a step's model is not in the catalog."""

    rule = "contributions"


class InvalidLinksError(CaptureRefusedError):
    """The links member is refused (Record §8): grammar, registry, profiles, rules, or an unresolved target."""

    rule = "links"


class InvalidMandateError(CaptureRefusedError):
    """A mandate document, statement or assertion is refused (Record §9.6-§9.8)."""

    rule = "mandate"


class MandateRefusedError(CaptureRefusedError):
    """A capture, issuance, revocation or confirmation under a mandate is refused (Record §9.6, §9.9, §9.10)."""

    rule = "mandate"


class InvalidAgentDescriptorError(CaptureRefusedError):
    """An agent descriptor is refused, or a capture names an agent the catalog does not hold (Record §6.9)."""

    rule = "agents"


class MandateClaimConflictError(TzunError):
    """A mandate slot claim lost its compare-and-swap: another capture took the slot first.

    Raised by an adapter's ``store()`` inside the transaction, which rolls
    back. :meth:`~tzun_sdk.core.Tzun.capture` re-reads the mandate and
    rebuilds the record at the next slot, as it does for a moved chain head.
    """

    code = "mandate_claim_conflict"
    retryable = True

    def __init__(self, mandate_id: str) -> None:
        super().__init__(f"Mandate {mandate_id}: another capture claimed the slot first.")
        self.mandate_id = mandate_id


__all__ = (
    "AdminTokenRequiredError",
    "CaptureRefusedError",
    "ChainConflictError",
    "CodegenDriftError",
    "DescriptorNotRegistered",
    "DuplicateEvidenceError",
    "InvalidAgentDescriptorError",
    "InvalidContributionsError",
    "InvalidDeciderError",
    "InvalidLinksError",
    "InvalidMandateError",
    "InvalidPayloadError",
    "InvalidSignoffExpectationError",
    "MandateClaimConflictError",
    "MandateRefusedError",
    "MissingExtraError",
    "ModelCatalogUnsupportedError",
    "SigstoreIdentityMismatchError",
    "StoreSchemaOutdatedError",
    "TamperDetected",
    "TsaUnavailableError",
    "TzunCaptureError",
    "TzunError",
    "VerificationError",
    "WebAuthnVerificationError",
    "WireFormatMismatch",
)
