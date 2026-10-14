"""Wire models — re-export shim over the generated module.

``tzun_sdk.models.X`` import paths are stable. The classes are emitted by
``scripts/codegen-python.ts`` into ``tzun_sdk/_generated/models.py`` from
``packages/engine/src/types/*.ts``; regenerate with ``pnpm run codegen:python``.

Hand-retained classes (not derivable from the engine type scan):
  - ``DecisionInput`` (TS source: ``src/sdk/wrappers.ts`` — outside engine type scan)
  - ``CaptureResult`` (Python-SDK-local runtime result shape; engine CaptureResult
    carries different fields under engine semantics — generated in _generated for
    wire use)
  - ``VerificationResult`` (Python-SDK-local runtime result shape; engine
    VerificationResult has richer fields — generated in _generated for wire use)
  - ``TamperIncident`` (Python-SDK-local runtime result shape; engine TamperIncident
    has richer incident-management fields — generated in _generated for wire use)
  - ``FailureRecord`` (Python-SDK-local runtime result shape; engine FailureRecord
    has different field semantics — generated in _generated for wire use)
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tzun_sdk._generated.models import *  # noqa: F403
from tzun_sdk._generated.models import (
    AgentReferenceCheck,
    AiBom,
    AiBomWithInlineDescriptor,
    AssertionProvenance,
    CaptureMandateSlot,
    ContributionsCheck,
    DeciderCheck,
    DeciderInput,
    DeciderOpening,
    EvidenceEnvelope,
    LinkInput,
    LinksCheck,
    MandateCheck,
    SignoffExpectationReason,
    StepActorInput,
)
from tzun_sdk._generated.models import __all__ as _GENERATED_ALL


class _Forbid(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ── Hand-retained: DecisionInput ──────────────────────────────────────────────


class DecisionInput(_Forbid):
    """Kwarg interception target for ``attach()``.

    The application constructs this and passes it via the ``tzun_capture``
    kwarg to a wrapped vendor client method. The wrapper strips the kwarg
    before forwarding, then calls ``hook()`` and ``capture()``: the model the
    vendor call used becomes the record's one contribution step
    (``single_model(ai_bom, actor=actor)``).

    Field names match the TS ``DecisionInput`` interface (camelCase) so the
    same shape parses identically in both languages: ``action`` and
    ``reason`` (the decision and its stated reason), ``decider`` (who
    decided), ``actor`` (the agent that called the model, as the step's
    actor; omitted for a model called directly), ``links``, and ``aiBom`` to
    record a model other than the one the call's response names.

    ``metadata`` is **not** forwarded and is not recorded in evidence: the
    shared envelope has no slot for it. ``attach()`` emits a WARNING naming
    the dropped keys rather than discarding them silently.
    """

    action: str
    reason: str
    decider: DeciderInput
    actor: StepActorInput | None = None
    links: list[LinkInput] | None = None
    aiSystemId: str | None = None
    metadata: dict[str, Any] | None = None
    aiBom: AiBom | AiBomWithInlineDescriptor | None = None


# ── Hand-retained: Python-SDK-local runtime result shapes ─────────────────────
# The engine types of the same names exist in _generated/models.py but carry
# different field sets (generated under their engine semantics for wire use).
# These are the Python SDK's public API result shapes — stable across 0.x.


class CaptureResult(_Forbid):
    """Return shape of ``Tzun.capture()``.

    ``deciderOpening`` is the opening of a ``cmt:`` decider the capture
    computed (``decider["commit"] = True``), also kept in the store;
    ``mandate`` is the slot and running totals a capture under a mandate
    claimed (Record §6.3, §9.6).
    """

    evidenceId: str
    canonicalDigest: str
    sequenceNumber: int
    envelope: EvidenceEnvelope
    deciderOpening: DeciderOpening | None = None
    mandate: CaptureMandateSlot | None = None


class VerificationResult(_Forbid):
    """Return shape of ``Tzun.verify()`` and ``Tzun.verify_range()``.

    ``custodyTrailValid`` mirrors the TS engine field of the
    same name: ``True``/``False`` when at least one ``custodyChain`` entry
    carries an ``entryHash``, ``None`` when none does — an unhashed trail is
    unverified, not invalid. Deliberately NOT folded into ``valid`` or
    ``reasons``: ``valid`` keeps meaning "the decision record and its chain
    link are intact"; a ``False`` here means the record of who did what to it
    afterwards has been altered.

    ``assertionProvenance`` mirrors the TS field of the same
    name: where the WebAuthn ceremony ran and what kind of key signed, and the
    checks ``verify()`` was asked for. ``None`` for a record with no
    assertion. This SDK holds no credential store, so no check in it is
    ``True``.

    ``signoffExpectationValid`` and ``signoffExpectationReason`` (Record §9,
    Verification §5) mirror the TS engine fields: the record's sign-off material
    against its hashed ``payload.signoffExpectation``, read from the record
    alone (``tzun_sdk.signoff_expectation.check_signoff_expectation``), and
    only when its digest recomputes: ``None``/``digest_invalid`` is a record
    whose digest does not hold, so its expectation is not authenticated and is
    not read. ``None``/``signature_missing`` is a record that lacks the signature its
    ``{policyDigest}`` expectation requires (awaiting sign-off, or stripped);
    ``False``/``signoff_stripped`` is a session record without the sign-off it
    was written with; ``False``/``signoff_unbound`` is a record carrying a
    sign-off that does not bind to it (moved, relabelled or made up). Like
    ``custodyTrailValid``, not folded into ``valid``.

    The record-rule rows (``decider``, ``contributions``, ``links``,
    ``mandate``, ``agents``, ``unhashedPayloadMembers``, ``fieldSet``) mirror
    the engine ``VerificationResult`` fields of the same names; like the
    expectation, none is folded into ``valid``.
    """

    valid: bool
    evidenceId: str
    canonicalDigest: str
    chainLinkValid: bool | None
    descriptorResolved: bool
    attestationVerified: bool | None
    reasons: list[str] = Field(default_factory=list)
    custodyTrailValid: bool | None = None
    assertionProvenance: AssertionProvenance | None = None
    signoffExpectationValid: bool | None = None
    signoffExpectationReason: SignoffExpectationReason | None = None
    #: On a digest mismatch, the earlier v1.0 field set the stored digest recomputes under (Record §4.1; explains, never excuses).
    fieldSet: str | None = None
    #: Payload members outside the format's twelve names: not hashed, reported (Record §2.2).
    unhashedPayloadMembers: list[str] = Field(default_factory=list)
    #: The record-rule rows (Verification §4.9-§4.12), read only where the digest holds.
    decider: DeciderCheck | None = None
    contributions: ContributionsCheck | None = None
    links: LinksCheck | None = None
    mandate: MandateCheck | None = None
    #: The decider's and every step actor's agent reference, resolved against the store's catalog.
    agents: list[AgentReferenceCheck] = Field(default_factory=list)


class TamperIncident(_Forbid):
    """Emitted by the monitoring layer when a tamper is detected.

    Python-SDK-local shape. The engine TamperIncident (in _generated/models.py)
    carries richer incident-management fields under engine semantics.
    """

    incidentId: str
    eventType: str
    evidenceId: str | None = None
    detectedAt: str
    details: dict[str, Any] = Field(default_factory=dict)


class FailureRecord(_Forbid):
    """Recorded when a decision capture cannot complete.

    Python-SDK-local shape. The engine FailureRecord (in _generated/models.py)
    carries different field semantics (failureType, diagnosticMetadata, capturedAt).
    """

    failureId: str
    reason: str
    timestamp: str
    metadata: dict[str, Any] = Field(default_factory=dict)


__all__ = (
    *_GENERATED_ALL,
    "CaptureResult",
    "DecisionInput",
    "FailureRecord",
    "TamperIncident",
    "VerificationResult",
)
