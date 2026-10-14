"""Shared rules for the append-only revision log.

The Python twin of ``src/storage/revision-log.ts``. The TypeScript SDK is the
one with a recovery path, and the whole defence lives there: a record whose
CURRENT ``canonicalDigest`` is not the one it was CAPTURED with was rewritten
after capture, and ``relink()`` refuses over it. This module exists so that
evidence captured through the PYTHON SDK also has that capture digest written
down — a record with no revision 0 is unprovable, and unprovable is exactly
the silence the rewrite-and-reseat attack needs.

WHAT IS NOT MIRRORED, AND WHY. The Python SDK has no recovery path to defend:
``tzun_sdk/recovery/manager.py:32`` ``relink()`` calls
``storage.store_relink(record)`` and nothing else — it stores a
``RelinkRecord`` and never rewrites a chain link, never appends a custody
entry, and never reports ``chainVerified``. There is therefore nothing here
that could launder a reseat, so only the capture write is mirrored. If Python
ever grows a real relink, the guard in
``src/monitoring/recovery-manager.ts`` is the thing to port with it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from tzun_sdk._generated.models import EvidenceEnvelope

#: Why a revision row was written. The Python SDK only ever writes ``capture``
#: (it has no recovery path); the others exist so a row written by the
#: TypeScript SDK into the shared table reads back with its real cause rather
#: than being coerced or rejected.
RevisionCause = Literal["capture", "relink", "attestation_retry", "anchor_fill"]


@dataclass(frozen=True)
class EnvelopeRevision:
    """One row of the append-only revision log. Mirrors the TS wire type."""

    evidenceId: str
    revisionNo: int
    canonicalDigest: str
    chainLink: str | None
    recordedAt: str
    cause: RevisionCause
    actor: str


def revision_from_row(row: Sequence[Any]) -> EnvelopeRevision:
    """Map a ``(evidence_id, revision_no, canonical_digest, chain_link,
    recorded_at, cause, actor)`` row, in that column order."""
    return EnvelopeRevision(
        evidenceId=row[0],
        revisionNo=int(row[1]),
        canonicalDigest=row[2],
        chainLink=row[3],
        recordedAt=row[4],
        cause=row[5],
        actor=row[6],
    )

#: The revision number ``store()`` always writes. Write-once per evidenceId:
#: ``store()`` refuses a duplicate id, and the INSERT carries an explicit
#: conflict clause so a delete-and-restore under the same id keeps the capture
#: revision it already has. Overwriting it would let a rewritten copy redefine
#: what the record was captured as.
CAPTURE_REVISION_NO = 0

#: Attribution for a capture whose envelope carries no custody entry.
REVISION_ACTOR_SDK = "tzun-sdk"


def capture_revision_actor(envelope: EvidenceEnvelope) -> str:
    """Who the capture revision is attributed to.

    The first custody entry on a freshly assembled envelope is the
    ``decision_captured`` one and its actor is the human the evidence is
    about. An envelope built without a custody chain falls back to the SDK
    rather than to an empty string: a revision row with a blank actor reads as
    "nobody", which is a worse statement than "the SDK".
    """
    if envelope.custodyChain:
        return envelope.custodyChain[0].actor
    return REVISION_ACTOR_SDK


__all__ = (
    "CAPTURE_REVISION_NO",
    "REVISION_ACTOR_SDK",
    "EnvelopeRevision",
    "RevisionCause",
    "capture_revision_actor",
    "revision_from_row",
)
