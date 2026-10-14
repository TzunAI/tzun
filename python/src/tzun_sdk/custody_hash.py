# HAND-MAINTAINED Python port of packages/engine/src/custody-hash.ts. NOT generated.
#
# Parity with the TypeScript is enforced by tests/cross-sdk/test_custody_hash_parity.py
# (live Node<->Python harness over vectors/custody-entry-hash-vectors.json, whose
# expected values were computed with the hosted service's implementation), not by the
# codegen-drift job. Edit both files together.
"""The custody entry hash and the offline custody-trail verifier.

A ``relinked`` / ``chain_forked`` / ``reviewed`` custody entry is bound by its
own hash, chained to the previous hashed entry on the SAME record and to the
record's canonical digest::

    entryHash = sha256( lp(prevEntryHash) || lp(evidenceId) || lp(canonicalDigest)
                      || lp(action) || lp(actor) || lp(timestamp) || lp(systemId)
                      || lp(canonical(metadata)) )

``lp(v)`` is ``"<Unicode code-point count>:" + v`` (``"-:"`` for absent/null) —
``len(s)`` in Python, which counts code points exactly as Postgres
``length(text)`` and the TypeScript ``codePointLength`` do — and
``canonical(metadata)`` is the engine canonical serializer over the JSON
round-tripped metadata object (``canonical_serialize``: keys sorted by UTF-16
code unit at every level, no whitespace). Bare lowercase hex, no ``sha256:``
prefix. The rule must agree byte for byte with the platform's
``backend/src/app/custody-hash.ts`` and its SQL twin ``tzun_custody_entry_hash``.

The Python SDK has no custody WRITER: ``RecoveryManager.relink/fork/annotate``
persist recovery records only (no chain-link rewrite, no custody append). What
Python does is READ: ``Tzun.verify()`` reports ``custodyTrailValid`` from
:func:`verify_custody_trail`, exactly as the TypeScript ``verifyEnvelope`` does.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from tzun_sdk._generated.canonical import canonical_serialize
from tzun_sdk._generated.models import CustodyTrailFailure, CustodyTrailVerdict

# Applied with fullmatch: `$` also matches before a trailing newline, so
# re.match(r"^...$") would accept "<64 hex>\n", which the TS engine and the
# platform refuse.
_HEX64 = re.compile(r"[0-9a-f]{64}")

#: The entry hash rule in words, as an export bundle's ``custody.hashPreimage``
#: states it. The same text as the engine's ``CUSTODY_ENTRY_HASH_PREIMAGE`` and
#: the hosted service's ``server.custody.hashPreimage``.
CUSTODY_ENTRY_HASH_PREIMAGE = (
    "sha256(lp(prevEntryHash)||lp(evidenceId)||lp(canonicalDigest)||lp(action)||lp(actor)"
    "||lp(timestamp)||lp(systemId)||lp(canonicalMetadata)); "
    'lp = "<code points>:<value>" or "-:" for null; '
    "canonicalMetadata = engine canonical JSON of metadata"
)


def code_point_length(s: str) -> int:
    """Unicode code points in ``s`` — what Postgres ``length(text)`` returns."""
    return len(s)


def length_prefix(value: str | None) -> str:
    """``tzun_lp``: ``<code-point length>:<value>``, ``-:`` for None."""
    return "-:" if value is None else f"{code_point_length(value)}:{value}"


def normalise_custody_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """What a JSON round trip yields — the value every reader will actually see."""
    if metadata is None:
        return None
    normalised: dict[str, Any] = json.loads(json.dumps(metadata))
    return normalised


def canonical_custody_metadata(metadata: Mapping[str, Any] | None) -> str | None:
    """Engine-canonical bytes of the metadata object, or None when absent."""
    m = normalise_custody_metadata(metadata)
    if m is None:
        return None
    return canonical_serialize(m, None)


def custody_entry_preimage(
    *,
    prev_entry_hash: str | None,
    evidence_id: str,
    canonical_digest: str,
    action: str,
    actor: str,
    timestamp: str,
    system_id: str,
    metadata: Mapping[str, Any] | None = None,
) -> str:
    return (
        length_prefix(prev_entry_hash)
        + length_prefix(evidence_id)
        + length_prefix(canonical_digest)
        + length_prefix(action)
        + length_prefix(actor)
        + length_prefix(timestamp)
        + length_prefix(system_id)
        + length_prefix(canonical_custody_metadata(metadata))
    )


def compute_custody_entry_hash(
    *,
    prev_entry_hash: str | None,
    evidence_id: str,
    canonical_digest: str,
    action: str,
    actor: str,
    timestamp: str,
    system_id: str,
    metadata: Mapping[str, Any] | None = None,
) -> str:
    preimage = custody_entry_preimage(
        prev_entry_hash=prev_entry_hash,
        evidence_id=evidence_id,
        canonical_digest=canonical_digest,
        action=action,
        actor=actor,
        timestamp=timestamp,
        system_id=system_id,
        metadata=metadata,
    )
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def _field(entry: Any, key: str) -> Any:
    """Read ``key`` off a custody entry given as a dict or as a pydantic model."""
    if isinstance(entry, Mapping):
        return entry.get(key)
    return getattr(entry, key, None)


def _is_plain_object(value: Any) -> bool:
    """True when ``value`` is a JSON object — the only shape metadata may be."""
    return isinstance(value, Mapping)


_CUSTODY_STRING_FIELDS = ("action", "actor", "timestamp", "systemId")


def _custody_prev_entry_hash_well_typed(entry: Any) -> bool:
    """``prevEntryHash`` is a string, ``None``, or absent (absent reads as None)."""
    prev = _field(entry, "prevEntryHash")
    return prev is None or isinstance(prev, str)


def _custody_entry_fields_well_typed(entry: Any) -> bool:
    """Whether every field the hash rule reads off ``entry`` is the required type.

    A non-string ``actor`` / ``timestamp`` / ``systemId`` is never coerced:
    ``str(_field(entry, "actor"))`` would turn ``123`` into ``"123"`` and a
    list into ``"[1, 2]"``, and a malformed entry would read as an ordinary
    ``entry_hash_mismatch``, as though the real value had been hashed and
    compared. ``custodyChain`` is client-supplied JSON on every server that
    verifies what a client sent, and JSON guarantees no type, so both SDKs
    answer ``entry_field_type`` on exactly the same inputs.
    """
    for field in _CUSTODY_STRING_FIELDS:
        if not isinstance(_field(entry, field), str):
            return False
    if not _custody_prev_entry_hash_well_typed(entry):
        return False
    metadata = _field(entry, "metadata")
    if metadata is not None and not _is_plain_object(metadata):
        return False
    return True


def is_hashed_custody_entry(entry: Any) -> bool:
    """True when ``entry`` carries a well-formed bare-hex ``entryHash`` (platform rule).

    Anything else — no key, ``None``, a prefixed or malformed string, uppercase,
    a trailing newline — is the client-attested form, which no server hash
    covers: counted, not vouched for.
    """
    if entry is None or isinstance(entry, (str, bytes, list, tuple)):
        return False
    value = _field(entry, "entryHash")
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def verify_custody_trail(
    custody_chain: Sequence[Any],
    *,
    evidence_id: str,
    canonical_digest: str,
) -> CustodyTrailVerdict:
    """The offline custody-trail verdict for one envelope.

    1. Every entry WITHOUT an ``entryHash`` must precede the first entry WITH
       one (``unhashed_after_hashed``).
    2. For hashed entries in order, ``prevEntryHash`` must equal the previous
       hashed entry's ``entryHash``, ``None`` for the first
       (``prev_entry_hash_mismatch``). An ABSENT ``prevEntryHash`` reads as
       ``None`` — a round trip cannot tell the two apart.
    3. ``entryHash`` must recompute from the entry's own fields, ``evidence_id``
       and ``canonical_digest`` (``entry_hash_mismatch``).
    4. Every field the hash rule consumes must be the type the rule requires
       (``entry_field_type``), and a plain-object ``metadata`` must actually
       canonicalize (``entry_metadata_unserializable``). NEVER RAISES on a
       malformed entry — see :func:`_custody_entry_fields_well_typed`
      .

    ``valid`` is ``None`` when the chain carries no hashed entry at all — an
    unhashed trail is UNVERIFIED, never a vacuous ``True``.
    """
    failures: list[CustodyTrailFailure] = []
    hashed: list[tuple[int, Any]] = []
    unhashed = 0
    seen_hashed = False

    if custody_chain is None or isinstance(custody_chain, (str, bytes, Mapping)):
        custody_chain = ()

    for index, entry in enumerate(custody_chain):
        if is_hashed_custody_entry(entry):
            seen_hashed = True
            hashed.append((index, entry))
        else:
            unhashed += 1
            if seen_hashed:
                failures.append(CustodyTrailFailure(reason="unhashed_after_hashed", index=index))

    # Both record-level strings are length-prefixed into EVERY entry's preimage,
    # so an ill-typed one makes no entry on the record recomputable.
    record_fields_well_typed = isinstance(evidence_id, str) and isinstance(canonical_digest, str)

    prev: str | None = None
    for index, entry in hashed:
        prev_well_typed = _custody_prev_entry_hash_well_typed(entry)
        # A wrong-typed prevEntryHash is a field-type failure, not a chain
        # break: "5 is not the previous entryHash" is true but says less than
        # "5 is not a hash at all".
        if prev_well_typed:
            claimed_prev = _field(entry, "prevEntryHash")
            if claimed_prev != prev:
                failures.append(
                    CustodyTrailFailure(reason="prev_entry_hash_mismatch", index=index)
                )

        entry_hash = str(_field(entry, "entryHash"))

        if not record_fields_well_typed or not _custody_entry_fields_well_typed(entry):
            failures.append(CustodyTrailFailure(reason="entry_field_type", index=index))
            prev = entry_hash
            continue

        try:
            recomputed = compute_custody_entry_hash(
                prev_entry_hash=_field(entry, "prevEntryHash"),
                evidence_id=evidence_id,
                canonical_digest=canonical_digest,
                action=_field(entry, "action"),
                actor=_field(entry, "actor"),
                timestamp=_field(entry, "timestamp"),
                system_id=_field(entry, "systemId"),
                metadata=_field(entry, "metadata"),
            )
        except Exception:
            # Bare `Exception` on purpose: ANY refusal from the serializer is
            # the same verdict, and a verifier must never let one escape to
            # its caller.
            # metadata is a plain object the canonical serializer still refuses:
            # a lone surrogate, nesting past MAX_DEPTH, a value with no JSON
            # form. There is no preimage, so there is no hash to compare — that
            # is a verdict, not an exception to raise at the caller.
            failures.append(
                CustodyTrailFailure(reason="entry_metadata_unserializable", index=index)
            )
            prev = entry_hash
            continue

        if recomputed != entry_hash:
            failures.append(CustodyTrailFailure(reason="entry_hash_mismatch", index=index))
        # Continue from the STORED hash so one bad entry is reported once, not
        # cascaded onto every later entry (same choice as the TS engine and the platform).
        prev = entry_hash

    return CustodyTrailVerdict(
        valid=None if not hashed else len(failures) == 0,
        hashedEntries=len(hashed),
        unhashedEntries=unhashed,
        failures=failures,
    )


__all__ = (
    "CUSTODY_ENTRY_HASH_PREIMAGE",
    "canonical_custody_metadata",
    "code_point_length",
    "compute_custody_entry_hash",
    "custody_entry_preimage",
    "is_hashed_custody_entry",
    "length_prefix",
    "normalise_custody_metadata",
    "verify_custody_trail",
)
