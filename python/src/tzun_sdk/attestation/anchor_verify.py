# HAND-MAINTAINED. NOT generated.
#
# The Python twin of src/attestation/anchor-verify.ts: `verifyAnchor`, steps 1 to 6
# of tzun-anchor/1 §10.3 and the anchor fields of §10.6. The verdict is a dict
# with the TypeScript SDK's field names, so the two SDKs' answers compare as JSON.
# tests/cross-sdk/test_anchor_verify_parity.py holds them to the same verdicts;
# tests/cross-sdk/test_checkpoint_vectors.py and test_anchor_e2e_vectors.py hold
# this module to the vector files. Edit both sides together.
"""``verify_anchor``: a record's ``nonRepudiation.anchor`` checked under tzun-anchor/1
§10.3, §10.6.

The artifact places the record's digest in its chain's evidence log, and that
log's checkpoint in the domain's anchor log. The anchor log's own checkpoint
hashes to P, and each publication commits to P:

1. the tags are known (``tzun-anchor/1``, ``rfc6962``), or the verifier abstains;
2. the members are exactly those of Anchor §8.1 with their types, and ``publications``
   is a non-empty list (``malformed_anchor``); both checkpoint bodies parse under
   the exact form (``malformed_checkpoint``); both paths are lists of hashes
   (``malformed_merkle_path``);
2b. the log origin is in the anchor origin's domain, is not itself an anchor
    origin; a store source log of any kind other than evidence never holds a
    record, whether or not a chain id is supplied; and, when a chain id is
    supplied, the log is that chain's evidence log (a platform origin is opaque,
    so neither its kind nor its chain is checked);
3. ``leafIndex`` is ``sequenceNumber - 1``, when a sequence number is supplied;
4. the digest is in the log checkpoint (RFC 6962 inclusion);
5. ``SHA-256(logCheckpoint)`` is in the anchor checkpoint;
6. each publication, on its own, against ``P = SHA-256(anchorCheckpoint)``.

Steps 1 to 5 run in order and stop at the first that fails; the checks after it
report ``blocked_by``. Steps 1 to 5 need only the standard library.

The verdict carries the check catalogue of tzun-anchor/1 §10.7, the ids the TS
SDK, this SDK and ``tzun-verify`` share: ``anchor`` (the anchor as a whole), one
check per step, and per publication the dispatch ``anchor.publication[i]`` and
its kind's checks, each suffixed with the publication's index.

``evm-calldata/1`` publications need the ``anchor`` extra
(``pip install 'tzun-sdk[anchor]'``); without it each one is ``None``,
``publication_not_checked``, with ``missing_dependency`` on ``anchor.evm.tx[i]``
and no facts.

``rfc3161/1`` publications are read by :mod:`tzun_sdk.attestation._rfc3161_token`,
which makes the TypeScript reader's decision (not by
:func:`tzun_sdk.attestation.rfc3161.extract_tst_info`): an unreadable token is
``False``, ``malformed_publication``. This SDK has no CMS signature or
certificate-path verifier, so a readable token is never ``True``: with no trust
anchors supplied it is ``None``, ``no_matching_trust_anchor`` on
``anchor.tsa.trust[i]``, as in the TypeScript SDK; with trust anchors supplied it
is ``None``, ``missing_dependency`` on ``anchor.tsa.token[i]``.

Two cases therefore get a different anchor verdict from the TypeScript SDK's
when a ``True`` publication sits beside the token: a token corrupted only inside
its certificates or signer infos (TypeScript refuses it; this reader does not
parse them), and, with trust anchors supplied, a token TypeScript decides
``False``. There TypeScript's ``anchorValid`` is ``False`` and this one's
``True``. Both readers are to be replaced by tzun-anchor/1 §10.5 step 1.

Never raises on the artifact: every input may be hostile JSON. Trust the caller
supplies, or the environment names, that cannot be read is refused with
:class:`~tzun_sdk.attestation._rfc3161_steps.UnreadableTrustAnchorError`, as the
TypeScript verifier refuses it and in its words.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from collections.abc import Mapping, Sequence
from typing import Any, Final, Literal, NotRequired, TypedDict

from tzun_sdk.attestation._ecmascript import js_safe_int, js_trim, millis_from_iso
from tzun_sdk.attestation._rfc3161_steps import UnreadableTrustAnchorError
from tzun_sdk.attestation._rfc3161_token import UnreadableToken, read_timestamp_token
from tzun_sdk.attestation._tsa_trust import check_trust_configuration
from tzun_sdk.attestation.checkpoint import (
    Checkpoint,
    check_origin_binding,
    is_platform_namespace,
    is_test_namespace,
    parse_checkpoint,
    parse_origin,
)
from tzun_sdk.attestation.evm_publication import (
    DEFAULT_EVM_TIMEOUT_MS,
    EvmCheckOutcome,
    EvmFinalityValue,
    EvmPublicationFacts,
    verify_evm_publication,
)
from tzun_sdk.attestation.evm_transaction import anchor_extra_available, keccak256
from tzun_sdk.attestation.merkle import MERKLE_SPEC, verify_merkle_proof

#: The ``anchorSpec`` tag this verifier implements.
ANCHOR_SPEC: Final = "tzun-anchor/1"

AnchorCheckId = Literal[
    "anchor",
    "anchor.spec",
    "anchor.checkpoint",
    "anchor.origin",
    "anchor.leafIndex",
    "anchor.inclusion",
    "anchor.anchorInclusion",
]
"""The tzun-anchor/1 §10.7 checks of a record's anchor that are not a publication's:
``anchor``, the anchor as a whole (its outcome follows ``anchorValid``, its reason
is ``anchorReason``), and the checks of steps 1 to 5."""

AnchorPublicationCheckId = str
"""The tzun-anchor/1 §10.7 checks of the publication at index ``i`` of
``publications`` (Anchor §10.3 step 6), each suffixed with that index:
``anchor.publication[i]`` (the dispatch), then ``anchor.evm.tx[i]`` and
``anchor.evm.canonical[i]`` for ``evm-calldata/1``, or ``anchor.tsa.token[i]`` and
``anchor.tsa.trust[i]`` for ``rfc3161/1``."""


class AnchorCheckResult(TypedDict):
    """One check of the tzun-anchor/1 §10.7 catalogue, with one of the four Anchor §10.1
    outcomes. ``id``, ``outcome``, ``reason`` and ``facts`` are what a report carries.

    ``facts`` are the ones Anchor §10.7 names for the check, re-derived by this verification:

    - ``anchor.origin``, whenever it is checked-correct: ``originAuthenticated``,
      ``namespace`` and ``chainChecked``;
    - ``anchor.leafIndex``: ``leafIndexChecked``, ``True`` when a supplied sequence
      number was compared (whether or not it matched), ``False`` when none was;
    - ``anchor.evm.tx[i]``, on every outcome once the transaction parses:
      ``transactionId``, ``txType``, ``sender`` and ``signedChainId``;
    - ``anchor.evm.canonical[i]``: ``finality`` on every outcome once the header
      source's chain id matched (absent when the source declares none), and, when
      it is checked-correct, ``chain``, ``namespace``, ``network``, ``blockTime``
      and ``inclusion``.
    """

    id: str
    outcome: EvmCheckOutcome
    #: ``True`` for checked-correct, ``False`` for checked-wrong, ``None`` otherwise.
    value: bool | None
    reason: NotRequired[str]
    facts: NotRequired[dict[str, Any]]


class Rfc3161Facts(TypedDict, total=False):
    #: Read from the token. Counts as proven only when the publication is ``True``.
    genTime: str
    tsaSubject: str


class AnchorPublicationVerdict(TypedDict):
    """One publication's verdict, in the order the artifact lists them."""

    index: int
    #: The kind the artifact states, when it is a string.
    kind: str | None
    valid: bool | None
    #: Present whenever ``valid`` is not ``True``.
    reason: NotRequired[str]
    #: This publication's slice of the Anchor §10.7 catalogue in ``checks``: the dispatch
    #: ``anchor.publication[i]``, then, only when it is checked-correct, its kind's
    #: two checks, each suffixed ``[i]``.
    checks: list[AnchorCheckResult]
    #: ``evm-calldata/1``: everything the EVM verifier established. The catalogue's
    #: EVM facts are on the checks as well.
    evm: NotRequired[EvmPublicationFacts]
    #: ``rfc3161/1``: read from the token.
    rfc3161: NotRequired[Rfc3161Facts]


class AnchorPosition(TypedDict):
    """Where the record sits, as far as ``leafIndexChecked``, ``chainChecked`` and
    ``authenticated`` say."""

    origin: str
    leafIndex: int
    treeSize: int
    anchorOrigin: str
    anchorLeafIndex: int
    anchorSize: int
    leafIndexChecked: bool
    chainChecked: bool
    authenticated: bool


class AnchorExistedByDict(TypedDict):
    at: str
    source: Literal["evm-calldata", "rfc3161"]


class AnchorVerification(TypedDict):
    """The Anchor §10.6 verdict on one record's anchor, under the TypeScript SDK's names."""

    #: Whether the artifacts carry an anchor at all, the new artifact or a legacy ``blockchainAnchor``.
    anchorPresent: bool
    #: ``False`` when a step from 2 to 5 fails or any publication is ``False``;
    #: ``True`` when steps 2 to 5 hold and a publication is ``True``; ``None`` otherwise.
    anchorValid: bool | None
    #: Present whenever ``anchorValid`` is not ``True`` and an anchor is attached.
    anchorReason: NotRequired[str]
    #: Steps 4 and 5 together: ``None`` when they did not run.
    merkleProofValid: bool | None
    anchorPublication: Literal["evm-calldata", "rfc3161"] | None
    anchorOriginAuthenticated: bool
    anchorPosition: AnchorPosition | None
    anchorNetwork: Any
    anchorFinality: EvmFinalityValue | None
    anchorNamespace: Literal["production", "test"] | None
    existedBy: AnchorExistedByDict | None
    #: P, ``SHA-256(anchorCheckpoint)`` in hex, once the anchor checkpoint parses.
    p: str | None
    #: The tzun-anchor/1 §10.7 catalogue for this anchor, in report order: ``anchor``,
    #: the six step checks (``anchor.spec`` to ``anchor.anchorInclusion``), then each
    #: publication's checks in list order (``anchor.publication[i]``, followed by its
    #: kind's checks when the dispatch is checked-correct). The publications are
    #: dispatched only once steps 1 to 5 hold, so no publication check is reported
    #: before that.
    checks: list[AnchorCheckResult]
    #: One verdict per publication; empty unless steps 1 to 5 hold.
    publications: list[AnchorPublicationVerdict]


_STEP_CHECKS: Final[tuple[str, ...]] = (
    "anchor.spec",
    "anchor.checkpoint",
    "anchor.origin",
    "anchor.leafIndex",
    "anchor.inclusion",
    "anchor.anchorInclusion",
)

#: The members of ``nonRepudiation.anchor`` (tzun-anchor/1 §8.1), and no others.
_ANCHOR_MEMBERS: Final = frozenset(
    {
        "anchorSpec",
        "merkleSpec",
        "leafIndex",
        "logCheckpoint",
        "logPath",
        "anchorLeafIndex",
        "anchorCheckpoint",
        "anchorPath",
        "publications",
    }
)

#: The publication-level abstentions (Anchor §10.1): a construction this verifier does not implement.
_PUBLICATION_ABSTENTIONS: Final = frozenset(
    {"unsupported_publication_kind", "unsupported_evm_tx_type"}
)

#: The Anchor §10.1 abstentions: a construction or version this verifier does not implement.
_ABSTENTIONS: Final = frozenset(
    {
        "unsupported_anchor_spec",
        "unsupported_merkle_spec",
        "legacy_blockchain_anchor",
        "unsupported_publication_kind",
        "unsupported_evm_tx_type",
    }
)

_HASH: Final = re.compile(r"[0-9a-fA-F]{64}")
_RAW_TX: Final = re.compile(r"0x(?:[0-9a-fA-F]{2})+")


def _as_json_object(value: object) -> object:
    """A pydantic model as the JSON it serialises to; anything else as it is."""
    if hasattr(value, "model_dump") and callable(value.model_dump):
        try:
            return value.model_dump(mode="json", by_alias=True, exclude_unset=True)
        except Exception:
            return value
    return value


def _is_index(value: object) -> bool:
    """A JSON integer in [0, 2^53 - 1]."""
    n = js_safe_int(value)
    return n is not None and n >= 0


def _is_hash(value: object) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _anchor_shape_holds(a: Mapping[Any, Any]) -> bool:
    """Step 2's shape (Anchor §8.1): exactly the nine members, the two indices JSON integers
    in [0, 2^53 - 1], and ``publications`` a non-empty list."""
    if len(a) != len(_ANCHOR_MEMBERS) or not all(k in _ANCHOR_MEMBERS for k in a):
        return False
    if not _is_index(a["leafIndex"]) or not _is_index(a["anchorLeafIndex"]):
        return False
    publications = a["publications"]
    return isinstance(publications, (list, tuple)) and len(publications) > 0


def _check(
    check_id: str,
    outcome: EvmCheckOutcome,
    reason: str | None = None,
    facts: dict[str, Any] | None = None,
) -> AnchorCheckResult:
    value = True if outcome == "checked-correct" else False if outcome == "checked-wrong" else None
    result: AnchorCheckResult = {"id": check_id, "outcome": outcome, "value": value}
    if reason is not None:
        result["reason"] = reason
    if facts is not None:
        result["facts"] = facts
    return result


def _blocked_after(check_id: str) -> list[AnchorCheckResult]:
    """Every step check after ``check_id`` reports that it was blocked by it."""
    later = _STEP_CHECKS[_STEP_CHECKS.index(check_id) + 1 :]
    return [_check(c, "not-checked", f"blocked_by:{check_id}") for c in later]


def _anchor_check(v: AnchorVerification) -> AnchorCheckResult:
    """Check ``anchor`` (Anchor §10.7), from the anchor fields: checked-correct when
    ``anchorValid`` is ``True``, checked-wrong when it is ``False``, and otherwise
    abstain or not-checked as ``anchorReason`` is or is not an abstention, with
    ``anchorReason`` as its reason. With nothing attached it is not-checked,
    ``absent``."""
    reason = v.get("anchorReason")
    if v["anchorValid"] is True:
        return _check("anchor", "checked-correct")
    if v["anchorValid"] is False:
        return _check("anchor", "checked-wrong", reason)
    if not v["anchorPresent"]:
        return _check("anchor", "not-checked", "absent")
    return _check("anchor", "abstain" if reason in _ABSTENTIONS else "not-checked", reason)


def _with_catalogue(v: AnchorVerification) -> AnchorVerification:
    """The verdict with its whole Anchor §10.7 catalogue: ``checks`` arrives holding the step
    checks, and leaves with ``anchor`` before them and each publication's checks
    after them."""
    catalogue = [_anchor_check(v), *v["checks"]]
    for pub in v["publications"]:
        catalogue.extend(pub["checks"])
    return {**v, "checks": catalogue}


def _at(check_id: str, index: int) -> str:
    """Check ``check_id`` of the publication at ``index``: the id suffixed ``[index]``
    (Anchor §10.3 step 6)."""
    return f"{check_id}[{index}]"


def _verdict(**fields: Any) -> AnchorVerification:
    out: dict[str, Any] = {
        "merkleProofValid": None,
        "anchorPublication": None,
        "anchorOriginAuthenticated": False,
        "anchorPosition": None,
        "anchorNetwork": None,
        "anchorFinality": None,
        "anchorNamespace": None,
        "existedBy": None,
        "p": None,
        "publications": [],
    }
    out.update(fields)
    return out  # type: ignore[return-value]


async def verify_anchor(
    artifacts: object,
    digest: object,
    *,
    sequence_number: object = None,
    chain_id: object = None,
    publisher_manifest: object = None,
    evm_header_sources: Mapping[str, object] | None = None,
    evm_networks: Mapping[str, object] | None = None,
    evm_timeout_ms: object = None,
    publication_material: object = None,
    trust_anchors_pem: object = None,
    authorities: object = None,
) -> AnchorVerification:
    """Verify a record's anchor (tzun-anchor/1 §10.3). Never raises on the artifact.

    :param artifacts: the record's ``nonRepudiation``, as JSON or as the SDK's
        model. ``anchor`` is read from it; a legacy ``blockchainAnchor`` alone is
        abstained on (``legacy_blockchain_anchor``).
    :param digest: the record's ``integrity.canonicalDigest``.

    The rest are the verifier's own inputs; none comes from the artifact, and each
    one omitted leaves what it would decide undecided, never passed:

    :param sequence_number: the record's ``payload.sequenceNumber``. Omitted: step 3
        is not checked.
    :param chain_id: the chain the record belongs to. Supplied, the log must be its
        evidence log, except under the platform's opaque origins.
    :param publisher_manifest: which wallets may publish for which anchor origin
        (Anchor §9). Omitted: no EVM publication can be ``True``.
    :param evm_header_sources: the verifier's header sources, keyed by CAIP-2 chain
        (see :class:`~tzun_sdk.attestation.evm_publication.EvmHeaderSource`).
        Omitted: no EVM publication can be ``True``.
    :param evm_networks: overrides or extends the CAIP-2 to network registry.
    :param evm_timeout_ms: one deadline for every header-source call this
        verification makes. Default 30 s.
    :param publication_material: the export bundle's publications for the anchor
        checkpoint (Anchor §9). An EVM entry supplies the fields the envelope leaves out
        (``rawTransaction``, ``blockHeader``, ``txIndex``, ``txProof``); where both
        carry a field, the envelope's value is used. The entry joined to an
        envelope that carries ``transactionId`` is the one whose
        ``keccak256(rawTransaction)`` is that id (and whose ``blockHash``, when both
        carry one, is the envelope's). An envelope with no ``transactionId`` is
        joined by ``blockHash``, and only when exactly one entry has it.
    :param trust_anchors_pem: trust anchors for ``rfc3161/1`` publications.
    :param authorities: timestamp authorities to trust, by registry key or URL.

    The trust these name, or with neither given ``TZUN_TSA_TRUST_ANCHORS`` and
    ``TZUN_TSA_AUTHORITIES``, is read first, whatever the artifact holds, as the
    TypeScript verifier reads it (:func:`check_trust_configuration`): a root that cannot
    be read, its key included, a file that cannot be read and an authority the registry
    does not know are refused (Verification §3.1). ``None`` is an input not given, where
    the TypeScript verifier refuses a ``null``.

    :raises UnreadableTrustAnchorError: when that trust cannot be read.
    """

    def given(value: object) -> bool:
        return value is not None and not (isinstance(value, (list, tuple)) and len(value) == 0)

    trust = {"trust_anchors_pem": trust_anchors_pem, "authorities": authorities}
    if _tsa_trust_supplied(trust) or given(trust_anchors_pem) or given(authorities):
        check_trust_configuration(
            trust_anchors_pem if given(trust_anchors_pem) else None,
            authorities if given(authorities) else None,
        )
    present = False
    try:
        bag_value = _as_json_object(artifacts)
        bag: Mapping[str, Any] = bag_value if isinstance(bag_value, Mapping) else {}
        present = bag.get("anchor") is not None or bag.get("blockchainAnchor") is not None
        options = {
            "sequence_number": sequence_number,
            "chain_id": chain_id,
            "publisher_manifest": publisher_manifest,
            "evm_header_sources": evm_header_sources,
            "evm_networks": evm_networks,
            "evm_timeout_ms": evm_timeout_ms,
            "publication_material": publication_material,
            "trust_anchors_pem": trust_anchors_pem,
            "authorities": authorities,
        }
        return _with_catalogue(await _decide(bag, digest, options))
    except UnreadableTrustAnchorError:
        raise
    except Exception:
        # Every expected failure returns a verdict. This keeps an unforeseen one
        # undecided rather than an exception or a verdict.
        fields: dict[str, Any] = {
            "anchorPresent": present,
            "anchorValid": None,
            "checks": [
                _check(c, "not-checked", "anchor_verifier_error" if present else "absent")
                for c in _STEP_CHECKS
            ],
        }
        if present:
            fields["anchorReason"] = "anchor_verifier_error"
        return _with_catalogue(_verdict(**fields))


async def _decide(
    bag: Mapping[str, Any], digest: object, options: dict[str, Any]
) -> AnchorVerification:
    # ---- Step 1: the tags --------------------------------------------------------------
    anchor_value = _as_json_object(bag.get("anchor"))
    if anchor_value is None:
        if bag.get("blockchainAnchor") is not None:
            return _verdict(
                anchorPresent=True,
                anchorValid=None,
                anchorReason="legacy_blockchain_anchor",
                checks=[
                    _check("anchor.spec", "abstain", "legacy_blockchain_anchor"),
                    *_blocked_after("anchor.spec"),
                ],
            )
        return _verdict(
            anchorPresent=False,
            anchorValid=None,
            checks=[_check(c, "not-checked", "absent") for c in _STEP_CHECKS],
        )

    # A non-object carries no `anchorSpec`, and an absent tag is abstained on.
    a: Mapping[Any, Any] = anchor_value if isinstance(anchor_value, Mapping) else {}

    def abstain(reason: str) -> AnchorVerification:
        return _verdict(
            anchorPresent=True,
            anchorValid=None,
            anchorReason=reason,
            checks=[_check("anchor.spec", "abstain", reason), *_blocked_after("anchor.spec")],
        )

    if not (isinstance(a.get("anchorSpec"), str) and a.get("anchorSpec") == ANCHOR_SPEC):
        return abstain("unsupported_anchor_spec")
    if not (isinstance(a.get("merkleSpec"), str) and a.get("merkleSpec") == MERKLE_SPEC):
        return abstain("unsupported_merkle_spec")

    checks: list[AnchorCheckResult] = [_check("anchor.spec", "checked-correct")]
    # Anchor §10.6: a test origin is 'test' whatever the verdict, so a failure after the
    # anchor checkpoint parsed reports it too.
    test_origin = False

    def fail(
        check_id: str, reason: str, facts: dict[str, Any] | None = None, **extra: Any
    ) -> AnchorVerification:
        return _verdict(
            anchorPresent=True,
            anchorValid=False,
            anchorReason=reason,
            checks=[
                *checks,
                _check(check_id, "checked-wrong", reason, facts),
                *_blocked_after(check_id),
            ],
            anchorNamespace="test" if test_origin else None,
            **extra,
        )

    # ---- Step 2: shape, both checkpoints, both paths -------------------------------------
    if not _anchor_shape_holds(a):
        return fail("anchor.checkpoint", "malformed_anchor")
    log_parsed = parse_checkpoint(a["logCheckpoint"])
    anchor_parsed = parse_checkpoint(a["anchorCheckpoint"])
    test_origin = anchor_parsed.checkpoint is not None and is_test_namespace(
        anchor_parsed.checkpoint.origin
    )
    if log_parsed.checkpoint is None or anchor_parsed.checkpoint is None:
        return fail("anchor.checkpoint", "malformed_checkpoint")
    log: Checkpoint = log_parsed.checkpoint
    anchor: Checkpoint = anchor_parsed.checkpoint
    paths_hold = all(
        isinstance(path, (list, tuple)) and all(_is_hash(h) for h in path)
        for path in (a["logPath"], a["anchorPath"])
    )
    if not paths_hold:
        return fail("anchor.checkpoint", "malformed_merkle_path")
    p = _sha256_hex(anchor.body)
    checks.append(_check("anchor.checkpoint", "checked-correct"))

    # ---- Step 2b: origin binding -----------------------------------------------------------
    # A log checkpoint that names the anchor origin itself is refused here: the log
    # origin's rest must not be `anchors`.
    binding = check_origin_binding(anchor.origin, log.origin, options["chain_id"])
    if not binding.ok:
        return fail("anchor.origin", str(binding.reason), p=p)
    # A store source log of another kind (``custody``, say) never holds a record: a
    # record has a leaf in its own chain's evidence log and nowhere else. The rule
    # holds without a chain id. A platform log's name is an opaque key, so its kind
    # cannot be read; the leaf preimage rule keeps its other kinds' leaves out of
    # the record domain. The shared check_origin_binding stays as it is, since a
    # source log of any kind is in its domain.
    log_origin = parse_origin(log.origin)
    if (
        log_origin is not None
        and log_origin.kind == "log"
        and not is_platform_namespace(log_origin.namespace)
    ):
        return fail("anchor.origin", "chain_id_mismatch", p=p)
    # The origin's facts as they stand if a later step fails: nothing is
    # authenticated, and the namespace is known only for a test origin. They are
    # restated below once the publications have been decided.
    origin_check_at = len(checks)
    checks.append(
        _check(
            "anchor.origin",
            "checked-correct",
            None,
            {
                "originAuthenticated": False,
                "namespace": "test" if test_origin else None,
                "chainChecked": binding.chain_checked,
            },
        )
    )

    # ---- Step 3: leafIndex = sequenceNumber - 1 --------------------------------------------
    # Not checked blocks nothing: no later step depends on it.
    leaf_index = js_safe_int(a["leafIndex"])
    anchor_leaf_index = js_safe_int(a["anchorLeafIndex"])
    assert leaf_index is not None and anchor_leaf_index is not None
    seq = options["sequence_number"]
    leaf_index_checked = seq is not None
    if leaf_index_checked:
        seq_int = js_safe_int(seq)
        if not (seq_int is not None and seq_int >= 1 and leaf_index == seq_int - 1):
            return fail("anchor.leafIndex", "leaf_index_mismatch", {"leafIndexChecked": True}, p=p)
        checks.append(
            _check("anchor.leafIndex", "checked-correct", None, {"leafIndexChecked": True})
        )
    else:
        checks.append(
            _check(
                "anchor.leafIndex",
                "not-checked",
                "input_not_supplied:sequence_number",
                {"leafIndexChecked": False},
            )
        )

    # ---- Step 4: the digest is in the log checkpoint ----------------------------------------
    # Step 2 held the index and the path to their types, so what fails here is the
    # proof: an index outside the tree, or a path that does not lead to the root.
    if not verify_merkle_proof(digest, leaf_index, log.size, a["logPath"], log.root):  # type: ignore[arg-type]
        return fail("anchor.inclusion", "merkle_proof_invalid", p=p, merkleProofValid=False)
    checks.append(_check("anchor.inclusion", "checked-correct"))

    # ---- Step 5: the log checkpoint is in the anchor checkpoint ----------------------------
    log_leaf = _sha256_hex(log.body)
    if not verify_merkle_proof(
        log_leaf, anchor_leaf_index, anchor.size, a["anchorPath"], anchor.root
    ):
        return fail("anchor.anchorInclusion", "anchor_proof_invalid", p=p, merkleProofValid=False)
    checks.append(_check("anchor.anchorInclusion", "checked-correct"))

    # ---- Step 6: each publication against P ---------------------------------------------------
    pubs = await _verify_publications(list(a["publications"]), p, anchor.origin, options)

    # Anchor §10.6: false when any publication is; true when one is; otherwise None, with
    # publication_not_checked when any publication was not checked, and otherwise
    # the first publication's abstention.
    first_false = next((v for v in pubs if v["valid"] is False), None)
    any_true = any(v["valid"] is True for v in pubs)
    anchor_valid: bool | None
    anchor_reason: str | None = None
    if first_false is not None:
        anchor_valid = False
        anchor_reason = first_false.get("reason")
    elif any_true:
        anchor_valid = True
    else:
        anchor_valid = None
        undecided = [v for v in pubs if v["valid"] is None]
        if any(v.get("reason") not in _PUBLICATION_ABSTENTIONS for v in undecided):
            anchor_reason = "publication_not_checked"
        elif undecided:
            anchor_reason = undecided[0].get("reason")

    # Facts come only from publications that are True, and none are reported for an
    # artifact that lies about a publication.
    trusted = [] if anchor_valid is False else [v for v in pubs if v["valid"] is True]
    evm_true = [v for v in trusted if v["kind"] == "evm-calldata/1" and v.get("evm") is not None]
    tsa_true = [
        v for v in trusted if v["kind"] == "rfc3161/1" and v.get("rfc3161", {}).get("genTime")
    ]
    authenticated = len(evm_true) > 0

    # Anchor §10.6: a test origin is 'test' whatever the manifest says and whatever the
    # verdict; otherwise an authenticated origin takes its manifest entry's namespace.
    anchor_namespace: Any
    if test_origin:
        anchor_namespace = "test"
    elif anchor_valid is False:
        anchor_namespace = None
    elif authenticated:
        anchor_namespace = _single([v["evm"].get("namespace") for v in evm_true])
    else:
        anchor_namespace = None
    anchor_network = _single([v["evm"].get("network") for v in evm_true]) if authenticated else None
    # Compared by value: two sources that both count 64 confirmations agree.
    finalities = [json.dumps(v["evm"].get("finality"), sort_keys=True) for v in evm_true]
    agreed = _single(finalities)
    anchor_finality = json.loads(agreed) if authenticated and agreed is not None else None

    bounds: list[tuple[int, int, AnchorExistedByDict]] = []
    for v in evm_true:
        at = v["evm"].get("blockTime")
        if isinstance(at, str):
            bounds.append((millis_from_iso(at), 0, {"at": at, "source": "evm-calldata"}))
    for v in tsa_true:
        at = v["rfc3161"]["genTime"]
        bounds.append((millis_from_iso(at), 1, {"at": at, "source": "rfc3161"}))
    # Earliest first; on a tie the EVM publication, which also authenticates the origin.
    bounds.sort(key=lambda b: (b[0], b[1]))
    existed_by = bounds[0][2] if bounds else None

    checks[origin_check_at] = _check(
        "anchor.origin",
        "checked-correct",
        None,
        {
            "originAuthenticated": authenticated,
            "namespace": anchor_namespace,
            "chainChecked": binding.chain_checked,
        },
    )

    anchor_position: AnchorPosition | None = (
        None
        if anchor_valid is False
        else {
            "origin": log.origin,
            "leafIndex": leaf_index,
            "treeSize": log.size,
            "anchorOrigin": anchor.origin,
            "anchorLeafIndex": anchor_leaf_index,
            "anchorSize": anchor.size,
            "leafIndexChecked": leaf_index_checked,
            "chainChecked": binding.chain_checked,
            "authenticated": authenticated,
        }
    )

    result: dict[str, Any] = {"anchorPresent": True, "anchorValid": anchor_valid}
    if anchor_valid is not True and anchor_reason is not None:
        result["anchorReason"] = anchor_reason
    result.update(
        {
            "merkleProofValid": True,
            "anchorPublication": None
            if anchor_valid is not True
            else "evm-calldata"
            if authenticated
            else "rfc3161"
            if tsa_true
            else None,
            "anchorOriginAuthenticated": anchor_valid is not False and authenticated,
            "anchorPosition": anchor_position,
            "anchorNetwork": None if anchor_valid is False else anchor_network,
            "anchorFinality": None if anchor_valid is False else anchor_finality,
            "anchorNamespace": anchor_namespace,
            "existedBy": None if anchor_valid is False else existed_by,
            "p": p,
            "checks": checks,
            "publications": pubs,
        }
    )
    return result  # type: ignore[return-value]


def _same_value_zero(a: Any, b: Any) -> bool:
    """JavaScript's SameValueZero, as a ``Set`` compares: numbers by value (NaN equal
    to NaN), strings, booleans and null by value, anything else by identity."""
    a_number = isinstance(a, (int, float)) and not isinstance(a, bool)
    b_number = isinstance(b, (int, float)) and not isinstance(b, bool)
    if a_number or b_number:
        return a_number and b_number and (a == b or (a != a and b != b))
    if isinstance(a, (str, bool, type(None))) or isinstance(b, (str, bool, type(None))):
        return type(a) is type(b) and a == b
    return a is b


def _single(values: Sequence[Any]) -> Any:
    """The one value every entry has, or ``None`` when they differ (or there are none)."""
    distinct: list[Any] = []
    for v in values:
        if not any(_same_value_zero(v, d) for d in distinct):
            distinct.append(v)
    return distinct[0] if len(distinct) == 1 else None


# ---- Step 6 ------------------------------------------------------------------------------------


async def _verify_publications(
    publications: list[Any], p: str, anchor_origin: str, options: dict[str, Any]
) -> list[AnchorPublicationVerdict]:
    """Each publication's verdict, in list order (Anchor §10.3 step 6). Step 2 made
    ``publications`` a non-empty list. The dispatch is check ``anchor.publication[i]``:
    an element that is not an object is ``False``, ``malformed_publication``; an
    absent, non-string or unknown kind abstains, ``unsupported_publication_kind``; in
    both cases no other check of the element is reported. A kind this verifier
    implements passes it, and its own checks follow."""
    requested = options["evm_timeout_ms"]
    timeout_ms = (
        float(requested)
        if isinstance(requested, (int, float))
        and not isinstance(requested, bool)
        and math.isfinite(requested)
        and requested > 0
        else float(DEFAULT_EVM_TIMEOUT_MS)
    )
    deadline = time.monotonic() + timeout_ms / 1000

    out: list[AnchorPublicationVerdict] = []
    for index, raw_pub in enumerate(publications):
        pub = _as_json_object(raw_pub)
        dispatch = _at("anchor.publication", index)
        if not isinstance(pub, Mapping):
            out.append(
                {
                    "index": index,
                    "kind": None,
                    "valid": False,
                    "reason": "malformed_publication",
                    "checks": [_check(dispatch, "checked-wrong", "malformed_publication")],
                }
            )
            continue
        kind = pub.get("kind") if isinstance(pub.get("kind"), str) else None
        decided: AnchorPublicationVerdict
        if kind == "evm-calldata/1":
            decided = await _verify_evm(index, pub, p, anchor_origin, options, deadline)
        elif kind == "rfc3161/1":
            decided = _verify_rfc3161(index, pub, options)
        else:
            out.append(
                {
                    "index": index,
                    "kind": kind,
                    "valid": None,
                    "reason": "unsupported_publication_kind",
                    "checks": [_check(dispatch, "abstain", "unsupported_publication_kind")],
                }
            )
            continue
        decided["checks"] = [_check(dispatch, "checked-correct"), *decided["checks"]]
        out.append(decided)
    return out


def _raw_transaction_id(raw: object) -> str | None:
    """``keccak256`` of a ``0x``-hex raw transaction, lowercase; ``None`` for anything else."""
    if not isinstance(raw, str) or _RAW_TX.fullmatch(raw) is None:
        return None
    return "0x" + keccak256(bytes.fromhex(raw[2:])).hex()


def _with_material(pub: Mapping[str, Any], material: object) -> Mapping[str, Any]:
    """The envelope's EVM publication, completed from the bundle's material for the
    same transaction. The envelope's own fields are kept. With no matching entry,
    the envelope is returned as it is."""
    if not isinstance(material, (list, tuple)):
        return pub
    entries = [
        m
        for m in (_as_json_object(x) for x in material)
        if isinstance(m, Mapping) and m.get("kind") == "evm-calldata/1"
    ]

    def in_block(m: Mapping[str, Any]) -> bool:
        return (
            isinstance(pub.get("blockHash"), str)
            and isinstance(m.get("blockHash"), str)
            and m["blockHash"].lower() == pub["blockHash"].lower()
        )

    entry: Mapping[str, Any] | None = None
    transaction_id = pub.get("transactionId")
    if isinstance(transaction_id, str):
        wanted = transaction_id.lower()
        for m in entries:
            if _raw_transaction_id(m.get("rawTransaction")) == wanted and (
                m.get("blockHash") is None or pub.get("blockHash") is None or in_block(m)
            ):
                entry = m
                break
    else:
        candidates = [m for m in entries if in_block(m)]
        entry = candidates[0] if len(candidates) == 1 else None
    if entry is None:
        return pub
    merged: dict[str, Any] = dict(entry)
    for key, value in pub.items():
        if value is not None:
            merged[key] = value
    return merged


def _missing_dependency_evm(index: int) -> AnchorPublicationVerdict:
    return {
        "index": index,
        "kind": "evm-calldata/1",
        "valid": None,
        "reason": "publication_not_checked",
        "checks": [
            _check(_at("anchor.evm.tx", index), "not-checked", "missing_dependency"),
            _check(
                _at("anchor.evm.canonical", index),
                "not-checked",
                f"blocked_by:{_at('anchor.evm.tx', index)}",
            ),
        ],
        "evm": {},
    }


async def _verify_evm(
    index: int,
    pub: Mapping[str, Any],
    p: str,
    anchor_origin: str,
    options: dict[str, Any],
    deadline: float,
) -> AnchorPublicationVerdict:
    # Without the extra no evm-calldata/1 publication is read, however it would
    # join its material: each one gets the same verdict, with no facts.
    if not anchor_extra_available():
        return _missing_dependency_evm(index)
    result = await verify_evm_publication(
        _with_material(pub, options["publication_material"]),
        p=p,
        anchor_origin=anchor_origin,
        manifest=options["publisher_manifest"],
        header_sources=options["evm_header_sources"],
        networks=options["evm_networks"],
        timeout_ms=max(1.0, (deadline - time.monotonic()) * 1000),
    )
    verdict: AnchorPublicationVerdict = {
        "index": index,
        "kind": "evm-calldata/1",
        "valid": result["valid"],
        "checks": [],
    }
    if result["valid"] is not True and "reason" in result:
        verdict["reason"] = result["reason"]
    facts: Mapping[str, Any] = result["facts"]
    # Anchor §10.7: the offline facts once the transaction parsed, whatever the outcome.
    tx_facts = (
        _pick(facts, ("transactionId", "txType", "sender", "signedChainId"))
        if "sender" in facts
        else None
    )
    # Anchor §10.4 item 14: `finality` on every outcome once the source's chain id matched;
    # the rest only when the chain confirmed the block.
    canonical_facts: dict[str, Any] = {}
    if "finality" in facts:
        canonical_facts["finality"] = facts["finality"]
    if result["checks"]["canonical"]["outcome"] == "checked-correct":
        canonical_facts.update(
            _pick(facts, ("chain", "namespace", "network", "blockTime", "inclusion"))
        )

    def suffixed(reason: str | None) -> str | None:
        if reason == "blocked_by:anchor.evm.tx":
            return f"blocked_by:{_at('anchor.evm.tx', index)}"
        return reason

    tx = result["checks"]["tx"]
    canonical = result["checks"]["canonical"]
    verdict["checks"] = [
        _check(_at("anchor.evm.tx", index), tx["outcome"], suffixed(tx.get("reason")), tx_facts),
        _check(
            _at("anchor.evm.canonical", index),
            canonical["outcome"],
            suffixed(canonical.get("reason")),
            canonical_facts or None,
        ),
    ]
    verdict["evm"] = result["facts"]
    return verdict


def _pick(facts: Mapping[str, Any], keys: Sequence[str]) -> dict[str, Any]:
    """The members of ``facts`` named in ``keys`` that are present, in that order."""
    return {key: facts[key] for key in keys if key in facts}


# ---- rfc3161/1 ---------------------------------------------------------------------------------


def _tsa_trust_supplied(options: dict[str, Any]) -> bool:
    """Whether the verifier was given TSA trust anchors of its own: in the options,
    or ``TZUN_TSA_TRUST_ANCHORS`` or ``TZUN_TSA_AUTHORITIES`` in the environment."""

    def listed(value: object) -> bool:
        return isinstance(value, (list, tuple)) and len(value) > 0

    def configured(name: str) -> bool:
        return js_trim(os.environ.get(name, "")) != ""

    return (
        listed(options["trust_anchors_pem"])
        or listed(options["authorities"])
        or configured("TZUN_TSA_TRUST_ANCHORS")
        or configured("TZUN_TSA_AUTHORITIES")
    )


def _verify_rfc3161(
    index: int, pub: Mapping[str, Any], options: dict[str, Any]
) -> AnchorPublicationVerdict:
    """An ``rfc3161/1`` publication, as far as this SDK can check one.

    - ``False``, ``malformed_publication``: the token is not a non-empty string, or
      does not read as an RFC 3161 TimeStampResp carrying a TSTInfo.
    - ``None``, ``publication_not_checked``, with ``no_matching_trust_anchor`` on
      ``anchor.tsa.trust[i]``: no trust anchors were supplied, so no path can reach
      a supplied root.
    - ``None``, ``publication_not_checked``, with ``missing_dependency`` on
      ``anchor.tsa.token[i]``: trust anchors were supplied, and the CMS signature
      and certificate path cannot be checked here.

    Its checks are ``anchor.tsa.token[i]`` and ``anchor.tsa.trust[i]``, ``i`` being
    ``index``.
    """
    base: dict[str, Any] = {"index": index, "kind": "rfc3161/1"}
    token_check = _at("anchor.tsa.token", index)
    trust_check = _at("anchor.tsa.trust", index)

    def unreadable() -> AnchorPublicationVerdict:
        return {
            **base,  # type: ignore[typeddict-item]
            "valid": False,
            "reason": "malformed_publication",
            "checks": [
                _check(token_check, "checked-wrong", "malformed_publication"),
                _check(trust_check, "not-checked", f"blocked_by:{token_check}"),
            ],
        }

    token = pub.get("token")
    if not isinstance(token, str) or token == "":
        return unreadable()
    try:
        gen_time = read_timestamp_token(token)
    except UnreadableToken:
        return unreadable()

    if not _tsa_trust_supplied(options):
        return {
            **base,  # type: ignore[typeddict-item]
            "valid": None,
            "reason": "publication_not_checked",
            "checks": [
                _check(token_check, "not-checked", f"blocked_by:{trust_check}"),
                _check(trust_check, "not-checked", "no_matching_trust_anchor"),
            ],
            "rfc3161": {"genTime": gen_time} if gen_time is not None else {},
        }
    return {
        **base,  # type: ignore[typeddict-item]
        "valid": None,
        "reason": "publication_not_checked",
        "checks": [
            _check(token_check, "not-checked", "missing_dependency"),
            _check(trust_check, "not-checked", f"blocked_by:{token_check}"),
        ],
        "rfc3161": {},
    }


__all__ = (
    "ANCHOR_SPEC",
    "AnchorCheckId",
    "AnchorCheckResult",
    "AnchorExistedByDict",
    "AnchorPosition",
    "AnchorPublicationCheckId",
    "AnchorPublicationVerdict",
    "AnchorVerification",
    "Rfc3161Facts",
    "verify_anchor",
)
