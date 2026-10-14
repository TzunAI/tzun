"""The decider member (Record §6): who took the decision, inside the digest.

The twin of ``packages/engine/src/decider.ts``: the grammar, the consistency of
a kind with its identifier and agent reference, the agreement with the
signature expectation and with the material a capture presents, identifier
commitments, and the reader's ``decider`` row.

Writers refuse (:func:`decider_violation`, :func:`decider_material_violation`);
readers report (:func:`check_decider`). They differ on purpose in two places:
a reader abstains on a kind or an identifier scheme it does not implement,
where a writer refuses one.

Every function takes JSON values (``dict``, ``list``, ``str``, numbers,
``None``) or models, never raises on untrusted input, and returns what the
engine returns: ``None`` for "no violation", or a ``dict`` with the same keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from typing import Any

from tzun_sdk._record_rules import (
    BARE_DIGEST_RE,
    canonical_value,
    has_exact_keys,
    is_bare_digest,
    is_plain_object,
    is_prefixed_digest,
    plain,
)
from tzun_sdk.attestation.webauthn import assertion_binds_digest

#: The kinds a 0.8.0 writer states.
DECIDER_KINDS: tuple[str, ...] = ("human", "agent", "agent-mandated", "policy-engine")

#: The identifier schemes this version implements.
DECIDER_SCHEMES: tuple[str, ...] = ("acct", "spiffe", "jkt", "desc", "cmt")

#: The members of a decider, all required.
DECIDER_MEMBERS: tuple[str, ...] = ("kind", "id", "agent", "credential", "freshness")

#: An identifier: ``<scheme>:<value>``, the scheme ``[a-z][a-z0-9+.-]{0,15}``, 0x21-0x7E.
_IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9+.-]{0,15}:[\x21-\x7e]+", re.ASCII)
DECIDER_ID_MIN_LENGTH = 3
DECIDER_ID_MAX_LENGTH = 1024

#: ``acct`` value: the relying party's account id. No ``@``, so an email address is refused.
ACCT_VALUE_RE = re.compile(r"[A-Za-z0-9._-]{1,128}", re.ASCII)
#: ``spiffe`` value: ``//<trust domain>/<path>``, the path one or more segments.
_SPIFFE_VALUE_RE = re.compile(r"//[a-z0-9._-]{1,255}(/[A-Za-z0-9._-]+)+", re.ASCII)
#: ``jkt`` value: an RFC 7638 thumbprint, 43 characters of base64url.
_JKT_VALUE_RE = re.compile(r"[A-Za-z0-9_-]{43}", re.ASCII)

#: A finalized-block reference ``<CAIP-2 chain>@<block number>:0x<64 hex>``.
FRESHNESS_REFERENCE_RE = re.compile(
    r"([-a-z0-9]{3,8}):([-_a-zA-Z0-9]{1,32})@(0|[1-9][0-9]{0,15}):(0x[0-9a-f]{64})", re.ASCII
)
_EIP155_REFERENCE_RE = re.compile(r"[1-9][0-9]{0,30}", re.ASCII)
_MAX_SAFE_INTEGER = 2**53 - 1

#: The domain separator of an identifier commitment (19 bytes).
_COMMITMENT_DOMAIN = b"tzun-decider-cmt-v1"
#: The salt of an identifier commitment, in bytes.
DECIDER_COMMITMENT_SALT_BYTES = 32
#: The domain separator of a derived commitment salt.
_COMMITMENT_SALT_DOMAIN = b"tzun-cmt-salt-v1"
#: The fewest bytes a commitment-salt secret has.
DECIDER_COMMITMENT_SECRET_MIN_BYTES = 32

_PERMITTED_SCHEMES: dict[str, tuple[str, ...]] = {
    "human": ("acct", "cmt"),
    "agent": ("spiffe", "jkt", "desc", "cmt"),
    "agent-mandated": ("spiffe", "jkt", "desc", "cmt"),
    "policy-engine": ("spiffe", "jkt", "desc", "cmt"),
}


def is_decider_kind(value: Any) -> bool:
    return isinstance(value, str) and value in DECIDER_KINDS


def identifier_scheme(identifier: Any) -> str | None:
    """The scheme of an identifier that meets the general grammar, or ``None``."""
    if not isinstance(identifier, str):
        return None
    if not DECIDER_ID_MIN_LENGTH <= len(identifier) <= DECIDER_ID_MAX_LENGTH:
        return None
    if _IDENTIFIER_RE.fullmatch(identifier) is None:
        return None
    return identifier[: identifier.index(":")]


def is_known_scheme_identifier(identifier: Any) -> bool:
    """Whether ``identifier`` meets the value grammar of a scheme this version implements (the writer's rule)."""
    scheme = identifier_scheme(identifier)
    if scheme is None:
        return False
    value = identifier[len(scheme) + 1 :]
    if scheme == "acct":
        return ACCT_VALUE_RE.fullmatch(value) is not None
    if scheme == "spiffe":
        return _SPIFFE_VALUE_RE.fullmatch(value) is not None and not any(
            s in (".", "..") for s in value.split("/")[3:]
        )
    if scheme == "jkt":
        return _JKT_VALUE_RE.fullmatch(value) is not None
    if scheme == "desc":
        return is_prefixed_digest(value)
    if scheme == "cmt":
        return BARE_DIGEST_RE.fullmatch(value) is not None
    return False


def parse_freshness_reference(value: Any) -> dict[str, Any] | None:
    """Parse a finalized-block reference, or ``None`` when it is not one."""
    if not isinstance(value, str):
        return None
    m = FRESHNESS_REFERENCE_RE.fullmatch(value)
    if m is None:
        return None
    namespace, reference, block_text, block_hash = m.groups()
    if namespace == "eip155" and _EIP155_REFERENCE_RE.fullmatch(reference) is None:
        return None
    block_number = int(block_text)
    if block_number > _MAX_SAFE_INTEGER:
        return None
    return {
        "chain": f"{namespace}:{reference}",
        "namespace": namespace,
        "reference": reference,
        "blockNumber": block_number,
        "blockHash": block_hash,
    }


def is_freshness_reference(value: Any) -> bool:
    return parse_freshness_reference(value) is not None


def format_freshness_reference(chain: str, block_number: int, block_hash: str) -> str:
    """Format a finalized-block reference from its parts. Raises ``ValueError`` when they do not make one."""
    ref = f"{chain}@{block_number}:{block_hash}"
    if not is_freshness_reference(ref):
        raise ValueError(
            "A freshness reference is a CAIP-2 chain, a safe block number and 0x followed by "
            "64 lowercase hex."
        )
    return ref


_MESSAGES: dict[str, str] = {
    "not_an_object": "{f} is required: an object with the members " + ", ".join(DECIDER_MEMBERS),
    "unknown_members": "{f} may have only the members " + ", ".join(DECIDER_MEMBERS),
    "missing_members": "{f} must have every member (" + ", ".join(DECIDER_MEMBERS)
    + "), null where it does not apply",
    "invalid_kind": "{f} must be one of " + ", ".join(DECIDER_KINDS),
    "invalid_identifier": "{f} must be <scheme>:<value> of 3 to 1024 characters 0x21-0x7E, in one of the "
    "schemes " + ", ".join(DECIDER_SCHEMES)
    + " and that scheme's value grammar (acct: [A-Za-z0-9._-]{{1,128}})",
    "scheme_not_permitted": "{f}: this identifier scheme is not permitted for this kind",
    "invalid_agent_reference": "{f} must be null or sha256: followed by 64 lowercase hex characters",
    "agent_reference_required": "{f} is required (an agent descriptor digest) for every kind but human",
    "agent_reference_forbidden": "{f} must be null for a human",
    "desc_identifier_mismatch": "{f}: a desc identifier must name the agent reference",
    "invalid_credential_reference": "{f} must be null or 64 lowercase hex characters",
    "invalid_freshness_reference": "{f} must be null or a finalized-block reference "
    "<CAIP-2>@<block number>:0x<64 lowercase hex>",
    "freshness_required": "{f} is required: no acceptable finalized-block reference is available",
    "kind_contradicts_expectation": "{f}: the kind contradicts the record's signature expectation",
    "kind_contradicts_material": "{f}: the kind contradicts the attestation material presented with the "
    "capture",
    "identity_contradicts_assertion": "{f}: the acct identifier differs from the user the assertion's "
    "credential is registered to",
    "commitment_not_supported_by_store": "{f}: this store cannot keep a commitment opening",
}


def decider_violation_of(code: str, field: str) -> dict[str, str]:
    """A decider violation with its message."""
    return {"code": code, "field": field, "message": _MESSAGES[code].format(f=field)}


def decider_violation(value: Any, prefix: str = "decider") -> dict[str, str] | None:
    """Why ``value`` is not a decider a writer may write, first failure first, or ``None``.

    ``None`` itself is refused (``not_an_object``): every 0.8.0 writer requires
    a decider.
    """
    value = plain(value)
    if not is_plain_object(value):
        return decider_violation_of("not_an_object", prefix)
    if any(k not in DECIDER_MEMBERS for k in value):
        return decider_violation_of("unknown_members", prefix)
    if not has_exact_keys(value, DECIDER_MEMBERS):
        return decider_violation_of("missing_members", prefix)
    return actor_violation(value, prefix, True)


def actor_violation(value: dict[str, Any], prefix: str, is_decider: bool) -> dict[str, str] | None:
    """The checks shared by a decider and a contribution step's actor."""
    kind = value.get("kind")
    if not is_decider_kind(kind):
        return decider_violation_of("invalid_kind", f"{prefix}.kind")
    identifier = value.get("id")
    if not isinstance(identifier, str) or not is_known_scheme_identifier(identifier):
        return decider_violation_of("invalid_identifier", f"{prefix}.id")
    agent = value.get("agent")
    if agent is not None and not is_prefixed_digest(agent):
        return decider_violation_of("invalid_agent_reference", f"{prefix}.agent")
    if is_decider:
        credential = value.get("credential")
        if credential is not None and not is_bare_digest(credential):
            return decider_violation_of("invalid_credential_reference", f"{prefix}.credential")
        freshness = value.get("freshness")
        if freshness is not None and not is_freshness_reference(freshness):
            return decider_violation_of("invalid_freshness_reference", f"{prefix}.freshness")
    if kind == "human" and agent is not None:
        return decider_violation_of("agent_reference_forbidden", f"{prefix}.agent")
    if kind != "human" and agent is None:
        return decider_violation_of("agent_reference_required", f"{prefix}.agent")
    scheme = identifier_scheme(identifier)
    assert scheme is not None
    if scheme not in _PERMITTED_SCHEMES[kind]:
        return decider_violation_of("scheme_not_permitted", f"{prefix}.id")
    if scheme == "desc" and identifier[len("desc:") :] != agent:
        return decider_violation_of("desc_identifier_mismatch", f"{prefix}.id")
    return None


def default_agent_decider_id(agent: str) -> str:
    """The identifier a writer gives an agent kind that names none: ``desc:<agent>``."""
    return f"desc:{agent}"


def decider_agrees_with_expectation(kind: Any, expectation: Any) -> bool | None:
    """Whether a decider of ``kind`` agrees with the record's signature expectation (Record §6.5).

    ``True``, ``False`` (the kind is contradicted), or ``None`` for a kind or
    expectation this version does not read.
    """
    from tzun_sdk.signoff_expectation import signoff_expectation_form

    if not is_decider_kind(kind):
        return None
    form = signoff_expectation_form(expectation)
    if form is None:
        return None
    if kind == "human":
        return form != "mandate"
    if kind == "agent-mandated":
        return form == "mandate"
    return form in ("none", "policy")


def decider_material_violation(
    decider: Any,
    *,
    digest: str | None = None,
    assertion: Any = None,
    assertion_user_id: str | None = None,
) -> dict[str, str] | None:
    """Why a capture's decider is refused for the material presented with it (Record §6.5), or ``None``.

    * ``kind_contradicts_material``: an agent kind with an assertion whose
      client data present this record's per-record challenge;
    * ``identity_contradicts_assertion``: an ``acct`` decider whose value
      differs from the user the assertion's credential is registered to.
    """
    decider = plain(decider)
    assertion = plain(assertion)
    if not is_plain_object(decider):
        return None
    kind = decider.get("kind")
    if (
        kind != "human"
        and is_decider_kind(kind)
        and is_plain_object(assertion)
        and isinstance(digest, str)
        and digest != ""
        and assertion_binds_digest(assertion, digest)
    ):
        return decider_violation_of("kind_contradicts_material", "decider.kind")
    identifier = decider.get("id")
    if (
        isinstance(identifier, str)
        and identifier_scheme(identifier) == "acct"
        and isinstance(assertion_user_id, str)
        and assertion_user_id != identifier[len("acct:") :]
    ):
        return decider_violation_of("identity_contradicts_assertion", "decider.id")
    return None


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_salt(salt: bytes | str) -> bytes | None:
    if isinstance(salt, (bytes, bytearray)):
        return bytes(salt)
    if not isinstance(salt, str) or re.fullmatch(r"[A-Za-z0-9_-]*", salt, re.ASCII) is None:
        return None
    if len(salt) % 4 == 1:
        return None
    try:
        raw = base64.urlsafe_b64decode(salt + "=" * (-len(salt) % 4))
    except ValueError:
        return None
    return raw if _b64url(raw) == salt else None


def _commits_to_other_scheme(inner_id: Any) -> bool:
    return (
        isinstance(inner_id, str)
        and is_known_scheme_identifier(inner_id)
        and identifier_scheme(inner_id) != "cmt"
    )


def decider_commitment(inner_id: str, salt: bytes | str) -> str:
    """The commitment ``cmt:<hex(SHA-256("tzun-decider-cmt-v1" ‖ salt ‖ UTF8(innerId)))>``.

    ``salt`` is 32 bytes, or their unpadded base64url; ``inner_id`` is an
    identifier of another scheme this version implements. Raises
    ``ValueError`` otherwise.
    """
    salt_bytes = _decode_salt(salt)
    if salt_bytes is None or len(salt_bytes) != DECIDER_COMMITMENT_SALT_BYTES:
        raise ValueError(f"A decider commitment's salt is {DECIDER_COMMITMENT_SALT_BYTES} bytes.")
    if not _commits_to_other_scheme(inner_id):
        raise ValueError("A decider commitment commits to an identifier of another scheme.")
    digest = hashlib.sha256(_COMMITMENT_DOMAIN + salt_bytes + inner_id.encode("utf-8")).hexdigest()
    return f"cmt:{digest}"


def random_commitment_salt() -> str:
    """A fresh 32-byte salt as unpadded base64url, the form a decider opening carries."""
    return _b64url(secrets.token_bytes(DECIDER_COMMITMENT_SALT_BYTES))


def _length_prefixed(text: str) -> bytes:
    raw = text.encode("utf-8")
    return len(raw).to_bytes(4, "big") + raw


def decider_commitment_salt(secret: bytes, idempotency_key: str, inner_id: str) -> str:
    """The salt of a commitment made under an idempotency key (Record §6.3).

    ``HMAC-SHA256(secret, "tzun-cmt-salt-v1" ‖ len ‖ UTF8(key) ‖ len ‖ UTF8(innerId))``,
    each ``len`` the 4-byte big-endian byte length of the field after it,
    returned as unpadded base64url. Raises ``ValueError`` for a secret
    shorter than 32 bytes, an empty key, or an identifier a commitment does
    not commit to.
    """
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < DECIDER_COMMITMENT_SECRET_MIN_BYTES:
        raise ValueError(
            f"A commitment-salt secret is at least {DECIDER_COMMITMENT_SECRET_MIN_BYTES} bytes."
        )
    if not isinstance(idempotency_key, str) or idempotency_key == "":
        raise ValueError("A derived commitment salt needs a non-empty idempotency key.")
    if not _commits_to_other_scheme(inner_id):
        raise ValueError("A decider commitment commits to an identifier of another scheme.")
    mac = hmac.new(
        bytes(secret),
        _COMMITMENT_SALT_DOMAIN + _length_prefixed(idempotency_key) + _length_prefixed(inner_id),
        hashlib.sha256,
    ).digest()
    return _b64url(mac)


def verify_decider_opening(identifier: Any, opening: Any) -> bool:
    """Whether ``opening`` (``{salt, id}``) opens the commitment identifier. Never raises."""
    opening = plain(opening)
    if not isinstance(identifier, str) or identifier_scheme(identifier) != "cmt":
        return False
    if not is_plain_object(opening):
        return False
    salt = opening.get("salt")
    inner = opening.get("id")
    if not isinstance(salt, str) or not isinstance(inner, str):
        return False
    try:
        return decider_commitment(inner, salt) == identifier
    except ValueError:
        return False


def reader_actor_inconsistent(kind: str, identifier: str, agent: Any) -> bool:
    """The reader's consistency test (Record §6.4) for a decider or a step actor of a known kind."""
    scheme = identifier_scheme(identifier)
    if scheme is None:
        return True
    if (agent is not None) if kind == "human" else (agent is None):
        return True
    if scheme in DECIDER_SCHEMES and scheme not in _PERMITTED_SCHEMES[kind]:
        return True
    return scheme == "desc" and identifier[len("desc:") :] != agent


def _decider_malformed(value: dict[str, Any]) -> bool:
    """The reader's grammar of a decider: shape and patterns, with any kind string and any scheme."""
    if not has_exact_keys(value, DECIDER_MEMBERS):
        return True
    if not isinstance(value.get("kind"), str):
        return True
    if identifier_scheme(value.get("id")) is None:
        return True
    if value.get("agent") is not None and not is_prefixed_digest(value.get("agent")):
        return True
    if value.get("credential") is not None and not is_bare_digest(value.get("credential")):
        return True
    return value.get("freshness") is not None and not is_freshness_reference(value.get("freshness"))


def binds_human_decision_material(envelope: Any) -> bool:
    """Whether a record carries human decision material bound to its digest, with no key."""
    from tzun_sdk.signoff_expectation import carries_batch_signoff

    envelope = plain(envelope)
    if not is_plain_object(envelope):
        return False
    nr = envelope.get("nonRepudiation") if is_plain_object(envelope.get("nonRepudiation")) else {}
    integrity = envelope.get("integrity") if is_plain_object(envelope.get("integrity")) else {}
    assertion = nr.get("webauthnAssertion")
    digest = integrity.get("canonicalDigest")
    if not is_plain_object(assertion) or not isinstance(digest, str) or digest == "":
        return False
    signoff = nr.get("signoff") if is_plain_object(nr.get("signoff")) else None
    if signoff is None:
        return assertion_binds_digest(assertion, digest)
    statement = signoff.get("statement") if is_plain_object(signoff.get("statement")) else None
    return (
        statement is not None
        and statement.get("meaning") != "review"
        and carries_batch_signoff(signoff, assertion, digest)
    )


def check_decider(envelope: Any) -> dict[str, Any]:
    """The reader's ``decider`` row (Verification §4.9) for a record whose digest holds. Never raises.

    1. the expectation is malformed → not-checked, blocked_by:signoff.expectation
    2. ``None`` → not-checked, absent
    3. grammar → checked-wrong, malformed_decider
    4. a kind this version does not know → abstain, unsupported_decider_kind
    5. consistency → checked-wrong, decider_inconsistent
    6. agreement with the expectation → checked-wrong, decider_kind_contradicted
    7. a scheme this version does not know → abstain, unsupported_identifier_scheme
    8. an agent kind with human decision material bound → not-checked, material_unverified
    9. otherwise → checked-correct
    """
    from tzun_sdk.signoff_expectation import signoff_expectation_violation

    env = plain(envelope)
    env = env if is_plain_object(env) else {}
    payload = env.get("payload") if is_plain_object(env.get("payload")) else {}
    if signoff_expectation_violation(payload.get("signoffExpectation")) is not None:
        return {"outcome": "not-checked", "valid": None, "reason": "blocked_by:signoff.expectation"}
    decider = payload.get("decider")
    if decider is None:
        return {"outcome": "not-checked", "valid": None, "reason": "absent"}
    if not is_plain_object(decider) or _decider_malformed(decider):
        return {"outcome": "checked-wrong", "valid": False, "reason": "malformed_decider"}
    kind = decider["kind"]
    if not is_decider_kind(kind):
        return {"outcome": "abstain", "valid": None, "reason": "unsupported_decider_kind", "kind": kind}
    identifier = decider["id"]
    scheme = identifier_scheme(identifier)
    known_scheme = scheme in DECIDER_SCHEMES
    if reader_actor_inconsistent(kind, identifier, decider.get("agent")):
        return {
            "outcome": "checked-wrong",
            "valid": False,
            "reason": "decider_inconsistent",
            "kind": kind,
            "scheme": scheme,
        }
    if decider_agrees_with_expectation(kind, payload.get("signoffExpectation")) is False:
        return {
            "outcome": "checked-wrong",
            "valid": False,
            "reason": "decider_kind_contradicted",
            "kind": kind,
            "scheme": scheme,
        }
    if not known_scheme:
        return {
            "outcome": "abstain",
            "valid": None,
            "reason": "unsupported_identifier_scheme",
            "kind": kind,
            "scheme": scheme,
        }
    human_material = binds_human_decision_material(env)
    if kind != "human" and human_material:
        return {
            "outcome": "not-checked",
            "valid": None,
            "reason": "material_unverified",
            "kind": kind,
            "scheme": scheme,
            "kindContradiction": "undetermined",
        }
    row: dict[str, Any] = {
        "outcome": "checked-correct",
        "valid": True,
        "kind": kind,
        "scheme": scheme,
        "level": "human-asserted" if kind == "human" else "agent-asserted",
    }
    if kind == "human" and human_material:
        row["levelUndetermined"] = "human-proven"
    if scheme == "cmt":
        row["committed"] = True
    return row


def same_actor(a: Any, b: Any) -> bool:
    """Whether a decider and a step actor (or two actors) are the same: ``kind``, ``id``, ``agent`` as canonical bytes."""
    a, b = plain(a), plain(b)
    if not is_plain_object(a) or not is_plain_object(b):
        return False
    try:
        return canonical_value(
            {"kind": a.get("kind"), "id": a.get("id"), "agent": a.get("agent")}
        ) == canonical_value({"kind": b.get("kind"), "id": b.get("id"), "agent": b.get("agent")})
    except Exception:
        return False


__all__ = (
    "ACCT_VALUE_RE",
    "DECIDER_COMMITMENT_SALT_BYTES",
    "DECIDER_COMMITMENT_SECRET_MIN_BYTES",
    "DECIDER_KINDS",
    "DECIDER_MEMBERS",
    "DECIDER_SCHEMES",
    "FRESHNESS_REFERENCE_RE",
    "actor_violation",
    "binds_human_decision_material",
    "check_decider",
    "decider_agrees_with_expectation",
    "decider_commitment",
    "decider_commitment_salt",
    "decider_material_violation",
    "decider_violation",
    "decider_violation_of",
    "default_agent_decider_id",
    "format_freshness_reference",
    "identifier_scheme",
    "is_decider_kind",
    "is_freshness_reference",
    "is_known_scheme_identifier",
    "parse_freshness_reference",
    "random_commitment_salt",
    "reader_actor_inconsistent",
    "same_actor",
    "verify_decider_opening",
)
