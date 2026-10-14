"""``payload.signoffExpectation``: what signature a record expects (Record §9.1).

The twin of ``packages/engine/src/signoff-expectation.ts`` and
``packages/engine/src/store-schema.ts``. ``vectors/signoff-expectation-vectors.json``
holds the two SDKs to the same answers.

The value is one of:

* ``None``: no signature is expected;
* ``{"policyDigest"}``: a signature is required under that sign-off policy,
  attached at capture or later;
* ``{"statementDigest", "sessionSeq"}``: the record was captured into a
  sign-off session, in slot ``sessionSeq``;
* the mandate form ``{"mandateAssertion", "mandateSeq", "totals",
  "confirm"}``: an agent decided under the mandate whose principal's
  assertion has that digest, in slot ``mandateSeq`` (Record §9.1). Only
  a capture under a mandate writes it.

It is in the v1.0 hashed field set, so a signature stripped from a record that
expects one, or a session signature moved onto a record that does not name
that session, is visible from the record alone (21 CFR 11.70).
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

from pydantic import BaseModel

from tzun_sdk._generated.canonical import (
    V1_HASHED_FIELDS_BEFORE_0_7,
    CanonicalSerializationError,
    canonical_serialize,
)
from tzun_sdk.attestation.merkle import verify_merkle_proof
from tzun_sdk.attestation.webauthn import assertion_binds_digest, assertion_presents_challenge

#: A policy or statement digest: 64 lowercase hex, and nothing around it
#: (``SIGNOFF_DIGEST_RE`` in the engine). Used with ``fullmatch``.
SIGNOFF_DIGEST_RE = re.compile(r"[0-9a-f]{64}")

#: The largest integer a JSON number carries exactly, 2^53 - 1.
_MAX_SAFE_INTEGER = 9007199254740991

_VIOLATION_MESSAGES = {
    "not_an_object": "signoffExpectation must be null or an object",
    "unknown_members": (
        "signoffExpectation must have exactly the member policyDigest, exactly the members "
        "statementDigest and sessionSeq, or exactly the members mandateAssertion, mandateSeq, "
        "totals and confirm"
    ),
    "invalid_policy_digest": "signoffExpectation.policyDigest must be 64 lowercase hex characters",
    "invalid_statement_digest": (
        "signoffExpectation.statementDigest must be 64 lowercase hex characters"
    ),
    "invalid_session_seq": "signoffExpectation.sessionSeq must be a safe integer of at least 1",
    "invalid_mandate_assertion": "signoffExpectation.mandateAssertion must be 64 lowercase hex characters",
    "invalid_mandate_seq": "signoffExpectation.mandateSeq must be a safe integer of at least 1",
    "invalid_totals": (
        "signoffExpectation.totals must be null or 1 to 16 caps named [A-Za-z0-9._-]{1,64}, each a "
        "non-negative safe integer"
    ),
    "invalid_confirm": "signoffExpectation.confirm must be true or false",
}


def describe_signoff_expectation_violation(violation: str) -> str:
    """The sentence a refusal carries for ``violation``."""
    return _VIOLATION_MESSAGES[violation]


def _plain(value: Any) -> Any:
    """A model as the JSON value it stands for; anything else as it is."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_unset=True)
    return value


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and SIGNOFF_DIGEST_RE.fullmatch(value) is not None


def _is_session_seq(value: Any) -> bool:
    # A JSON number: `bool` is not one, and an integral float (JSON `3.0`) is
    # the integer JavaScript reads it as.
    if isinstance(value, bool):
        return False
    if isinstance(value, float):
        if not value.is_integer():
            return False
        value = int(value)
    return isinstance(value, int) and 1 <= value <= _MAX_SAFE_INTEGER


def signoff_expectation_violation(value: Any) -> str | None:
    """Why ``value`` is not a signoff expectation, or ``None`` when it is one.

    The codes are ``SignoffExpectationViolation``'s: ``not_an_object``,
    ``unknown_members``, ``invalid_policy_digest``, ``invalid_statement_digest``,
    ``invalid_session_seq``, and for the mandate form ``invalid_mandate_assertion``,
    ``invalid_mandate_seq``, ``invalid_totals`` and ``invalid_confirm``. ``None``
    is the "none expected" value.
    """
    from tzun_sdk.mandate.expectation import (
        has_mandate_expectation_members,
        mandate_expectation_member_violation,
    )

    value = _plain(value)
    if value is None:
        return None
    if not isinstance(value, dict):
        return "not_an_object"
    keys = sorted(value.keys())
    if keys == ["policyDigest"]:
        return None if _is_digest(value["policyDigest"]) else "invalid_policy_digest"
    if keys == ["sessionSeq", "statementDigest"]:
        if not _is_digest(value["statementDigest"]):
            return "invalid_statement_digest"
        return None if _is_session_seq(value["sessionSeq"]) else "invalid_session_seq"
    if has_mandate_expectation_members(value):
        return mandate_expectation_member_violation(value)
    return "unknown_members"


def is_session_attachment_expectation(value: Any) -> bool:
    """Whether ``value`` is the session form, ``{statementDigest, sessionSeq}``."""
    value = _plain(value)
    return (
        isinstance(value, dict)
        and "sessionSeq" in value
        and signoff_expectation_violation(value) is None
    )


def is_mandate_expectation(value: Any) -> bool:
    """Whether ``value`` is the mandate form, well formed."""
    from tzun_sdk.mandate.expectation import has_mandate_expectation_members

    value = _plain(value)
    return (
        isinstance(value, dict)
        and has_mandate_expectation_members(value)
        and signoff_expectation_violation(value) is None
    )


def signoff_expectation_form(value: Any) -> str | None:
    """The form of a well-formed expectation: ``none``, ``policy``, ``session`` or ``mandate``; ``None`` when malformed."""
    value = _plain(value)
    if signoff_expectation_violation(value) is not None:
        return None
    if value is None:
        return "none"
    if "policyDigest" in value:
        return "policy"
    if "sessionSeq" in value:
        return "session"
    return "mandate"


def _printable_ascii(value: str) -> bool:
    return all(0x20 <= ord(c) <= 0x7E for c in value)


def _statement_domain(statement: dict[Any, Any]) -> dict[str, str | int] | None:
    """``statement`` with each integral float read as the integer it is, or
    ``None`` when it is outside the value domain Record §9.4 defines canonical
    bytes for.

    That domain is a flat object whose keys and string values are printable
    ASCII and whose other values are non-negative safe integers: nothing
    nested, no fraction, no boolean, no ``None``. The engine's
    ``isStatementDomain`` applies the same rule, so the two SDKs never hash a
    statement differently. A JSON ``4.0`` is the integer 4, as JavaScript
    reads it; an integer past 2^53 - 1, which the two languages' JSON parsers
    read differently, is outside the domain.
    """
    plain: dict[str, str | int] = {}
    for key, value in statement.items():
        if not isinstance(key, str) or not _printable_ascii(key):
            return None
        if isinstance(value, str):
            if not _printable_ascii(value):
                return None
            plain[key] = value
        elif isinstance(value, bool):
            return None
        elif isinstance(value, int) and 0 <= value <= _MAX_SAFE_INTEGER:
            plain[key] = value
        elif isinstance(value, float) and value.is_integer() and 0 <= value <= _MAX_SAFE_INTEGER:
            plain[key] = int(value)
        else:
            return None
    return plain


def signoff_statement_digest(statement: Any) -> str | None:
    """A sign-off statement's digest (Record §9.4).

    Lowercase hex SHA-256 of the statement's canonical bytes, every member
    included. ``None`` when the statement is not an object whose keys and
    string values are printable ASCII and whose other values are non-negative
    safe integers, the only statements Record §9.4 defines canonical bytes for.
    Whether its keys are the fixed set for its mode is the sign-off
    verifier's check, not this one. The engine's ``signoffStatementDigest``
    is the twin.
    """
    statement = _plain(statement)
    if not isinstance(statement, dict):
        return None
    plain = _statement_domain(statement)
    if plain is None:
        return None
    try:
        canonical = canonical_serialize(plain)
    except (CanonicalSerializationError, TypeError, ValueError):
        return None
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


#: The domain separator of a sign-off statement's WebAuthn challenge (Record §9.4).
_SIGNOFF_CHALLENGE_DOMAIN = "tzun-signoff-v1"


def signoff_statement_challenge(statement_digest: str) -> str:
    """The WebAuthn challenge a batch or session ceremony presents (Record §9.4).

    ``base64url_nopad(SHA-256("tzun-signoff-v1" || statementDigest))``, the
    engine's ``signoffStatementChallenge``.
    """
    raw = hashlib.sha256((_SIGNOFF_CHALLENGE_DOMAIN + statement_digest).encode("utf-8")).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def carries_batch_signoff(block: dict[str, Any] | None, assertion: Any, digest: Any) -> bool:
    """Whether the record whose stored digest is ``digest`` carries a batch
    sign-off that covers it, by every check that needs no key (Record §9.5).

    ``block`` is the ``signoff`` block (an object), or ``None``. The block is
    an object whose statement is an object with
    ``mode: "batch"`` that has a digest, the assertion presented that
    statement's challenge, and the inclusion proof puts ``digest`` in the tree
    of ``statement.treeSize`` leaves whose root is ``statement.root``. The
    engine's ``carriesBatchSignoff`` is the twin.
    """
    if block is None:
        return False
    statement = block.get("statement")
    if not isinstance(statement, dict) or statement.get("mode") != "batch":
        return False
    statement_digest = signoff_statement_digest(statement)
    if statement_digest is None:
        return False
    if not assertion_presents_challenge(assertion, signoff_statement_challenge(statement_digest)):
        return False
    inclusion = block.get("inclusion")
    if not isinstance(inclusion, dict) or not isinstance(digest, str):
        return False
    return verify_merkle_proof(
        digest,
        inclusion.get("leafIndex"),  # type: ignore[arg-type]
        statement.get("treeSize"),  # type: ignore[arg-type]
        inclusion.get("path"),  # type: ignore[arg-type]
        statement.get("root"),  # type: ignore[arg-type]
    )


def check_signoff_expectation(envelope: Any) -> dict[str, Any]:
    """Check a record's sign-off material against its hashed expectation.

    Returns ``{"valid": True}``, or ``{"valid": False | None, "reason": ...}``,
    by the engine's ``checkSignoffExpectation`` rules. A sign-off is carried
    when the record holds a ``signoff`` block (any value but ``None``) and a
    ``webauthnAssertion`` object. It binds when every check that needs no key
    holds: for a batch, the statement is an object with ``mode: "batch"``, the
    assertion presented that statement's challenge (Record §9.4), and the inclusion
    proof puts the record's stored digest under the statement's ``root`` and
    ``treeSize``; for a session, the assertion presented the session
    statement's challenge. A session sign-off is a ``signoff`` whose
    statement's ``mode`` is ``session``, or that carries ``sessionSeq``.

    * expectation ``None``: a session sign-off is ``False``,
      ``session_signoff_not_expected``; a carried sign-off that does not bind
      as a batch sign-off of the record is ``False``, ``signoff_unbound``;
      anything else is ``True``;
    * ``{policyDigest}``: a session sign-off is ``False``,
      ``session_signoff_not_expected``; no ``webauthnAssertion`` is ``None``,
      ``signature_missing``; with a ``signoff`` block, one that binds as a
      batch sign-off of the record is ``True`` and any other is ``False``,
      ``signoff_unbound``; without one, an assertion whose challenge is derived
      from the record's digest is ``True``, and anything else ``None``,
      ``signature_missing``;
    * ``{statementDigest, sessionSeq}``: no ``signoff`` is ``False``,
      ``signoff_stripped``; a statement with another digest is ``False``,
      ``statement_digest_mismatch``; another slot is ``False``,
      ``session_seq_mismatch``; no ``webauthnAssertion`` is ``False``,
      ``signoff_stripped``; an assertion that did not present the statement's
      challenge is ``False``, ``signoff_unbound``; otherwise ``True``;
    * a value of neither form is ``False``, ``malformed_signoff_expectation``.

    ``None`` is left to the policy form, whose signature may arrive after
    capture; a session record is written with its sign-off. A carried sign-off
    that does not bind was moved, relabelled or made up. ``True`` says the
    record carries the sign-off its expectation names as far as can be read
    without a key, not that it verifies. Never raises: an envelope is
    untrusted input.
    """
    env = _plain(envelope)
    env = env if isinstance(env, dict) else {}
    payload = env.get("payload") if isinstance(env.get("payload"), dict) else {}
    integrity = env.get("integrity") if isinstance(env.get("integrity"), dict) else {}
    non_repudiation = (
        env.get("nonRepudiation") if isinstance(env.get("nonRepudiation"), dict) else {}
    )
    expectation = payload.get("signoffExpectation")

    form = signoff_expectation_form(expectation)
    if form is None:
        return {"valid": False, "reason": "malformed_signoff_expectation"}

    signoff = non_repudiation.get("signoff")
    has_signoff = signoff is not None
    block = signoff if isinstance(signoff, dict) else None
    statement = block.get("statement") if block is not None else None
    statement = statement if isinstance(statement, dict) else None
    is_session_signoff = block is not None and (
        (statement is not None and statement.get("mode") == "session") or "sessionSeq" in block
    )
    assertion = non_repudiation.get("webauthnAssertion")
    has_assertion = isinstance(assertion, dict)
    digest = integrity.get("canonicalDigest")

    if form == "mandate":
        from tzun_sdk.mandate.expectation import check_mandate_expectation_material

        return check_mandate_expectation_material(expectation, non_repudiation, digest, is_session_signoff)

    # Row 1a: a mandate block is carried only by a record in the mandate form.
    if non_repudiation.get("mandate") is not None:
        return {"valid": False, "reason": "mandate_not_expected"}

    if expectation is None:
        if is_session_signoff:
            return {"valid": False, "reason": "session_signoff_not_expected"}
        if has_signoff and has_assertion and not carries_batch_signoff(block, assertion, digest):
            return {"valid": False, "reason": "signoff_unbound"}
        return {"valid": True}

    if "policyDigest" in expectation:
        if is_session_signoff:
            return {"valid": False, "reason": "session_signoff_not_expected"}
        if not has_assertion:
            return {"valid": None, "reason": "signature_missing"}
        if has_signoff:
            if carries_batch_signoff(block, assertion, digest):
                return {"valid": True}
            return {"valid": False, "reason": "signoff_unbound"}
        # An empty stored digest binds nothing: webauthn_challenge_for_digest
        # refuses it, and the engine makes the same exception.
        if isinstance(digest, str) and digest and assertion_binds_digest(assertion, digest):
            return {"valid": True}
        return {"valid": None, "reason": "signature_missing"}

    if not has_signoff:
        return {"valid": False, "reason": "signoff_stripped"}
    if signoff_statement_digest(statement) != expectation["statementDigest"]:
        return {"valid": False, "reason": "statement_digest_mismatch"}
    if not _same_number(block.get("sessionSeq") if block else None, expectation["sessionSeq"]):
        return {"valid": False, "reason": "session_seq_mismatch"}
    if not has_assertion:
        return {"valid": False, "reason": "signoff_stripped"}
    if assertion_presents_challenge(assertion, signoff_statement_challenge(expectation["statementDigest"])):
        return {"valid": True}
    return {"valid": False, "reason": "signoff_unbound"}


def _same_number(a: Any, b: Any) -> bool:
    """``a === b`` as JavaScript compares two JSON values read from one record."""
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return False


def record_predates_signoff_expectation(envelope: Any) -> bool:
    """Whether ``envelope`` is a record a release before 0.7.0 captured.

    Its payload has no ``signoffExpectation`` key, and its stored
    ``canonicalDigest`` recomputes under the v1.0 hashed field set those
    releases used. Every 0.7.0 capture writes the key (``None`` by default),
    and a record whose payload or digest was altered recomputes under neither
    set, so neither is mistaken for an old record. The twin of
    ``recordPredatesSignoffExpectation`` in the engine. Never raises.
    """
    env = _plain(envelope)
    if not isinstance(env, dict):
        return False
    payload = env.get("payload")
    integrity = env.get("integrity")
    if not isinstance(payload, dict) or not isinstance(integrity, dict):
        return False
    if "signoffExpectation" in payload:
        return False
    digest = integrity.get("canonicalDigest")
    if not isinstance(digest, str):
        return False
    try:
        canonical = canonical_serialize(payload, list(V1_HASHED_FIELDS_BEFORE_0_7))
    except (CanonicalSerializationError, TypeError, ValueError):
        return False
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest() == digest


__all__ = (
    "SIGNOFF_DIGEST_RE",
    "carries_batch_signoff",
    "check_signoff_expectation",
    "describe_signoff_expectation_violation",
    "is_mandate_expectation",
    "is_session_attachment_expectation",
    "record_predates_signoff_expectation",
    "signoff_expectation_form",
    "signoff_expectation_violation",
    "signoff_statement_challenge",
    "signoff_statement_digest",
)
