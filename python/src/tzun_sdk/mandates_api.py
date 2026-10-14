"""The mandate API of :class:`~tzun_sdk.Tzun` (Record §9.6): ``tzun.mandates``.

A principal signs a mandate once; an agent then decides under it, each
record claiming a slot and running totals in the transaction that stores it.

* ``prepare(document)``: the statement ``tzun-signoff-mandate/1`` and the
  challenge the principal's ceremony signs; nothing is stored.
* ``issue(document=..., statement=..., assertion=...)``: verifies the
  principal's assertion, then captures the issuance record (``tzun:mandate``,
  ``issue-mandate``) with the mandate row, its totals and its ``issued``
  event, in one transaction. A successor (``document.predecessor``) supersedes
  its predecessor in the same transaction.
* ``prepare_revocation(...)`` and ``revoke(mandate_id=..., prepared=..., assertion=...)``:
  the revoker signs the revocation record itself (a per-record assertion);
  any account with a verified, user-verifying assertion may revoke.
  ``revoke`` rebuilds the record from the mandate row and takes only the
  identity, the reason, the claimed instant and the decider's freshness
  from ``prepared``.
* ``confirm(evidence_id, assertion)``: the human confirmation a record
  captured with ``confirm: true`` owes, filled once.
* ``get``, ``totals``, ``events``, ``expire_due``.

``capture(..., mandate={"mandateId": ...})`` is the capture under a mandate;
:class:`MandateClaim` is the part of it that plans and claims the slot.

Ceremonies are verified by the ``assertion_verifier`` given to
``Tzun.init()``: the relying party's credential store, behind
:class:`AssertionVerifier` (:class:`WebAuthnAssertionVerifier` is one, over
``py_webauthn``). This SDK runs no ceremony itself.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Protocol

from tzun_sdk._capture import CaptureRequest, prepared_identity_violation
from tzun_sdk._instant import is_mandate_instant, js_date_parse_ms
from tzun_sdk._record_rules import canonical_value, deep_plain, sha256_hex
from tzun_sdk.decider import ACCT_VALUE_RE
from tzun_sdk.errors import InvalidMandateError, MandateClaimConflictError, MandateRefusedError
from tzun_sdk.mandate.assertion_digest import assertion_digest
from tzun_sdk.mandate.document import mandate_digest, mandate_document_violation
from tzun_sdk.mandate.issuance import (
    MANDATE_AI_SYSTEM_ID,
    MANDATE_ISSUE_ACTION,
    MANDATE_REVOKE_ACTION,
    build_mandate_event_body,
)
from tzun_sdk.mandate.lifecycle import (
    mandate_confirmation_violation,
    mandate_expired_at,
    plan_mandate_claim,
    predecessor_principal_violation,
    revocation_instant_violation,
)
from tzun_sdk.mandate.statement import (
    build_mandate_statement,
    mandate_confirmation_challenge,
    mandate_statement_challenge,
    mandate_statement_digest,
    mandate_statement_violation,
)
from tzun_sdk.models import (
    CaptureResult,
    MandateCapLimit,
    MandateEventRow,
    MandateExpireStore,
    MandateIssueStore,
    MandateRevokeStore,
    MandateRow,
)

if TYPE_CHECKING:
    from tzun_sdk.core import Tzun


class AssertionVerifier(Protocol):
    """The relying party's verification of a WebAuthn assertion, against its credential store.

    ``verify`` checks the signature with the credential's registered key, the
    common checks (origin, RP id, sign count), user verification, and that the
    client data presented ``expected_challenge``; it returns the user id the
    credential is registered to, and raises on any failure. ``user_id_of``
    answers that user id for a credential, or ``None``.
    """

    async def verify(self, assertion: dict[str, Any], *, expected_challenge: str) -> str: ...

    async def user_id_of(self, credential_key_id: str) -> str | None: ...


class WebAuthnAssertionVerifier:
    """An :class:`AssertionVerifier` over ``py_webauthn``.

    ``credentials`` is ``async (credential_id) -> {"userId", "publicKey",
    "signCount"} | None``: the relying party's credential store, the public
    key as COSE bytes. ``rp_id`` and ``origins`` are the relying party's.
    User verification is required. A verified assertion's new sign count is
    handed to ``on_sign_count`` when given.
    """

    def __init__(
        self,
        credentials: Callable[[str], Awaitable[dict[str, Any] | None]],
        *,
        rp_id: str,
        origins: list[str] | str,
        on_sign_count: Callable[[str, int], Awaitable[None]] | None = None,
    ) -> None:
        self._credentials = credentials
        self._rp_id = rp_id
        self._origins = origins
        self._on_sign_count = on_sign_count

    async def user_id_of(self, credential_key_id: str) -> str | None:
        credential = await self._credentials(credential_key_id)
        user_id = credential.get("userId") if credential else None
        return user_id if isinstance(user_id, str) else None

    async def verify(self, assertion: dict[str, Any], *, expected_challenge: str) -> str:
        import base64

        from tzun_sdk.attestation.webauthn import WebAuthnBackend
        from tzun_sdk.errors import WebAuthnVerificationError

        credential_id = assertion.get("credentialKeyId")
        if not isinstance(credential_id, str):
            raise WebAuthnVerificationError("the assertion names no credential")
        credential = await self._credentials(credential_id)
        if credential is None:
            raise WebAuthnVerificationError("the credential is not registered")

        def b64url(value: Any) -> str:
            if not isinstance(value, str):
                return ""
            return value.replace("+", "-").replace("/", "_").rstrip("=")

        blob = {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "authenticatorData": b64url(assertion.get("authenticatorData")),
                "clientDataJSON": b64url(assertion.get("clientDataJSON")),
                "signature": b64url(assertion.get("signature")),
            },
        }
        padded = expected_challenge + "=" * (-len(expected_challenge) % 4)
        verified = WebAuthnBackend().verify_assertion(
            blob,
            credential["publicKey"],
            expected_challenge=base64.urlsafe_b64decode(padded),
            expected_origin=self._origins,
            expected_rp_id=self._rp_id,
            current_sign_count=int(credential.get("signCount", 0)),
            require_user_verification=True,
        )
        if self._on_sign_count is not None:
            await self._on_sign_count(credential_id, int(getattr(verified, "new_sign_count", 0)))
        user_id = credential.get("userId")
        if not isinstance(user_id, str):
            raise WebAuthnVerificationError("the credential is registered to no user")
        return user_id


def _refused(code: str, field: str, message: str, **details: Any) -> MandateRefusedError:
    return MandateRefusedError(code, field, message, **details)


def _event_row(mandate_id: str, body: dict[str, Any]) -> MandateEventRow:
    canonical = canonical_value(body)
    return MandateEventRow.model_validate(
        {"mandateId": mandate_id, "body": body, "canonical": canonical, "digest": sha256_hex(canonical)}
    )


def _caps_of(document: dict[str, Any]) -> list[dict[str, Any]]:
    cumulative = (document.get("limits") or {}).get("cumulative")
    if not isinstance(cumulative, dict):
        return []
    return [{"cap": cap, "max": int(definition["max"])} for cap, definition in sorted(cumulative.items())]


async def _row_state(tzun: Tzun, mandate_id: str) -> tuple[MandateRow | None, dict[str, int]]:
    storage = tzun._storage
    if not hasattr(storage, "get_mandate"):
        raise _refused(
            "mandate_not_supported_by_store",
            "mandate",
            "this store does not host mandates (the cloud store in 0.8.0); use a local store",
        )
    row = await storage.get_mandate(mandate_id)
    totals = await storage.get_mandate_totals(mandate_id) if row is not None else {}
    return row, totals


def _issuance_target(row: MandateRow) -> dict[str, Any]:
    # This SDK's stores keep no evidence log, so the issuance record's
    # position is not disclosed in the link (its locator is null).
    return {"digest": row.issuanceDigest, "evidenceId": row.issuanceEvidenceId, "locator": None}


def _known_issuance_target(row: MandateRow) -> dict[str, Any]:
    """A link input naming a mandate's issuance record by its digest and evidence id (the TS ``knownTarget``).

    Resolved as a same-store target when the store holds the record intact;
    written as given when its copy is damaged, so a damaged issuance record
    cannot block its mandate's revocation or supersession.
    """
    return {"digest": row.issuanceDigest, "evidenceId": row.issuanceEvidenceId, "external": True}


def _check_revoker(revoker: Any) -> str:
    if not isinstance(revoker, str) or ACCT_VALUE_RE.fullmatch(revoker) is None:
        raise InvalidMandateError(
            "invalid_identifier",
            "revoker",
            "revoker must be an opaque account id [A-Za-z0-9._-]{1,128}, never an email address or a name",
        )
    return revoker


def _revocation_request(
    row: MandateRow,
    *,
    claimed: str,
    reason: str,
    revoker: str,
    captured_at: str | None = None,
) -> CaptureRequest:
    """The revocation record's capture request (Record §9.6), built from the mandate row."""
    return CaptureRequest(
        ai_output={
            "claimedRevocationInstant": claimed,
            "mandateDigest": row.mandateDigest,
            "reason": reason,
            "statementDigest": row.statementDigest,
        },
        action=MANDATE_REVOKE_ACTION,
        reason=reason,
        decider={"kind": "human", "id": f"acct:{revoker}", "freshness": "auto"},
        ai_system_id=MANDATE_AI_SYSTEM_ID,
        links=[{"rel": "revokes", "target": _known_issuance_target(row)}],
        system_record="mandate",
        allow_reserved=("revokes",),
        captured_at=captured_at,
    )


async def _expire(tzun: Tzun, row: MandateRow, totals: dict[str, int]) -> None:
    """Move an open mandate whose window has ended to ``expired``, with its event (its own transaction)."""
    body = build_mandate_event_body(
        event="expired",
        mandate_digest=row.mandateDigest,
        record=row.issuanceDigest,
        used=row.used,
        totals=dict(totals) if totals else None,
    )
    await tzun._storage.expire_mandate(
        MandateExpireStore(
            mandateId=row.mandateId,
            expectState="open",
            expectUsed=row.used,
            expectTotals=dict(totals) if totals else None,
            event=_event_row(row.mandateId, body),
        )
    )


async def _expire_if_still_due(tzun: Tzun, row: MandateRow, totals: dict[str, int]) -> bool:
    """:func:`_expire`, ``False`` when a capture or another closer moved the mandate first."""
    try:
        await _expire(tzun, row, totals)
    except (MandateRefusedError, MandateClaimConflictError):
        return False
    return True


class MandateClaim:
    """A capture's claim on a mandate (Record §9.6): opened once, planned at every attempt."""

    def __init__(self, tzun: Tzun, row: MandateRow) -> None:
        self._tzun = tzun
        self._mandate_id = row.mandateId
        self._document = json.loads(row.documentBytes)
        self._block = {
            "statement": json.loads(row.statementJson),
            "assertion": json.loads(row.assertionJson),
            "assertionTimestamp": row.assertionTimestamp,
            "document": self._document,
        }

    @classmethod
    async def open(cls, tzun: Tzun, mandate_id: str) -> MandateClaim:
        """The mandate a capture names: refused when the store hosts none, holds none, or it is not open."""
        row, _ = await _row_state(tzun, mandate_id)
        if row is None:
            raise _refused("mandate_not_found", "mandate.mandateId", f"no mandate {mandate_id!r} in this store")
        if row.state != "open":
            raise _refused("mandate_not_open", "mandate", f"mandate {mandate_id!r} is {row.state}")
        return cls(tzun, row)

    async def plan(self, draft: dict[str, Any]) -> dict[str, Any]:
        """What this attempt claims, from the mandate as the store holds it now; raises when refused."""
        row, totals = await _row_state(self._tzun, self._mandate_id)
        if row is None:
            raise _refused("mandate_not_found", "mandate.mandateId", f"no mandate {self._mandate_id!r} in this store")
        plan = plan_mandate_claim(
            document=self._document,
            mandate={"state": row.state, "used": row.used, "totals": totals},
            payload=draft,
            assertion_digest=row.assertionDigest,
            issuance=_issuance_target(row),
        )
        if not plan["ok"]:
            from tzun_sdk.core import _utcnow_iso

            # Closed only when the SDK's clock says the window has ended, never
            # on a value of the record.
            if plan.get("expired") and row.state == "open" and mandate_expired_at(row.notAfter, _utcnow_iso()):
                await _expire_if_still_due(self._tzun, row, totals)
            raise _refused(plan["code"], plan["field"], plan["message"], findings=plan.get("findings"))
        expectation = plan["expectation"]
        slot = expectation["mandateSeq"]
        statement = self._block["statement"]
        decider_id = draft["decider"]["id"]
        custody: list[dict[str, Any]] = [
            {
                "actor": decider_id,
                "action": "captured_under_mandate",
                "metadata": {
                    "mandateId": self._mandate_id,
                    "slot": slot,
                    "statementDigest": mandate_statement_digest(statement),
                    "assertionDigest": row.assertionDigest,
                },
            }
        ]
        if expectation["confirm"] is True:
            custody.append(
                {
                    "actor": decider_id,
                    "action": "confirmation_required",
                    "metadata": {"mandateId": self._mandate_id, "slot": slot, "predicates": plan["confirmHolding"]},
                }
            )
        return {
            "expectation": expectation,
            "links": plan["links"],
            "block": self._block,
            "custody": custody,
            "claim": {
                "mandateId": self._mandate_id,
                "expectUsed": plan["expectUsed"],
                "caps": plan["caps"],
                "now": draft["capturedAt"],
            },
            "result": {"mandateId": self._mandate_id, "slot": slot, "totals": expectation["totals"]},
        }


class MandatesNamespace:
    """``tzun.mandates`` (Record §9.6)."""

    def __init__(self, tzun: Tzun) -> None:
        self._tzun = tzun

    def _verifier(self) -> AssertionVerifier:
        verifier = self._tzun._assertion_verifier
        if verifier is None:
            raise InvalidMandateError(
                "assertion_not_verified",
                "assertion",
                "no assertion_verifier is configured (Tzun.init): a mandate's ceremonies are verified against the "
                "relying party's credential store",
            )
        return verifier  # type: ignore[no-any-return]

    async def _verified_user(self, assertion: Any, challenge: str) -> str:
        assertion = deep_plain(assertion)
        if not isinstance(assertion, dict):
            raise InvalidMandateError("assertion_not_verified", "assertion", "the assertion must be an object")
        try:
            return await self._verifier().verify(assertion, expected_challenge=challenge)
        except InvalidMandateError:
            raise
        except Exception as exc:
            raise InvalidMandateError(
                "assertion_not_verified", "assertion", "the assertion did not verify against the credential store"
            ) from exc

    async def _open_predecessor(self, document: dict[str, Any]) -> tuple[MandateRow | None, dict[str, int]]:
        predecessor = document.get("predecessor")
        if predecessor is None:
            return None, {}
        storage = self._tzun._storage
        if not hasattr(storage, "get_mandate_by_digest"):
            raise _refused("mandate_not_supported_by_store", "mandate", "this store does not host mandates")
        row = await storage.get_mandate_by_digest(predecessor)
        if row is None or row.state != "open":
            raise _refused("mandate_not_open", "document.predecessor", "the predecessor is not an open mandate")
        violation = predecessor_principal_violation(document, json.loads(row.documentBytes))
        if violation is not None:
            raise _refused(violation["code"], violation["field"], violation["message"])
        return row, await storage.get_mandate_totals(row.mandateId)

    async def prepare(self, document: Any) -> dict[str, Any]:
        """The statement and the challenge a principal signs: ``{statement, statementDigest, challenge}``.

        Checks the document's grammar, the restriction at signing and the
        0.8.0 rules (no sub-mandates; a window that does not end before it
        begins; an open predecessor with the same principal). ``notBefore``
        is the store's shared finalized block, or ``none``. Stores nothing.
        """
        self._tzun._require_active()
        d = deep_plain(document)
        violation = mandate_document_violation(d)
        if violation is not None:
            raise InvalidMandateError(violation["code"], violation["field"], violation["message"])
        await self._open_predecessor(d)
        digest = mandate_digest(d)
        assert digest is not None
        statement = build_mandate_statement(
            mandate_digest=digest,
            signer=d["principal"]["signer"],
            policy_digest=d["policyDigest"],
            not_before=await self._tzun._freshness_reference(),
        )
        statement_digest = mandate_statement_digest(statement)
        assert statement_digest is not None
        return {
            "statement": statement,
            "statementDigest": statement_digest,
            "challenge": mandate_statement_challenge(statement_digest),
        }

    async def issue(
        self,
        *,
        document: Any,
        statement: Any,
        assertion: Any,
        reason: str = "Mandate issued",
    ) -> dict[str, Any]:
        """Verify the principal's assertion and capture the issuance record (Record §9.6).

        Returns ``{mandateId, mandateDigest, issuance}`` (``issuance`` the
        :class:`~tzun_sdk.models.CaptureResult` of the issuance record).
        The mandate row, its totals and its ``issued`` event are written in
        the transaction that stores the issuance record; a successor
        supersedes its predecessor in the same transaction.
        """
        self._tzun._require_active()
        d = deep_plain(document)
        s = deep_plain(statement)
        a = deep_plain(assertion)
        violation = mandate_document_violation(d)
        if violation is not None:
            raise InvalidMandateError(violation["code"], violation["field"], violation["message"])
        reason_text = mandate_statement_violation(s)
        if reason_text is not None:
            raise InvalidMandateError(
                "invalid_statement", "statement", f"the statement is not a mandate statement: {reason_text}"
            )
        m_digest = mandate_digest(d)
        policy = d.get("policyDigest")
        if (
            s["mandateDigest"] != m_digest
            or s["signer"] != d["principal"]["signer"]
            or s.get("policyDigest") != (policy if policy is not None else "none")
        ):
            raise InvalidMandateError(
                "invalid_statement",
                "statement",
                "the statement must name the document's digest, principal and policy, as prepare() forms it",
            )
        statement_digest = mandate_statement_digest(s)
        assert statement_digest is not None and m_digest is not None
        storage = self._tzun._storage
        if hasattr(storage, "get_mandate") and (
            await storage.get_mandate(d["mandateId"]) is not None
            or await storage.get_mandate_by_digest(m_digest) is not None
        ):
            raise _refused(
                "mandate_already_issued", "document.mandateId", "a mandate with this id or this document is already issued"
            )
        user_id = await self._verified_user(a, mandate_statement_challenge(statement_digest))
        if user_id != d["principal"]["signer"]:
            raise InvalidMandateError(
                "assertion_not_verified", "assertion", "the asserting credential is not registered to the principal"
            )
        a_digest = assertion_digest(a)
        if a_digest is None:
            raise InvalidMandateError("assertion_not_verified", "assertion", "the assertion has no assertion digest")
        token: str | None = None
        if self._tzun._assertion_timestamper is not None:
            try:
                token = await self._tzun._assertion_timestamper(a_digest)
            except Exception:
                token = None
        predecessor, predecessor_totals = await self._open_predecessor(d)
        block = {"statement": s, "assertion": a, "assertionTimestamp": token, "document": d}
        mandate_id = d["mandateId"]
        validity = d["validity"]

        async def store_options(envelope: dict[str, Any]) -> dict[str, Any]:
            record_digest = envelope["integrity"]["canonicalDigest"]
            record = MandateRow(
                mandateId=mandate_id,
                mandateDigest=m_digest,
                documentBytes=canonical_value(d),
                statementJson=json.dumps(s, separators=(",", ":")),
                statementDigest=statement_digest,
                assertionJson=json.dumps(a, separators=(",", ":")),
                assertionDigest=a_digest,
                assertionTimestamp=token,
                state="open",
                used=0,
                maxRecords=d["limits"]["maxRecords"],
                notBefore=validity["notBefore"],
                notAfter=validity["notAfter"],
                issuanceEvidenceId=envelope["payload"]["evidenceId"],
                issuanceDigest=record_digest,
                createdAt=envelope["payload"]["capturedAt"],
            )
            out: dict[str, Any] = {
                "mandateIssue": MandateIssueStore(
                    record=record,
                    caps=[MandateCapLimit(**c) for c in _caps_of(d)],
                    event=_event_row(
                        mandate_id,
                        build_mandate_event_body(event="issued", mandate_digest=m_digest, record=record_digest),
                    ),
                )
            }
            if predecessor is not None:
                held_row, held_totals = await _row_state(self._tzun, predecessor.mandateId)
                assert held_row is not None
                totals = dict(held_totals) if held_totals else None
                out["mandateRevoke"] = MandateRevokeStore(
                    mandateId=held_row.mandateId,
                    expectState="open",
                    newState="superseded",
                    expectUsed=held_row.used,
                    expectTotals=totals,
                    event=_event_row(
                        held_row.mandateId,
                        build_mandate_event_body(
                            event="superseded",
                            mandate_digest=held_row.mandateDigest,
                            record=record_digest,
                            successor=m_digest,
                            used=held_row.used,
                            totals=totals,
                        ),
                    ),
                )
            return out

        del predecessor_totals
        request = CaptureRequest(
            ai_output={"assertionDigest": a_digest, "mandateDigest": m_digest, "statementDigest": statement_digest},
            action=MANDATE_ISSUE_ACTION,
            reason=reason,
            decider={"kind": "human", "id": f"acct:{d['principal']['signer']}", "credential": d["principal"]["credential"]},
            ai_system_id=MANDATE_AI_SYSTEM_ID,
            links=(
                [{"rel": "supersedes", "target": _known_issuance_target(predecessor)}]
                if predecessor is not None
                else None
            ),
            system_record="mandate",
            mandate_issuance=block,
            store_options=store_options,
            assertion_user_id=user_id,
        )
        issuance = await self._tzun._capture_request(request)
        return {"mandateId": mandate_id, "mandateDigest": m_digest, "issuance": issuance}

    async def prepare_revocation(
        self,
        *,
        mandate_id: str,
        reason: str,
        revoker: str,
        effective_at: str | None = None,
    ) -> dict[str, Any]:
        """The revocation record ``revoke`` will store, for the revoker to sign (a per-record challenge).

        ``revoker`` is the revoker's opaque account id (the record's decider
        is ``acct:<revoker>``). ``effective_at`` (an ISO 8601 UTC instant with
        milliseconds, no later than the record's capture) defaults to the
        record's ``capturedAt``. Returns what
        :meth:`~tzun_sdk.Tzun.prepare_assertion_challenge` returns, with
        ``mandateId``, ``aiOutput`` and ``reason``.
        """
        from tzun_sdk.core import _utcnow_iso

        self._tzun._require_active()
        _check_revoker(revoker)
        row = await self._open_mandate(mandate_id)
        captured_at = _utcnow_iso()
        claimed = effective_at if effective_at is not None else captured_at
        if not is_mandate_instant(claimed):
            raise InvalidMandateError(
                "invalid_revocation_instant", "effectiveAt", "effectiveAt must be an ISO 8601 UTC instant with milliseconds"
            )
        violation = revocation_instant_violation(claimed, captured_at)
        if violation is not None:
            raise InvalidMandateError(violation["code"], violation["field"], violation["message"])
        request = _revocation_request(row, claimed=claimed, reason=reason, revoker=revoker, captured_at=captured_at)
        prepared = await self._tzun._prepare_request(request)
        prepared["mandateId"] = mandate_id
        prepared["aiOutput"] = request.ai_output
        prepared["reason"] = reason
        return prepared

    async def _open_mandate(self, mandate_id: Any, field: str = "mandateId") -> MandateRow:
        """The open mandate with this id, or a refusal (``mandate_not_found``, ``mandate_not_open``)."""
        row = None
        if isinstance(mandate_id, str) and mandate_id:
            row, _ = await _row_state(self._tzun, mandate_id)
        if row is None or row.mandateId != mandate_id:
            raise InvalidMandateError("mandate_not_found", field, "this store holds no mandate with that id")
        if row.state != "open":
            raise _refused("mandate_not_open", field, f"the mandate is {row.state}, not open")
        return row

    async def revoke(
        self,
        *,
        mandate_id: str,
        prepared: Any,
        assertion: Any,
        reason: str | None = None,
        effective_at: str | None = None,
    ) -> CaptureResult:
        """Verify the revoker's assertion over the prepared record and store it (Record §9.6).

        The record is rebuilt from the mandate row, as
        :meth:`prepare_revocation` built it: its ``aiOutput`` (the mandate's
        digests), its ``revokes`` link and its decider (``acct:`` the
        revoker, whose verified assertion this must be). From ``prepared`` it
        takes the evidence id, the capture time, the decider's freshness, the
        reason and the claimed instant (``reason`` and ``effective_at``, when
        given, must be the prepared ones), so a prepared object that was
        edited to describe anything else fails the digest the ceremony signed.
        The mandate moves to ``revoked`` with its ``revoked`` event (carrying
        ``used`` and ``totals``) in the transaction that stores the
        revocation record; later captures under it are refused at the claim.
        """
        from tzun_sdk.attestation.webauthn import webauthn_challenge_for_digest

        self._tzun._require_active()
        p = deep_plain(prepared)
        a = deep_plain(assertion)
        if not isinstance(p, dict) or not isinstance(p.get("digest"), str) or not isinstance(p.get("capturedAt"), str):
            raise InvalidMandateError("invalid_prepared", "prepared", "prepared must be what prepare_revocation() returned")
        if p.get("mandateId") is not None and p["mandateId"] != mandate_id:
            raise InvalidMandateError(
                "invalid_prepared", "prepared", "prepared is the revocation prepare_revocation() formed for another mandate"
            )
        prepared_reason = p.get("reason")
        if reason is not None and prepared_reason is not None and reason != prepared_reason:
            raise InvalidMandateError(
                "invalid_prepared", "prepared", "prepared is the revocation prepare_revocation() formed for another reason"
            )
        reason_text = reason if reason is not None else prepared_reason
        ai_output = p.get("aiOutput") if isinstance(p.get("aiOutput"), dict) else {}
        prepared_instant = ai_output.get("claimedRevocationInstant")
        if effective_at is not None and prepared_instant is not None and effective_at != prepared_instant:
            raise InvalidMandateError(
                "invalid_prepared", "prepared", "prepared is the revocation prepare_revocation() formed for another instant"
            )
        instant = effective_at if effective_at is not None else prepared_instant
        if not isinstance(instant, str):
            raise InvalidMandateError(
                "invalid_revocation_instant",
                "effectiveAt",
                "pass the effective_at prepare_revocation() used, or the prepared revocation it returned",
            )
        identity = prepared_identity_violation(p)
        if identity is not None:
            raise identity
        decider_id = p["decider"].get("id") if isinstance(p["decider"].get("id"), str) else ""
        revoker = _check_revoker(decider_id[len("acct:") :] if decider_id.startswith("acct:") else "")
        row = await self._open_mandate(mandate_id)
        late = revocation_instant_violation(instant, p["capturedAt"])
        if late is not None:
            raise InvalidMandateError(late["code"], late["field"], late["message"])
        user_id = await self._verified_user(a, webauthn_challenge_for_digest(p["digest"]))
        if user_id != revoker:
            raise InvalidMandateError(
                "assertion_not_verified", "assertion", "the assertion was made by a credential not registered to the revoker"
            )
        if not isinstance(reason_text, str):
            raise InvalidMandateError("invalid_prepared", "prepared", "prepared must be what prepare_revocation() returned")

        async def store_options(envelope: dict[str, Any]) -> dict[str, Any]:
            held, totals = await _row_state(self._tzun, row.mandateId)
            if held is None or held.state != "open":
                raise _refused("mandate_not_open", "mandateId", "the mandate is no longer open")
            held_totals = dict(totals) if totals else None
            return {
                "mandateRevoke": MandateRevokeStore(
                    mandateId=held.mandateId,
                    expectState="open",
                    newState="revoked",
                    expectUsed=held.used,
                    expectTotals=held_totals,
                    event=_event_row(
                        held.mandateId,
                        build_mandate_event_body(
                            event="revoked",
                            mandate_digest=held.mandateDigest,
                            record=envelope["integrity"]["canonicalDigest"],
                            used=held.used,
                            totals=held_totals,
                        ),
                    ),
                )
            }

        request = _revocation_request(row, claimed=instant, reason=reason_text, revoker=revoker)
        request.webauthn_assertion = a
        request.store_options = store_options
        request.prepared = p
        request.assertion_user_id = user_id
        return await self._tzun._capture_request(request)

    async def confirm(self, evidence_id: str, assertion: Any) -> dict[str, Any]:
        """Fill a mandated record's owed confirmation (Record §9.6), once; ``{evidenceId, confirmedBy}``."""
        self._tzun._require_active()
        raw = await self._tzun._stored_raw(evidence_id) if isinstance(evidence_id, str) else None
        if raw is None:
            raise InvalidMandateError("record_not_found", "evidenceId", "this store holds no record with that id")
        violation = mandate_confirmation_violation(raw)
        if violation is not None:
            raise _refused(violation["code"], violation["field"], violation["message"])
        digest = raw["integrity"]["canonicalDigest"]
        a = deep_plain(assertion)
        user_id = await self._verified_user(a, mandate_confirmation_challenge(digest))
        storage = self._tzun._storage
        if not hasattr(storage, "fill_confirmation"):
            raise _refused("mandate_not_supported_by_store", "mandate", "this store does not host mandates")
        if not await storage.fill_confirmation(evidence_id, a):
            raise _refused("already_confirmed", "nonRepudiation.confirmation", "the record is already confirmed")
        from tzun_sdk.core import _utcnow_iso

        payload = raw["payload"]
        block = raw.get("nonRepudiation", {}).get("mandate") if isinstance(raw.get("nonRepudiation"), dict) else None
        document = block.get("document") if isinstance(block, dict) else None
        mandate_of_record = document.get("mandateId") if isinstance(document, dict) else None
        await storage.append_custody(
            evidence_id,
            {
                "timestamp": _utcnow_iso(),
                "actor": f"acct:{user_id}",
                "action": "mandate_confirmed",
                "systemId": payload.get("aiSystemId"),
                "metadata": {"mandateId": mandate_of_record, "slot": payload["signoffExpectation"]["mandateSeq"]},
            },
        )
        return {"evidenceId": evidence_id, "confirmedBy": f"acct:{user_id}"}

    async def get(self, mandate_id: str) -> MandateRow | None:
        """The mandate record, or ``None``."""
        self._tzun._require_active()
        row, _ = await _row_state(self._tzun, mandate_id)
        return row

    async def totals(self, mandate_id: str) -> dict[str, int]:
        """The running total of each cap of a mandate."""
        self._tzun._require_active()
        _, totals = await _row_state(self._tzun, mandate_id)
        return totals

    async def events(self, mandate_id: str) -> list[MandateEventRow]:
        """Every event of a mandate, oldest first."""
        self._tzun._require_active()
        await _row_state(self._tzun, mandate_id)
        events: list[MandateEventRow] = await self._tzun._storage.list_mandate_events(mandate_id)
        return events

    async def expire_due(self, now: str | None = None) -> list[str]:
        """Move every open mandate whose window has ended (before ``now``) to ``expired``; the ids moved."""
        from tzun_sdk.core import _utcnow_iso

        self._tzun._require_active()
        storage = self._tzun._storage
        if not hasattr(storage, "list_mandates"):
            return []
        at = js_date_parse_ms(now or _utcnow_iso())
        moved: list[str] = []
        for row in await storage.list_mandates(state="open"):
            end = js_date_parse_ms(row.notAfter)
            if end is not None and at is not None and at > end:
                totals = await storage.get_mandate_totals(row.mandateId)
                if await _expire_if_still_due(self._tzun, row, totals):
                    moved.append(row.mandateId)
        return moved


__all__ = ("AssertionVerifier", "MandateClaim", "MandatesNamespace", "WebAuthnAssertionVerifier")
