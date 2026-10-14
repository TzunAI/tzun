"""The capture pipeline's member resolution and payload build (Record §6 to §8).

The twin of the TS SDK's ``src/sdk/capture-input.ts`` and the member
resolution of ``src/sdk/index.ts``. A capture, in this order, before any
sequence number is taken:

1. the input's shape (:func:`capture_input_violation`): no 0.7 name, ``aiOutput``
   an object, ``action`` and ``reason`` by the payload rules, ``aiSystemId`` not
   reserved, ``decider`` an object of ``DeciderInput``'s members, ``links``
   ``None`` or a non-empty list;
2. the decider (:func:`resolve_decider`): ``desc:<agent>`` for an agent kind
   naming no ``id``, freshness ``"auto"`` from the store's shared finalized
   block, ``require_freshness``, and ``commit`` (a ``cmt:`` commitment whose
   opening the store keeps);
3. the contributions: each step's model resolved against the catalog (an
   inline descriptor registered) and :func:`build_contributions`;
4. the agent references, against the store's agent catalog;
5. the links: same-store targets resolved, then :func:`build_links`.

Each attempt then builds the payload with every writer rule applied
(:func:`build_payload`), its digest, and the envelope.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from tzun_sdk._generated.canonical import (
    V1_HASHED_FIELDS,
    CanonicalSerializationError,
    canonical_serialize,
)
from tzun_sdk._record_rules import canonical_value, deep_plain
from tzun_sdk.attestation.webauthn import assertion_binds_digest
from tzun_sdk.contributions import ContributionsBuildError, build_contributions, step_class
from tzun_sdk.decider import (
    decider_commitment,
    decider_violation,
    default_agent_decider_id,
    identifier_scheme,
    is_known_scheme_identifier,
    random_commitment_salt,
    verify_decider_opening,
)
from tzun_sdk.errors import (
    CaptureRefusedError,
    InvalidAgentDescriptorError,
    InvalidContributionsError,
    InvalidDeciderError,
    InvalidLinksError,
    InvalidMandateError,
    InvalidPayloadError,
    InvalidSignoffExpectationError,
    MandateRefusedError,
    ModelCatalogUnsupportedError,
)
from tzun_sdk.links import LINKS_MAX, HeldLinkTarget, LinksBuildError, build_links
from tzun_sdk.payload_rules import (
    CURRENT_SCHEMA_VERSION,
    action_violation,
    ai_bom_violation,
    ai_system_id_violation,
    captured_at_claim_violation,
    fill_ai_bom_nulls,
    is_evidence_id,
    reason_violation,
)
from tzun_sdk.record_rules import payload_record_rule_violation

if TYPE_CHECKING:
    from tzun_sdk.core import Tzun

#: The members ``decider`` takes at capture.
DECIDER_INPUT_KEYS = ("kind", "id", "agent", "credential", "freshness", "commit")

_RULE_ERRORS: dict[str, type[CaptureRefusedError]] = {
    "payload": InvalidPayloadError,
    "decider": InvalidDeciderError,
    "contributions": InvalidContributionsError,
    "links": InvalidLinksError,
    "mandate": MandateRefusedError,
    "agents": InvalidAgentDescriptorError,
}


def refusal(member: str, code: str, field: str, message: str, **details: Any) -> Exception:
    """The typed error a refusal of ``rule`` raises."""
    if member == "signoffExpectation":
        return InvalidSignoffExpectationError(code, message)
    cls = _RULE_ERRORS.get(member, InvalidPayloadError)
    return cls(code, field, message, **details)


def _violation_error(rule: str, v: dict[str, Any]) -> Exception:
    details = {k: v[k] for k in ("renamedTo", "movedTo", "step", "link", "rule", "linkRule") if k in v}
    return refusal(rule, v["code"], v["field"], v["message"], **details)


@dataclass
class CaptureRequest:
    """One capture, as the pipeline resolves and builds it."""

    ai_output: dict[str, Any]
    action: Any
    reason: Any
    decider: dict[str, Any]
    ai_system_id: str
    contributions: dict[str, Any] | None = None
    links: list[Any] | None = None
    signoff_expectation: dict[str, Any] | None = None
    evidence_id: str | None = None
    captured_at: str | None = None
    #: ``"mandate"`` or ``"link"`` for a system record; ``None`` for a caller's capture.
    system_record: str | None = None
    allow_reserved: tuple[str, ...] = ()
    link_record: bool = False
    mandate_id: str | None = None
    require_freshness: bool = False
    webauthn_assertion: dict[str, Any] | None = None
    mandate_issuance: dict[str, Any] | None = None
    #: Per attempt, the further store options of a system record (``mandateIssue``, ``mandateRevoke``).
    store_options: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]] | None = None
    #: A prepared record (``Tzun.prepare_assertion_challenge``): its identity, its decider's freshness
    #: and a commitment's opening are reused; its members must be what this request resolves to.
    prepared: dict[str, Any] | None = None
    #: The user the assertion's credential is registered to, when the caller knows it.
    assertion_user_id: str | None = None


@dataclass
class ResolvedMembers:
    """A capture's members, resolved once before any sequence number is taken."""

    decider: dict[str, Any]
    opening: dict[str, str] | None
    contributions: dict[str, Any] | None
    links: list[dict[str, Any]] | None
    extra: dict[str, Any] = field(default_factory=dict)


def capture_input_violation(
    *,
    ai_output: Any,
    action: Any,
    reason: Any,
    ai_system_id: Any,
    decider: Any,
    contributions: Any,
    links: Any,
) -> Exception | None:
    """The capture input's shape, first failure first (the TS SDK's ``captureInputViolation``)."""
    if not isinstance(ai_output, dict):
        return InvalidPayloadError("invalid_ai_output", "aiOutput", "aiOutput is required and must be a plain object")
    member = action_violation(action) or reason_violation(reason)
    if member:
        return InvalidPayloadError(member["code"], member["field"], member["message"])
    if ai_system_id is not None:
        issue = ai_system_id_violation(ai_system_id)
        if issue:
            return InvalidPayloadError(issue["code"], issue["field"], issue["message"])
    if decider is None:
        return InvalidDeciderError(
            "missing_members",
            "decider",
            'decider is required: who decided, for example {"kind": "human", "id": "acct:<account id>"}',
        )
    if not isinstance(decider, dict):
        return InvalidDeciderError("not_an_object", "decider", "decider must be an object")
    unknown = next((k for k in decider if k not in DECIDER_INPUT_KEYS), None)
    if unknown is not None:
        return InvalidDeciderError("unknown_members", f"decider.{unknown}", f"decider.{unknown} is not a member of a decider input")
    if contributions is not None:
        if not isinstance(contributions, dict):
            return InvalidContributionsError("not_an_object", "contributions", "contributions must be an object or None")
    if links is not None:
        if not isinstance(links, list):
            return InvalidLinksError("not_an_array", "links", "links must be a list or None")
        if len(links) == 0:
            return InvalidLinksError("empty_links", "links", "links must not be empty: pass None (or leave it out) for no link")
    return None


def settle_signoff_expectation(
    value: Any, *, mandate: bool, field: str = "signoffExpectation"
) -> dict[str, Any] | None:
    """A ``signoff_expectation`` (or, with ``field="prepared.signoffExpectation"``, a prepared one):
    ``None`` or ``{policyDigest}``, checked before anything is built (the TS SDK's ``settleSignoffExpectation``)."""
    from tzun_sdk.signoff_expectation import (
        describe_signoff_expectation_violation,
        is_mandate_expectation,
        is_session_attachment_expectation,
        signoff_expectation_violation,
    )

    value = deep_plain(value)
    violation = signoff_expectation_violation(value)
    if violation is not None:
        message = describe_signoff_expectation_violation(violation)
        if field != "signoffExpectation" and message.startswith("signoffExpectation"):
            message = field + message[len("signoffExpectation") :]
        raise InvalidSignoffExpectationError(violation, message)
    if is_session_attachment_expectation(value):
        raise InvalidSignoffExpectationError(
            "session_form_not_writable",
            f"{field} names a sign-off session slot ({{ statementDigest, sessionSeq }}); only the capture "
            "that claimed the slot may write that, and this SDK opens no sign-off sessions",
        )
    if is_mandate_expectation(value):
        raise InvalidSignoffExpectationError(
            "mandate_form_not_writable",
            f"{field} is the mandate form; only capture(..., mandate={{'mandateId': ...}}) writes it, "
            "from the mandate's claim",
        )
    if mandate and value is not None:
        raise InvalidSignoffExpectationError(
            "expectation_with_mandate",
            "signoffExpectation cannot be given with mandate: a capture under a mandate writes the mandate form itself",
        )
    if value is None:
        return None
    return {"policyDigest": value["policyDigest"]}


def prepared_identity_violation(prepared: Any) -> Exception | None:
    """The identity rule for a ``prepared`` capture (the TS SDK's ``preparedIdentityViolation``).

    ``prepared.evidenceId`` and ``prepared.capturedAt`` become the stored
    record's, so they are held to the rules for a client-chosen identity: a v4
    UUID, and an ISO-8601 date-time no more than five minutes ahead of now.
    """
    if not isinstance(prepared, dict) or not isinstance(prepared.get("digest"), str):
        return InvalidDeciderError(
            "invalid_prepared", "prepared", "prepared must be the object prepare_assertion_challenge() returned"
        )
    if not is_evidence_id(prepared.get("evidenceId")):
        return InvalidPayloadError("invalid_evidence_id", "prepared.evidenceId", "prepared.evidenceId must be a v4 UUID")
    claim = captured_at_claim_violation(prepared.get("capturedAt"))
    if claim is not None:
        return InvalidPayloadError(
            "invalid_captured_at",
            "prepared.capturedAt",
            "prepared.capturedAt is more than five minutes in the future"
            if claim == "future_dated"
            else "prepared.capturedAt must be an ISO-8601 date-time with a zone",
        )
    if not isinstance(prepared.get("decider"), dict):
        return InvalidDeciderError(
            "invalid_prepared", "prepared.decider", "prepared must be the object prepare_assertion_challenge() returned"
        )
    return None


async def resolve_decider(tzun: Tzun, request: CaptureRequest) -> tuple[dict[str, Any], dict[str, str] | None]:
    """The record's decider from the caller's input (Record §6.3, §6.6), and a commitment's opening.

    For a prepared capture, ``"auto"`` freshness is the prepared decider's
    reference and a commitment's salt the prepared opening's: the two values
    a resolution does not reproduce, fixed when the ceremony's record was built.
    """
    d = request.decider
    prepared = request.prepared
    agent = d.get("agent")
    identifier = d.get("id")
    if identifier is None and d.get("kind") != "human" and isinstance(agent, str):
        identifier = default_agent_decider_id(agent)
    freshness_in = d.get("freshness", "auto")
    if freshness_in != "auto":
        freshness = freshness_in
    elif prepared is not None:
        freshness = prepared["decider"].get("freshness")
    else:
        freshness = await tzun._freshness_reference()
    # A decision under a mandate needs a reference wherever one can be had:
    # without it, its currency against a later revocation can never
    # be shown. Here that is wherever a freshness chain is configured.
    required = request.require_freshness or (d.get("kind") == "agent-mandated" and tzun._freshness_chain is not None)
    if required and freshness is None:
        raise InvalidDeciderError(
            "freshness_required",
            "decider.freshness",
            "a finalized-block reference is required for this capture and none younger than freshness_max_age_ms "
            "is available",
        )
    commit = d.get("commit")
    if commit is not None and not isinstance(commit, bool):
        raise InvalidDeciderError("invalid_identifier", "decider.commit", "decider.commit must be True or False")
    opening: dict[str, str] | None = None
    if commit is True:
        if not isinstance(identifier, str) or not is_known_scheme_identifier(identifier) or identifier_scheme(identifier) == "cmt":
            raise InvalidDeciderError(
                "invalid_identifier",
                "decider.id",
                "decider.commit needs decider.id to be an identifier of another scheme to commit to",
            )
        if not hasattr(tzun._storage, "get_decider_commitment_secret"):
            raise InvalidDeciderError(
                "commitment_not_supported_by_store",
                "decider.commit",
                "this store does not keep commitment openings; pass a cmt: identifier you computed, and keep its "
                "opening",
            )
        salt = random_commitment_salt()
        if prepared is not None:
            held = prepared.get("deciderOpening")
            if not isinstance(held, dict) or not isinstance(held.get("salt"), str):
                raise InvalidDeciderError(
                    "invalid_prepared",
                    "prepared.deciderOpening",
                    "a prepared capture under decider.commit carries the opening prepare_assertion_challenge() returned",
                )
            salt = held["salt"]
        opening = {"salt": salt, "id": identifier}
        identifier = decider_commitment(identifier, salt)
    decider = {
        "kind": d.get("kind"),
        "id": identifier,
        "agent": agent,
        "credential": d.get("credential"),
        "freshness": freshness,
    }
    issue = decider_violation(decider)
    if issue:
        raise InvalidDeciderError(issue["code"], issue["field"], issue["message"])
    return decider, opening


async def resolve_step_models(tzun: Tzun, contributions: dict[str, Any]) -> dict[str, Any]:
    """Each step's ``aiBom`` in the pre-built form (Record §7.4).

    An inline descriptor (``modelDescriptor``) is registered through the
    catalog (register-if-absent) and replaced with its digest; a pre-built
    digest must be in the catalog (``descriptor_not_registered``); absent
    nullable members are written as ``None``.
    """
    from tzun_sdk.models import ModelDescriptor

    steps = contributions.get("steps")
    if not isinstance(steps, list):
        return contributions
    out: list[Any] = []
    for i, step in enumerate(steps):
        bom = step.get("aiBom") if isinstance(step, dict) else None
        if not isinstance(bom, dict):
            out.append(step)
            continue
        f = f"contributions.steps[{i}].aiBom"
        if "modelDescriptor" in bom:
            try:
                descriptor = ModelDescriptor.model_validate(bom["modelDescriptor"])
            except Exception as exc:
                raise InvalidContributionsError(
                    "invalid_step_ai_bom", f"{f}.modelDescriptor", f"{f}.modelDescriptor is not a model descriptor"
                ) from exc
            cannot_register = InvalidContributionsError(
                "invalid_step_ai_bom",
                f,
                f"{f} carries an inline model descriptor, and this store cannot register one: register it first "
                "and pass its modelDescriptorDigest",
            )
            if not hasattr(tzun._storage, "register_descriptor"):
                raise cannot_register
            try:
                digest = await tzun._storage.register_descriptor(descriptor)
            except ModelCatalogUnsupportedError as exc:
                # The HTTP backend against a platform without the model
                # catalog: the same answer as a store without one.
                raise cannot_register from exc
            rest = {k: v for k, v in bom.items() if k != "modelDescriptor"}
            out.append({**step, "aiBom": fill_ai_bom_nulls({**rest, "modelDescriptorDigest": digest})})
            continue
        digest = bom.get("modelDescriptorDigest")
        known = False
        if isinstance(digest, str):
            if tzun.descriptor_cache_obj.get(digest) is not None:
                known = True
            else:
                resolved = await tzun._storage.get_descriptor(digest)
                if resolved is not None:
                    tzun.descriptor_cache_obj.put(digest, resolved)
                    known = True
        if not known:
            raise InvalidContributionsError(
                "descriptor_not_registered",
                f"{f}.modelDescriptorDigest",
                f"{f}.modelDescriptorDigest is not in the catalog: register the descriptor before capture, or pass "
                "it inline",
                modelDescriptorDigest=digest if isinstance(digest, str) else None,
            )
        filled = fill_ai_bom_nulls(bom)
        issue = ai_bom_violation(filled, f)
        if issue:
            raise InvalidContributionsError("invalid_step_ai_bom", issue["field"], issue["message"])
        out.append({**step, "aiBom": filled})
    return {**contributions, "steps": out}


def committed_decide_actor(
    contributions: dict[str, Any], decider_input: dict[str, Any], decider: dict[str, Any]
) -> dict[str, Any]:
    """Under ``decider.commit``, a ``decide`` step whose actor is the caller's decider carries the commitment too."""
    if decider_input.get("commit") is not True or not isinstance(contributions.get("steps"), list):
        return contributions

    def default_id(who: dict[str, Any]) -> Any:
        if "id" in who and who["id"] is not None:
            return who["id"]
        if who.get("kind") != "human" and isinstance(who.get("agent"), str):
            return default_agent_decider_id(who["agent"])
        return None

    inner = default_id(decider_input)
    steps = []
    for step in contributions["steps"]:
        actor = step.get("actor") if isinstance(step, dict) else None
        if not isinstance(actor, dict) or step_class(step.get("role")) != "decide":
            steps.append(step)
            continue
        if (
            actor.get("kind") != decider_input.get("kind")
            or default_id(actor) != inner
            or actor.get("agent") != decider_input.get("agent")
        ):
            steps.append(step)
            continue
        steps.append({**step, "actor": {"kind": decider["kind"], "id": decider["id"], "agent": decider["agent"]}})
    return {**contributions, "steps": steps}


def agent_references(decider: dict[str, Any], contributions: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Every agent reference a record names: the decider's, then each step actor's, in step order."""
    refs: list[dict[str, Any]] = []
    if isinstance(decider.get("agent"), str):
        refs.append({"field": "decider.agent", "kind": decider["kind"], "agent": decider["agent"]})
    for i, step in enumerate((contributions or {}).get("steps") or []):
        actor = step.get("actor") if isinstance(step, dict) else None
        if isinstance(actor, dict) and isinstance(actor.get("agent"), str):
            refs.append({"field": f"contributions.steps[{i}].actor.agent", "kind": actor["kind"], "agent": actor["agent"]})
    return refs


async def check_agent_references(tzun: Tzun, refs: list[dict[str, Any]]) -> None:
    """Refuse an agent reference the store's catalog does not hold, or whose kind its descriptor contradicts (Record §6.9).

    A store without the catalog accepts references as given. The HTTP backend
    leaves the check to the platform, which keeps the key's own agent catalog
    and refuses the same two cases at capture (``400 invalid_request``,
    reason ``agent_not_registered`` or ``agent_kind_mismatch``): nothing is
    read here, so a capture costs no catalog request and cannot fail on one.
    """
    import json

    from tzun_sdk.agents import agent_kind_mismatch
    from tzun_sdk.storage.http import HttpBackendAdapter

    storage = tzun._storage
    if not hasattr(storage, "get_agent_descriptor") or isinstance(storage, HttpBackendAdapter):
        return
    for ref in refs:
        try:
            row = await storage.get_agent_descriptor(ref["agent"])
        except InvalidAgentDescriptorError as exc:
            # A store whose catalog methods answer that it keeps none.
            if exc.code == "agent_not_supported_by_store":
                return
            raise
        if row is None:
            raise InvalidAgentDescriptorError(
                "agent_not_registered",
                ref["field"],
                f"{ref['field']} names an agent descriptor this store's catalog does not hold: register it first "
                "(tzun.agents.register)",
            )
        try:
            descriptor = json.loads(row.canonicalBytes)
        except ValueError:
            descriptor = None
        if agent_kind_mismatch(ref["kind"], descriptor):
            raise InvalidAgentDescriptorError(
                "agent_kind_mismatch",
                ref["field"],
                f"{ref['field']}: a policy-engine's descriptor names no model",
            )


def record_intact(raw: Any) -> bool:
    """Whether a stored record's payload recomputes to its stored digest (the TS SDK's ``recordIntact``)."""
    payload = raw.get("payload") if isinstance(raw, dict) else None
    integrity = raw.get("integrity") if isinstance(raw, dict) else None
    stored = integrity.get("canonicalDigest") if isinstance(integrity, dict) else None
    if not isinstance(payload, dict) or not isinstance(stored, str):
        return False
    try:
        return payload_digest(payload) == stored
    except (CanonicalSerializationError, TypeError, ValueError):
        return False


async def resolve_link_targets(tzun: Tzun, inputs: list[Any]) -> list[HeldLinkTarget | None]:
    """Each input's same-store target, or ``None`` (Record §8.7; the TS link hook's ``resolveLinkTargets``).

    Without ``external``: by ``evidenceId`` when the input gives one,
    otherwise by ``digest``; a store that cannot look a record up by digest
    refuses a digest-only target (``links_not_supported_by_store``). With
    ``external: True``: by evidence id, then by digest; a target that resolves
    here is a same-store target, and one that does not is written as given.
    A held record must recompute to its stored digest, or the capture is
    refused (``link_target_mismatch`` on ``target.digest``), except an
    ``external`` target named by that record's stored digest, which is written
    as given so that a damaged copy cannot block a record that names it.
    Resolution never crosses the store.
    """
    if len(inputs) > LINKS_MAX:
        raise InvalidLinksError("too_many_links", "links", f"links holds at most {LINKS_MAX} links")
    storage = tzun._storage
    by_id = getattr(storage, "retrieve_raw", None)
    by_digest = getattr(storage, "retrieve_raw_by_digest", None)
    held: list[HeldLinkTarget | None] = []
    for i, item in enumerate(inputs):
        target = item.get("target") if isinstance(item, dict) else None
        if not isinstance(target, dict):
            held.append(None)
            continue
        f = f"links[{i}].target"
        external = target.get("external") is True
        evidence_id = target.get("evidenceId")
        digest = target.get("digest")
        has_id = isinstance(evidence_id, str)
        has_digest = isinstance(digest, str)
        raw: dict[str, Any] | None = await by_id(evidence_id) if has_id and by_id is not None else None
        if raw is None and has_digest and (external or not has_id):
            if by_digest is not None:
                raw = await by_digest(digest)
            elif not external:
                raise InvalidLinksError(
                    "links_not_supported_by_store",
                    f,
                    "this store cannot look a record up by digest: name the target by evidenceId, or pass "
                    "external: True for a record of another store",
                    link=i,
                )
        if raw is None or not isinstance(raw.get("payload"), dict) or not isinstance(raw.get("integrity"), dict):
            held.append(None)
            continue
        stored_digest = raw["integrity"].get("canonicalDigest")
        if not isinstance(stored_digest, str):
            held.append(None)
            continue
        if not record_intact(raw):
            if external and has_digest and digest == stored_digest:
                held.append(None)
                continue
            raise InvalidLinksError(
                "link_target_mismatch",
                f"{f}.digest",
                f"{f}: the record the target names does not recompute to its stored digest; it cannot be linked",
                link=i,
            )
        held.append(HeldLinkTarget(payload=raw["payload"], digest=stored_digest, origin=None))
    return held


async def commitment_openings(
    tzun: Tzun, decider: dict[str, Any], opening: dict[str, str] | None, held: list[HeldLinkTarget | None]
) -> dict[str, str]:
    """The identifiers the ``cmt:`` deciders of a capture's link rules commit to (Record §6.3, §8.3 ``reviews``).

    The capture's own decider from its opening, and each held record's from
    the store's ``decider_openings``, kept only when the opening verifies
    against the commitment. A commitment this store cannot open is left out,
    and its rule stays undetermined.
    """
    openings: dict[str, str] = {}
    own = decider.get("id")
    if opening is not None and isinstance(own, str) and verify_decider_opening(own, opening):
        openings[own] = opening["id"]
    reader = getattr(tzun._storage, "get_decider_opening", None)
    if reader is None:
        return openings
    for target in held:
        if target is None:
            continue
        d = target.payload.get("decider")
        identifier = d.get("id") if isinstance(d, dict) else None
        evidence_id = target.payload.get("evidenceId")
        if (
            not isinstance(identifier, str)
            or identifier_scheme(identifier) != "cmt"
            or identifier in openings
            or not isinstance(evidence_id, str)
        ):
            continue
        stored = await reader(evidence_id)
        if stored is not None and verify_decider_opening(identifier, stored):
            openings[identifier] = stored.id
    return openings


async def resolve_members(tzun: Tzun, request: CaptureRequest) -> ResolvedMembers:
    """Resolve a capture's members once, before any sequence number is taken."""
    canonical_serialize({"aiOutput": request.ai_output}, ["aiOutput"])
    decider, opening = await resolve_decider(tzun, request)
    contributions: dict[str, Any] | None = None
    if request.contributions is not None:
        resolved = await resolve_step_models(tzun, request.contributions)
        try:
            contributions = build_contributions(
                committed_decide_actor(resolved, request.decider, decider),
                {"decider": decider, "action": request.action, "reason": request.reason, "aiOutput": request.ai_output},
            )
        except ContributionsBuildError as exc:
            raise InvalidContributionsError(exc.code, exc.field, str(exc), step=exc.step) from exc
    await check_agent_references(tzun, agent_references(decider, contributions))
    links: list[dict[str, Any]] | None = None
    if request.links is not None:
        held = await resolve_link_targets(tzun, request.links)
        openings = await commitment_openings(tzun, decider, opening, held)
        try:
            links = build_links(
                request.links,
                held=held,
                open_commitment=openings.get,
                allow_reserved=request.allow_reserved,
                link_record=request.link_record,
                context={
                    "aiSystemId": request.ai_system_id,
                    "action": request.action,
                    "decider": decider,
                    "contributions": contributions,
                    "aiOutput": request.ai_output,
                    "signoffExpectation": request.signoff_expectation,
                },
            )
        except LinksBuildError as exc:
            raise InvalidLinksError(exc.code, exc.field, str(exc), link=exc.link, rule=exc.rule) from exc
    if request.prepared is not None:
        _check_prepared_members(request.prepared, decider=decider, contributions=contributions, links=links)
    return ResolvedMembers(decider=decider, opening=opening, contributions=contributions, links=links)


def _same_canonical(a: Any, b: Any) -> bool:
    try:
        return canonical_value(a) == canonical_value(b)
    except (CanonicalSerializationError, TypeError, ValueError):
        return False


def _check_prepared_members(
    prepared: dict[str, Any],
    *,
    decider: dict[str, Any],
    contributions: dict[str, Any] | None,
    links: list[dict[str, Any]] | None,
) -> None:
    """Refuse a prepared record whose members are not what the capture's input resolves to.

    The members of a prepared capture are resolved again from the input, with
    every rule a capture applies (the decider grammar, the step models, the
    agent catalog, the link targets and the reserved relations), and must
    equal the prepared ones: a ``prepared`` object is the caller's, so its
    members are never taken unchecked.
    """
    for name, resolved in (("decider", decider), ("contributions", contributions), ("links", links)):
        if not _same_canonical(resolved, prepared.get(name)):
            raise InvalidDeciderError(
                "invalid_prepared",
                f"prepared.{name}",
                f"prepared.{name} is not what this capture's input resolves to: capture with the input "
                "prepare_assertion_challenge() was given",
            )


def build_payload(
    request: CaptureRequest,
    members: ResolvedMembers,
    *,
    sequence_number: int,
    evidence_id: str,
    captured_at: str,
    expectation: dict[str, Any] | None,
    links: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """The record's payload with every key written, checked by every writer rule (Record §2.2)."""
    payload = {
        "evidenceId": evidence_id,
        "schemaVersion": CURRENT_SCHEMA_VERSION,
        "aiSystemId": request.ai_system_id,
        "aiOutput": request.ai_output,
        "action": request.action,
        "reason": request.reason,
        "capturedAt": captured_at,
        "sequenceNumber": sequence_number,
        "decider": dict(members.decider),
        "contributions": members.contributions,
        "links": links,
        "signoffExpectation": expectation,
    }
    issue = payload_record_rule_violation(payload, system_record=request.system_record)
    if issue:
        raise _violation_error(issue["rule"], issue)
    return payload


def draft_payload(
    request: CaptureRequest,
    members: ResolvedMembers,
    *,
    sequence_number: int,
    evidence_id: str,
    captured_at: str,
) -> dict[str, Any]:
    """The payload as built so far, unchecked, with ``signoffExpectation`` ``None``: what a mandate claim plans over."""
    return {
        "evidenceId": evidence_id,
        "schemaVersion": CURRENT_SCHEMA_VERSION,
        "aiSystemId": request.ai_system_id,
        "aiOutput": request.ai_output,
        "action": request.action,
        "reason": request.reason,
        "capturedAt": captured_at,
        "sequenceNumber": sequence_number,
        "decider": dict(members.decider),
        "contributions": members.contributions,
        "links": members.links,
        "signoffExpectation": None,
    }


def payload_digest(payload: dict[str, Any]) -> str:
    """The canonical digest of a payload under the v1.0 hashed field set."""
    return hashlib.sha256(canonical_serialize(payload, list(V1_HASHED_FIELDS)).encode("utf-8")).hexdigest()


def attestation_status(non_repudiation: dict[str, Any], digest: str) -> str:
    """The engine's ``determineAttestationStatus`` over what a capture writes."""
    assertion = non_repudiation.get("webauthnAssertion")
    has_signature = isinstance(assertion, dict) and assertion_binds_digest(assertion, digest)
    has_timestamp = bool(non_repudiation.get("rfc3161Token"))
    has_anchor = bool(non_repudiation.get("anchor"))
    if has_signature and has_timestamp and has_anchor:
        return "complete"
    if has_signature or has_timestamp or has_anchor:
        return "partial"
    return "none"


def mandate_refusal(plan: dict[str, Any]) -> MandateRefusedError:
    """A refused mandate plan as the error the capture raises."""
    findings = plan.get("findings")
    return MandateRefusedError(plan["code"], plan["field"], plan["message"], findings=findings)


def invalid_mandate(code: str, field: str, message: str) -> InvalidMandateError:
    return InvalidMandateError(code, field, message)


__all__ = (
    "DECIDER_INPUT_KEYS",
    "CaptureRequest",
    "ResolvedMembers",
    "agent_references",
    "attestation_status",
    "build_payload",
    "capture_input_violation",
    "check_agent_references",
    "committed_decide_actor",
    "draft_payload",
    "invalid_mandate",
    "mandate_refusal",
    "payload_digest",
    "prepared_identity_violation",
    "record_intact",
    "refusal",
    "resolve_decider",
    "resolve_link_targets",
    "resolve_members",
    "resolve_step_models",
    "settle_signoff_expectation",
)
