"""The contributions member (Record §7): the only place a record states a model's bill of materials.

The twin of ``packages/engine/src/contributions.ts``: output and step digests,
the builder, the writer's structure rules and the reader's two rows
(``contributions`` for structure, ``contributions.binding`` for process). A
single model is a list of one ``propose`` step (:func:`single_model`).

``outputDigest(v) = "sha256:" ‖ hex(SHA-256(C(v)))`` and
``stepDigest(i) = "sha256:" ‖ hex(SHA-256(C(steps[i])))``.

Capture refuses broken structure; it accepts a flawed process (an unbound
review, a stale approval, a changed output), which the reader reports.
"""

from __future__ import annotations

import re
from typing import Any

from tzun_sdk._record_rules import (
    bytes_key,
    canonical_value,
    has_exact_keys,
    has_lone_surrogate,
    is_prefixed_digest,
    is_strictly_increasing,
    plain,
    sha256_hex,
    utf16_length,
)
from tzun_sdk.decider import (
    DECIDER_SCHEMES,
    actor_violation,
    default_agent_decider_id,
    identifier_scheme,
    is_decider_kind,
    reader_actor_inconsistent,
    same_actor,
)
from tzun_sdk.payload_rules import REASON_MAX_LENGTH, ai_bom_violation, fill_ai_bom_nulls

#: The most steps a contributions member holds (a grammar maximum).
CONTRIBUTIONS_MAX_STEPS = 32
#: The most ``inputs`` per step, and the most ``externals`` (grammar maxima).
CONTRIBUTIONS_MAX_SET = 64

_CONTRIBUTIONS_KEYS = ("pipeline", "externals", "steps")
_STEP_KEYS = ("role", "actor", "aiBom", "inputs", "output", "verdict", "reason", "prev")
_ACTOR_KEYS = ("kind", "id", "agent")
_STEP_INPUT_KEYS = (*_STEP_KEYS, "outputOf")
_ROLE_RE = re.compile(r"(propose|review|decide|other)(:[A-Za-z0-9._-]{1,48})?", re.ASCII)
_VERDICTS = ("approve", "reject", "concerns")


def output_digest(value: Any) -> str:
    """``"sha256:" ‖ hex(SHA-256(C(value)))``. Raises for a value the serializer refuses."""
    return "sha256:" + sha256_hex(canonical_value(plain(value)))


def step_digest(step: Any) -> str:
    """The step digest of one step."""
    return output_digest(step)


def step_class(role: Any) -> str | None:
    """The class of a role (the part before the first ``:``), or ``None`` for a role that is not one."""
    if not isinstance(role, str) or _ROLE_RE.fullmatch(role) is None:
        return None
    return role.split(":")[0]


def deciding_step_index(steps: list[Any]) -> int | None:
    """The index of the one ``decide`` step, ``None`` when none, ``-1`` when more than one."""
    decides = [i for i, s in enumerate(steps) if isinstance(s, dict) and step_class(s.get("role")) == "decide"]
    if len(decides) > 1:
        return -1
    return decides[0] if len(decides) == 1 else None


def deciding_output(action: Any, reason: Any) -> str:
    """The output a decide step must have: ``outputDigest({action, reason})``."""
    return output_digest({"action": action, "reason": reason})


def _last_proposal_before(steps: list[Any], before: int) -> int | None:
    for i in range(min(before, len(steps)) - 1, -1, -1):
        step = steps[i] if isinstance(steps[i], dict) else {}
        if step_class(step.get("role")) == "propose":
            return i
    return None


_MESSAGES: dict[str, str] = {
    "not_an_object": "contributions must be null or an object",
    "unknown_members": "contributions may have only the members pipeline, externals and steps",
    "missing_members": "contributions must have every member (pipeline, externals, steps)",
    "invalid_pipeline": "contributions.pipeline must be null or sha256: followed by 64 lowercase hex",
    "invalid_externals": f"contributions.externals must be an array of at most {CONTRIBUTIONS_MAX_SET} prefixed digests",
    "not_a_set": "the array must be strictly increasing by bytes, with no repeated element",
    "no_steps": "contributions.steps must be a non-empty array",
    "too_many_steps": f"contributions.steps holds at most {CONTRIBUTIONS_MAX_STEPS} steps",
    "step_unknown_members": "a step may have only the members " + ", ".join(_STEP_KEYS),
    "step_missing_members": "a step must have every member (" + ", ".join(_STEP_KEYS)
    + "), null where it does not apply",
    "invalid_role": "role must be propose, review, decide or other, optionally followed by :[A-Za-z0-9._-]{1,48}",
    "invalid_actor": "actor must be null or have exactly kind, id and agent, with the decider grammar and consistency",
    "actor_required": "actor may be null only on a step that is not a decide step and records a model (aiBom)",
    "invalid_step_ai_bom": "a step aiBom must be null or an exact AiBom naming a catalogued descriptor",
    "invalid_inputs": f"inputs must be an array of at most {CONTRIBUTIONS_MAX_SET} prefixed digests",
    "invalid_output": "output must be sha256: followed by 64 lowercase hex",
    "invalid_verdict": "verdict must be null, approve, reject or concerns",
    "verdict_not_allowed": "a propose or other step must have verdict null",
    "invalid_step_reason": f"a step reason must be null or 1 to {REASON_MAX_LENGTH} UTF-16 code units with no lone "
    "surrogate",
    "prev_mismatch": "prev must be null on step 0 and the step digest of the step before on every later step",
    "multiple_deciding_steps": "at most one step has the decide class",
    "step_after_deciding": "no propose or review step follows the decide step",
    "decider_not_deciding_actor": "the record's decider must equal the decide step's actor (kind, id, agent)",
    "deciding_output_mismatch": "a decide step's output must be outputDigest({ action, reason }) of the record",
}


def _violation(code: str, field: str, step: int | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"code": code, "field": field, "message": f"{field}: {_MESSAGES[code]}"}
    if step is not None:
        out["step"] = step
    return out


def _step_shape_violation(step: Any, i: int) -> dict[str, Any] | None:
    f = f"contributions.steps[{i}]"
    if not isinstance(step, dict):
        return _violation("step_unknown_members", f, i)
    if any(k not in _STEP_KEYS for k in step):
        return _violation("step_unknown_members", f, i)
    if not has_exact_keys(step, _STEP_KEYS):
        return _violation("step_missing_members", f, i)
    cls = step_class(step["role"])
    if cls is None:
        return _violation("invalid_role", f"{f}.role", i)
    actor = step["actor"]
    if actor is None:
        if step["aiBom"] is None or cls == "decide":
            return _violation("actor_required", f"{f}.actor", i)
    elif (
        not isinstance(actor, dict)
        or not has_exact_keys(actor, _ACTOR_KEYS)
        or actor_violation(actor, f"{f}.actor", False) is not None
    ):
        return _violation("invalid_actor", f"{f}.actor", i)
    if step["aiBom"] is not None and ai_bom_violation(step["aiBom"], f"{f}.aiBom") is not None:
        return _violation("invalid_step_ai_bom", f"{f}.aiBom", i)
    inputs = step["inputs"]
    if not isinstance(inputs, list) or len(inputs) > CONTRIBUTIONS_MAX_SET or not all(is_prefixed_digest(x) for x in inputs):
        return _violation("invalid_inputs", f"{f}.inputs", i)
    if not is_strictly_increasing(inputs):
        return _violation("not_a_set", f"{f}.inputs", i)
    if not is_prefixed_digest(step["output"]):
        return _violation("invalid_output", f"{f}.output", i)
    verdict = step["verdict"]
    if verdict is not None and not (isinstance(verdict, str) and verdict in _VERDICTS):
        return _violation("invalid_verdict", f"{f}.verdict", i)
    if verdict is not None and cls in ("propose", "other"):
        return _violation("verdict_not_allowed", f"{f}.verdict", i)
    reason = step["reason"]
    if reason is not None and (
        not isinstance(reason, str)
        or not 1 <= utf16_length(reason) <= REASON_MAX_LENGTH
        or has_lone_surrogate(reason)
    ):
        return _violation("invalid_step_reason", f"{f}.reason", i)
    if step["prev"] is not None and not is_prefixed_digest(step["prev"]):
        return _violation("prev_mismatch", f"{f}.prev", i)
    return None


def _broken_chain_index(steps: list[Any]) -> int | None:
    for i, step in enumerate(steps):
        expected: str | None = None
        if i > 0:
            try:
                expected = step_digest(steps[i - 1])
            except Exception:
                return i
        if not isinstance(step, dict) or step.get("prev") != expected:
            return i
    return None


def contributions_violation(value: Any, context: dict[str, Any]) -> dict[str, Any] | None:
    """Why ``value`` is not a contributions member a writer may write, or ``None`` (``None`` is one).

    ``context`` holds the record's ``decider``, ``action`` and ``reason``.
    """
    value = plain(value)
    if value is None:
        return None
    ctx = plain(context) if isinstance(plain(context), dict) else {}
    if not isinstance(value, dict):
        return _violation("not_an_object", "contributions")
    if any(k not in _CONTRIBUTIONS_KEYS for k in value):
        return _violation("unknown_members", "contributions")
    if not has_exact_keys(value, _CONTRIBUTIONS_KEYS):
        return _violation("missing_members", "contributions")
    if value["pipeline"] is not None and not is_prefixed_digest(value["pipeline"]):
        return _violation("invalid_pipeline", "contributions.pipeline")
    externals = value["externals"]
    if (
        not isinstance(externals, list)
        or len(externals) > CONTRIBUTIONS_MAX_SET
        or not all(is_prefixed_digest(x) for x in externals)
    ):
        return _violation("invalid_externals", "contributions.externals")
    if not is_strictly_increasing(externals):
        return _violation("not_a_set", "contributions.externals")
    steps = value["steps"]
    if not isinstance(steps, list) or len(steps) == 0:
        return _violation("no_steps", "contributions.steps")
    if len(steps) > CONTRIBUTIONS_MAX_STEPS:
        return _violation("too_many_steps", "contributions.steps")
    for i, step in enumerate(steps):
        shape = _step_shape_violation(step, i)
        if shape:
            return shape
    chain = _broken_chain_index(steps)
    if chain is not None:
        return _violation("prev_mismatch", f"contributions.steps[{chain}].prev", chain)
    deciding = deciding_step_index(steps)
    if deciding == -1:
        return _violation("multiple_deciding_steps", "contributions.steps")
    if deciding is not None:
        for i in range(deciding + 1, len(steps)):
            if step_class(steps[i]["role"]) in ("propose", "review"):
                return _violation("step_after_deciding", f"contributions.steps[{i}].role", i)
        if not same_actor(ctx.get("decider"), steps[deciding]["actor"]):
            return _violation("decider_not_deciding_actor", f"contributions.steps[{deciding}].actor", deciding)
        expected: str | None
        try:
            action, reason = ctx.get("action"), ctx.get("reason")
            expected = deciding_output(action, reason) if isinstance(action, str) and isinstance(reason, str) else None
        except Exception:
            expected = None
        if steps[deciding]["output"] != expected:
            return _violation("deciding_output_mismatch", f"contributions.steps[{deciding}].output", deciding)
    return None


class ContributionsBuildError(ValueError):
    """Raised by :func:`build_contributions` for input a writer refuses."""

    def __init__(self, violation: dict[str, Any]) -> None:
        super().__init__(violation["message"])
        self.code: str = violation["code"]
        self.field: str = violation["field"]
        self.step: int | None = violation.get("step")


def single_model(ai_bom: Any, *, actor: Any = None) -> dict[str, Any]:
    """The builder form of a list of one (Record §7.3): one ``propose`` step recording ``ai_bom``.

    ``actor`` is the agent that called the model, or ``None`` for a model
    called directly. :func:`build_contributions` fills its output from the
    record's ``aiOutput``.
    """
    return {"steps": [{"role": "propose", "actor": plain(actor), "aiBom": plain(ai_bom), "inputs": []}]}


_UNSET = object()


def build_contributions(contributions_input: Any, context: dict[str, Any]) -> dict[str, Any]:
    """Build a contributions member from builder input against the record's ``context``.

    ``context`` holds ``decider``, ``action``, ``reason`` and ``aiOutput``.
    Step ``aiBom``s must already be in the pre-built form. Raises
    :class:`ContributionsBuildError`.
    """
    inp = plain(contributions_input)
    if not isinstance(inp, dict):
        raise ContributionsBuildError(_violation("not_an_object", "contributions"))
    if any(k not in _CONTRIBUTIONS_KEYS for k in inp):
        raise ContributionsBuildError(_violation("unknown_members", "contributions"))
    ctx = plain(context) if isinstance(plain(context), dict) else {}
    raw_steps = inp.get("steps")
    if not isinstance(raw_steps, list) or len(raw_steps) == 0:
        raise ContributionsBuildError(_violation("no_steps", "contributions.steps"))
    if len(raw_steps) > CONTRIBUTIONS_MAX_STEPS:
        raise ContributionsBuildError(_violation("too_many_steps", "contributions.steps"))
    raw_steps = [plain(s) for s in raw_steps]

    def sort_set(values: Any, field: str, step: int | None = None) -> list[str]:
        if values is _UNSET:
            return []
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ContributionsBuildError(
                _violation("invalid_externals" if step is None else "invalid_inputs", field, step)
            )
        ordered = sorted(values, key=bytes_key)
        if not is_strictly_increasing(ordered):
            raise ContributionsBuildError(_violation("not_a_set", field, step))
        return ordered

    deciding = deciding_step_index(raw_steps)
    last_proposal = _last_proposal_before(
        [s if isinstance(s, dict) else {} for s in raw_steps],
        len(raw_steps) if deciding is None or deciding == -1 else deciding,
    )
    steps: list[dict[str, Any]] = []
    for i, s in enumerate(raw_steps):
        f = f"contributions.steps[{i}]"
        if not isinstance(s, dict) or any(k not in _STEP_INPUT_KEYS for k in s):
            raise ContributionsBuildError(_violation("step_unknown_members", f, i))
        actor: dict[str, Any] | None = None
        actor_in = plain(s.get("actor"))
        if actor_in is not None:
            if not isinstance(actor_in, dict) or any(k not in _ACTOR_KEYS for k in actor_in):
                raise ContributionsBuildError(_violation("invalid_actor", f"{f}.actor", i))
            agent = actor_in.get("agent")
            identifier = actor_in.get("id", _UNSET)
            if (
                identifier is _UNSET
                and is_decider_kind(actor_in.get("kind"))
                and actor_in.get("kind") != "human"
                and isinstance(agent, str)
            ):
                identifier = default_agent_decider_id(agent)
            actor = {"kind": actor_in.get("kind"), "id": None if identifier is _UNSET else identifier, "agent": agent}
        cls = step_class(s.get("role"))
        output = s.get("output", _UNSET)
        if output is _UNSET and "outputOf" in s:
            try:
                output = output_digest(s["outputOf"])
            except Exception as exc:
                raise ContributionsBuildError(_violation("invalid_output", f"{f}.outputOf", i)) from exc
        if output is _UNSET and i == last_proposal and "aiOutput" in ctx:
            try:
                output = output_digest(ctx["aiOutput"])
            except Exception as exc:
                raise ContributionsBuildError(_violation("invalid_output", f"{f}.output", i)) from exc
        if output is _UNSET and cls == "decide":
            action, reason = ctx.get("action"), ctx.get("reason")
            if not isinstance(action, str) or not isinstance(reason, str):
                raise ContributionsBuildError(_violation("deciding_output_mismatch", f"{f}.output", i))
            try:
                output = deciding_output(action, reason)
            except Exception as exc:
                raise ContributionsBuildError(_violation("deciding_output_mismatch", f"{f}.output", i)) from exc
        reason_value = s.get("reason")
        if reason_value is None and cls == "decide" and isinstance(ctx.get("reason"), str):
            reason_value = ctx["reason"]
        ai_bom = s.get("aiBom")
        step: dict[str, Any] = {
            "role": s.get("role"),
            "actor": actor,
            "aiBom": None if ai_bom is None else fill_ai_bom_nulls(ai_bom),
            "inputs": sort_set(s.get("inputs", _UNSET), f"{f}.inputs", i),
            "output": None if output is _UNSET else output,
            "verdict": s.get("verdict"),
            "reason": reason_value,
            "prev": None,
        }
        shape = _step_shape_violation(step, i)
        if shape:
            raise ContributionsBuildError(shape)
        prev = None if i == 0 else step_digest(steps[i - 1])
        if "prev" in s and s["prev"] != prev:
            raise ContributionsBuildError(_violation("prev_mismatch", f"{f}.prev", i))
        step["prev"] = prev
        steps.append(step)
    built = {
        "pipeline": inp.get("pipeline"),
        "externals": sort_set(inp.get("externals", _UNSET), "contributions.externals"),
        "steps": steps,
    }
    v = contributions_violation(built, ctx)
    if v:
        raise ContributionsBuildError(v)
    return built


def _actor_supported(actor: dict[str, Any]) -> str | None:
    if not is_decider_kind(actor.get("kind")):
        return "kind"
    scheme = identifier_scheme(actor.get("id"))
    if scheme is None or scheme not in DECIDER_SCHEMES:
        return "scheme"
    return None


def _reader_step_malformed(step: Any) -> bool:
    if not isinstance(step, dict) or not has_exact_keys(step, _STEP_KEYS):
        return True
    cls = step_class(step["role"])
    if cls is None:
        return True
    actor = step["actor"]
    if actor is None:
        if step["aiBom"] is None or cls == "decide":
            return True
    else:
        if not isinstance(actor, dict) or not has_exact_keys(actor, _ACTOR_KEYS):
            return True
        if not isinstance(actor["kind"], str) or identifier_scheme(actor["id"]) is None:
            return True
        if actor["agent"] is not None and not is_prefixed_digest(actor["agent"]):
            return True
        if _actor_supported(actor) is None and reader_actor_inconsistent(actor["kind"], actor["id"], actor["agent"]):
            return True
    inputs = step["inputs"]
    if not isinstance(inputs, list) or len(inputs) > CONTRIBUTIONS_MAX_SET or not all(is_prefixed_digest(x) for x in inputs):
        return True
    if not is_strictly_increasing(inputs):
        return True
    if not is_prefixed_digest(step["output"]):
        return True
    verdict = step["verdict"]
    if verdict is not None and not (isinstance(verdict, str) and verdict in _VERDICTS):
        return True
    if verdict is not None and cls in ("propose", "other"):
        return True
    if step["reason"] is not None and not isinstance(step["reason"], str):
        return True
    return step["prev"] is not None and not is_prefixed_digest(step["prev"])


def _binding_blocked(reason: str) -> dict[str, Any]:
    return {
        "outcome": "not-checked",
        "valid": None,
        "reason": reason,
        "approvals": [],
        "staleApprovals": [],
        "uncoveredReviews": [],
        "proposals": [],
        "decisionBinding": "not-applicable",
    }


def _not_checked(reason: str) -> dict[str, Any]:
    return {"outcome": "not-checked", "valid": None, "reason": reason, "binding": _binding_blocked(reason)}


def _wrong(reason: str, **extra: Any) -> dict[str, Any]:
    return {
        "outcome": "checked-wrong",
        "valid": False,
        "reason": reason,
        **extra,
        "binding": _binding_blocked("blocked_by:contributions"),
    }


def check_contributions(payload: Any) -> dict[str, Any]:
    """The reader's ``contributions`` and ``contributions.binding`` rows (Verification §4.10). Never raises."""
    from tzun_sdk.links import link_target_inputs

    p = plain(payload)
    p = p if isinstance(p, dict) else {}
    value = p.get("contributions")
    if value is None:
        return _not_checked("absent")
    if not isinstance(value, dict) or not has_exact_keys(value, _CONTRIBUTIONS_KEYS):
        return _wrong("malformed_contributions")
    if value["pipeline"] is not None and not is_prefixed_digest(value["pipeline"]):
        return _wrong("malformed_contributions")
    externals = value["externals"]
    if (
        not isinstance(externals, list)
        or len(externals) > CONTRIBUTIONS_MAX_SET
        or not all(is_prefixed_digest(x) for x in externals)
        or not is_strictly_increasing(externals)
    ):
        return _wrong("malformed_contributions")
    steps = value["steps"]
    if not isinstance(steps, list) or len(steps) == 0 or len(steps) > CONTRIBUTIONS_MAX_STEPS:
        return _wrong("malformed_contributions")
    for i, step in enumerate(steps):
        if _reader_step_malformed(step):
            return _wrong("malformed_contributions", failedStep=i)
    deciding = deciding_step_index(steps)
    if deciding == -1:
        return _wrong("malformed_contributions")
    if deciding is not None:
        for i in range(deciding + 1, len(steps)):
            if step_class(steps[i]["role"]) in ("propose", "review"):
                return _wrong("malformed_contributions", failedStep=i)
    chain = _broken_chain_index(steps)
    if chain is not None:
        return _wrong("step_chain_broken", failedStep=chain)
    if deciding is not None:
        if not same_actor(p.get("decider"), steps[deciding]["actor"]):
            return _wrong("decider_not_deciding_actor", failedStep=deciding)
        try:
            expected: str | None = deciding_output(p.get("action"), p.get("reason"))
        except Exception:
            expected = None
        if steps[deciding]["output"] != expected:
            return _wrong("deciding_output_mismatch", failedStep=deciding)
    for step in steps:
        if step["actor"] is None:
            continue
        unsupported = _actor_supported(step["actor"])
        if unsupported is not None:
            return {
                "outcome": "abstain",
                "valid": None,
                "reason": "unsupported_actor_kind" if unsupported == "kind" else "unsupported_identifier_scheme",
                "binding": _binding_blocked("blocked_by:contributions"),
            }
    models: list[str] = []
    for step in steps:
        bom = step["aiBom"]
        digest = bom.get("modelDescriptorDigest") if isinstance(bom, dict) else None
        if isinstance(digest, str) and digest not in models:
            models.append(digest)
    result: dict[str, Any] = {
        "outcome": "checked-correct",
        "valid": True,
        "steps": len(steps),
        "models": models,
        "decidingStep": "record" if deciding is None else deciding,
        "binding": _check_binding(steps, deciding, externals, p, link_target_inputs(p.get("links"))),
    }
    if value["pipeline"] is not None:
        result["pipeline"] = {"outcome": "abstain", "reason": "unsupported_pipeline"}
    return result


def _check_binding(
    steps: list[dict[str, Any]],
    deciding: int | None,
    externals: list[str],
    payload: dict[str, Any],
    link_targets: set[str],
) -> dict[str, Any]:
    proposals = [i for i, s in enumerate(steps) if step_class(s["role"]) == "propose"]
    external_set = set(externals)
    final_proposal = _last_proposal_before(steps, len(steps) if deciding is None else deciding)
    decision_binding = "not-applicable" if final_proposal is None else "checked"
    approvals: list[int] = []
    stale: list[int] = []
    uncovered: list[int] = []

    def base() -> dict[str, Any]:
        return {"approvals": approvals, "staleApprovals": stale, "uncoveredReviews": uncovered, "proposals": proposals}

    def failure(reason: str, failed_step: int, failed_digest: str | None = None) -> dict[str, Any]:
        out = {
            "outcome": "checked-wrong",
            "valid": False,
            "reason": reason,
            **base(),
            "decisionBinding": decision_binding,
            "failedStep": failed_step,
        }
        if failed_digest is not None:
            out["failedDigest"] = failed_digest
        return out

    outputs: list[str] = []
    for i, step in enumerate(steps):
        for item in step["inputs"]:
            if item not in outputs and item not in link_targets and item not in external_set:
                return failure("input_undeclared", i, item)
        outputs.append(step["output"])

    for i, step in enumerate(steps):
        if step_class(step["role"]) != "review":
            continue
        covered = _last_proposal_before(steps, i)
        if covered is None:
            uncovered.append(i)
            continue
        if steps[covered]["output"] not in step["inputs"]:
            return failure("review_unbound", i, steps[covered]["output"])
        if step["verdict"] != "approve":
            continue
        if covered == final_proposal:
            approvals.append(i)
        else:
            stale.append(i)

    if final_proposal is None:
        return {"outcome": "checked-correct", "valid": True, **base(), "decisionBinding": decision_binding}
    proposed = steps[final_proposal]["output"]
    try:
        decided: str | None = output_digest(payload.get("aiOutput"))
    except Exception:
        decided = None
    if decided != proposed:
        return failure("decided_output_differs", final_proposal, proposed)
    if deciding is not None and proposed not in steps[deciding]["inputs"]:
        return failure("decision_unbound", deciding, proposed)
    return {"outcome": "checked-correct", "valid": True, **base(), "decisionBinding": decision_binding}


__all__ = (
    "CONTRIBUTIONS_MAX_SET",
    "CONTRIBUTIONS_MAX_STEPS",
    "ContributionsBuildError",
    "build_contributions",
    "check_contributions",
    "contributions_violation",
    "deciding_output",
    "deciding_step_index",
    "output_digest",
    "single_model",
    "step_class",
    "step_digest",
)
