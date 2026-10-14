"""Cross-SDK parity for the custody entry hash and the custody-trail verdict.

The rule lives in ONE place per SDK — ``packages/engine/src/custody-hash.ts``
and ``python/src/tzun_sdk/custody_hash.py`` — and both are held here to
``vectors/custody-entry-hash-vectors.json``, whose expected values were computed
with the hosted service's implementation. So this file pins three-way agreement:
TS engine == Python port == the service's ledger, byte for byte on the preimage and
on the hash. It then takes a TS-captured envelope, has the TS side mint two
chained entries, and checks that Python and TS reach the same verdict on the
clean trail and on a rewritten one.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from tzun_sdk.custody_hash import (
    compute_custody_entry_hash,
    custody_entry_preimage,
    verify_custody_trail,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
VECTORS = json.loads(
    (REPO_ROOT / "vectors" / "custody-entry-hash-vectors.json").read_text(encoding="utf-8")
)["vectors"]


def _kwargs(v: dict) -> dict:
    return {
        "prev_entry_hash": v["prevEntryHash"],
        "evidence_id": v["evidenceId"],
        "canonical_digest": v["canonicalDigest"],
        "action": v["action"],
        "actor": v["actor"],
        "timestamp": v["timestamp"],
        "system_id": v["systemId"],
        "metadata": v.get("metadata"),
    }


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"][:40] for v in VECTORS])
def test_ts_python_and_platform_agree_on_every_vector(ts_invoke, vector: dict) -> None:  # type: ignore[no-untyped-def]
    ts = ts_invoke({"action": "custody-entry-hash", "preimage": vector["input"]})
    assert ts["preimage"] == vector["preimage"], "TS preimage drifted from the platform's"
    assert ts["entryHash"] == vector["entryHash"], "TS hash drifted from the platform's"
    assert custody_entry_preimage(**_kwargs(vector["input"])) == ts["preimage"]
    assert compute_custody_entry_hash(**_kwargs(vector["input"])) == ts["entryHash"]


def test_python_and_ts_reach_the_same_verdict_on_a_ts_hashed_trail(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    envelope = ts_invoke(
        {
            "action": "capture",
            "aiOutput": {"score": 0.7, "label": "approve"},
            "decision": {"action": "approved", "reason": "ok"},
        }
    )["envelope"]
    evidence_id = envelope["payload"]["evidenceId"]
    digest = envelope["integrity"]["canonicalDigest"]
    envelope["custodyChain"] = [
        {"timestamp": "t0", "actor": "jane", "action": "decision_captured", "systemId": "sys"}
    ]

    prev = None
    for i, action in enumerate(("relinked", "reviewed")):
        entry = {
            "timestamp": f"2026-09-09T10:0{i}:00.000Z",
            "actor": "admin@acme.example",
            "action": action,
            "systemId": "tzun-recovery",
            "metadata": {"step": i, "note": "ünï 😀"},
        }
        # TS mints the hash — the writer side — Python only ever reads it.
        minted = ts_invoke(
            {
                "action": "custody-entry-hash",
                "preimage": {
                    "prevEntryHash": prev,
                    "evidenceId": evidence_id,
                    "canonicalDigest": digest,
                    **{k: entry[k] for k in ("action", "actor", "timestamp")},
                    "systemId": entry["systemId"],
                    "metadata": entry["metadata"],
                },
            }
        )["entryHash"]
        envelope["custodyChain"].append({**entry, "entryHash": minted, "prevEntryHash": prev})
        prev = minted

    py = verify_custody_trail(envelope["custodyChain"], evidence_id=evidence_id, canonical_digest=digest)
    ts = ts_invoke({"action": "verify", "envelope": envelope})
    assert ts["valid"] is True
    assert (py.valid, ts["custodyTrailValid"]) == (True, True)
    assert py.hashedEntries == 2 and py.unhashedEntries == 1

    # Rewrite the actor of the FIRST hashed entry: both sides must fail it, at
    # the same index, and report it once (the second entry chains to the stored
    # hash, so it is not cascaded).
    envelope["custodyChain"][1]["actor"] = "mallory@acme.example"
    py = verify_custody_trail(envelope["custodyChain"], evidence_id=evidence_id, canonical_digest=digest)
    ts = ts_invoke({"action": "verify", "envelope": envelope})
    assert ts["valid"] is True  # the digest is untouched; the trail is its own verdict
    assert (py.valid, ts["custodyTrailValid"]) == (False, False)
    assert [f.model_dump() for f in py.failures] == ts["custodyTrailFailures"] == [
        {"reason": "entry_hash_mismatch", "index": 1}
    ]


# ---- How an entryHash must be spelled ---------------------------------------------
#
# An entry counts as hashed only when its entryHash is exactly 64 lowercase hex
# digits, matched against the whole string. Each spelling below is the correct
# hash written another way, so the spelling is the only fault: both SDKs read the
# entry as client-attested and, since it follows a hashed entry, report
# unhashed_after_hashed at its index.

ENTRY_HASH_SPELLINGS = {
    "trailing newline": lambda h: h + "\n",
    "trailing CRLF": lambda h: h + "\r\n",
    "leading space": lambda h: " " + h,
    "uppercase": str.upper,
    "63 hex digits": lambda h: h[:63],
    "65 hex digits": lambda h: h + "0",
    "0x prefix": lambda h: "0x" + h,
    "0x prefix, 64 chars": lambda h: "0x" + h[2:],
}


def test_python_and_ts_read_every_misspelled_entry_hash_the_same_way(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    envelope = ts_invoke(
        {
            "action": "capture",
            "aiOutput": {"score": 0.4, "label": "refer"},
            "decision": {"action": "modified", "reason": "entryHash spelling corpus"},
        }
    )["envelope"]
    evidence_id = envelope["payload"]["evidenceId"]
    digest = envelope["integrity"]["canonicalDigest"]

    hashed = []
    prev = None
    for i, action in enumerate(("relinked", "reviewed")):
        entry = {
            "timestamp": f"2026-09-25T10:0{i}:00.000Z",
            "actor": "admin@acme.example",
            "action": action,
            "systemId": "tzun-recovery",
        }
        minted = ts_invoke(
            {
                "action": "custody-entry-hash",
                "preimage": {
                    "prevEntryHash": prev,
                    "evidenceId": evidence_id,
                    "canonicalDigest": digest,
                    **entry,
                    "metadata": None,
                },
            }
        )["entryHash"]
        hashed.append({**entry, "entryHash": minted, "prevEntryHash": prev})
        prev = minted
    genesis = {"timestamp": "t0", "actor": "jane", "action": "decision_captured", "systemId": "sys"}

    def verdicts(chain: list[dict]) -> tuple[tuple, tuple]:
        envelope["custodyChain"] = chain
        py = verify_custody_trail(chain, evidence_id=evidence_id, canonical_digest=digest)
        ts = ts_invoke({"action": "verify", "envelope": envelope})
        assert ts["valid"] is True
        return (
            (py.valid, [f.model_dump() for f in py.failures]),
            (ts["custodyTrailValid"], ts["custodyTrailFailures"]),
        )

    # Control: the trail as minted verifies on both sides.
    py, ts = verdicts([genesis, *hashed])
    assert py == ts == (True, [])

    for name, spell in ENTRY_HASH_SPELLINGS.items():
        misspelled = {**hashed[1], "entryHash": spell(hashed[1]["entryHash"])}
        py, ts = verdicts([genesis, hashed[0], misspelled])
        assert py == ts, name
        assert ts == (False, [{"reason": "unhashed_after_hashed", "index": 2}]), name
