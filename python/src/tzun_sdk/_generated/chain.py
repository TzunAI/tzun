# HAND-MAINTAINED Python port of packages/engine/src/evidence-chain.ts. NOT generated.
#
# scripts/codegen-python.ts writes only _generated/models.py and never touches
# this file, so regenerating does not carry a TypeScript change across: a
# change to the TypeScript source must be made here too.
#
# Parity with the TypeScript is enforced by the `cross-sdk` CI job (live
# Node<->Python harness over vectors/v1.0-canonical-vectors.json), not by the
# codegen-drift job.
"""Chain-link primitive — byte-parity with @tzun/engine evidence-chain.ts.

chainLink = SHA-256(previousCanonicalDigest + currentCanonicalDigest) as bare
hex; genesis (no previous) is None. Both digests are the BARE-hex evidence
canonicalDigest (no 'sha256:' prefix). Do not change without changing the TS
reference + the cross-SDK integrity vectors.
"""
from __future__ import annotations

import hashlib


def compute_chain_link(previous_digest: str | None, current_digest: str) -> str | None:
    if previous_digest is None:
        return None
    return hashlib.sha256((previous_digest + current_digest).encode("utf-8")).hexdigest()
