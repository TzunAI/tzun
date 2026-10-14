# HAND-MAINTAINED. NOT generated.
#
# The twin of packages/engine/src/merkle.ts, written from the RFCs.
#
# - The generators are structurally independent. The TS walks node indices over
#   stored layers; this module follows RFC 6962's recursive MTH, PATH and
#   SUBPROOF over leaf ranges.
# - The verifiers are not independent. Both follow the RFC 9162 §2.1.3.2 and
#   §2.1.4.2 step lists, as any conforming verifier must, so a misreading of a
#   step could sit in both, and the cross-SDK parity test would not see it.
#   python/tests/attestation/test_merkle.py pins each guard of the inclusion
#   fold on its own for that reason.
#
# The two share the wire contract: the bytes of every root and proof, the hex
# rule, and the refusal vocabulary of the consistency verifier.
# tests/cross-sdk/test_merkle_*.py hold them together; edit both when the
# contract moves.
"""RFC 6962 Merkle trees over evidence digests: the tree hash, inclusion proofs
and consistency proofs.

Wire rules (Tree §3 and §4, with the consistency edge rules of Tree §3.5):

- A leaf is the RAW 32 bytes of a SHA-256 digest (hex-decoded), never its 64
  ASCII characters. ``leaf hash = SHA-256(0x00 || d)``; an internal node is
  ``SHA-256(0x01 || left || right)`` over raw 32-byte children.
- ``MTH(D[n])`` splits at the largest power of two strictly less than ``n``.
  Equivalently, an odd trailing node is promoted, never duplicated, so the tree
  shape is a function of the size and ``[a, b, c]`` and ``[a, b, c, c]`` have
  different roots (the CVE-2012-2459 shape).
- Proofs are lists of bare lowercase hex, innermost element first, with no
  left/right labels: the side of each step follows from the sizes, which is
  what lets a stock Certificate Transparency verifier check them unmodified.
- Every hash this module reads is a ``str`` of exactly 64 hex digits, matched
  against the whole string with ``re.fullmatch``. Upper and mixed case are
  accepted and normalised to lowercase; a trailing newline, surrounding
  whitespace, 63 or 65 digits, a ``0x`` prefix and a non-string are refused.
- Every size or index this module reads is a JSON integer: an ``int`` (never a
  ``bool``) or an integral ``float``, within ``±(2**53 - 1)``. JSON has one
  number type, so ``3.0`` is ``3``; past ``2**53 - 1`` a JSON number no longer
  names one integer, and the size is refused.

Neither verifier raises on any input: a malformed argument is a verdict. The
inclusion verifier returns a bare ``bool``; the consistency verifier returns a
:class:`ConsistencyVerification` whose ``reason`` is one of
:data:`ConsistencyProofReason`, the same vocabulary, in the same order of
precedence, as the TS engine's ``verifyConsistencyProof``.

What a verified proof does not establish: the tree size is an input, not a
finding. Most honest proofs also verify under some other claimed size (the
``sizeMalleability`` census in ``vectors/merkle-consistency-vectors.json``), so
sizes must come from an authenticated checkpoint.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Literal

#: The ``merkleSpec`` wire tag. A verifier that does not recognise the tag on an
#: artifact reports an unsupported spec; it never falls back to another rule.
MERKLE_SPEC: Final = "rfc6962"

_HEX64: Final = re.compile(r"[0-9a-fA-F]{64}")
_MAX_SAFE_INTEGER: Final = 2**53 - 1

ConsistencyProofReason = Literal[
    "malformed_tree",
    "malformed_size",
    "size_out_of_range",
    "malformed_root",
    "malformed_proof",
    "proof_length_mismatch",
    "first_root_mismatch",
    "second_root_mismatch",
]
"""Why a consistency proof could not be generated or did not verify.

- ``malformed_tree``: the generator was not given a :class:`MerkleTree`.
- ``malformed_size``: a size is not a JSON integer in the safe range.
- ``size_out_of_range``: the sizes break ``0 < first <= second`` (and, for the
  generator, ``second <= leaf_count``). Tzun never publishes an empty log, so
  ``first = 0`` is always out of range, even with an empty proof.
- ``malformed_root``, ``malformed_proof``: not 64-digit hex, or a proof that is
  not a list of it.
- ``proof_length_mismatch``: more or fewer elements than the two sizes call
  for; equal sizes call for none.
- ``first_root_mismatch``, ``second_root_mismatch``: the proof does not
  reconstruct that root. Equal sizes with different roots report the second.
"""


@dataclass(frozen=True)
class ConsistencyVerification:
    """The verdict of :func:`verify_consistency_proof`."""

    valid: bool
    #: ``None`` exactly when ``valid`` is true.
    reason: ConsistencyProofReason | None


@dataclass(frozen=True)
class ConsistencyProofResult:
    """The result of :func:`get_consistency_proof`: a proof, or why there is none."""

    ok: bool
    #: ``PROOF(first, D[second])`` as bare lowercase hex when ``ok``, else ``None``.
    proof: tuple[str, ...] | None = None
    #: ``None`` exactly when ``ok`` is true.
    reason: ConsistencyProofReason | None = None


_VALID: Final = ConsistencyVerification(valid=True, reason=None)


def _refuse(reason: ConsistencyProofReason) -> ConsistencyVerification:
    return ConsistencyVerification(valid=False, reason=reason)


# ---- Input rules --------------------------------------------------------------------


def _as_digest(value: object) -> str | None:
    """The lowercase form of a 64-hex-digit string, or ``None`` for anything else."""
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        return None
    return value.lower()


def _as_size(value: object) -> int | None:
    """``value`` as an ``int`` when it is a JSON integer in the safe range, else ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if abs(value) <= _MAX_SAFE_INTEGER else None
    if isinstance(value, float) and value.is_integer() and abs(value) <= _MAX_SAFE_INTEGER:
        return int(value)
    return None


# ---- RFC 6962 §2.1 hashing -------------------------------------------------------------


def _leaf_hash(digest: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + digest).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """k, the largest power of two strictly less than ``n`` (``n >= 2``)."""
    return 1 << ((n - 1).bit_length() - 1)


def merkle_leaf_hash(digest_hex: str) -> str:
    """RFC 6962 leaf hash of a digest: ``SHA-256(0x00 || the digest's raw 32 bytes)``.

    :raises ValueError: when ``digest_hex`` is not a 64-digit hex string.
    """
    digest = _as_digest(digest_hex)
    if digest is None:
        raise ValueError("Merkle leaf must be a 64-character hex SHA-256 digest.")
    return _leaf_hash(bytes.fromhex(digest)).hex()


class MerkleTree:
    """An RFC 6962 tree over evidence digests, in the order given.

    Order is load-bearing and never sorted. The digests are validated and
    normalised to lowercase when the tree is made; subtree hashes are computed on
    first use and kept, so each node of the tree is hashed at most once however
    many proofs are read from it.

    :raises ValueError: when ``digests`` is empty, when an entry is not a 64-digit
        hex string, or when a digest repeats (compared after lowercasing). Evidence
        digests are unique by construction (Tree §5.4), so the last refuses
        nothing honest and leaves no doubt about what a root covers.
    """

    __slots__ = ("_digests", "_leaves", "_memo")

    def __init__(self, digests: Sequence[str]) -> None:
        if isinstance(digests, (str, bytes)) or not isinstance(digests, Sequence):
            raise ValueError("Cannot build Merkle tree: digests must be a list of hex digests.")
        if len(digests) == 0:
            raise ValueError("Cannot build Merkle tree: at least one digest is required.")
        normalised: list[str] = []
        seen: set[str] = set()
        for i, value in enumerate(digests):
            digest = _as_digest(value)
            if digest is None:
                raise ValueError(
                    f"Cannot build Merkle tree: entry {i} is not a 64-character hex digest."
                )
            if digest in seen:
                raise ValueError(
                    f"Cannot build Merkle tree: duplicate digest at index {i} makes the root "
                    "ambiguous (CVE-2012-2459)."
                )
            seen.add(digest)
            normalised.append(digest)
        self._digests: tuple[str, ...] = tuple(normalised)
        self._leaves: tuple[bytes, ...] = tuple(bytes.fromhex(d) for d in normalised)
        self._memo: dict[tuple[int, int], bytes] = {}

    @property
    def leaf_count(self) -> int:
        """The number of leaves, ``n``."""
        return len(self._leaves)

    @property
    def digests(self) -> tuple[str, ...]:
        """The leaf digests, lowercase, in order."""
        return self._digests

    @property
    def root(self) -> str:
        """``MTH(D[n])`` as lowercase hex."""
        return self._mth(0, self.leaf_count).hex()

    def __repr__(self) -> str:
        return f"MerkleTree(leaf_count={self.leaf_count}, root={self.root!r})"

    # RFC 6962 §2.1, over the leaf range [lo, hi). Every range these recursions
    # reach is a node of the tree of the range they started from.

    def _mth(self, lo: int, hi: int) -> bytes:
        """MTH(D[lo:hi]) for a non-empty range."""
        key = (lo, hi)
        cached = self._memo.get(key)
        if cached is not None:
            return cached
        if hi - lo == 1:
            value = _leaf_hash(self._leaves[lo])
        else:
            k = _split(hi - lo)
            value = _node_hash(self._mth(lo, lo + k), self._mth(lo + k, hi))
        self._memo[key] = value
        return value

    def _path(self, m: int, lo: int, hi: int) -> list[bytes]:
        """RFC 6962 §2.1.1 PATH(m, D[lo:hi]) for 0 <= m < hi - lo."""
        n = hi - lo
        if n == 1:
            return []
        k = _split(n)
        if m < k:
            return [*self._path(m, lo, lo + k), self._mth(lo + k, hi)]
        return [*self._path(m - k, lo + k, hi), self._mth(lo, lo + k)]

    def _subproof(self, m: int, lo: int, hi: int, m_root_known: bool) -> list[bytes]:
        """RFC 6962 §2.1.2 SUBPROOF(m, D[lo:hi], b) for 0 < m <= hi - lo.

        ``m_root_known`` is the RFC's ``b``: whether D[lo:lo+m] is a complete
        subtree of the original tree, so that its hash is the verifier's own first
        root and is left out.
        """
        n = hi - lo
        if m == n:
            return [] if m_root_known else [self._mth(lo, hi)]
        k = _split(n)
        if m <= k:
            return [*self._subproof(m, lo, lo + k, m_root_known), self._mth(lo + k, hi)]
        return [*self._subproof(m - k, lo + k, hi, False), self._mth(lo, lo + k)]


def build_merkle_tree(digests: Sequence[str]) -> MerkleTree:
    """A :class:`MerkleTree` over ``digests``, in order. Raises as :class:`MerkleTree` does."""
    return MerkleTree(digests)


def get_merkle_root(tree: MerkleTree) -> str:
    """``MTH(D[n])`` of a built tree, as lowercase hex.

    :raises TypeError: when ``tree`` is not a :class:`MerkleTree`.
    """
    if not isinstance(tree, MerkleTree):
        raise TypeError("Cannot read Merkle root: expected a MerkleTree.")
    return tree.root


def get_merkle_proof(tree: MerkleTree, leaf_index: int) -> list[str]:
    """RFC 6962 §2.1.1 audit path ``PATH(leaf_index, D[n])``, leaf-first, as bare lowercase hex.

    A single-leaf tree yields an empty path: a valid anchor and a worthless
    inclusion proof (Tree §5.4), never evidence of batching.

    :raises TypeError: when ``tree`` is not a :class:`MerkleTree`.
    :raises ValueError: when ``leaf_index`` is not an integer in ``[0, leaf_count)``.
    """
    if not isinstance(tree, MerkleTree):
        raise TypeError("Cannot build a Merkle proof: expected a MerkleTree.")
    index = _as_size(leaf_index)
    if index is None or not 0 <= index < tree.leaf_count:
        raise ValueError(
            f"Leaf index {leaf_index!r} is out of bounds (tree has {tree.leaf_count} leaves)."
        )
    return [h.hex() for h in tree._path(index, 0, tree.leaf_count)]


def get_consistency_proof(
    tree: MerkleTree, first: int, second: int | None = None
) -> ConsistencyProofResult:
    """RFC 6962 §2.1.2 consistency proof ``PROOF(first, D[second])``, as bare lowercase hex.

    ``second`` defaults to the tree's leaf count; a smaller ``second`` gives the
    proof between two earlier sizes of the same log. Equal sizes give the empty
    proof.

    Never raises. A ``tree`` that is not a :class:`MerkleTree` is
    ``malformed_tree``; sizes that are not JSON integers are ``malformed_size``;
    sizes outside ``0 < first <= second <= leaf_count`` are ``size_out_of_range``.
    """
    if not isinstance(tree, MerkleTree):
        return ConsistencyProofResult(ok=False, reason="malformed_tree")
    m = _as_size(first)
    n = tree.leaf_count if second is None else _as_size(second)
    if m is None or n is None:
        return ConsistencyProofResult(ok=False, reason="malformed_size")
    if not 0 < m <= n <= tree.leaf_count:
        return ConsistencyProofResult(ok=False, reason="size_out_of_range")
    proof = tuple(h.hex() for h in tree._subproof(m, 0, n, True))
    return ConsistencyProofResult(ok=True, proof=proof)


# ---- Verification: RFC 9162 §2.1.3.2 and §2.1.4.2 ----------------------------------------


def verify_merkle_proof(
    leaf: str,
    leaf_index: int,
    tree_size: int,
    proof: Sequence[str],
    expected_root: str,
) -> bool:
    """Verify an inclusion proof: that ``leaf`` (a digest, not a leaf hash) is leaf
    ``leaf_index`` of the tree of ``tree_size`` leaves whose root is ``expected_root``.

    RFC 9162 §2.1.3.2. Never raises: every argument may be client-supplied JSON,
    and anything malformed is ``False``.

    A ``True`` proves membership under ``expected_root`` only. It does not show
    that the root was ever published, since the root arrives in the artifact
    under examination, and it does not authenticate ``tree_size``.
    """
    digest = _as_digest(leaf)
    root = _as_digest(expected_root)
    if digest is None or root is None:
        return False
    if not isinstance(proof, (list, tuple)):
        return False
    index = _as_size(leaf_index)
    size = _as_size(tree_size)
    if index is None or size is None:
        return False
    # Step 1.
    if not 0 <= index < size:
        return False
    # Each step of the fold shifts sn right at least once, so a path longer than
    # the bit length of size - 1 always runs out of tree (step 4a). Step 4a
    # alone would refuse it too, after decoding every element; this check
    # refuses it on its length, before any element is read.
    if len(proof) > (size - 1).bit_length():
        return False
    siblings: list[bytes] = []
    for element in proof:
        sibling = _as_digest(element)
        if sibling is None:
            return False
        siblings.append(bytes.fromhex(sibling))

    # Steps 2 and 3.
    fn, sn = index, size - 1
    r = _leaf_hash(bytes.fromhex(digest))
    # Step 4.
    for p in siblings:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = _node_hash(p, r)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _node_hash(r, p)
        fn >>= 1
        sn >>= 1
    # Step 5.
    return sn == 0 and r == bytes.fromhex(root)


def verify_consistency_proof(
    first: int,
    second: int,
    proof: Sequence[str],
    first_root: str,
    second_root: str,
) -> ConsistencyVerification:
    """Verify that the log of ``second`` leaves with root ``second_root`` extends the
    log of ``first`` leaves with root ``first_root``.

    RFC 9162 §2.1.4.2, with the Tzun edge rules of Tree §3.5: ``0 < first <= second``;
    equal sizes hold only with an empty proof and equal roots; otherwise the proof is
    non-empty and reconstructs both roots with nothing left over and nothing missing.

    Never raises. Checks run in a fixed order and the first failure is the
    reason: sizes (``malformed_size``, ``size_out_of_range``), roots
    (``malformed_root``), the proof's type (``malformed_proof``), its length
    against the longest proof the sizes allow (``proof_length_mismatch``), its
    elements (``malformed_proof``), then the fold.
    """
    m = _as_size(first)
    n = _as_size(second)
    if m is None or n is None:
        return _refuse("malformed_size")
    if not 0 < m <= n:
        return _refuse("size_out_of_range")
    first_hex = _as_digest(first_root)
    second_hex = _as_digest(second_root)
    if first_hex is None or second_hex is None:
        return _refuse("malformed_root")
    if not isinstance(proof, (list, tuple)):
        return _refuse("malformed_proof")
    # PROOF(m, D[n]) holds at most one hash per level of the second tree plus the
    # subtree the walk starts from: ceil(log2 n) + 1. A longer list is refused on
    # its length, before any element is read.
    if len(proof) > (n - 1).bit_length() + 1:
        return _refuse("proof_length_mismatch")
    path: list[bytes] = []
    for element in proof:
        value = _as_digest(element)
        if value is None:
            return _refuse("malformed_proof")
        path.append(bytes.fromhex(value))
    first_hash = bytes.fromhex(first_hex)
    second_hash = bytes.fromhex(second_hex)

    if m == n:
        if path:
            return _refuse("proof_length_mismatch")
        return _VALID if first_hash == second_hash else _refuse("second_root_mismatch")

    # Step 1.
    if not path:
        return _refuse("proof_length_mismatch")
    # Step 2: when first is a power of two, the first tree is a complete subtree
    # of the second, and the proof leaves out the hash the verifier already has.
    if m & (m - 1) == 0:
        path.insert(0, first_hash)
    # Steps 3 and 4.
    fn, sn = m - 1, n - 1
    while fn % 2 == 1:
        fn >>= 1
        sn >>= 1
    # Step 5.
    fr = sr = path[0]
    # Step 6.
    for c in path[1:]:
        if sn == 0:
            return _refuse("proof_length_mismatch")
        if fn % 2 == 1 or fn == sn:
            fr = _node_hash(c, fr)
            sr = _node_hash(c, sr)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    # Step 7.
    if sn != 0:
        return _refuse("proof_length_mismatch")
    if fr != first_hash:
        return _refuse("first_root_mismatch")
    if sr != second_hash:
        return _refuse("second_root_mismatch")
    return _VALID


__all__ = (
    "MERKLE_SPEC",
    "ConsistencyProofReason",
    "ConsistencyProofResult",
    "ConsistencyVerification",
    "MerkleTree",
    "build_merkle_tree",
    "get_consistency_proof",
    "get_merkle_proof",
    "get_merkle_root",
    "merkle_leaf_hash",
    "verify_consistency_proof",
    "verify_merkle_proof",
)
