"""SigstoreBackend must fail closed rather than fake a verification.

The backend parses no bundle, checks no signature and proves no
transparency-log inclusion, so ``verify()`` and ``sign()`` raise
``NotImplementedError`` for every input. A ``verify()`` that applied only the
identity filter and returned ``True`` would report an attacker-authored dict as
verified, and a ``sign()`` that returned a dict describing its own inputs could
be taken for a Sigstore bundle. These tests pin that contract, including the
two inputs an identity-filter-only check would pass.
"""

from __future__ import annotations

import pytest

from tzun_sdk.attestation import SigstoreBackend


def test_verify_rejects_a_blob_that_matches_the_identity_policy() -> None:
    """``verify({'identity': 'x'}, b'')`` raises.

    An attacker-authored dict whose ``identity`` key matches the allow-list
    must not be reported as verified: nothing but that key would be checked.
    """
    backend = SigstoreBackend(allowed_identities=["x"])
    with pytest.raises(NotImplementedError):
        backend.verify({"identity": "x"}, b"")


def test_verify_rejects_an_empty_blob_over_arbitrary_bytes() -> None:
    """``verify({}, b'anything')`` raises: an empty blob verifies nothing."""
    backend = SigstoreBackend()
    with pytest.raises(NotImplementedError):
        backend.verify({}, b"anything")


def test_verify_rejects_even_with_tlog_verification_disabled() -> None:
    """``verify_tlog=False`` does not turn ``verify()`` into a pass: it raises."""
    backend = SigstoreBackend()
    with pytest.raises(NotImplementedError):
        backend.verify({"subject": "s"}, b"bytes", verify_tlog=False)


def test_sign_does_not_return_a_signature_object_without_signing() -> None:
    """``sign()`` raises rather than return an object that holds no signature.

    A dict describing the inputs could not be told apart from a real Sigstore
    bundle by its type, so a caller would hold a signature where nothing was
    signed.
    """
    backend = SigstoreBackend()
    with pytest.raises(NotImplementedError):
        backend.sign(b"canonical", "oidc-token")


async def test_attest_is_a_no_op() -> None:
    """Capture stores no Sigstore artifact: ``attest()`` returns ``None``."""
    backend = SigstoreBackend()
    assert await backend.attest(None) is None  # type: ignore[arg-type]


def test_constructing_the_backend_works() -> None:
    """The class is exported and constructible; only the crypto fails closed."""
    assert SigstoreBackend(allowed_identities=["a@b.c"]) is not None
