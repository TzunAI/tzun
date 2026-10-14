"""Public-API surface tests."""

from __future__ import annotations

import inspect


def test_top_level_exports() -> None:
    """Every required public name imports from tzun_sdk."""
    import tzun_sdk

    required = ["Tzun", "TzunSync", "hook", "attach", "errors", "models", "storage"]
    for name in required:
        assert hasattr(tzun_sdk, name), f"tzun_sdk.{name} missing"


def test_no_underscore_exports() -> None:
    """No leading-underscore names in __all__."""
    import tzun_sdk

    for name in tzun_sdk.__all__:
        assert not name.startswith("_") or name == "__version__"


def test_errors_module_has_typed_classes() -> None:
    from tzun_sdk import errors

    for cls in (
        "TzunError",
        "VerificationError",
        "TamperDetected",
        "DescriptorNotRegistered",
        "WireFormatMismatch",
        "MissingExtraError",
        "CodegenDriftError",
        "TsaUnavailableError",
        "WebAuthnVerificationError",
        "SigstoreIdentityMismatchError",
        "AdminTokenRequiredError",
        "DuplicateEvidenceError",
    ):
        assert hasattr(errors, cls), f"errors.{cls} missing"


def test_storage_adapters_importable() -> None:
    from tzun_sdk import storage

    for adapter in (
        "MemoryAdapter",
        "SqliteAdapter",
        "PostgresAdapter",
        "HttpBackendAdapter",
        "StorageAdapter",
    ):
        assert hasattr(storage, adapter), f"storage.{adapter} missing"


def test_models_module_has_core_shapes() -> None:
    from tzun_sdk import models

    for cls in (
        "EvidenceEnvelope",
        "EvidencePayload",
        "AiBom",
        "ModelDescriptor",
        "DecisionInput",
        "CaptureResult",
        "VerificationResult",
    ):
        assert hasattr(models, cls), f"models.{cls} missing"


def test_tzun_init_is_async_classmethod() -> None:
    """Tzun.init is async."""
    from tzun_sdk import Tzun

    assert inspect.iscoroutinefunction(Tzun.init)


def test_tzun_supports_async_context_manager() -> None:
    """__aenter__ / __aexit__."""
    from tzun_sdk import Tzun

    assert hasattr(Tzun, "__aenter__")
    assert hasattr(Tzun, "__aexit__")
