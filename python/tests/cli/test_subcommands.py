"""CLI subcommand behavior tests.

These exercise the real capture -> verify lifecycle through the Typer
``CliRunner`` against a SQLite-backed instance (state must persist across
the two separate CLI invocations). The round trip also covers how ``capture``
forwards its arguments: ``Tzun.capture`` is a keyword-only coroutine, so the
command must call ``Tzun.capture(ai_output=..., action=..., reason=...,
decider=...)``; forwarding them positionally would fail every CLI capture.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from typer.testing import CliRunner

from tzun_sdk.cli.main import app


def _db_uri(tmp_path: pathlib.Path) -> str:
    return f"sqlite:{tmp_path / 'cli.db'}"


# ── Shared fixtures for catalog/alias/annotate tests ─────────────────────────

@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def sqlite_uri(tmp_path: pathlib.Path):
    """Persistent sqlite URI for a test's tmp directory."""
    return _db_uri(tmp_path)


@pytest.fixture
def registered_digest(runner, sqlite_uri, tmp_path: pathlib.Path):
    """Register a descriptor via the CLI and return its digest."""
    from tests.storage.test_catalog_primitives import mvd
    descriptor_file = tmp_path / "descriptor.json"
    descriptor_file.write_text(mvd().model_dump_json(), encoding="utf-8")
    r = runner.invoke(
        app, ["--json", "--storage", sqlite_uri, "models", "register",
              "--from-file", str(descriptor_file)]
    )
    assert r.exit_code == 0, r.output
    return json.loads(r.output)["digest"]


def test_capture_then_verify_roundtrip_json(tmp_path: pathlib.Path) -> None:
    """Capture writes an envelope; verify confirms it valid."""
    runner = CliRunner()
    ai_output = tmp_path / "ai.json"
    ai_output.write_text(json.dumps({"text": "approve"}), encoding="utf-8")
    db = _db_uri(tmp_path)

    cap = runner.invoke(
        app,
        [
            "--json",
            "--storage",
            db,
            "capture",
            "--ai-output",
            str(ai_output),
            "--action",
            "approved",
            "--reason",
            "looks good",
            "--decider",
            "acct:cli-user",
        ],
    )
    assert cap.exit_code == 0, cap.output
    captured = json.loads(cap.output)
    evidence_id = captured["evidenceId"]
    assert len(captured["canonicalDigest"]) == 64 and ":" not in captured["canonicalDigest"]
    assert captured["sequenceNumber"] == 1

    ver = runner.invoke(app, ["--json", "--storage", db, "verify", evidence_id])
    assert ver.exit_code == 0, ver.output
    verified = json.loads(ver.output)
    assert verified["valid"] is True
    assert verified["evidenceId"] == evidence_id
    assert verified["canonicalDigest"] == captured["canonicalDigest"]


def test_capture_human_text_output(tmp_path: pathlib.Path) -> None:
    """Without --json, capture prints rich human-readable text."""
    runner = CliRunner()
    ai_output = tmp_path / "ai.json"
    ai_output.write_text(json.dumps({"text": "approve"}), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--storage",
            _db_uri(tmp_path),
            "capture",
            "--ai-output",
            str(ai_output),
            "--action",
            "approved",
            "--reason",
            "ok",
            "--decider",
            "acct:cli-user",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Captured" in result.output
    assert "digest:" in result.output


def test_verify_unknown_evidence_id(tmp_path: pathlib.Path) -> None:
    """Verifying a non-existent id surfaces a clean error, not a traceback."""
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["--storage", _db_uri(tmp_path), "verify", "does-not-exist"],
    )
    # main() converts TzunError into a clean exit code 2 (no traceback).
    assert result.exit_code != 0


def test_export_roundtrip_json(tmp_path: pathlib.Path) -> None:
    """Export returns a JSON bundle with the captured evidence."""
    runner = CliRunner()
    ai_output = tmp_path / "ai.json"
    ai_output.write_text(json.dumps({"text": "approve"}), encoding="utf-8")
    db = _db_uri(tmp_path)

    # Capture first
    cap = runner.invoke(
        app,
        ["--json", "--storage", db, "capture",
         "--ai-output", str(ai_output),
         "--action", "approved",
         "--reason", "looks good", "--decider", "acct:cli-user"],
    )
    assert cap.exit_code == 0, cap.output
    evidence_id = json.loads(cap.output)["evidenceId"]

    # Export
    exp = runner.invoke(app, ["--json", "--storage", db, "export", evidence_id])
    assert exp.exit_code == 0, exp.output
    bundle = json.loads(exp.output)
    assert bundle["envelope"]["payload"]["evidenceId"] == evidence_id
    assert isinstance(bundle["resolvedModelDescriptors"], dict)


def test_export_missing_id_exits_1(tmp_path: pathlib.Path) -> None:
    """Export of a nonexistent id exits with code 1."""
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["--storage", _db_uri(tmp_path), "export", "does-not-exist"],
    )
    assert result.exit_code == 1
    assert "not found" in result.stderr or "not found" in result.output


# ── models list / annotate / alias ─────────────────────────────────────────────


def test_models_list_json(runner, sqlite_uri, registered_digest):
    """models list returns a JSON array with at least one row."""
    r = runner.invoke(app, ["--storage", sqlite_uri, "--json", "models", "list"])
    assert r.exit_code == 0, r.output
    rows = json.loads(r.output)
    assert isinstance(rows, list) and rows and "modelDescriptorDigest" in rows[0]


def test_models_list_vendor_filter_and_paging(runner, sqlite_uri, registered_digest):
    """--vendor and --limit flags are forwarded to the catalog primitive."""
    r = runner.invoke(
        app, ["--storage", sqlite_uri, "--json", "models", "list",
              "--vendor", "openai", "--limit", "1", "--offset", "0"]
    )
    assert r.exit_code == 0
    assert len(json.loads(r.output)) <= 1


def test_annotate_freeform_needs_no_admin(runner, sqlite_uri, registered_digest):
    """Freeform-note annotation requires no admin token."""
    r = runner.invoke(
        app, ["--storage", sqlite_uri, "--json", "models", "annotate",
              registered_digest, "--type", "freeform-note",
              "--value", '{"text":"n"}', "--reviewer", "dana"]
    )
    assert r.exit_code == 0, r.output
    assert json.loads(r.output)["annotatedBy"] == "dana"


def test_annotate_typed_requires_admin_token(runner, sqlite_uri, registered_digest):
    """Typed annotation without matching admin token exits 2."""
    # Tzun instance built with admin_token="s3cret" but no matching token supplied
    # on the annotate call → AdminTokenRequiredError → exit 2.
    r = runner.invoke(
        app, ["--storage", sqlite_uri, "--admin-token", "s3cret",
              "models", "annotate",
              registered_digest, "--type", "deprecation",
              "--value", '{"reason":"old"}', "--admin"],
        env={"TZUN_ADMIN_TOKEN": "wrongtoken"},
    )
    # admin_token from CLI flag wins over env var; but we pass --admin-token s3cret
    # AND env TZUN_ADMIN_TOKEN=wrongtoken — CLI flag wins → Tzun init has s3cret,
    # annotate call also sends s3cret → actually succeeds. Pin the flag-wins behavior:
    assert r.exit_code == 0, r.output
    # Real guard: Tzun instance has admin_token="s3cret" but annotate sends None.
    no_token = runner.invoke(
        app, ["--storage", sqlite_uri, "--admin-token", "s3cret",
              "models", "annotate",
              registered_digest, "--type", "deprecation",
              "--value", '{"reason":"old"}'],  # no --admin flag → admin_token=None passed
    )
    assert no_token.exit_code == 2, no_token.output

    # With correct admin token via --admin flag → success
    ok = runner.invoke(
        app, ["--storage", sqlite_uri, "--admin-token", "s3cret",
              "--json", "models", "annotate",
              registered_digest, "--type", "deprecation",
              "--value", '{"reason":"old"}', "--admin"],
    )
    assert ok.exit_code == 0, ok.output


# ── models register --quick / --weights ────────────────────────────────────────


def test_register_quick(runner):
    """--quick builds a vendor-asserted MVD from flags."""
    r = runner.invoke(
        app, ["--json", "models", "register", "--quick",
              "--vendor", "openai", "--name", "gpt-4o", "--version", "2024-08-06"]
    )
    assert r.exit_code == 0, r.output
    assert json.loads(r.output)["digest"].startswith("sha256:")


def test_register_weights_with_quick(runner, tmp_path):
    """--weights with --quick computes modelDigest and sets weight-attested tier."""
    (tmp_path / "w.bin").write_bytes(b"weights")
    r = runner.invoke(
        app, ["--json", "models", "register", "--quick",
              "--vendor", "acme", "--name", "m", "--version", "1",
              "--weights", str(tmp_path)]
    )
    assert r.exit_code == 0, r.output
    assert json.loads(r.output)["digest"].startswith("sha256:")


def test_register_weights_alone_rejected(runner, tmp_path):
    """--weights without --quick or --from-file exits 2."""
    r = runner.invoke(app, ["models", "register", "--weights", str(tmp_path)])
    assert r.exit_code == 2


def test_register_mutual_exclusion(runner, tmp_path):
    """--quick and --from-file are mutually exclusive."""
    f = tmp_path / "d.json"
    f.write_text("{}")
    r = runner.invoke(
        app, ["models", "register", "--quick", "--from-file", str(f),
              "--vendor", "v", "--name", "n", "--version", "1"]
    )
    assert r.exit_code == 2


def test_verify_range_json(runner, sqlite_uri, tmp_path):
    """verify-range returns a JSON array."""
    ai_output = tmp_path / "ai.json"
    ai_output.write_text(json.dumps({"text": "ok"}), encoding="utf-8")
    runner.invoke(
        app, ["--storage", sqlite_uri, "capture",
              "--ai-output", str(ai_output),
              "--action", "approved", "--reason", "ok", "--decider", "acct:cli-user"],
    )
    r = runner.invoke(
        app, ["--json", "--storage", sqlite_uri, "verify-range", "--from", "1", "--to", "1"]
    )
    assert r.exit_code == 0, r.output
    results = json.loads(r.output)
    assert isinstance(results, list) and len(results) == 1
    assert results[0]["valid"] is True


def test_models_show_and_compute_digest(runner, sqlite_uri, registered_digest, tmp_path):
    """models show and compute-digest return parseable output."""
    show = runner.invoke(
        app, ["--json", "--storage", sqlite_uri, "models", "show", registered_digest]
    )
    assert show.exit_code == 0, show.output
    data = json.loads(show.output)
    assert data["vendor"] == "openai"

    # compute-digest on a tmp dir
    (tmp_path / "w.bin").write_bytes(b"example-weights")
    cd = runner.invoke(app, ["--json", "models", "compute-digest", str(tmp_path)])
    assert cd.exit_code == 0, cd.output
    obj = json.loads(cd.output)
    assert obj["model_digest"].startswith("sha256:")


def test_alias_set_resolve_and_miss(runner, sqlite_uri, registered_digest):
    """Alias set + resolve round trip."""
    s = runner.invoke(
        app, ["--storage", sqlite_uri, "--admin-token", "s3cret",
              "models", "alias", "set", "prod", registered_digest, "--set-by", "ops"]
    )
    assert s.exit_code == 0, s.output

    r = runner.invoke(app, ["--storage", sqlite_uri, "models", "alias", "resolve", "prod"])
    assert r.exit_code == 0
    assert registered_digest in r.output

    miss = runner.invoke(app, ["--storage", sqlite_uri, "models", "alias", "resolve", "nope"])
    assert miss.exit_code == 1
