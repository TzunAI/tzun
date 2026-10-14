"""CLI entry point tests."""

from __future__ import annotations

from typer.testing import CliRunner

from tzun_sdk.cli.main import app


def test_help_lists_subcommands() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for sub in ("capture", "verify", "verify-range", "models", "version"):
        assert sub in result.output


def test_version_subcommand() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    import tzun_sdk

    assert tzun_sdk.__version__ in result.output


def test_models_help() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["models", "--help"])
    assert result.exit_code == 0
    for sub in ("register", "show", "compute-digest"):
        assert sub in result.output


# ── console script, error handling, and admin-token hygiene ───────────────


def _pyproject() -> dict:
    import pathlib
    import tomllib

    p = pathlib.Path(__file__).parent.parent.parent / "pyproject.toml"
    return tomllib.loads(p.read_text(encoding="utf-8"))


def test_console_script_points_at_main_not_app() -> None:
    """The `tzun` script must go through main(), or its error handler is dead.

    pyproject registered `tzun = "tzun_sdk.cli.main:app"`, so the
    `except (TzunError, AdminTokenRequiredError)` wrapper inside main() was
    never on the call path and a TzunError reached the operator as a raw
    Python traceback.
    """
    assert _pyproject()["project"]["scripts"]["tzun"] == "tzun_sdk.cli.main:main"


def test_main_turns_a_tzun_error_into_a_message_and_exit_2(monkeypatch, capsys) -> None:
    import pytest

    from tzun_sdk.cli import main as cli_main
    from tzun_sdk.errors import TzunError

    def _boom() -> None:
        raise TzunError("storage unavailable")

    monkeypatch.setattr(cli_main, "app", _boom)
    with pytest.raises(SystemExit) as exc:
        cli_main.main()
    assert exc.value.code == 2
    assert "error: storage unavailable" in capsys.readouterr().err


def test_admin_token_on_argv_is_detected() -> None:
    from tzun_sdk.cli.main import _admin_token_on_argv

    assert _admin_token_on_argv(["--admin-token", "s3cret", "models", "list"]) is True
    assert _admin_token_on_argv(["--admin-token=s3cret", "models", "list"]) is True
    # Env-var path: nothing on argv, so no warning is due.
    assert _admin_token_on_argv(["models", "list"]) is False


def test_admin_token_flag_warns_about_ps_exposure() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--admin-token", "s3cret", "version"])
    assert "TZUN_ADMIN_TOKEN" in result.output
    assert "ps" in result.output


def test_docstring_does_not_promise_unread_config_files() -> None:
    """The module promised a tzun.toml / ~/.config/tzun/config.toml tier.

    No code has ever opened either file, so an operator who wrote one had it
    silently ignored.
    """
    import tzun_sdk.cli.main as cli_main

    doc = cli_main.__doc__ or ""
    assert "No configuration FILE is read" in doc
    assert "grep" not in doc
    src = __import__("inspect").getsource(cli_main)
    # The only mentions of the config filenames are in the disclaimer.
    assert src.count("config.toml") == 1


def test_admin_token_from_env_does_not_warn(monkeypatch) -> None:
    """The env-var path is the recommended one: no nag for using it."""
    monkeypatch.setenv("TZUN_ADMIN_TOKEN", "s3cret")
    runner = CliRunner()
    result = runner.invoke(app, ["version"])
    assert "TZUN_ADMIN_TOKEN" not in result.output
