"""``tzun`` CLI entry point.

Typer app with subcommands matching the TS CLI:

* ``tzun capture --ai-output FILE --action TEXT --reason TEXT --decider ID``
* ``tzun verify <evidence-id>``
* ``tzun verify-range --from N --to N``
* ``tzun export <evidence-id>``
* ``tzun models register``, ``list``, ``show``, ``compute-digest``,
  ``annotate``, ``alias``.

Default output: human-readable text. ``--json`` switches to
machine-readable JSON.

Config precedence: CLI flags > env vars. No configuration FILE is read —
neither ``tzun.toml`` nor ``~/.config/tzun/config.toml``, so settings written
to either file have no effect.

Secrets: prefer ``TZUN_ADMIN_TOKEN`` in the environment. ``--admin-token`` is
accepted for compatibility but a value passed on the command line is visible
in ``ps`` output and in shell history to every other user on the host, so the
CLI warns when it is used.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import anyio
import typer

from tzun_sdk import __version__
from tzun_sdk.ai_bom.compute_model_digest import compute_model_digest
from tzun_sdk.core import Tzun
from tzun_sdk.errors import AdminTokenRequiredError, TzunError
from tzun_sdk.models import ModelDescriptor
from tzun_sdk.storage._protocol import StorageAdapter
from tzun_sdk.storage.memory import MemoryAdapter
from tzun_sdk.storage.sqlite import SqliteAdapter

app = typer.Typer(
    name="tzun",
    help="Tzun Python SDK CLI — the receipt for every AI decision.",
    add_completion=False,
    no_args_is_help=True,
)

models_app = typer.Typer(help="Model catalog commands.")
app.add_typer(models_app, name="models")


def _build_tzun(storage_uri: str | None, admin_token: str | None = None) -> Tzun:
    """Map a storage URI to a Tzun instance.

    memory:// (default) → MemoryAdapter
    sqlite:<path>       → SqliteAdapter
    """
    uri = storage_uri or os.environ.get("TZUN_STORAGE_URI", "memory://")
    storage: StorageAdapter
    if uri == "memory://" or uri == "memory":
        storage = MemoryAdapter()
    elif uri.startswith("sqlite:"):
        path = uri[len("sqlite:") :]
        storage = SqliteAdapter(path)
    else:
        raise typer.BadParameter(f"Unsupported storage URI: {uri!r}")

    async def _init() -> Tzun:
        return await Tzun.init(storage=storage, admin_token=admin_token)

    return anyio.run(_init)


def _admin_token_on_argv(argv: list[str] | None = None) -> bool:
    """True when --admin-token was passed on the command line.

    typer resolves the option from TZUN_ADMIN_TOKEN as well, and only the argv
    form leaks the secret to `ps` and to shell history, so the two have to be
    told apart before warning.
    """
    args = sys.argv[1:] if argv is None else argv
    return any(a == "--admin-token" or a.startswith("--admin-token=") for a in args)


def _admin_token_from_command_line(admin_token: str, argv: list[str] | None = None) -> bool:
    """Did --admin-token come from argv rather than from the environment?

    typer fills the option from TZUN_ADMIN_TOKEN too, and only the argv form
    leaks the secret to `ps` and to shell history. Two independent signals,
    because neither alone is reliable: the literal flag appearing in argv, and
    the resolved value differing from what TZUN_ADMIN_TOKEN holds (which it
    cannot if the env var is where the value came from).
    """
    if _admin_token_on_argv(argv):
        return True
    return os.environ.get("TZUN_ADMIN_TOKEN") != admin_token


@app.callback(invoke_without_command=False)
def _common(
    ctx: typer.Context,
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    storage: str | None = typer.Option(
        None, "--storage", help="Storage URI (memory:// or sqlite:<path>)."
    ),
    admin_token: str | None = typer.Option(
        None,
        "--admin-token",
        envvar="TZUN_ADMIN_TOKEN",
        help="Admin token. Prefer the TZUN_ADMIN_TOKEN environment variable: a "
        "value passed here is visible in `ps` to every user on the host.",
    ),
) -> None:
    """Top-level options."""
    ctx.ensure_object(dict)
    ctx.obj["json"] = json_out
    ctx.obj["storage"] = storage
    ctx.obj["admin_token"] = admin_token
    # typer fills admin_token from TZUN_ADMIN_TOKEN too, so "was it on argv?"
    # has to be asked of argv itself.
    if admin_token is not None and _admin_token_from_command_line(admin_token):
        typer.echo(
            "warning: --admin-token puts the admin secret in `ps` output and in "
            "shell history. Export TZUN_ADMIN_TOKEN instead.",
            err=True,
        )


@app.command()
def version() -> None:
    """Print the installed SDK version."""
    typer.echo(__version__)


@app.command()
def capture(
    ctx: typer.Context,
    ai_output: str = typer.Option(..., "--ai-output", help="Path to JSON file."),
    action: str = typer.Option(..., "--action", help="The decision taken."),
    reason: str = typer.Option(..., "--reason", help="The stated reason."),
    decider: str = typer.Option(
        ...,
        "--decider",
        help='Who decided: an opaque identifier (acct:<account id>), or a JSON decider such as '
        '\'{"kind": "agent", "agent": "sha256:..."}\'.',
    ),
    ai_bom_file: str | None = typer.Option(
        None, "--ai-bom-file", help="Path to the JSON bill of materials of the one model the decision used."
    ),
) -> None:
    """Capture a decision."""
    with open(ai_output, encoding="utf-8") as fh:
        payload = json.loads(fh.read())
    contributions = None
    if ai_bom_file is not None:
        from tzun_sdk.contributions import single_model

        with open(ai_bom_file, encoding="utf-8") as fh:
            contributions = single_model(json.loads(fh.read()))
    decider_input: Any = (
        json.loads(decider) if decider.lstrip().startswith("{") else {"kind": "human", "id": decider}
    )
    tzun = _build_tzun(ctx.obj.get("storage"))

    async def _capture() -> Any:
        return await tzun.capture(
            ai_output=payload,
            action=action,
            reason=reason,
            decider=decider_input,
            contributions=contributions,
        )

    try:
        result = anyio.run(_capture)
    finally:
        anyio.run(tzun.close)
    out = result.model_dump(mode="json")
    if ctx.obj.get("json"):
        typer.echo(json.dumps(out))
    else:
        typer.echo(f"Captured {result.evidenceId}")
        typer.echo(f"  digest: {result.canonicalDigest}")
        typer.echo(f"  seq:    {result.sequenceNumber}")


@app.command()
def verify(
    ctx: typer.Context,
    evidence_id: str = typer.Argument(...),
) -> None:
    """Verify a stored envelope by id."""
    tzun = _build_tzun(ctx.obj.get("storage"))
    try:
        result = anyio.run(tzun.verify, evidence_id)
    finally:
        anyio.run(tzun.close)
    out = result.model_dump(mode="json")
    if ctx.obj.get("json"):
        typer.echo(json.dumps(out))
    else:
        status = "valid" if result.valid else "INVALID"
        typer.echo(f"Verify {evidence_id}: {status}")


@app.command(name="verify-range")
def verify_range(
    ctx: typer.Context,
    from_n: int = typer.Option(..., "--from"),
    to_n: int = typer.Option(..., "--to"),
) -> None:
    """Verify every envelope in [from, to]."""
    tzun = _build_tzun(ctx.obj.get("storage"))
    try:
        results = anyio.run(tzun.verify_range, from_n, to_n)
    finally:
        anyio.run(tzun.close)
    out = [r.model_dump(mode="json") for r in results]
    if ctx.obj.get("json"):
        typer.echo(json.dumps(out))
    else:
        for r in results:
            status = "valid" if r.valid else "INVALID"
            typer.echo(f"{r.evidenceId}: {status}")


@app.command(name="export")
def export_cmd(
    ctx: typer.Context,
    evidence_id: str = typer.Argument(...),
    walk_lineage: bool = typer.Option(
        True,
        "--walk-lineage/--no-walk-lineage",
        help="Bundle ancestor descriptors (default on).",
    ),
) -> None:
    """Export a court-ready evidence bundle as JSON."""
    tzun = _build_tzun(ctx.obj.get("storage"))
    try:
        bundle = anyio.run(
            lambda: tzun.export_evidence(evidence_id, walk_lineage=walk_lineage)
        )
    except TzunError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        anyio.run(tzun.close)
    if not ctx.obj.get("json"):
        typer.echo(
            f"Exported {evidence_id} ({len(bundle.resolvedModelDescriptors)} descriptors)",
            err=True,
        )
    typer.echo(json.dumps(bundle.model_dump(mode="json")))


@models_app.command(name="compute-digest")
def models_compute_digest(
    ctx: typer.Context,
    weights_path: str = typer.Argument(...),
) -> None:
    """Compute the tzun-model-manifest-v1 digest of a directory."""
    result = compute_model_digest(weights_path)
    out = {"model_digest": result.model_digest, "file_count": len(result.manifest)}
    if ctx.obj.get("json"):
        typer.echo(json.dumps(out))
    else:
        typer.echo(f"Model digest: {result.model_digest}")
        typer.echo(f"Files:        {len(result.manifest)}")


def _quick_descriptor(vendor: str, name: str, version: str) -> ModelDescriptor:
    """Build a minimal vendor-asserted MVD for --quick registration."""
    from tzun_sdk._generated.models import TrainingInfo
    return ModelDescriptor(
        descriptorVersion="d1",
        vendor=vendor,
        modelName=name,
        modelVersion=version,
        modelType=None,
        integrityTier="vendor-asserted",
        modelDigest=None,
        parentModelDescriptorDigest=None,
        derivation=None,
        trainedBy=None,
        license=None,
        modelCardUrl=None,
        training=TrainingInfo(
            trainingDataDigest=None,
            trainingDataRef=None,
            lastTrainingDate=None,
            evaluations=[],
        ),
        regulatoryMarkings=[],
        externalIdentifiers=[],
    )


@models_app.command(name="register")
def models_register(
    ctx: typer.Context,
    from_file: str | None = typer.Option(None, "--from-file"),
    quick: bool = typer.Option(False, "--quick"),
    weights: str | None = typer.Option(None, "--weights"),
    vendor: str | None = typer.Option(None, "--vendor"),
    name: str | None = typer.Option(None, "--name"),
    version: str | None = typer.Option(None, "--version"),
) -> None:
    """Register a ModelDescriptor (mirrors TS registerCmd).

    No interactive mode in the Python CLI — use --quick, --from-file,
    or --from-file with --weights.
    """
    if quick and from_file:
        typer.echo("error: --quick and --from-file are mutually exclusive", err=True)
        raise typer.Exit(code=2)
    if weights and not (quick or from_file):
        typer.echo(
            "error: --weights requires --quick or --from-file "
            "(weight-only registration is not a complete descriptor)",
            err=True,
        )
        raise typer.Exit(code=2)
    if from_file:
        with open(from_file, encoding="utf-8") as fh:
            descriptor = ModelDescriptor.model_validate_json(fh.read())
    elif quick:
        if not (vendor and name and version):
            typer.echo("error: --quick requires --vendor, --name and --version", err=True)
            raise typer.Exit(code=2)
        descriptor = _quick_descriptor(vendor, name, version)
    else:
        typer.echo(
            "error: provide --quick or --from-file (no interactive mode)",
            err=True,
        )
        raise typer.Exit(code=2)
    if weights:
        result = compute_model_digest(weights)
        descriptor = descriptor.model_copy(
            update={"modelDigest": result.model_digest, "integrityTier": "weight-attested"}
        )
    tzun = _build_tzun(ctx.obj.get("storage"), ctx.obj.get("admin_token"))
    try:
        digest = anyio.run(tzun.models.register, descriptor)
    finally:
        anyio.run(tzun.close)
    out = {"digest": digest}
    if ctx.obj.get("json"):
        typer.echo(json.dumps(out))
    else:
        typer.echo(f"Registered: {digest}")


@models_app.command(name="list")
def models_list(
    ctx: typer.Context,
    vendor: str | None = typer.Option(None, "--vendor", help="Filter by vendor."),
    limit: int | None = typer.Option(None, "--limit", help="Maximum rows returned."),
    offset: int | None = typer.Option(None, "--offset", help="Row offset for paging."),
) -> None:
    """List catalog descriptors (mirrors TS listCmd flags)."""
    tzun = _build_tzun(ctx.obj.get("storage"), ctx.obj.get("admin_token"))
    try:
        rows = anyio.run(
            lambda: tzun.models.list(vendor=vendor, limit=limit, offset=offset)
        )
    finally:
        anyio.run(tzun.close)
    if ctx.obj.get("json"):
        typer.echo(json.dumps([r.model_dump(mode="json") for r in rows]))
        return
    for r in rows:
        typer.echo(
            f"{r.modelDescriptorDigest[:24]}…  {r.vendor}  {r.modelName}  {r.modelVersion}"
        )


@models_app.command(name="annotate")
def models_annotate(
    ctx: typer.Context,
    digest: str = typer.Argument(...),
    annotation_type: str = typer.Option(..., "--type", help="Annotation type."),
    value: str = typer.Option(..., "--value", help="JSON object."),
    note: str | None = typer.Option(None, "--note"),
    reviewer: str = typer.Option("cli", "--reviewer", help="Attribution."),
    admin: bool = typer.Option(False, "--admin", help="Required for typed annotation types."),
) -> None:
    """Append an annotation. freeform-note needs no --admin."""
    parsed = json.loads(value)
    tzun = _build_tzun(ctx.obj.get("storage"), ctx.obj.get("admin_token"))
    try:
        row = anyio.run(
            lambda: tzun.models.annotate(
                digest, annotation_type, parsed,
                annotated_by=reviewer, note=note,
                admin_token=ctx.obj.get("admin_token") if admin else None,
            )
        )
    except AdminTokenRequiredError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        anyio.run(tzun.close)
    out = row.model_dump(mode="json")
    if ctx.obj.get("json"):
        typer.echo(json.dumps(out))
    else:
        typer.echo(f"Annotated {digest[:24]}…: {row.annotationType}")


alias_app = typer.Typer(help="Descriptor alias commands.")
models_app.add_typer(alias_app, name="alias")


@alias_app.command(name="set")
def alias_set(
    ctx: typer.Context,
    slug: str = typer.Argument(...),
    digest: str = typer.Argument(...),
    set_by: str = typer.Option("cli", "--set-by"),
) -> None:
    """Bind slug → digest (append-only; latest set wins on resolve)."""
    tzun = _build_tzun(ctx.obj.get("storage"), ctx.obj.get("admin_token"))
    try:
        anyio.run(
            lambda: tzun.models.set_alias(
                slug, digest, set_by=set_by,
                admin_token=ctx.obj.get("admin_token"),
            )
        )
    finally:
        anyio.run(tzun.close)
    if ctx.obj.get("json"):
        typer.echo(json.dumps({"slug": slug, "digest": digest}))
    else:
        typer.echo(f"alias {slug} → {digest[:24]}…")


@alias_app.command(name="resolve")
def alias_resolve(ctx: typer.Context, slug: str = typer.Argument(...)) -> None:
    """Resolve slug → digest; exit 1 when no binding exists."""
    tzun = _build_tzun(ctx.obj.get("storage"), ctx.obj.get("admin_token"))
    try:
        digest = anyio.run(tzun.models.resolve_alias, slug)
    finally:
        anyio.run(tzun.close)
    if digest is None:
        typer.echo(f"No alias binding for {slug!r}", err=True)
        raise typer.Exit(code=1)
    if ctx.obj.get("json"):
        typer.echo(json.dumps({"digest": digest}))
    else:
        typer.echo(digest)


@models_app.command(name="show")
def models_show(
    ctx: typer.Context,
    digest: str = typer.Argument(...),
) -> None:
    """Show a ModelDescriptor by digest."""
    tzun = _build_tzun(ctx.obj.get("storage"))
    try:
        descriptor = anyio.run(tzun.models.get, digest)
    finally:
        anyio.run(tzun.close)
    if descriptor is None:
        typer.echo(f"No descriptor for {digest!r}", err=True)
        raise typer.Exit(code=1)
    out = descriptor.model_dump(mode="json")
    if ctx.obj.get("json"):
        typer.echo(json.dumps(out))
    else:
        for k, v in out.items():
            typer.echo(f"  {k}: {v}")


def main() -> Any:
    """Console-script entry point."""
    try:
        app()
    except (TzunError, AdminTokenRequiredError) as exc:
        typer.echo(f"error: {exc}", err=True)
        sys.exit(2)


if __name__ == "__main__":
    main()


__all__ = ("app", "main")
