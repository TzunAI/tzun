# @tzun/ts-example

Minimal end-to-end example demonstrating the `@tzun/sdk` TypeScript SDK.

## What it does

1. Constructs a `Tzun` client in `mode: 'dev'` (in-memory, no network).
2. Captures one evidence envelope from a tiny example payload.
3. Verifies the envelope.
4. Prints the envelope id, digest and attestation status, and the verification result.

## Run

```bash
pnpm install
pnpm dev              # tsx (no build step)
# or
pnpm build && pnpm start
```

## Expected output

```
Captured envelope:
  id:     <uuid>
  digest: <hex>
  status: none
Verification:
  verified: true
```

## What this example does NOT show

- Production-mode attestation (RFC 3161 timestamp, WebAuthn signature).
- Storage backends (Postgres / SQLite).

For those, see the main [README](../../README.md) (Modes, Signing a decision, Timestamp authorities) and [`docs/integration/`](../../docs/integration/).

## Related

- The Python equivalent of this example lives at [`../py-example/`](../py-example/) — runnable (`python -m tzun_example`).
- Cross-SDK wire-format parity tests live at [`tests/cross-sdk/`](../../tests/cross-sdk/) and run in CI's `cross-sdk` job.
