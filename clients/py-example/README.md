# tzun-sdk Python example

Minimal end-to-end example app demonstrating `tzun-sdk` in Python.

Mirrors [`../ts-example/`](../ts-example/) at the API surface.

## What it does

1. Initializes a `Tzun` client with the in-memory storage adapter.
2. Mocks a vendor call (literal `(request, response)` dict pair).
3. Calls `tzun_sdk.hook("openai", request, response)` to build an AI-BOM.
4. Calls `tzun.capture(...)` with the AI-BOM.
5. Calls `tzun.verify(evidence_id)`.
6. Prints a success line.

## Run

```bash
# From the repo root: the SDK from its source in python/, then the example.
pip install ./python
pip install -e clients/py-example
python -m tzun_example
```

Expected output:

```
captured: <uuid> digest=<hex>
verified: valid=True
done.
```
