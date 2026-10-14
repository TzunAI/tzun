"""Runnable example — init → hook → capture → verify."""

from __future__ import annotations

import asyncio

import tzun_sdk
from tzun_sdk.contributions import single_model
from tzun_sdk.storage import MemoryAdapter


async def main() -> None:
    """End-to-end: hook → capture → verify, all in-memory."""
    async with await tzun_sdk.Tzun.init(storage=MemoryAdapter()) as tzun:
        # Step 1: build an AI-BOM via hook() from a fake (request, response).
        request = {"temperature": 0.7, "max_tokens": 200}
        response = {
            "model": "gpt-4o-2024-08-06",
            "system_fingerprint": "fp_example",
            "choices": [{"text": "Approve"}],
        }
        ai_bom = await tzun_sdk.hook("openai", request, response, tzun=tzun)
        # Step 2: capture the decision, the model as a contributions list of one.
        result = await tzun.capture(
            ai_output={"score": 0.87, "label": "approve"},
            action="approved",
            reason="risk threshold met",
            # Who decided, by an opaque account id (never an email address or a name).
            decider={"kind": "human", "id": "acct:u-example"},
            contributions=single_model(ai_bom),
        )
        print(f"captured: {result.evidenceId} digest={result.canonicalDigest}")
        # Step 3: verify.
        v = await tzun.verify(result.evidenceId)
        print(f"verified: valid={v.valid}")
        print("done.")


if __name__ == "__main__":
    asyncio.run(main())
