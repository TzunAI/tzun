"""``verify_anchor`` and ``verify_evm_publication``: what only the Python SDK has.

Verdicts are held to the TypeScript SDK's by ``tests/cross-sdk/test_anchor_verify_parity.py``
and to the vector files by ``tests/cross-sdk/test_checkpoint_vectors.py`` and
``test_anchor_e2e_vectors.py``. This suite pins the Python surface around them:
header sources that answer synchronously, the SDK's own models as input, the
``anchor`` extra missing, the JSON-RPC header source, the ECMAScript date rules,
and that no input makes either verifier raise.
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys
from typing import Any

import httpx
import pytest

from tests.attestation.mock_tsa import build_timestamp_response
from tzun_sdk.attestation._ecmascript import iso_from_millis, millis_from_iso, node_base64_decode
from tzun_sdk.attestation._rfc3161_steps import UnreadableTrustAnchorError
from tzun_sdk.attestation._rfc3161_token import UnreadableToken, read_timestamp_token
from tzun_sdk.attestation.anchor_verify import verify_anchor
from tzun_sdk.attestation.evm_publication import (
    RpcEvmHeaderSource,
    checked_finality,
    parse_evm_block_header,
    rfc3339_seconds,
    verify_evm_publication,
    verify_evm_transaction_proof,
)
from tzun_sdk.attestation.evm_rlp import MAX_RLP_DEPTH, decode_rlp, encode_rlp
from tzun_sdk.attestation.evm_transaction import keccak256
from tzun_sdk.attestation.rfc3161 import _wrap_der
from tzun_sdk.errors import MissingExtraError
from tzun_sdk.models import EvidenceEnvelope

from ._anchor_extra import needs_anchor_extra

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
E2E: dict[str, Any] = json.loads(
    (REPO_ROOT / "vectors" / "anchor-e2e-vectors.json").read_text(encoding="utf-8")
)
RECORD = E2E["records"][0]
EPOCH = E2E["epochs"][RECORD["epoch"]]
CHAIN = E2E["chain"]

needs_extra = needs_anchor_extra


def _inputs(**overrides: Any) -> dict[str, Any]:
    envelope = RECORD["envelope"]
    options: dict[str, Any] = {
        "sequence_number": envelope["payload"]["sequenceNumber"],
        "chain_id": RECORD["chainId"],
        "publisher_manifest": E2E["manifest"],
        "publication_material": [EPOCH["publication"]],
    }
    options.update(overrides)
    return options


class SyncSource:
    """The source the vector file states, answering without awaiting."""

    finality = "finalized"

    def chain_id(self) -> int:
        return int(E2E["headerSource"]["chainId"])

    def finalized_block_number(self) -> int:
        return int(E2E["headerSource"]["finalizedBlockNumber"])

    def canonical_block(self, n: int) -> dict[str, Any] | None:
        block = EPOCH["canonicalBlock"]
        return (
            {"hash": block["hash"], "timestamp": block["timestamp"]}
            if n == block["number"]
            else None
        )


class AsyncSource(SyncSource):
    async def chain_id(self) -> int:  # type: ignore[override]
        return super().chain_id()

    async def finalized_block_number(self) -> int:  # type: ignore[override]
        return super().finalized_block_number()

    async def canonical_block(self, n: int) -> dict[str, Any] | None:  # type: ignore[override]
        return super().canonical_block(n)


async def _verify(**overrides: Any) -> Any:
    envelope = RECORD["envelope"]
    return await verify_anchor(
        envelope["nonRepudiation"], envelope["integrity"]["canonicalDigest"], **_inputs(**overrides)
    )


@needs_extra
async def test_a_header_source_may_answer_synchronously_or_asynchronously() -> None:
    sync = await _verify(evm_header_sources={CHAIN: SyncSource()})
    asynchronous = await _verify(evm_header_sources={CHAIN: AsyncSource()})
    assert sync == asynchronous
    assert sync["anchorValid"] is True and sync["anchorFinality"] == "finalized"


@needs_extra
async def test_the_sdk_models_verify_as_their_json_does() -> None:
    envelope = EvidenceEnvelope.model_validate(RECORD["envelope"])
    from_model = await verify_anchor(
        envelope.nonRepudiation,
        envelope.integrity.canonicalDigest,
        **_inputs(evm_header_sources={CHAIN: SyncSource()}),
    )
    from_json = await _verify(evm_header_sources={CHAIN: SyncSource()})
    assert from_model == from_json


@needs_extra
async def test_a_source_that_is_not_a_header_source_is_unavailable() -> None:
    class NotASource:
        pass

    verdict = await _verify(evm_header_sources={CHAIN: NotASource()})
    canonical = verdict["publications"][0]["checks"][2]
    assert canonical["id"] == "anchor.evm.canonical[0]"
    assert canonical["reason"] == "evm_header_source_unavailable"


@needs_extra
async def test_a_finality_that_raises_declares_nothing() -> None:
    class Raising(SyncSource):
        @property
        def finality(self) -> Any:  # type: ignore[override]
            raise RuntimeError("no")

    verdict = await _verify(evm_header_sources={CHAIN: Raising()})
    assert verdict["anchorValid"] is True
    assert verdict["anchorFinality"] is None
    assert "finality" not in verdict["publications"][0]["evm"]


class TestWithoutTheAnchorExtra:
    @pytest.fixture(autouse=True)
    def _no_extra(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A None entry makes `import coincurve` raise ImportError.
        monkeypatch.setitem(sys.modules, "coincurve", None)

    def test_the_primitives_raise_a_clear_import_error(self) -> None:
        from tzun_sdk.attestation.evm_transaction import (
            anchor_extra_available,
            decode_signed_transaction,
            keccak256,
        )

        assert anchor_extra_available() is False
        for call in (lambda: keccak256(b""), lambda: decode_signed_transaction(b"\x02")):
            with pytest.raises(MissingExtraError, match=r"pip install 'tzun-sdk\[anchor\]'"):
                call()

    async def test_an_evm_publication_is_missing_dependency_and_steps_1_to_5_still_hold(
        self,
    ) -> None:
        verdict = await _verify(evm_header_sources={CHAIN: SyncSource()})
        assert verdict["merkleProofValid"] is True
        assert (verdict["anchorValid"], verdict["anchorReason"]) == (
            None,
            "publication_not_checked",
        )
        assert verdict["publications"][0]["checks"] == [
            {"id": "anchor.publication[0]", "outcome": "checked-correct", "value": True},
            {
                "id": "anchor.evm.tx[0]",
                "outcome": "not-checked",
                "value": None,
                "reason": "missing_dependency",
            },
            {
                "id": "anchor.evm.canonical[0]",
                "outcome": "not-checked",
                "value": None,
                "reason": "blocked_by:anchor.evm.tx[0]",
            },
        ]
        # The whole §10.7 catalogue: `anchor`, the steps, then the publication's checks.
        assert [c["id"] for c in verdict["checks"]] == [
            "anchor",
            "anchor.spec",
            "anchor.checkpoint",
            "anchor.origin",
            "anchor.leafIndex",
            "anchor.inclusion",
            "anchor.anchorInclusion",
            "anchor.publication[0]",
            "anchor.evm.tx[0]",
            "anchor.evm.canonical[0]",
        ]
        assert verdict["checks"][0] == {
            "id": "anchor",
            "outcome": "not-checked",
            "value": None,
            "reason": "publication_not_checked",
        }

    async def test_every_evm_publication_gets_the_same_verdict_however_it_joins(self) -> None:
        # Joined by transaction id, by block hash, with no material, and malformed.
        by_id = await _verify()
        envelope = json.loads(json.dumps(RECORD["envelope"]))
        publication = envelope["nonRepudiation"]["anchor"]["publications"][0]
        del publication["transactionId"]
        by_hash = await verify_anchor(
            envelope["nonRepudiation"], envelope["integrity"]["canonicalDigest"], **_inputs()
        )
        alone = await _verify(publication_material=None)
        publication["blockHash"] = "junk"
        malformed = await verify_anchor(
            envelope["nonRepudiation"], envelope["integrity"]["canonicalDigest"], **_inputs()
        )
        expected = {
            "index": 0,
            "kind": "evm-calldata/1",
            "valid": None,
            "reason": "publication_not_checked",
            "checks": [
                {"id": "anchor.publication[0]", "outcome": "checked-correct", "value": True},
                {
                    "id": "anchor.evm.tx[0]",
                    "outcome": "not-checked",
                    "value": None,
                    "reason": "missing_dependency",
                },
                {
                    "id": "anchor.evm.canonical[0]",
                    "outcome": "not-checked",
                    "value": None,
                    "reason": "blocked_by:anchor.evm.tx[0]",
                },
            ],
            "evm": {},
        }
        for verdict in (by_id, by_hash, alone, malformed):
            assert verdict["publications"] == [expected]

    async def test_the_publication_verifier_says_so_on_its_own(self) -> None:
        verdict = await verify_evm_publication(
            EPOCH["publication"],
            p=EPOCH["p"],
            anchor_origin=E2E["anchorOrigin"],
            manifest=E2E["manifest"],
        )
        assert verdict["valid"] is None
        assert verdict["checks"]["tx"]["reason"] == "missing_dependency"
        # What was read before the transaction is still reported.
        assert verdict["facts"] == {
            "blockNumber": EPOCH["publication"]["blockNumber"],
            "blockHash": EPOCH["publication"]["blockHash"],
        }


def _list_of(items: list[bytes]) -> bytes:
    """An RLP list of items already encoded."""
    payload = b"".join(items)
    if len(payload) <= 55:
        return bytes([0xC0 + len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(length)]) + length + payload


def _nested_lists(depth: int) -> bytes:
    """``depth`` lists, each holding the next, the innermost empty."""
    encoded = encode_rlp([])
    for _ in range(depth - 1):
        encoded = _list_of([encoded])
    return encoded


class TestRlpDepthInHeadersAndTrieNodes:
    """An item nested more than MAX_RLP_DEPTH lists deep is refused wherever the
    verifier decodes RLP, as the TypeScript verifier refuses it, even in a field
    or trie slot neither verifier reads."""

    @needs_extra
    def test_a_header_whose_unread_first_field_nests_too_deep_is_not_a_header(self) -> None:
        block = json.loads(
            (REPO_ROOT / "tests" / "ts" / "fixtures" / "evm-sepolia-block.json").read_text(
                encoding="utf-8"
            )
        )
        fields = decode_rlp(bytes.fromhex(block["header"][2:]))
        assert isinstance(fields, list)
        rest = [encode_rlp(f) for f in fields[1:]]

        def with_first(first: bytes) -> str:
            return "0x" + _list_of([first, *rest]).hex()

        # The header's own list is one level: its first field may nest 63 more.
        assert parse_evm_block_header(with_first(_nested_lists(MAX_RLP_DEPTH - 1))) is not None
        for depth in (MAX_RLP_DEPTH, 1_000, 3_000, 20_000):
            assert parse_evm_block_header(with_first(_nested_lists(depth))) is None

    @needs_extra
    def test_a_trie_node_that_nests_too_deep_off_the_keys_path_proves_nothing(self) -> None:
        # A branch node whose slot 8 holds an embedded leaf for key rlp(0) = 0x80
        # (nibbles 8, 0) and whose slot 3 holds nested lists the walk never reads.
        leaf = encode_rlp([b"\x30", b"\xab\xcd"])

        def branch(junk: bytes) -> bytes:
            slots = [encode_rlp(b"")] * 17
            slots[3] = junk
            slots[8] = leaf
            return _list_of(slots)

        shallow = branch(_nested_lists(MAX_RLP_DEPTH - 1))
        root = "0x" + keccak256(shallow).hex()
        assert verify_evm_transaction_proof(root, 0, ["0x" + shallow.hex()]) == "0xabcd"
        for depth in (MAX_RLP_DEPTH, 1_000, 3_000):
            deep = branch(_nested_lists(depth))
            root = "0x" + keccak256(deep).hex()
            assert verify_evm_transaction_proof(root, 0, ["0x" + deep.hex()]) is None


class TestRpcEvmHeaderSource:
    def _source(
        self, answers: dict[str, Any], **kwargs: Any
    ) -> tuple[RpcEvmHeaderSource, list[dict[str, Any]]]:
        seen: list[dict[str, Any]] = []

        def handle(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            seen.append(body)
            key = body["method"] + ("" if not body["params"] else ":" + str(body["params"][0]))
            answer = answers.get(key, answers.get(body["method"]))
            if isinstance(answer, Exception):
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "error": {"code": -32000, "message": str(answer)},
                    },
                )
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": answer})

        return RpcEvmHeaderSource(
            "http://node.invalid", transport=httpx.MockTransport(handle), **kwargs
        ), seen

    async def test_reads_the_chain_the_finalized_tag_blocks_and_transactions(self) -> None:
        source, seen = self._source(
            {
                "eth_chainId": "0xaa36a7",
                "eth_getBlockByNumber:finalized": {
                    "number": "0x10",
                    "hash": "0x" + "11" * 32,
                    "timestamp": "0x1",
                },
                "eth_getBlockByNumber:0x7": {
                    "number": "0x7",
                    "hash": "0x" + "22" * 32,
                    "timestamp": "0x6ab716b3",
                },
                "eth_getBlockByNumber:0x8": None,
                "eth_getTransactionByHash": {
                    "from": "0xAB",
                    "blockHash": "0x" + "22" * 32,
                    "blockNumber": "0x7",
                },
            }
        )
        assert source.finality == "finalized"
        assert await source.chain_id() == 11155111
        assert await source.finalized_block_number() == 16
        assert await source.canonical_block(7) == {
            "hash": "0x" + "22" * 32,
            "timestamp": 0x6AB716B3,
        }
        assert await source.canonical_block(8) is None
        assert await source.transaction("0xabc") == {
            "from": "0xAB",
            "blockHash": "0x" + "22" * 32,
            "blockNumber": 7,
        }
        assert [s["method"] for s in seen] == [
            "eth_chainId",
            "eth_getBlockByNumber",
            "eth_getBlockByNumber",
            "eth_getBlockByNumber",
            "eth_getTransactionByHash",
        ]

    async def test_a_pending_transaction_names_no_block(self) -> None:
        source, _ = self._source(
            {"eth_getTransactionByHash": {"from": "0xab", "blockHash": None, "blockNumber": None}}
        )
        assert await source.transaction("0x01") == {
            "from": "0xab",
            "blockHash": None,
            "blockNumber": None,
        }

    async def test_a_confirmation_depth_counts_the_block_itself(self) -> None:
        source, _ = self._source({"eth_blockNumber": "0x100"}, finality={"confirmations": 64})
        assert source.finality == {"confirmations": 64}
        assert await source.finalized_block_number() == 256 - 63

    async def test_a_node_error_raises_so_the_verifier_reports_it_unavailable(self) -> None:
        source, _ = self._source({"eth_chainId": RuntimeError("boom")})
        with pytest.raises(RuntimeError, match="eth_chainId failed"):
            await source.chain_id()
        source, _ = self._source({"eth_getBlockByNumber": None})
        with pytest.raises(RuntimeError, match="no finalized block"):
            await source.finalized_block_number()

    @pytest.mark.parametrize(
        "finality",
        [
            {"confirmations": 63},
            {"confirmations": 0},
            {"confirmations": 1.5},
            {"confirmations": "64"},
            "latest",
            7,
        ],
    )
    def test_refuses_a_finality_that_is_not_final_or_not_a_finality(self, finality: Any) -> None:
        with pytest.raises(ValueError):
            checked_finality(finality, "RpcEvmHeaderSource")

    def test_accepts_a_shallow_depth_only_with_accept_non_final(self) -> None:
        assert checked_finality({"confirmations": 2, "acceptNonFinal": True}, "x") == {
            "confirmations": 2,
            "acceptNonFinal": True,
        }
        assert checked_finality(None, "x") == "finalized"
        assert checked_finality({"confirmations": 64.0}, "x") == {"confirmations": 64}


class TestEcmascriptDates:
    @pytest.mark.parametrize(
        ("ms", "iso"),
        [
            (0, "1970-01-01T00:00:00.000Z"),
            (-1000, "1969-12-31T23:59:59.000Z"),
            (253402300799000, "9999-12-31T23:59:59.000Z"),
            (253402300800000, "+010000-01-01T00:00:00.000Z"),
            (8_640_000_000_000_000, "+275760-09-13T00:00:00.000Z"),
            (-62198755200000, "-000001-01-01T00:00:00.000Z"),
            (1790294400123, "2026-09-25T00:00:00.123Z"),
        ],
    )
    def test_iso_strings_as_to_iso_string_writes_them(self, ms: int, iso: str) -> None:
        assert iso_from_millis(ms) == iso
        assert millis_from_iso(iso) == ms

    def test_outside_the_date_range_is_an_error(self) -> None:
        with pytest.raises(ValueError):
            iso_from_millis(8_640_000_000_000_001)

    @pytest.mark.parametrize(
        ("text", "instant"),
        [
            ("2026-09-25T00:00:00Z", (1790294400, False)),
            ("2026-09-25T00:00:00.000Z", (1790294400, False)),
            ("2026-09-25T00:00:00.000000000000Z", (1790294400, False)),
            # Below a millisecond, the fraction still counts (tzun-anchor/1 §9).
            ("2026-09-25T00:00:00.0005Z", (1790294400, True)),
            ("2026-09-25T00:00:00.0000000001Z", (1790294400, True)),
            ("2026-09-25T00:00:00.9999999999999Z", (1790294400, True)),
            ("2026-09-25T00:00:00+05:30", (1790274600, False)),
            ("2026-09-25T00:00:00.0005+05:30", (1790274600, True)),
            ("2026-09-25T00:00:00-00:00", (1790294400, False)),
            ("0000-01-01T00:00:00Z", (-62167219200, False)),
            ("2028-02-29T23:59:59.9Z", (1835481599, True)),
            ("2000-02-29T00:00:00Z", (951782400, False)),
            ("2026-09-31T00:00:00Z", None),
            ("2026-02-29T00:00:00Z", None),
            ("2100-02-29T00:00:00Z", None),
            ("2016-12-31T23:59:60Z", None),
            ("2026-09-25T24:00:00Z", None),
            ("2026-09-25t00:00:00Z", None),
            ("2026-09-25T00:00:00z", None),
            ("2026-09-25T00:00:00.Z", None),
            ("2026-09-25T00:00:0" + chr(0x667) + "Z", None),
            ("2026-09-25T00:00:00.00" + chr(0x665) + "Z", None),
        ],
    )
    def test_rfc3339_reads_at_full_precision(
        self, text: str, instant: tuple[int, bool] | None
    ) -> None:
        assert rfc3339_seconds(text) == instant

    @pytest.mark.parametrize(
        ("text", "hex_"),
        [
            ("AQID", "010203"),
            ("AQ", "01"),
            ("A", ""),
            ("AQ==AQ==", "01"),
            ("AQ-_", "010fbf"),
            ("@@AQID", "010203"),
            ("=AQ", ""),
            # Node looks each UTF-16 code unit up by its low byte: U+0141 reads as
            # 'A', U+4E2D as '-', U+013D and the high surrogate of an emoji as '='.
            ("\u0141QUJD", "010509"),
            ("\u4e2dQUJD", "f90509"),
            ("\u013dQUJD", ""),
            ("QU\u013dJD", "41"),
            ("\U0001f600QUJD", ""),
            ("\uff41QUJD", "010509"),
            ("\uff21QUJD", "414243"),
            ("\u00e9QUJD", "414243"),
            ("QUJD\u0100", "414243"),
            ("\ude00QUJD", "414243"),
        ],
    )
    def test_base64_as_node_reads_it(self, text: str, hex_: str) -> None:
        assert node_base64_decode(text).hex() == hex_


def _response_with_status(status_content: bytes) -> str:
    """A readable TimeStampResp whose PKIStatus INTEGER holds ``status_content``, in base64."""
    der = build_timestamp_response("ab" * 32, None)
    header = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
    body = der[header:]
    granted = bytes.fromhex("3003020100")
    assert body.startswith(granted)
    status_info = _wrap_der(0x30, _wrap_der(0x02, status_content))
    return base64.b64encode(_wrap_der(0x30, status_info + body[len(granted) :])).decode()


class TestTimestampTokenStatus:
    """The PKIStatus as the TypeScript reader reads it: asn1js reads an INTEGER of
    four or more bytes as 0, so a padded status of any value reads as granted."""

    @pytest.mark.parametrize(
        "content", ["00", "01", "0000", "000001", "00000002", "0000000003", "ffffffff", "7f" * 9]
    )
    def test_granted_and_every_status_of_four_or_more_bytes_are_read(self, content: str) -> None:
        assert read_timestamp_token(_response_with_status(bytes.fromhex(content))) is not None

    @pytest.mark.parametrize("content", ["02", "03", "ff", "0002", "000003", "ffffff", "8000"])
    def test_any_other_status_of_up_to_three_bytes_is_refused(self, content: str) -> None:
        with pytest.raises(UnreadableToken, match="non-success status"):
            read_timestamp_token(_response_with_status(bytes.fromhex(content)))


JUNK: list[Any] = [
    None,
    0,
    "",
    "x",
    [],
    {},
    [None],
    {"anchor": {"anchorSpec": "tzun-anchor/1", "merkleSpec": "rfc6962"}},
    object(),
]


@pytest.mark.parametrize("junk", JUNK, ids=[f"junk-{i}" for i in range(len(JUNK))])
async def test_neither_verifier_raises(junk: Any) -> None:
    verdict = await verify_anchor(
        junk,
        junk,
        sequence_number=junk,
        chain_id=junk,
        publisher_manifest=junk,
        evm_header_sources=junk,
        publication_material=junk,
    )
    assert verdict["anchorValid"] in (None, False)
    evm = await verify_evm_publication(
        junk,
        p=junk,
        anchor_origin=junk,
        manifest=junk,
        header_sources=junk,
        networks=junk,
        timeout_ms=junk,
    )
    assert evm["valid"] in (None, False)


@pytest.mark.parametrize(
    "roots",
    [["not a certificate"], [7], ["-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----"]],
    ids=["no-block", "not-a-string", "not-a-certificate"],
)
async def test_a_trust_anchor_that_cannot_be_read_is_refused_whatever_the_artifact(roots: list[Any]) -> None:
    # Verification §3.1: the auditor's input, refused rather than dropped, as the
    # TypeScript verifier refuses it; the artifact is not read first.
    root = (REPO_ROOT / "src" / "attestation" / "certs" / "freetsa-ca.pem").read_text("utf-8")
    for artifacts in ({}, RECORD["envelope"]["nonRepudiation"], None):
        with pytest.raises(UnreadableTrustAnchorError):
            await verify_anchor(artifacts, RECORD["envelope"]["integrity"]["canonicalDigest"], trust_anchors_pem=roots)
        with pytest.raises(UnreadableTrustAnchorError):
            await verify_anchor(artifacts, "x", trust_anchors_pem=[root, *roots])
    # A root that reads is taken, and the verdict is the artifact's.
    verdict = await verify_anchor({}, "x", trust_anchors_pem=[root])
    assert verdict["anchorPresent"] is False


_UNKNOWN_AUTHORITY = (
    'the trust anchors cannot be read: Unknown timestamp authority "{}". Known keys: freetsa, sectigo, '
    "digicert, sslcom, globalsign, certum, identrust, apple, mesign, entrust, aimoda. Pass a registry key, "
    "or a URL exactly as registered, or supply the anchor yourself with trustAnchorsPem / "
    "TZUN_TSA_TRUST_ANCHORS."
)


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"TZUN_TSA_TRUST_ANCHORS": "/nonexistent/tzun-trust-root.pem"}, "TZUN_TSA_TRUST_ANCHORS: /nonexistent/tzun-trust-root.pem cannot be read"),
        (
            {"TZUN_TSA_TRUST_ANCHORS": "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"},
            "trust anchor 1 is not base64",
        ),
        ({"TZUN_TSA_AUTHORITIES": "freetsa, no-such-authority"}, _UNKNOWN_AUTHORITY.format("no-such-authority")),
    ],
    ids=["missing-file", "inline-junk", "unknown-authority"],
)
async def test_the_environment_s_trust_is_refused_when_it_cannot_be_read(
    env: dict[str, str], message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Verification §3.1: with neither option given, the environment is the trust, read
    # first and refused in the TypeScript verifier's words.
    for name in ("TZUN_TSA_TRUST_ANCHORS", "TZUN_TSA_AUTHORITIES"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(UnreadableTrustAnchorError) as refused:
        await verify_anchor({}, "x")
    assert str(refused.value) == message
    # Options that name trust stand for the environment.
    root = (REPO_ROOT / "src" / "attestation" / "certs" / "freetsa-ca.pem").read_text("utf-8")
    assert (await verify_anchor({}, "x", trust_anchors_pem=[root]))["anchorPresent"] is False


async def test_white_space_alone_is_no_trust_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    # ECMAScript's white space, as the TypeScript verifier trims it: U+FEFF included.
    monkeypatch.setenv("TZUN_TSA_TRUST_ANCHORS", " \t\ufeff\u3000")
    monkeypatch.setenv("TZUN_TSA_AUTHORITIES", "  ")
    assert (await verify_anchor({}, "x"))["anchorPresent"] is False


@pytest.mark.parametrize(
    ("authorities", "message"),
    [
        (["nope"], _UNKNOWN_AUTHORITY.format("nope")),
        ("freetsa", "the authorities are not a list of names"),
        ([42], "the authorities are not a list of names"),
    ],
    ids=["unknown", "not-a-list", "not-a-name"],
)
async def test_an_authority_that_cannot_be_read_is_refused(authorities: object, message: str) -> None:
    with pytest.raises(UnreadableTrustAnchorError) as refused:
        await verify_anchor({}, "x", authorities=authorities)
    assert str(refused.value) == message


@pytest.mark.parametrize(
    "selector",
    [
        "freetsa",
        "https://freetsa.org/tsr",
        "HTTPS://FreeTSA.org:443/tsr/",
        "https:\\\\freetsa.org\\x\\..\\tsr#frag",
        "https://\uff46reetsa.org/tsr",
        "http://ts.\u1e9el.com",
        "http://timestamp.digicert.com:80/",
    ],
)
async def test_an_authority_is_named_by_its_key_or_its_url(selector: str) -> None:
    assert (await verify_anchor({}, "x", authorities=[selector]))["anchorPresent"] is False
