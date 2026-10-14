"""Checkpoint bodies and origins (tzun-anchor/1 §4).

The byte rules are pinned by ``vectors/checkpoint-vectors.json``
(``tests/cross-sdk/test_checkpoint_vectors.py``) and held to the TypeScript
module by ``tests/cross-sdk/test_anchor_verify_parity.py``. This suite pins the
reasons, the writers' refusals, and that no reader raises: the same cases as
``tests/ts/checkpoint.test.ts``.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from tzun_sdk.attestation.checkpoint import (
    PLATFORM_NAMESPACE,
    Checkpoint,
    CheckpointParseResult,
    OriginBinding,
    TzunOrigin,
    anchor_log_origin,
    chain_id_from_segment,
    chain_id_refusal,
    chain_segment,
    check_origin_binding,
    checkpoint_digest,
    evidence_log_origin,
    format_checkpoint,
    is_origin_text,
    is_platform_namespace,
    is_test_namespace,
    parse_checkpoint,
    parse_origin,
    source_log_origin,
)

ROOT = "ab" * 32
ORIGIN = "local.invalid/3f2a9c0e5b7d4e1f8a6c2b9d0e4f7a1c/anchors"
BODY = format_checkpoint(ORIGIN, 7, ROOT)
LINES = BODY[:-1].split("\n")
PREFIX = "local.invalid/3f2a9c0e5b7d4e1f8a6c2b9d0e4f7a1c"


def _refused(reason: str) -> CheckpointParseResult:
    return CheckpointParseResult(ok=False, reason=reason)  # type: ignore[arg-type]


class TestParseCheckpoint:
    def test_reads_the_exact_form(self) -> None:
        root_b64 = base64.b64encode(bytes.fromhex(ROOT)).decode()
        assert BODY == f"{ORIGIN}\n7\n{root_b64}\n"
        assert parse_checkpoint(BODY) == CheckpointParseResult(
            ok=True, checkpoint=Checkpoint(origin=ORIGIN, size=7, root=ROOT, body=BODY)
        )

    @pytest.mark.parametrize(
        ("reason", "body"),
        [
            ("not_a_string", None),
            ("not_a_string", BODY.encode()),
            ("carriage_return", BODY.replace("\n", "\r\n")),
            ("carriage_return", f"{LINES[0]}\n7\r\n{LINES[2]}\n"),
            ("missing_final_newline", BODY[:-1]),
            ("extension_lines", f"{BODY}ext\n"),
            ("extension_lines", f"{BODY}\n"),
            ("too_few_lines", f"{LINES[0]}\n7\n"),
            ("too_few_lines", "\n"),
            ("malformed_origin", f"\n7\n{LINES[2]}\n"),
            ("malformed_origin", f"a b\n7\n{LINES[2]}\n"),
            ("malformed_origin", f"a+b\n7\n{LINES[2]}\n"),
            ("malformed_origin", f"café\n7\n{LINES[2]}\n"),
            ("malformed_size", f"{LINES[0]}\n07\n{LINES[2]}\n"),
            ("malformed_size", f"{LINES[0]}\n-7\n{LINES[2]}\n"),
            ("malformed_size", f"{LINES[0]}\n7.0\n{LINES[2]}\n"),
            ("malformed_size", f"{LINES[0]}\n\n{LINES[2]}\n"),
            # Unicode digits are not ASCII decimal.
            ("malformed_size", f"{LINES[0]}\n{chr(0x667)}\n{LINES[2]}\n"),
            ("size_out_of_range", f"{LINES[0]}\n0\n{LINES[2]}\n"),
            ("size_out_of_range", f"{LINES[0]}\n9007199254740992\n{LINES[2]}\n"),
            ("size_out_of_range", f"{LINES[0]}\n{'9' * 40}\n{LINES[2]}\n"),
            ("malformed_root", f"{LINES[0]}\n7\n{LINES[2][:-1]}\n"),
            ("malformed_root", f"{LINES[0]}\n7\n{ROOT}\n"),
            ("malformed_root", f"{LINES[0]}\n7\n{base64.b64encode(bytes(48)).decode()}\n"),
        ],
    )
    def test_refuses_with_its_reason(self, reason: str, body: object) -> None:
        assert parse_checkpoint(body) == _refused(reason)

    def test_accepts_the_largest_safe_size(self) -> None:
        assert parse_checkpoint(f"{LINES[0]}\n9007199254740991\n{LINES[2]}\n").ok

    def test_refuses_a_root_whose_last_digit_carries_unused_bits(self) -> None:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        canonical = LINES[2]
        sibling = canonical[:42] + alphabet[alphabet.index(canonical[42]) | 1] + "="
        # A lenient decoder reads both as the same 32 bytes.
        assert base64.b64decode(sibling) == base64.b64decode(canonical)
        assert parse_checkpoint(f"{LINES[0]}\n7\n{sibling}\n") == _refused("malformed_root")


class TestFormatAndDigest:
    def test_lowercases_the_root(self) -> None:
        assert format_checkpoint(ORIGIN, 7, ROOT.upper()) == BODY

    def test_an_integral_float_size_is_the_integer(self) -> None:
        assert format_checkpoint(ORIGIN, 7.0, ROOT) == BODY

    @pytest.mark.parametrize(
        ("origin", "size", "root"),
        [
            ("", 7, ROOT),
            ("a b", 7, ROOT),
            (ORIGIN, 0, ROOT),
            (ORIGIN, 1.5, ROOT),
            (ORIGIN, 2**53, ROOT),
            (ORIGIN, True, ROOT),
            (ORIGIN, 7, "ab"),
            (ORIGIN, 7, "0x" + ROOT[2:]),
            (ORIGIN, 7, None),
        ],
    )
    def test_refuses(self, origin: str, size: int, root: str) -> None:
        with pytest.raises(ValueError):
            format_checkpoint(origin, size, root)

    def test_hashes_exactly_the_body_bytes(self) -> None:
        assert checkpoint_digest(BODY) == hashlib.sha256(BODY.encode()).hexdigest()

    def test_refuses_to_hash_anything_that_is_not_a_body(self) -> None:
        with pytest.raises(ValueError, match="missing_final_newline"):
            checkpoint_digest(BODY[:-1])
        with pytest.raises(ValueError, match="not_a_string"):
            checkpoint_digest(42)  # type: ignore[arg-type]


class TestOrigins:
    def test_writes_and_reads_the_three_sdk_forms(self) -> None:
        assert anchor_log_origin(PREFIX) == f"{PREFIX}/anchors"
        assert evidence_log_origin(PREFIX, "default") == f"{PREFIX}/evidence/64656661756c74"
        assert parse_origin(f"{PREFIX}/anchors") == TzunOrigin(
            kind="anchors", domain_prefix=PREFIX, namespace="local.invalid"
        )
        assert parse_origin(f"{PREFIX}/evidence/64656661756c74") == TzunOrigin(
            kind="evidence", domain_prefix=PREFIX, namespace="local.invalid", chain_id="default"
        )
        assert parse_origin(f"{PREFIX}/k2") == TzunOrigin(
            kind="log", domain_prefix=PREFIX, namespace="local.invalid", name="k2"
        )

    @pytest.mark.parametrize(
        "origin",
        [
            "local.invalid",
            PREFIX,
            f"{PREFIX}/evidence",
            f"{PREFIX}/anchors/",
            f"{PREFIX}/k2/64",
            f"{PREFIX}/evidence/64656661756C74",
            7,
        ],
    )
    def test_reads_no_origin(self, origin: object) -> None:
        assert parse_origin(origin) is None

    def test_refuses_a_malformed_domain_prefix_when_writing(self) -> None:
        for call in (
            lambda: anchor_log_origin("local.invalid"),
            lambda: anchor_log_origin(f"{PREFIX}/x"),
            lambda: evidence_log_origin("a b/c", "default"),
            lambda: source_log_origin("local.invalid", "k2"),
        ):
            with pytest.raises(ValueError):
                call()

    def test_writes_a_source_log_and_reads_it_back(self) -> None:
        assert source_log_origin(PREFIX, "custody") == f"{PREFIX}/custody"
        assert parse_origin(source_log_origin(PREFIX, "custody")) == TzunOrigin(
            kind="log", domain_prefix=PREFIX, namespace="local.invalid", name="custody"
        )
        platform = f"{PLATFORM_NAMESPACE}/0f1e2d3c4b5a69788796a5b4c3d2e1f0"
        opaque = "a1b2c3d4e5f60718293a4b5c6d7e8f90"  # pragma: allowlist secret
        assert source_log_origin(platform, opaque) == f"{platform}/{opaque}"
        for name in ("anchors", "evidence", "", "a/b", "a b", "a+b", "é", 7):
            with pytest.raises(ValueError, match="one segment of origin text"):
                source_log_origin(PREFIX, name)  # type: ignore[arg-type]

    def test_refuses_a_value_that_is_not_a_chain_id(self) -> None:
        for bad in ("\ud800", "a\x00b", "", 7):
            with pytest.raises(ValueError):
                chain_segment(bad)  # type: ignore[arg-type]
        assert chain_id_refusal("") == "empty_chain_id"
        for bad_id in ("\ud800", "a\udc00", "\ude00\ud83d", "\x00", "a\x00b", 7, None):
            assert chain_id_refusal(bad_id) == "invalid_chain_id"
        for good in ("default", "\U0001f512", "﻿a", " ", "a/b+c"):
            assert chain_id_refusal(good) is None

    def test_reads_no_chain_id_from_a_segment_with_a_zero_byte(self) -> None:
        assert chain_id_from_segment("00") is None
        assert chain_id_from_segment("610062") is None
        assert parse_origin(f"{PREFIX}/evidence/610062") is None
        assert check_origin_binding(
            f"{PREFIX}/anchors", f"{PREFIX}/evidence/610062"
        ) == OriginBinding(ok=False, reason="origin_not_in_domain")

    @pytest.mark.parametrize(
        ("segment", "why"),
        [
            ("c0af", "an overlong encoding"),
            ("eda080", "a UTF-8 surrogate"),
            ("f4908080", "above U+10FFFF"),
            ("e282", "a truncated sequence"),
            ("ff", "not UTF-8 at all"),
        ],
    )
    def test_reads_no_chain_id_from_bytes_that_are_not_strict_utf8(
        self, segment: str, why: str
    ) -> None:
        assert chain_id_from_segment(segment) is None, why

    def test_keeps_a_leading_byte_order_mark(self) -> None:
        assert chain_id_from_segment("efbbbf61") == "﻿a"

    def test_knows_a_test_namespace_by_its_prefix_only(self) -> None:
        assert is_test_namespace("test.tzun.dev")
        assert not is_test_namespace("test")
        assert not is_test_namespace("local.invalid")
        assert not is_test_namespace("log.tzun.ai")
        assert not is_test_namespace(None)

    def test_knows_the_platform_namespaces_exactly_and_nothing_that_extends_them(self) -> None:
        assert is_platform_namespace(PLATFORM_NAMESPACE)
        assert is_platform_namespace("log.tzun.ai")
        assert is_platform_namespace("test.log.tzun.ai")
        for other in (
            "test.log.tzun.ai.example",
            "log.tzun.ai.example",
            "x.log.tzun.ai",
            "test.test.log.tzun.ai",
            "LOG.TZUN.AI",
            "local.invalid",
            "test.tzun.dev",
            "",
            None,
            7,
        ):
            assert not is_platform_namespace(other)

    def test_origin_text_excludes_space_plus_and_non_printable_ascii(self) -> None:
        assert is_origin_text("a/b.c-d_e~f")
        for bad in ("", " ", "a+b", "a\tb", "é", "\x7f", "a\n", None):
            assert not is_origin_text(bad)

    def test_a_chain_id_needs_its_evidence_log_except_under_the_platform(self) -> None:
        anchors = f"{PREFIX}/anchors"
        assert check_origin_binding(anchors, f"{PREFIX}/custody", "default") == OriginBinding(
            ok=False, reason="chain_id_mismatch"
        )
        assert check_origin_binding(anchors, f"{PREFIX}/custody", None) == OriginBinding(
            ok=True, namespace="local.invalid", chain_checked=False
        )
        test = "test.tzun.dev/3f2a9c0e5b7d4e1f8a6c2b9d0e4f7a1c"
        assert check_origin_binding(f"{test}/anchors", f"{test}/k2", "default") == OriginBinding(
            ok=False, reason="chain_id_mismatch"
        )
        assert PLATFORM_NAMESPACE == "log.tzun.ai"
        platform = f"{PLATFORM_NAMESPACE}/0f1e2d3c4b5a69788796a5b4c3d2e1f0"
        assert check_origin_binding(
            f"{platform}/anchors", f"{platform}/a1b2c3d4e5f60718293a4b5c6d7e8f90", "user-abc"
        ) == OriginBinding(ok=True, namespace=PLATFORM_NAMESPACE, chain_checked=False)
        lookalike = "log.tzun.ai.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0"
        assert check_origin_binding(
            f"{lookalike}/anchors", f"{lookalike}/k2", "user-abc"
        ) == OriginBinding(ok=False, reason="chain_id_mismatch")

    def test_a_supplied_chain_id_that_is_not_a_string_matches_no_evidence_log(self) -> None:
        log = evidence_log_origin(PREFIX, "default")
        anchors = f"{PREFIX}/anchors"
        assert check_origin_binding(anchors, log, 7) == OriginBinding(
            ok=False, reason="chain_id_mismatch"
        )
        assert check_origin_binding(anchors, log, "") == OriginBinding(
            ok=False, reason="chain_id_mismatch"
        )
        assert check_origin_binding(anchors, log, None) == OriginBinding(
            ok=True, namespace="local.invalid", chain_checked=False
        )
        assert check_origin_binding(anchors, log, "default") == OriginBinding(
            ok=True, namespace="local.invalid", chain_checked=True
        )


JUNK: list[object] = [
    None,
    0,
    float("nan"),
    "",
    "\n\n\n",
    [],
    {},
    object(),
    lambda: 1,
    "x" * 100_000,
    "\ud800\n1\nAA==\n",
    b"bytes",
    True,
]


@pytest.mark.parametrize("junk", JUNK, ids=[f"junk-{i}" for i in range(len(JUNK))])
def test_no_reader_raises(junk: object) -> None:
    assert parse_checkpoint(junk).ok is False
    assert parse_origin(junk) is None
    assert chain_id_from_segment(junk) is None
    assert check_origin_binding(junk, junk, junk).ok is False
    assert is_origin_text(junk) is (junk == "x" * 100_000)
