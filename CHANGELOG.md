# Changelog

All notable changes to `@tzun/sdk`, `@tzun/engine` and the Python package
`tzun-sdk` are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with one project-specific rule:

> **Anything that changes a computed digest is breaking.** The hashed field set,
> the canonicalization rules and number/string formatting are a contract with
> every record already captured. Record format v1.0 is not yet frozen
> ([Specs §2](https://spec.tzun.ai/#s2)); while it is not, a change to the hashed
> field set can be made under the same `v1.0` tag as a breaking release whose
> notes here say how to rebuild a store. A change to the canonicalization rules
> or number/string formatting gets a new schema version and a migration note
> here, not a patch release, as does any change to the set once v1.0 is frozen.

`@tzun/sdk`, `@tzun/engine` and `tzun-sdk` are versioned **in lockstep**. The
SDK depends on the engine through the pnpm `workspace:` protocol, which is
rewritten to the engine's exact version at publish time.

## [Unreleased]

## [0.8.3] — 2026-10-14

### Changed

- The `evm-calldata/1` publication verifier (`verifyEvmPublication`,
  `verify_evm_publication`) applies the seven rules tzun-anchor/1 §10.4 item 2
  states for a transaction to decode and yield a sender, itself, before any
  signature is recovered. On the points those rules cover, the outcome and
  reason no longer depend on the Ethereum library a verifier uses; on other
  points they still can. Each of these is now `false`, `malformed_publication`,
  in both SDKs:
  - **Chain id**: a typed transaction (EIP-2930, EIP-1559) signed for chain id
    0;
  - **Legacy v**: a legacy `v` other than 27, 28, or `chainId * 2 + 35` or
    `+ 36` for a chain id of 1 or more, so `v` 35 and 36;
  - **Signature values**: `r` outside [1, n - 1], `s` outside [1, (n - 1) / 2]
    (EIP-2), or a typed `yParity` other than 0 or 1;
  - **Fees**: an EIP-1559 `maxPriorityFeePerGas` above its `maxFeePerGas`;
  - **Recovery**: a signature from which no public key recovers;
  - **Encoding**: a `rawTransaction` that is not the canonical RLP of its
    fields: an integer with a leading zero byte (0 must be the empty string),
    a single byte below `0x80` written as a one-byte string, a length not in
    its minimal form, or anything after the list;
  - **Field sizes**: a `nonce` or `gasLimit` above 2^64 - 1; a chain id,
    `value`, `gasPrice`, `maxPriorityFeePerGas` or `maxFeePerGas` above
    2^256 - 1; a legacy `v` above 2 * (2^256 - 1) + 36.

  No block on a chain a manifest can name can include such a transaction
  today, so no real anchor is refused. Before, ethers recovered a sender for a
  typed transaction on chain id 0, for a high `s` (read as `n - s`), for
  non-canonical RLP and for a `gasLimit` of 2^64 or more, so such a
  publication from a listed publisher could be `evm_chain_mismatch` or
  `true`; go-ethereum recovers one for a legacy `v` of 35 or 36, for a tip
  above the fee cap, and for a `value` or fee of 2^256 or more, which ethers
  refuses. An unprotected legacy transaction (`v` 27 or 28) is read as
  before, and §10.4 item 5 refuses its chain. Types other than 0, 1 and 2
  abstain as before. See TzunAI/tzun-verify#37.

### Fixed

- A transaction with a `nonce` from 2^53 to 2^64 - 1 is read and its sender
  recovered. A chain can hold such a nonce, and the SDKs refused it as
  `malformed_publication` only because ethers reads a nonce as a JavaScript
  safe integer (the Python SDK copied that limit). A legacy `v` above
  2^256 - 1 (a chain id of 2^255 or more) is read for the same reason.

### Added

- `readEvmTransaction` and `evmRlpForm` (`src/attestation/blockchain.ts`,
  exported from that module, not from the package entry) read a signed
  transaction as item 2 does and report the rule it breaks; ethers supplies
  RLP decoding, keccak-256 and secp256k1 recovery, and no longer reads the
  transaction (`Transaction.from`). `decodeEvmTransaction` returns the
  transaction or `null`. In Python, `decode_signed_transaction`
  (`tzun_sdk.attestation.evm_transaction`) raises `EvmTransactionError` with
  the same rule as `.rule`, and `rlp_form` (`tzun_sdk.attestation.evm_rlp`)
  is `evmRlpForm`.
- `vectors/evm-anchor-vectors.json` gains `transactionCases`: signed
  transactions at each edge of each rule of item 2, those it refuses and those
  just inside, each refused case with the one rule it breaks (`chain-id`,
  `legacy-v`, `signature-values`, `fees`, `recovery`, `encoding`,
  `field-sizes`), and the verdict for each. Its existing cases are unchanged.

## [0.8.2] — 2026-10-06

**The first public release of the source.** Tzun records a tamper-evident
Decision Evidence Object (DEO) when a human acts on an AI recommendation:
canonical serialization, a SHA-256 digest, an append-only hash chain per
evidence chain, optional WebAuthn sign-off, RFC 3161 timestamps, Merkle
anchoring, and a record of the AI systems that contributed to the decision. The
record format, its verification rules, the proof bundle, the anchor format and
the conformance vectors are specified at [spec.tzun.ai](https://spec.tzun.ai).

### Licence and packages

- The source is published so that it can be read. No licence is granted: see
  [`LICENSE.md`](./LICENSE.md).
- `@tzun/sdk` and `@tzun/engine` (npm) and `tzun-sdk` (PyPI) are not published.
  Each manifest marks its package unpublishable, and the release workflows stop
  while one does.
- The conformance vectors in `vectors/` are CC0-1.0.
- The code of conduct in `CODE_OF_CONDUCT.md` is the Contributor Covenant 2.1,
  under CC BY 4.0.

### Changed

- `TzunWebAuthn.verifyAssertion()` refuses an assertion whose `clientDataJSON`
  states `crossOrigin: true` and names a `topOrigin`, unless that `topOrigin`
  is listed in the new `WebAuthnConfig.allowedTopOrigins`, which it passes to
  `@simplewebauthn/server` as `expectedTopOrigin`. 14.x refuses such a
  response when the caller names no expected top origin; 13.3.3 did not check
  the top origin. A ceremony in the browser-extension side panel runs in a
  cross-origin frame, so a relying party that verifies one lists the
  extension's origins:
  `new TzunWebAuthn({ ..., allowedTopOrigins: ['chrome-extension://<id>'] })`.
  The option takes the same list as `allowedTopOrigins` for `Tzun.verify()`
  and `verifyAttestation()`, but `verifyAssertion()` checks it only for an
  assertion that states `crossOrigin: true` and names a `topOrigin`;
  `assertionProvenance.topOriginValid` checks every assertion. An assertion
  that names no `topOrigin` (a ceremony run directly in a tab, a cross-origin
  frame in Safari, or one that does not state `crossOrigin`) verifies as
  before whether or not the option is set. 14.x also refuses an assertion that
  names a `topOrigin` without stating `crossOrigin: true`.

### Removed

- `mandateEventLeaf` (`@tzun/engine`) and `mandate_event_leaf`
  (`tzun_sdk.mandate`), and the `leaf` member of the event bodies in
  `vectors/mandate-vectors.json` and `vectors/v1.0-worked-example-vectors.json`.
  Nothing used them: no mandate log is built, stored or anchored, and the form
  of a mandate log's leaves is settled when one is. `mandateEventBodyDigest` and
  `mandate_event_body_digest` (`SHA-256(C(body))`) are unchanged.

### Security

- `@simplewebauthn/server` is upgraded from 13.3.3 to 14.0.3. In 13.3.3,
  registration verification fetched the CRL URL named by each certificate in
  an attestation statement's `x5c`, and cached the result process-wide, before
  checking that the certificate chained to a trust anchor. It did so whenever
  the format had a trust anchor to chain to: `apple` and `android-safetynet`
  have default roots, and `android-key` uses the `x5c`'s own last certificate.
  So a crafted registration response made the server request a URL the client
  chose. Since 14.0.2 the library checks revocation only along a chain that has
  reached a supplied trust anchor, verifies a CRL's signature against the
  issuer's key, and keys its CRL cache by the issuer's key identifier. The
  advisories
  ([GHSA-j3h4-m3m2-7p7j](https://github.com/MasterKale/SimpleWebAuthn/security/advisories/GHSA-j3h4-m3m2-7p7j),
  [GHSA-2g3p-m8c9-hhwh](https://github.com/MasterKale/SimpleWebAuthn/security/advisories/GHSA-2g3p-m8c9-hhwh))
  list 14.0.1 as the affected version; 13.3.3 has the same code path.
- 14.0.3 still fetches for `android-key`. That format's verifier validates the
  `x5c` against the `x5c`'s own last certificate, and checks that this root is
  a known Google root only afterwards, so a response whose leaf certificate is
  issued by a root the client made still has the server fetch the CRL URLs the
  certificates of that chain name. `TzunWebAuthn.finishRegistration()`
  therefore replaces the attestation statement of every registration response
  with format `none` and an empty statement before verifying it: the library
  reads no attestation certificate, and registration verification fetches
  nothing, whatever the response. The SDK stores nothing from an attestation
  statement, and a response is accepted exactly when the same authenticator
  data sent with format `none` would be. `startRegistration()` asks for
  attestation `none`, as it did by default; it now says so explicitly.
- `TzunWebAuthn.finishRegistration()` accepts only the algorithms
  `startRegistration()` offers: Ed25519 (-8) and ES256 (-7). It used to verify
  against the library's default list, which includes RS256, and stored a
  credential of an algorithm other than those two labelled ES256. It takes the
  label from the credential key alone, and refuses a key that states no
  algorithm it can read, where it used to fall back to the response's
  `publicKeyAlgorithm` field and then to ES256.

### Before 0.8.2

Earlier versions were not publicly released. Their history is not part of this
repository. The format versions they implement are listed at
[spec.tzun.ai](https://spec.tzun.ai).
