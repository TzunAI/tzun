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

## [0.8.3] — 2026-10-15

### Added

- `readEvmTransaction` and `evmRlpForm` (`src/attestation/blockchain.ts`,
  exported from that module, not from the package entry) read a signed
  transaction as tzun-anchor/1 §10.4 item 2 does and report the rule it breaks;
  ethers supplies RLP decoding, keccak-256 and secp256k1 recovery, and no
  longer reads the transaction (`Transaction.from`). `decodeEvmTransaction`
  returns the transaction or `null`. In Python, `decode_signed_transaction`
  (`tzun_sdk.attestation.evm_transaction`) raises `EvmTransactionError` with
  the same rule as `.rule`, and `rlp_form` (`tzun_sdk.attestation.evm_rlp`) is
  `evmRlpForm`.
- `withLowS` and `transactionToBroadcast` (`src/anchoring/evm-chain.ts`,
  exported from that module, not from the package entry). `withLowS` is the
  high-`s` replacement, for a typed transaction or an EIP-155 legacy `v`, and
  `null` for a legacy `v` of 27 or 28. `transactionToBroadcast` is a signed
  transaction as it meets item 2: unchanged, with its `s` lowered, or the rule
  of item 2 it breaks. The checks of §7.2 rule 3, of the type, the chain id and
  the sender, are made in `checkSignedTransaction`.
- `vectors/evm-anchor-vectors.json` gains `transactionCases`: signed
  transactions at each edge of each rule of item 2, those it refuses and those
  just inside, each refused case with the one rule it breaks (`chain-id`,
  `legacy-v`, `signature-values`, `fees`, `recovery`, `encoding`,
  `field-sizes`), and the verdict for each. Each case states the `sender` and
  `signedChainId` that `anchor.evm.tx` reports once item 2 reads the
  transaction: `signedChainId` is the chain id in decimal, `null` for the two
  cases with `v` 27 and 28, and `null` for a refused case, which reports no
  facts. Its existing cases are unchanged.

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

  Ethereum mainnet, Sepolia and Hoodi, the chains of the network table in §9,
  refuse such a transaction under the rules they apply today, so no block they
  produce today holds one, and refusing it refuses no publication made on
  them. A development chain can be more lenient: anvil, for one, mines a
  transaction whose `s` is above (n - 1) / 2. A publication on such a chain
  that breaks one of these rules is refused like any other. Before, ethers
  recovered a sender for a typed transaction on chain id 0, for a high `s`
  (read as `n - s`), for non-canonical RLP and for a `gasLimit` of 2^64 or
  more, so such a publication from a listed publisher could be
  `evm_chain_mismatch` or `true`; go-ethereum recovers one for a legacy `v` of
  35 or 36, for a tip above the fee cap, and for a `value` or fee of 2^256 or
  more, which ethers refuses. An unprotected legacy transaction (`v` 27 or 28)
  is read as before, and §10.4 item 5 refuses its chain. Types other than 0, 1
  and 2 abstain as before. See TzunAI/tzun-verify#37.
- The `signedChainId` fact of a legacy transaction whose `v` is 27 or 28,
  which signs no chain id (§10.4 item 2), is `null` in both SDKs, as
  tzun-anchor/1 §10.7 states and tzun-verify reports. It was `"0"`. The type
  is `string | null` (`EvmPublicationFacts.signedChainId`) and `str | None` in
  Python, and the `anchor.evm.tx` check of `verifyAnchor` and `verify_anchor`
  carries the `null`. The verdict is unchanged: such a transaction signs no
  chain id, so §10.4 item 5 matches it to no manifest entry
  (`evm_chain_mismatch`).
- The anchor scheduler sends only transactions that meet the seven rules of
  §10.4 item 2, read with the verifier's own reader, as tzun-anchor/1 §7.2
  rule 3 and §11 item 6 require of a writer. The Python SDK has no anchor
  writer.
  - It checks every transaction its signer returns before it stores or
    broadcasts it. This covers every signer path: a private key, an ethers
    `Signer`, and a KMS or HSM signer. A signature whose `s` is above
    (n - 1) / 2, which some KMS and HSM signers return, is replaced by the
    equivalent one, `s` as n - `s` with `yParity` flipped: the same key's
    signature over the same hash, from which the same sender recovers. The
    scheduler stores and broadcasts that transaction, whose id is not the one
    the signer returned. Before, it refused a high `s` as a signature
    mismatch and published nothing. A transaction that breaks any other rule
    (a chain id of 0, a tip above the fee cap, RLP that is not canonical, and
    so on) is neither stored nor broadcast: the pass fails with an
    `AnchorSignerError` whose `field` and new `rule` name the rule, and the
    `anchor_signer_mismatch` alarm. A transaction that meets every rule is
    stored and broadcast with its bytes unchanged. A transaction of a type
    item 2 does not read (3, 4 and so on) is refused for its `type`, and the
    error's message names the type and says item 2 does not read it. A high
    `s` on a legacy `v` of 27 or 28 is never lowered: such a transaction
    signs no chain id, and rule 3 requires one. A publisher passed to
    `createAnchorScheduler` as `publisher` returns the bytes that are sent,
    and nothing it returns is lowered: before anything it returns is stored
    or enrols the wallet, the scheduler reads it the same way. It must meet
    every rule as returned, a high `s` included, be of a type item 2 reads
    (another is refused for its `type`), sign the publisher's chain id,
    recover the publisher's address, be at the nonce asked for, and have the
    hash of its bytes as its hash. A publication must also carry the
    calldata 0x ‖ P and no value; an accounted transaction must go to the
    recipient, with the value and the calldata, asked for. A publication's
    recipient, and the gas and fees of either, are not compared. Otherwise
    it is refused with an `AnchorSignerError` and nothing is stored,
    enrolled or sent; a publication's pass fails with the
    `anchor_signer_mismatch` alarm and is retried, unless what it returned
    is the publication asked for and the publisher's window in the
    manifest closed while it signed: then the pass defers
    (`anchor_publisher_outside_window`). Before, what such a publisher
    returned was stored and broadcast as it was.
  - It checks the bytes it is about to send on every broadcast, a stored
    transaction sent again included: they must meet every rule, sign the
    publisher's chain id, and recover the sender authenticated for the
    publication, or the wallet for an accounted transaction (`sweep`,
    `handover`). A publication's bytes must also carry the nonce and the
    calldata, 0x ‖ P, it was signed or authenticated with this pass, not
    those of a row read since, and no value: another transaction of the same
    key, at another nonce, over other calldata or with a value, is not sent
    in its place. Anyone who can write the store can replace a stored
    transaction, without the key, with its twin (`s` as n - `s`, the parity
    flipped) or with its values in RLP that is not canonical; both recover the
    same sender, and every verifier refuses both. Such bytes are not sent and
    never lowered or repaired, since a stored attempt is append-only:
    `anchor_publication_unexplained`, or `anchor_wallet_tx_unexplained` for an
    accounted transaction, stops anchoring. Before, a stored transaction was
    sent again as it was stored.
  - It accepts an earlier publication as its own only when item 2 reads each
    of its transactions: the publication checks read them with
    `readEvmTransaction`, which supplies the sender, chain id and calldata;
    ethers, which recovers the same sender from either twin, reads only the
    nonce, value and fee caps of bytes item 2 has already read.
    `assertAnchorWalletTx`, which the SQLite and Postgres stores run on every
    accounted transaction they insert and the scheduler on every one it reads,
    refuses one that item 2 does not read, naming the rule, and takes its
    sender and chain id from item 2's reading.

### Removed

- `uuid` is no longer a dependency of `@tzun/sdk`. Nothing imports it
  (TzunAI/tzun#2).
- `rich` is no longer a dependency of `tzun-sdk`. Nothing in the package
  imports it; the `tzun` command is built on `typer`, which depends on `rich`
  itself (TzunAI/tzun#2).
- The `sigstore` extra of `tzun-sdk`, which `all` included. It installed
  `sigstore`, which nothing imports: `SigstoreBackend` is not implemented and
  raises `NotImplementedError`, as before. `sigstore` 4.5 caps `rich` below 16
  and `rfc3161-client` below 1.1, so raising either floor would have made
  `[sigstore]` and `[all]` impossible to install (TzunAI/tzun#2).

### Fixed

- A transaction with a `nonce` from 2^53 to 2^64 - 1 is read and its sender
  recovered. An account's nonce is a 64-bit integer, so a nonce above 2^53 - 1
  can be real; the SDKs refused it as `malformed_publication` only because
  ethers reads a nonce as a JavaScript safe integer (the Python SDK copied
  that limit). A legacy `v` above 2^256 - 1 (a chain id of about 2^255 or
  more) is read for the same reason.
- `@tzun/sdk` lists `@types/better-sqlite3` and `@types/pg` as dependencies,
  not dev dependencies. Its declarations import types from `better-sqlite3`
  and `pg`: the storage extension and log-store signatures take a
  `better-sqlite3` database and a `pg` pool. A project that type-checks
  library declarations (`skipLibCheck: false`) and did not install the two
  `@types` packages itself failed to compile against the packed SDK with
  TS7016. The ranges, `^7.6.0 || ^9.6.0` and `^8.11.0`, also accept the
  older versions a project may have installed itself. CI now packs
  `@tzun/engine` and `@tzun/sdk` and compiles two strict consumers of the two
  tarballs, one with nothing else installed and one with the oldest version
  of each `@types` package the ranges accept
  (`scripts/check-packed-types.sh`) (TzunAI/tzun#9).

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
