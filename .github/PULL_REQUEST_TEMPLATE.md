## What and why

<!-- What changes, and what problem it solves. If you rejected another approach, say which and why. -->

Closes #

## Contract impact

- [ ] This changes **nothing** the digest covers, no wire type, no published API
- [ ] This changes a digest, the hashed field set, canonicalization, or a wire
      type — **a schema version and migration story are described below**
- [ ] This changes a published API surface (breaking change noted in the commit)

<!-- If either of the last two: what breaks, for whom, and what they do about it. -->

## Cross-language parity

- [ ] Not applicable (no canonicalization / digest / wire-type change)
- [ ] TypeScript and Python both updated in this PR, with a conformance vector in
      `vectors/` that fails before this change

## Tests

- [ ] A test fails before this change and passes after
- [ ] Any existing test that asserted the old (wrong) behaviour is **inverted, not deleted**
- [ ] For a verification or attestation change: the negative case is covered
      (forged artifact, duplicate sequence, nulled link, wrong-chain predecessor)

## Checks

- [ ] `pnpm test` and, if Python changed, `pytest` pass locally
- [ ] Lint and typecheck pass
- [ ] No secret, token, customer payload or real personal data in code, tests or fixtures
