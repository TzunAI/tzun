# Security Policy

Tzun produces cryptographic evidence that people rely on to show *what a human
decided, when, and on what basis*. A defect that lets that record be forged,
altered, or reported as verified when it was not is a security defect here even
if it is not exploitable by a stranger — please report those the same way.

## Reporting a vulnerability

**Please do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting on this repository:
**Security → Advisories → Report a vulnerability**
([direct link](https://github.com/TzunAI/tzun/security/advisories/new)).

If you cannot use that, email **security@tzun.ai** (or hello@tzun.ai) with
`[SECURITY]` in the subject.

Please include, as far as you can:

- the affected version or commit,
- what an attacker (or an honest-but-mistaken caller) can achieve,
- a minimal reproduction — a failing script or test is ideal,
- whether it requires credentials, a specific configuration, or store access.

### What to expect

| Stage | Target |
|---|---|
| We acknowledge your report | within **3 business days** |
| We confirm or dispute it, with reasoning | within **10 business days** |
| Fix or documented mitigation for a confirmed high-severity issue | within **90 days** of confirmation |

We will keep you updated if any of those slip. With your permission we credit
reporters in the advisory and the changelog; tell us if you would rather not be
named.

## Scope

**In scope** — this repository: the evidence engine (`packages/engine`), the
TypeScript SDK (`src/`), the Python SDK (`python/`), the storage adapters, the
attestation layer, the packages `@tzun/sdk`, `@tzun/engine` and `tzun-sdk`,
and the build/release pipeline that produces them.

Particularly interesting to us:

- canonicalization or digest behaviour that lets two different payloads produce
  the same digest, or the same payload produce different digests across our two
  language implementations;
- any path where a verifier returns success without performing the check it
  names — including "the artifact is present" standing in for "the artifact was
  verified";
- chain manipulation that a completeness check or the scheduled scanner does not
  detect (insertion, reordering, truncation at either end, duplicate sequence
  numbers, cross-chain splicing);
- attestation artifacts (RFC 3161 timestamps, WebAuthn assertions, anchors) that
  verify against a record they were not created for;
- anything that lets a caller cause the SDK to record something untrue about a
  human decision.

**Out of scope** — the hosted service at `api.tzun.ai` and the other Tzun
surfaces (report those to security@tzun.ai and we will route them), findings
that require an attacker to already control the machine running the SDK with no
further consequence, dependency advisories with no reachable call path (tell us
anyway, but expect a lower severity), and automated scanner output without a
demonstrated impact.

## Supported versions

Pre-1.0, only the latest minor is supported. We will state a longer support
policy at 1.0.

| Version (`@tzun/sdk`, `@tzun/engine`, `tzun-sdk`) | Supported |
|---|---|
| 0.8.x | ✅ |
| < 0.8 | ❌ |

## Safe harbour

We will not pursue or support legal action under computer-misuse,
anti-circumvention or similar laws against anyone who, in good faith, researches
what is in scope above and reports it under this policy, who avoids privacy
violations and service degradation, and who gives us reasonable time to
remediate before disclosing publicly. This safe harbour does not cover testing
any system you do not own or have permission to test, Tzun's hosted services
among them. Listing something as in scope above is not permission to test
Tzun's own instance of it.

This safe harbour is not a licence under any patent, patent application or
copyright: see [`LICENSE.md`](./LICENSE.md).
