# @tzun/engine

The evidence engine of the [Tzun SDK](https://github.com/TzunAI/tzun):
canonical serialization, the SHA-256 digest pipeline, the hash chain, the schema
registry and envelope verification for Tzun Decision Evidence Objects (DEOs).
Pure functions with no I/O. It uses only Node's built-in `crypto` module and has
no runtime npm dependencies.

Most applications want `@tzun/sdk`, which depends on this package at the same
version and adds capture, storage, attestation and anchoring. The engine on its
own computes or checks a record's digest without the SDK:

```ts
import { verifyEnvelope } from '@tzun/engine';

// envelope: a stored record; previousDigest: its predecessor's canonicalDigest
const result = verifyEnvelope(envelope, previousDigest);
result.verified;          // the digest recomputes and the chain link holds
result.recomputedDigest;  // equals envelope.integrity.canonicalDigest for an intact record
```

The record format, the canonical serialization and the digest are specified in
[DEO Record Format 1.0](https://spec.tzun.ai/record/1.0/).

## License

No licence is granted. The source is published so that it can be read: see
[LICENSE.md](https://github.com/TzunAI/tzun/blob/main/LICENSE.md) and
[NOTICE](https://github.com/TzunAI/tzun/blob/main/NOTICE). The package is not
on npm. The conformance vectors in the repository's `vectors/` directory are
CC0-1.0. For a licence, contact licensing@tzun.ai.
