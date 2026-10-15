# AI-BOM runbook

How to wire the Tzun AI Bill of Materials (AI-BOM) layer into a real application, along three onboarding paths:

- **Path A — closed-vendor consumer.** You call OpenAI / Anthropic / Bedrock / Vertex / Azure AI / NIM / HF. Wrap the client, ship.
- **Path B — self-hosted or custom model.** You own the weights. Register them (`tzun.models.register(descriptor, { weightsPath })`, or `tzun models register --weights` from the Python SDK's command line), get a weight-attested descriptor, capture decisions against the digest.
- **Path C — CI-integrated registration.** Your model pipeline produces a release artifact. A pipeline step registers the descriptor; the resulting digest flows into the deployment config.

Plus four cross-cutting topics every integrator needs:

- Backfilling provenance after registration (annotations).
- Verifying DEOs with and without lineage walks.
- Exporting offline-verifiable evidence bundles.
- Recovering from integrity events (annotate / re-link / fork).

A record names the models behind a decision in its contributions ([Record §7](https://spec.tzun.ai/record/1.0/#s7)): each contribution step carries the bill of materials of the model that drove it ([Record §7.4](https://spec.tzun.ai/record/1.0/#s7-4)), which names the model's descriptor by digest. The model descriptor, the catalog that holds it and its annotations are defined by the SDK, not by the specification.

---

## 1. Quick start — Path A: closed-vendor consumer

If you call a managed AI API, you do not need to register anything by hand. Per-call AI-BOM extraction is done via `tzun.hook(vendor, request, response)`. For applications that want auto-capture per call, `tzun.attach(client)` returns a wrapped client where any method invocation carrying a `tzun_capture` kwarg fires `hook()` + `capture()` after the underlying call returns.

The eight vendor labels cover nine logical surfaces:

| Vendor label | SDK / endpoint | Detection (for attach) |
|--------------|----------------|------------------------|
| `openai` | OpenAI direct, Azure OpenAI | `client.chat.completions.create` (any base URL but OpenRouter's) |
| `anthropic` | Anthropic direct | `client.messages.create` |
| `bedrock` | AWS Bedrock | `client.send` + `BedrockRuntimeClient` |
| `vertex` | GCP Vertex AI | `client.generateContent` or `.predict` |
| `azure-ai` | Azure AI Foundry | `client.complete` or `.getChatCompletions` |
| `nvidia-nim` | NVIDIA NIM | OpenAI-compatible; pass `{ vendor: 'nvidia-nim' }` |
| `hf-inference` | HF Inference Endpoints | `client.chatCompletion` or `.textGeneration` |
| `openrouter` | OpenRouter gateway (models of every maker it lists) | `client.chat.completions.create` with `baseURL` on `openrouter.ai`, or `wrapOpenRouter` |

Below is one snippet per supported vendor. All eight follow the same shape: import the SDK, instantiate as you would today, hand the client to `tzun.attach()`, then use the wrapped client exactly as before — adding `tzun_capture: { action, reason, decider }` to the call when it drives a decision. The wrapper records the model as a contributions list of one (`singleModel(aiBom)`), the only place a record states a model. On the cloud transport (`apiKey`) the model is registered in the hosted service's per-account catalog (`POST /v1/models`); against a service that does not serve that endpoint the wrapper records the decision without its model (`contributions: null`) and logs `capture_model_not_recordable`. `decider` names who decided by an opaque id (`{ kind: 'human', id: 'acct:<account id>' }`), never an email address or a name.

### OpenAI

```typescript
import OpenAI from 'openai';
import { Tzun, singleModel } from '@tzun/sdk';

const tzun = await Tzun.init();
const openai = tzun.attach(new OpenAI({ apiKey: process.env.OPENAI_API_KEY }), {
  aiSystemId: 'underwriting-copilot',
});

await openai.chat.completions.create({
  model: 'gpt-4o-2024-08-06',
  temperature: 0.3,
  max_tokens: 256,
  messages: [{ role: 'user', content: 'Score applicant 12345' }],
  tzun_capture: {
    action: 'approved',
    reason: 'risk score acceptable; meets policy thresholds',
    decider: { kind: 'human', id: 'acct:jdoe' },
  },
});
```

For streaming or multi-call decisions, drop the `attach()` sugar and use `hook()` + `capture()` explicitly:

```typescript
const response = await openai.chat.completions.create({ /* ...vendor-native call... */ });
const aiBom = await tzun.hook('openai', request, response);
await tzun.capture({
  aiOutput: response,
  action: 'approved',
  reason: 'risk score acceptable',
  decider: { kind: 'human', id: 'acct:u-4821' },
  // `hook()` returns null when the connector names no model, or when the store
  // has no model catalog to register it in (the cloud transport against a
  // service that does not serve POST /v1/models).
  contributions: aiBom === null ? null : singleModel(aiBom),
});
```

### Anthropic

```typescript
import Anthropic from '@anthropic-ai/sdk';
import { Tzun } from '@tzun/sdk';

const tzun = await Tzun.init();
const anthropic = tzun.attach(new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }), {
  aiSystemId: 'claims-triage',
});

await anthropic.messages.create({
  model: 'claude-3-7-sonnet-20250219',
  max_tokens: 1024,
  messages: [{ role: 'user', content: 'Summarize claim notes...' }],
  tzun_capture: {
    action: 'escalated',
    reason: 'narrative inconsistencies; routing to senior adjuster',
    decider: { kind: 'human', id: 'acct:mchan' },
  },
});
```

### AWS Bedrock

Bedrock's `send(command)` is single-argument, so `tzun_capture` rides on the command object itself rather than as a kwarg:

```typescript
import { BedrockRuntimeClient, ConverseCommand } from '@aws-sdk/client-bedrock-runtime';
import { Tzun } from '@tzun/sdk';

const tzun = await Tzun.init();
const bedrock = tzun.attach(new BedrockRuntimeClient({ region: 'us-east-1' }), {
  aiSystemId: 'fraud-screen',
});

const command = new ConverseCommand({
  modelId: 'anthropic.claude-3-5-sonnet-20240620-v1:0',
  messages: [{ role: 'user', content: [{ text: 'Analyze transaction...' }] }],
  inferenceConfig: { temperature: 0.2, maxTokens: 512 },
});
(command as Record<string, unknown>).tzun_capture = {
  action: 'cleared',
  reason: 'no fraud indicators; auto-approved',
  decider: { kind: 'human', id: 'acct:u-4821' },
};
await bedrock.send(command);
```

### GCP Vertex AI

```typescript
import { VertexAI } from '@google-cloud/vertexai';
import { Tzun } from '@tzun/sdk';

const tzun = await Tzun.init();
const vertex = new VertexAI({ project: 'my-proj', location: 'us-central1' });
const gemini = tzun.attach(
  vertex.getGenerativeModel({ model: 'gemini-1.5-pro-002' }),
  { aiSystemId: 'clinical-summary' },
);

await gemini.generateContent({
  contents: [{ role: 'user', parts: [{ text: 'Summarize visit notes...' }] }],
  generationConfig: { temperature: 0.1, maxOutputTokens: 800 },
  tzun_capture: {
    action: 'accepted',
    reason: 'clinically accurate; matches chart',
    decider: { kind: 'human', id: 'acct:dr-park' },
  },
});
```

### Azure AI Foundry (non-OpenAI Azure models)

For Azure **OpenAI** deployments, use `tzun.attach(client)` against an OpenAI-compatible client pointed at the Azure deployment URL; the connector resolves the deployment name. For non-OpenAI Azure models (Llama, Mistral, Phi, etc. served via Azure AI Foundry):

```typescript
import ModelClient from '@azure-rest/ai-inference';
import { AzureKeyCredential } from '@azure/core-auth';
import { Tzun } from '@tzun/sdk';

const tzun = await Tzun.init();
const azure = tzun.attach(
  ModelClient(
    process.env.AZURE_AI_ENDPOINT!,
    new AzureKeyCredential(process.env.AZURE_AI_KEY!),
  ),
  { aiSystemId: 'content-mod' },
);

await azure.complete({
  model: 'Meta-Llama-3-1-70B-Instruct',
  messages: [{ role: 'user', content: 'Moderate this post...' }],
  temperature: 0,
  max_tokens: 200,
  tzun_capture: {
    action: 'flagged',
    reason: 'policy violation: hate speech',
    decider: { kind: 'human', id: 'acct:u-4821' },
  },
});
```

### NVIDIA NIM

NIM exposes an OpenAI-compatible surface that duck-type-collides with OpenAI direct. Pass `{ vendor: 'nvidia-nim' }` to disambiguate:

```typescript
import OpenAI from 'openai';
import { Tzun } from '@tzun/sdk';

const tzun = await Tzun.init();
const nim = tzun.attach(
  new OpenAI({
    baseURL: 'https://integrate.api.nvidia.com/v1',
    apiKey: process.env.NVIDIA_API_KEY,
  }),
  { vendor: 'nvidia-nim', aiSystemId: 'doc-extract' },
);

await nim.chat.completions.create({
  model: 'meta/llama-3.1-405b-instruct',
  messages: [{ role: 'user', content: 'Extract entities from...' }],
  temperature: 0.0,
  tzun_capture: {
    action: 'accepted',
    reason: 'all fields match source document',
    decider: { kind: 'human', id: 'acct:u-4821' },
  },
});
```

### OpenRouter

OpenRouter serves models of many makers (OpenAI, Anthropic, Google, Meta, Mistral, xAI, DeepSeek, Qwen, NVIDIA, Microsoft, Amazon, Cohere, Moonshot AI, Z.ai, MiniMax and more) through one OpenAI-compatible API. Point the OpenAI SDK at it and attach: a client whose `baseURL` host is `openrouter.ai` is detected as `openrouter`.

```typescript
import OpenAI from 'openai';
import { Tzun } from '@tzun/sdk';

const tzun = await Tzun.init();
const router = tzun.attach(
  new OpenAI({
    baseURL: 'https://openrouter.ai/api/v1',
    apiKey: process.env.OPENROUTER_API_KEY,
  }),
  { aiSystemId: 'claims-triage' },
);

await router.chat.completions.create({
  model: 'nvidia/nemotron-3-super-120b-a12b:free',
  messages: [{ role: 'user', content: 'Triage this claim...' }],
  temperature: 0.2,
  tzun_capture: {
    action: 'accepted',
    reason: 'matches the policy wording',
    decider: { kind: 'human', id: 'acct:u-4821' },
  },
});
```

The record states what the gateway reported, and nothing it did not:

| Field | Value | From |
|---|---|---|
| descriptor `vendor` | `openrouter` | the API that served the call |
| `modelName` | `nvidia/nemotron-3-super-120b-a12b:free` | `response.model`, verbatim, variant suffix included |
| `modelVersion` | `unknown` | OpenRouter ids carry no version |
| `trainedBy` | `nvidia` | the author prefix of the served id |
| `integrityTier` | `vendor-asserted` | asserted by the gateway; nothing is attested by the maker |
| `infrastructure.provider` | `Nvidia` | `response.provider`: the upstream OpenRouter routed the call to, as OpenRouter names it |
| `infrastructure.endpoint` | `https://openrouter.ai/api/v1` | the client's base URL, without credentials, query or trailing `/`, its host lowercased and a default port (`:443`, `:80`) dropped |
| `infrastructure.region`, `.apiVersion` | `null` | OpenRouter reports neither |

- **The served model, not the requested one.** With a `models` fallback list or a router such as `openrouter/auto`, the model that answered is not necessarily the one asked for; the record names the one in `response.model`. A response with no `model` gets no AI-BOM (`connector_no_aibom`).
- **The maker is the gateway's author id.** For this vendor `trainedBy` is the author prefix of the id as OpenRouter writes it (`openai`, `meta-llama`, `x-ai`, `qwen`), with an alias's leading `~` dropped; OpenRouter's routers (`openrouter/*`) and ids with no prefix name no maker. It is not a display name, so a Llama served through Bedrock says `Meta` and one served through OpenRouter says `meta-llama`, and one maker can have more than one prefix: Meta's Llama models are listed under `meta-llama/` and its Muse models under `meta/`. Only the `openrouter/` namespace is treated as a router. A router another publisher lists in its own namespace (`nvidia/switchyard`, `typesafe/jev-router`) is recorded with that publisher as `trainedBy` if a response names the router rather than the model it routed to.
- **Variants.** A `:free` or `:batch` id is its own descriptor, enriched from the base model's entry in the bundled reference (`nvidia/nemotron-3-super-120b-a12b:free` takes the license and Hugging Face repo of `nvidia/nemotron-3-super-120b-a12b`).
- **The tier.** `vendor-asserted` means the identity is asserted by the vendor, and the vendor is the API that served the call: for a gateway, the gateway. OpenRouter asserts the served id, the author and the upstream provider.
- **Enrichment.** The bundled reference (`data/known-models.json`) carries entries for selected current models of the major makers on OpenRouter, not for every id it lists. A model without one is still recorded truthfully, only with `license`, `modelType` and `modelCardUrl` null. Each entry follows these rules:
  - **Published weights.** The entry names the Hugging Face repository as an `hf-repo` external identifier, by its canonical id as the Hugging Face API resolves it, which may differ in case or organisation name from the `hugging_face_id` in OpenRouter's model list. A model published only as quantised repositories, with no base repository, is named by its full-precision (BF16) one.
  - **The license of published weights** is the model card's `license`; when the card says `other`, the card's `license_name`; when the card names no license id, a slug of the title of the repository's `LICENSE` file (`mistral-modified-mit` for the Modified MIT License of Mistral Medium 3.5).
  - **Unpublished weights.** The license is `<maker>-commercial` (`openai-commercial`, `anthropic-commercial`, `google-commercial`, `meta-commercial`, `mistral-commercial`, `cohere-commercial`, `xai-commercial`, `amazon-commercial`), which means the weights are not published and the model is used under its maker's commercial terms. Such an entry names no repository.
- **Not recorded in the AI-BOM:** the generation id, token usage and cost are per-call facts, not a bill of materials; through `attach()` the whole response, `provider` and `usage` included, is the record's `aiOutput` already.
- **`hook()` callers** pass the base URL as `request.openrouter_endpoint` to record it; no endpoint is assumed without it. A gateway behind a host of your own (a proxy in front of OpenRouter) is pinned with `wrapOpenRouter(client, tzun)`; `{ vendor: 'openai' }` restores the `openai` classification for an OpenRouter client.

### Hugging Face Inference Endpoints

```typescript
import { InferenceClient } from '@huggingface/inference';
import { Tzun } from '@tzun/sdk';

const tzun = await Tzun.init();
const hf = tzun.attach(new InferenceClient(process.env.HF_TOKEN), {
  aiSystemId: 'sentiment',
});

await hf.chatCompletion({
  model: 'meta-llama/Meta-Llama-3-8B-Instruct',
  messages: [{ role: 'user', content: 'Classify sentiment of...' }],
  max_tokens: 100,
  tzun_capture: {
    action: 'overridden',
    reason: 'model flagged neutral; human reads as negative',
    decider: { kind: 'human', id: 'acct:u-4821' },
  },
});
```

**That's the whole Path A integration.** `attach()` builds an `AiBom` per call (via `hook()`), registers the inferred descriptor on cold cache miss, and threads it through `tzun.capture(...)`. No descriptor file, no CLI step.

---

## 2. Self-hosted models — Path B

You own the weights. You want a `weight-attested` integrity tier instead of `vendor-asserted` — Tzun can prove the bytes on disk hash to a known digest. The flow is one registration call plus a regular `tzun.capture(...)` call against the resulting digest.

### Programmatic

```typescript
import { Tzun, singleModel } from '@tzun/sdk';

const tzun = await Tzun.init();

const { digest, descriptor, alreadyExisted } = await tzun.models.register(
  {
    vendor: 'my-co',
    modelName: 'credit-scorer',
    modelVersion: 'v2.3.1',
    license: 'proprietary',
    trainedBy: 'my-co data-science',
  },
  { weightsPath: '/opt/models/credit-scorer-v2.3' },
);

console.log(digest);                       // sha256:f1c3...e89a
console.log(descriptor.integrityTier);     // 'weight-attested'
console.log(descriptor.modelDigest);       // sha256:7b2a...11d4
console.log(alreadyExisted);               // false on first registration
```

Because `weightsPath` was given, `modelDigest` is the content-addressed hash Tzun computed by walking the weights directory, and `integrityTier: 'weight-attested'` follows from it. The `tzun-model-manifest-v1` algorithm is deterministic: same weights → same digest, reproducible by any external verifier with no access to your catalog.

### Command line (Python SDK)

The `tzun` command comes with the Python SDK; the npm package ships no command-line tool. It registers into the store that `--storage` (or `TZUN_STORAGE_URI`) names: `memory://`, the default, which is discarded when the command exits, or `sqlite:<path>`, which needs the `sqlite` extra. It cannot write to a Postgres store or to the hosted service's catalog; register there from code.

```bash
tzun --storage sqlite:./tzun.db models register \
  --quick \
  --vendor my-co \
  --name credit-scorer \
  --version v2.3.1 \
  --weights /opt/models/credit-scorer-v2.3
```

Output:

```
Registered: sha256:f1c3...e89a
```

`tzun --storage sqlite:./tzun.db models show sha256:f1c3...e89a` prints the stored descriptor field by field, `integrityTier: weight-attested` and the `modelDigest` among them. `--json`, placed before the subcommand like `--storage`, switches either command's output to JSON.

Registration modes:

- `--quick` — a minimal descriptor from `--vendor`, `--name` and `--version`, all three required; every other field is null or empty.
- `--from-file descriptor.json` — a complete descriptor as JSON, used as it stands (`--vendor`, `--name` and `--version` do not apply to it). Cannot be combined with `--quick`.
- `--weights <path>` — compute `modelDigest` from the directory and set the tier to `weight-attested`. Needs `--quick` or `--from-file`.

There is no interactive mode.

### Capturing decisions against the digest

Once registered, reference the digest at capture time:

```typescript
await tzun.capture({
  aiSystemId: 'credit-scorer',
  aiOutput: { score: 0.82, decision: 'approve' },
  action: 'approved',
  reason: 'matches policy auto-approve threshold',
  decider: { kind: 'human', id: 'acct:u-4821' },
  contributions: singleModel({
    modelDescriptorDigest: digest,
    vendorFingerprint: null,
    promptTemplate: null,
    inferenceParameters: { temperature: 0, topP: null, maxTokens: null, seed: null, stopSequences: null },
    infrastructure: { provider: null, region: 'us-east-1', apiVersion: null, endpoint: null },
  }),
});
```

The bill of materials carries exactly the members of [Record §7.4](https://spec.tzun.ai/record/1.0/#s7-4), nullable ones written as `null`; a member outside them is refused.

The descriptor is content-addressed: the same descriptor over the same weights, registered again later by anyone, produces the same digest, idempotently. The `tzun-model-manifest-v1` algorithm walks the directory recursively, excludes hidden / cache / pyc files, builds a `(path, size, sha256)` triple per file, sorts, canonicalizes, and SHA-256s the result. The implementation is `src/models/compute-model-digest.ts`.

---

## 3. CI-integrated registration — Path C

Wire registration into the model promotion pipeline. The CI job registers the descriptor in the catalog your inference service captures against and produces its digest as an output artifact; the next deployment of the service consumes it.

### Example: GitHub Actions

```yaml
name: model-release

on:
  push:
    tags:
      - 'model-v*'

jobs:
  register-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Install dependencies
        run: npm ci   # your project's dependencies, the Tzun SDK among them

      - name: Download weights artifact
        run: |
          aws s3 sync \
            s3://my-co-model-artifacts/${{ github.ref_name }} \
            ./build/weights

      - name: Register model descriptor
        id: register
        env:
          # Read by the script below. For a Postgres store, pass DATABASE_URL instead.
          TZUN_API_KEY: ${{ secrets.TZUN_API_KEY }}
        run: |
          node ./scripts/register-model.mjs \
            ./model-release/descriptor.json \
            ./build/weights \
            ./digest.txt
          echo "digest=$(cat ./digest.txt)" >> "$GITHUB_OUTPUT"

      - uses: actions/upload-artifact@v4
        with:
          name: model-descriptor-digest
          path: ./digest.txt
```

The script the job runs:

```javascript
// scripts/register-model.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { Tzun } from '@tzun/sdk';

const [descriptorPath, weightsPath, outPath] = process.argv.slice(2);
const descriptor = JSON.parse(readFileSync(descriptorPath, 'utf8'));

// The hosted service's catalog; `{ dbUrl: process.env.DATABASE_URL }` for a Postgres store.
const tzun = await Tzun.init({ apiKey: process.env.TZUN_API_KEY });
try {
  const { digest } = await tzun.models.register(descriptor, { weightsPath });
  writeFileSync(outPath, `${digest}\n`);
} finally {
  await tzun.close();
}
```

It writes the digest to a file rather than to stdout, because the SDK logs one-line JSON events to stdout unless `onLog` routes them elsewhere. For a Python service whose store is a SQLite file, the job can run the Python CLI against that file instead: `tzun --json --storage sqlite:<path> models register --from-file descriptor.json --weights <dir>` prints `{"digest": "sha256:..."}` (the CLI's `--from-file` takes a complete descriptor; `tzun.models.register` fills in what a partial one leaves out).

The next stage of the pipeline (deploy job) reads `digest.txt` and injects the value as an environment variable on the inference service. The service references it at capture time:

```typescript
await tzun.capture({
  // ... action, reason, decider, aiOutput ...
  contributions: singleModel({
    modelDescriptorDigest: process.env.MODEL_DESCRIPTOR_DIGEST!,
    vendorFingerprint: null,
    promptTemplate: null,
    inferenceParameters: { temperature: 0, topP: null, maxTokens: null, seed: null, stopSequences: null },
    infrastructure: null,
  }),
});
```

Path C is just Path B re-staged: the same `tzun.models.register` call, the digest plumbed through your existing artifact / secret machinery. The deployment carries the registered digest as configuration; runtime captures reference it; everyone (regulators, downstream verifiers) can re-derive the model identity from the digest alone. The service's store must hold the descriptor: a digest its catalog does not hold is refused at capture (`descriptor_not_registered`, §9).

---

## 4. Backfilling provenance — annotation walkthrough

You registered a model six months ago. The legal team now has a regulatory marking (FDA 510(k) clearance, EU AI Act risk classification, an internal sign-off) that needs to attach to it without invalidating any of the millions of DEOs that already reference its digest.

That's what annotations are for. An annotation appends to a separate log keyed by descriptor digest. The canonical descriptor bytes do not change. The digest does not change. Existing DEOs continue to verify. The **enriched view** — what `tzun.models.getEnriched` and the export bundle surface — incorporates the annotation.

### Programmatic

```typescript
const row = await tzun.models.annotate(
  'sha256:f1c3...e89a',
  {
    annotationType: 'add-regulatory-marking',
    value: {                               // a RegulatoryMarking
      authority: 'FDA',
      identifier: 'K263041',
      status: 'active',
      effectiveDate: '2026-03-14T00:00:00Z',
      expiresAt: null,
      scope: '510(k) premarket clearance',
      evidenceUrl: null,
    },
  },
  { isAdmin: true, annotatedBy: 'regulatory@my-co' },
);
```

The value is stored as given: nothing checks it against the `RegulatoryMarking` type, and the enriched view appends it to `regulatoryMarkings` as it stands, so write every member.

### Command line (Python SDK)

```bash
tzun --storage sqlite:./tzun.db models annotate sha256:f1c3...e89a \
  --type add-regulatory-marking \
  --value '{"authority":"FDA","identifier":"K263041","status":"active","effectiveDate":"2026-03-14T00:00:00Z","expiresAt":null,"scope":"510(k) premarket clearance","evidenceUrl":null}' \
  --reviewer regulatory@my-co \
  --admin
```

Output:

```
Annotated sha256:f1c3...e89a…: add-regulatory-marking
```

With `--json` before the subcommand, the command prints the whole annotation row instead (`annotationId`, `annotatedAt`, `annotatedBy`, `valueJson`, …). Pass `--admin` for every typed kind (only `freeform-note` goes without). The local CLI is its own admin: it opens the store with the admin token it was given, if any, and `--admin` hands that same token back, so no credential is checked. With `TZUN_ADMIN_TOKEN` set, a typed annotation without `--admin` is refused. Set the token in the environment rather than with `--admin-token`, which puts it in `ps` output and shell history.

### What changes — and what doesn't

- **Canonical descriptor bytes:** unchanged. The descriptor row's `canonicalBytes` and the `modelDescriptorDigest` are immutable.
- **Past DEOs:** unchanged. `tzun.verify(evidenceId)` against any prior DEO still passes — the descriptor it references still hashes to the claimed digest.
- **Enriched view:** the next call to `tzun.models.getEnriched(digest)` returns a `ModelDescriptor` with the FDA marking appended to `regulatoryMarkings`. The export bundle (§6 below) carries the enriched view alongside canonical bytes. `getEnriched` reads a local store (`dbPath` / `dbUrl`); the cloud transport does not serve it.

### Retraction

You appended an annotation in error. You can't delete it (the log is append-only by design — auditors need to see the correction trail). You append a `retract` annotation that names it and says why:

```typescript
await tzun.models.annotate(
  'sha256:f1c3...e89a',
  { annotationType: 'retract', value: { retractsAnnotationId: row.annotationId } },
  { isAdmin: true, annotatedBy: 'regulatory@my-co', note: 'entered against the wrong model' },
);
```

The Python CLI takes the same as `--type retract --value '{"retractsAnnotationId":"<annotation id>"}' --note '...' --admin`.

The retracted annotation moves out of the enriched view but stays in the annotation log. Downstream auditors see: *the original marking, the retraction referencing it, and the reason the retraction was issued.*

The seven typed annotation kinds are `add-regulatory-marking`, `add-evaluation`, `set-model-card-url`, `set-license`, `add-training-disclosure`, `add-external-identifier` and `retract`, and every kind but `freeform-note` needs `isAdmin: true`. The rules that apply annotations to the enriched view are in `src/models/enriched-view.ts`.

---

## 5. Verifying DEOs — with and without lineage walk

`tzun.verify(evidenceId)` returns a `VerificationResult` describing whether the envelope's stored digest matches a fresh re-canonicalization of its payload and whether its chain link matches its predecessor. When a contribution step records a model, it also resolves and re-hashes the descriptor the step references and walks the descriptor's parent DAG.

### Full verify — descriptor resolution + lineage walk (the default)

```typescript
const result = await tzun.verify(evidenceId);

if (!result.verified) {
  for (const incident of result.tamperIncidents ?? []) {
    console.error(incident.type, incident);
  }
}

// One entry per contribution step that records a model:
//   { step, descriptorDigest, lineage }
// `lineage` runs leaf to root; each entry is
//   { descriptorDigest, integrityTier, derivation, trainedBy }
for (const { step, lineage } of result.modelLineage ?? []) {
  for (const d of lineage) {
    console.log(`step ${step}: ${d.descriptorDigest}  (${d.integrityTier})`);
  }
}
```

### Lightweight verify — no descriptor resolution

```typescript
const result = await tzun.verify(evidenceId, undefined, { aiBom: false });
// Digest and chain link only: the descriptor is not resolved and the
// lineage is not walked.
```

### Calling the engine directly

`tzun.verify` calls `verifyEnvelope(envelope, previousDigest, registry, options)`. Call it yourself only when you hold an envelope outside a Tzun store:

```typescript
// `verifyEnvelope` is exported by the engine package, not by a subpath of the
// SDK: @tzun/sdk publishes no `exports` map and its built tree is
// `dist/src/**`, so '@tzun/sdk/engine/verify' does not resolve.
import { verifyEnvelope } from '@tzun/engine';

const result = await verifyEnvelope(envelope, predecessorDigest, undefined, {
  storage: tzun.getStorage(),   // where descriptors are resolved
  walkLineage: true,
});
```

`predecessorDigest` is the `canonicalDigest` of the record before it in its chain (`undefined` for sequence number 1). A later record checked without it reports `verified: false`, because its chain link cannot be checked.

### The four descriptor-specific incident types

When the AI-BOM verification path runs (a contribution step records a model AND storage was supplied), four tamper-incident types can surface, each naming the step:

| Incident type | Severity | Meaning |
|---|---|---|
| `descriptor_resolution_failure` | warning | The descriptor digest is not in the catalog. Often benign (cross-environment export, retired vendor). |
| `descriptor_digest_mismatch` | **critical** | The descriptor row's `canonicalBytes` no longer hashes to the claimed digest. Real tampering. |
| `parent_descriptor_resolution_failure` | warning | An ancestor descriptor in the DAG is unresolvable. Lineage walk truncated. |
| `parent_descriptor_digest_mismatch` | **critical** | An ancestor descriptor's bytes don't hash to its claimed digest. Real tampering upstream. |

These flow through the monitoring event bus alongside the chain-tamper incident types and route to whatever notification channels the deployment has configured.

---

## 6. Exporting DEO bundles for offline verification

A regulator, an audit firm, or a customer's litigation-support team wants to verify a decision without your catalog. They get a self-contained JSON bundle.

This export is the SDK's own shape, built to carry the model descriptors. The specification's proof bundle, [Bundle b1](https://spec.tzun.ai/bundle/b1/), is a different document with no member for descriptors: `tzun.exportBundle(evidenceId)` writes one on a local store, and `verifyBundle()` checks it.

### Endpoint

```
GET /v1/evidence/<evidenceId>/export?walkLineage=true
```

Returns an `ExportedEvidenceEnvelope`:

```jsonc
{
  "envelope": {
    "payload": { /* the original DEO payload, incl. contributions.steps[*].aiBom */ },
    "integrity": { "canonicalDigest": "<64 hex>", "chainLink": "<64 hex>" },
    "nonRepudiation": { /* WebAuthn / RFC 3161 / anchor (tzun-anchor/1) artifacts */ },
    "custodyChain": [ /* the mirror of the custody ledger below */ ],
    "attestationStatus": "partial"
  },
  "resolvedModelDescriptors": {
    "sha256:f1c3...e89a": {
      "canonicalBytes": "{...exact bytes the digest was taken over...}",
      "enrichedView": { /* descriptor + applied annotations */ },
      "annotations": [ /* full annotation log for this descriptor */ ]
    },
    "sha256:abcd...0000": {
      /* parent descriptor (walkLineage walked the DAG) */
    }
  },
  "exportedAt": "2026-05-25T20:14:31.842Z",
  "exportedBy": "rest-export",
  // The record's position in its chain: the predecessor `integrity.chainLink`
  // was computed over, so the link can be recomputed with no store access.
  // `predecessor` is null for a genesis record, and for one whose predecessor
  // the store no longer holds — `verdict.chainLink` says which.
  "chain": {
    "chainId": "default",
    "predecessor": { "evidenceId": "...", "sequenceNumber": 41, "canonicalDigest": "<64 hex>" }
  },
  // The custody ledger: the `custody_entries` rows behind every `entryHash` in
  // `envelope.custodyChain`, the rows-against-mirror verdict, and the
  // envelope-only verdict. The hosted service's export carries the same shape.
  "custody": {
    "hashPreimage": "sha256(lp(prevEntryHash)||lp(evidenceId)||...)",
    "entries": [ /* id, action, actor, timestamp, systemId, metadata,
                    canonicalDigest, prevEntryHash, entryHash, recoveryId */ ],
    "trail": { "evidenceId": "...", "valid": true, "rows": 1,
               "hashedEntries": 1, "unhashedEntries": 1, "failures": [] },
    "offlineTrail": { "valid": true, "hashedEntries": 1, "unhashedEntries": 1, "failures": [] }
  },
  // What the exporting store's own checks found. A claim: the receiver
  // recomputes it from the rest of the bundle.
  "verdict": {
    "status": "valid",
    "digest": { "status": "valid", "stored": "<64 hex>", "recomputed": "<64 hex>" },
    "custodyTrail": { "status": "valid", "ledger": { /* = custody.trail */ } },
    "chainLink": { "status": "valid", "predecessorDigest": "<64 hex>" },
    "checkedAt": "2026-05-25T20:14:31.842Z"
  }
}
```

A record that fails its checks is exported all the same, with an `invalid`
verdict — an export is never refused over what the checks found. A custody
ledger or predecessor the store could not read leaves `custody.entries` /
`chain.predecessor` null and the verdict's check `unmeasured` with the error.

Two more members appear on a local export: `resolvedAgentDescriptors`, every
agent descriptor the record's decider and step actors reference
([Record §6.9](https://spec.tzun.ai/record/1.0/#s6-9)), and
`assertionProvenance`, what the record's WebAuthn assertion states (`null` when
it has none). A bundle relayed from the hosted service also carries `server`,
the service's receipt for the record, and has no `exportedAt` / `exportedBy`.

### Programmatic equivalent

```typescript
const bundle = await tzun.exportEvidence(evidenceId, {
  walkLineage: true,
  exportedBy: 'subpoena-response-2026-05',
});

// Hand the bundle to the receiving party as JSON.
```

### Offline verification — what the receiver does

The receiver re-derives every digest in the bundle without contacting your catalog:

1. **Envelope.** Re-canonicalize `bundle.envelope.payload` over the hashed field set ([Record §4.1](https://spec.tzun.ai/record/1.0/#s4-1), [§4.2](https://spec.tzun.ai/record/1.0/#s4-2)), SHA-256 the result, compare to `bundle.envelope.integrity.canonicalDigest`. Any mismatch → tampered.
2. **Per-descriptor.** For each entry in `resolvedModelDescriptors`, SHA-256 the `canonicalBytes` and compare to the dictionary key (the claimed digest). Any mismatch → tampered.
3. **Lineage closure.** Starting from each `bundle.envelope.payload.contributions.steps[*].aiBom.modelDescriptorDigest`, follow `parentModelDescriptorDigest` through the bundled descriptors. Every digest reached must be present in `resolvedModelDescriptors`. Depth-limited (default 16), cycle-safe.
4. **Chain link.** SHA-256(`bundle.chain.predecessor.canonicalDigest` ‖ `bundle.envelope.integrity.canonicalDigest`), over the two digests as hex text ([Record §5](https://spec.tzun.ai/record/1.0/#s5)), must equal `envelope.integrity.chainLink`, and the predecessor must sit at the previous sequence number. A record past genesis with no predecessor in the bundle is a gap: its link cannot be checked, so the bundle proves nothing about the record's position.
5. **Custody trail.** Each `custody.entries` row's `entryHash` must recompute from its own fields and the previous row's hash, and the hashed entries in `envelope.custodyChain` must correspond one to one, in order, with the rows and carry their hashes (`verifyCustodyLedger` in `@tzun/engine`). This is what catches a hashed entry deleted from the end of the mirror, which the envelope alone cannot show.
6. **The verdict.** Recompute it (`recordVerdict` in `@tzun/engine`) and compare with the shipped `verdict`: it is the exporter's claim, not evidence.

A reference offline verifier lives at `tests/ts/helpers/verify-exported.ts` in this repository, built on Node's `createHash('sha256')` plus `canonicalSerialize`, `verifyCustodyLedger` and `recordVerdict` imported from `@tzun/engine`. It also reads the hosted service's export, whose custody block is `server.custody` with the same shape. It is NOT stdlib-only: reimplementing it in another stack means reimplementing the canonicalizer too, which is exactly what `vectors/v1.0-canonical-vectors.json` exists to pin. Any production-grade verifier should match its checklist and validate against that corpus.

`walkLineage=true` is the default and is the right choice for a court-ready bundle: a self-contained export must carry every ancestor descriptor. Use `walkLineage=false` only when bundle size matters and the receiver has confirmed they can resolve ancestors themselves.

---

## 7. Per-vendor recipes (quick reference)

This section repeats the same one-shape recipe per supported vendor. Every vendor:

1. Imports `Tzun` from `@tzun/sdk`.
2. Calls `tzun.attach(client, options?)` (or pairs `tzun.hook()` + `tzun.capture()` explicitly).
3. Adds `tzun_capture: { action, reason, decider }` on the call that drives a decision.

The wrapped client is transparent — your existing call code does not change beyond the optional `tzun_capture` kwarg.

### OpenAI (and Azure OpenAI)

```typescript
import OpenAI from 'openai';

const openai = tzun.attach(new OpenAI());
await openai.chat.completions.create({
  model: 'gpt-4o',
  messages,
  tzun_capture: { action, reason, decider },
});
```

For Azure OpenAI, point an OpenAI-compatible client at the Azure deployment URL; the connector detects the Azure endpoint. For a deployment name it cannot resolve to a model, see §9.

### Anthropic

```typescript
import Anthropic from '@anthropic-ai/sdk';

const anthropic = tzun.attach(new Anthropic());
await anthropic.messages.create({
  model: 'claude-3-7-sonnet-20250219',
  messages,
  tzun_capture: { action, reason, decider },
});
```

### AWS Bedrock

```typescript
import { BedrockRuntimeClient, ConverseCommand } from '@aws-sdk/client-bedrock-runtime';

const bedrock = tzun.attach(new BedrockRuntimeClient({ region }));
const command = new ConverseCommand({ modelId, messages, inferenceConfig });
(command as Record<string, unknown>).tzun_capture = { action, reason, decider };
await bedrock.send(command);
```

The wrapper intercepts every `send()`; a command that carries no `tzun_capture` passes through untouched. The `bedrock` connector reads the command's input: `inferenceConfig` marks a Converse call and `body` an InvokeModel call, which covers `ConverseCommand`, `InvokeModelCommand` and their streaming variants.

### GCP Vertex AI

```typescript
import { VertexAI } from '@google-cloud/vertexai';

const model = vertex.getGenerativeModel({ model: 'gemini-1.5-pro-002' });
const gemini = tzun.attach(model);
await gemini.generateContent({
  contents,
  generationConfig,
  tzun_capture: { action, reason, decider },
});
```

Intercepts both `generateContent` (Gemini) and `predict` (PaLM / publisher models) when present.

### Azure AI Foundry (non-OpenAI surface)

```typescript
import ModelClient from '@azure-rest/ai-inference';
import { AzureKeyCredential } from '@azure/core-auth';

const raw = ModelClient(endpoint, new AzureKeyCredential(key));
const azure = tzun.attach(raw);
await azure.complete({
  model: 'Meta-Llama-3-1-70B-Instruct',
  messages,
  tzun_capture: { action, reason, decider },
});
```

Intercepts `complete` and `getChatCompletions`. For Azure **OpenAI** deployments, use the OpenAI recipe above against an OpenAI-compatible client pointed at the Azure URL.

### NVIDIA NIM

```typescript
import OpenAI from 'openai';

const raw = new OpenAI({ baseURL: 'https://integrate.api.nvidia.com/v1', apiKey });
const nim = tzun.attach(raw, { vendor: 'nvidia-nim' });
await nim.chat.completions.create({
  model: 'meta/llama-3.1-405b-instruct',
  messages,
  tzun_capture: { action, reason, decider },
});
```

NIM shares OpenAI's call surface; `{ vendor: 'nvidia-nim' }` is required to disambiguate. The connector sets `vendor: 'nvidia-nim'` on the descriptor regardless of the underlying client class.

### OpenRouter

```typescript
import OpenAI from 'openai';

const router = tzun.attach(new OpenAI({ baseURL: 'https://openrouter.ai/api/v1', apiKey }));
await router.chat.completions.create({
  model: 'anthropic/claude-sonnet-5.5',
  messages,
  tzun_capture: { action, reason, decider },
});
```

Detected by the client's base URL host (`openrouter.ai`); `wrapOpenRouter(client, tzun)` pins the vendor for any base URL. The descriptor's `vendor` is `openrouter`, `trainedBy` is the author prefix of the served id, `infrastructure.provider` is the upstream OpenRouter reports and `infrastructure.endpoint` is the base URL (see §1).

### Hugging Face Inference Endpoints

```typescript
import { InferenceClient } from '@huggingface/inference';

const hf = tzun.attach(new InferenceClient(process.env.HF_TOKEN));
await hf.chatCompletion({
  model: 'meta-llama/Meta-Llama-3-8B-Instruct',
  messages,
  tzun_capture: { action, reason, decider },
});
```

Intercepts `chatCompletion` and `textGeneration`.

### `AttachOptions`

```typescript
interface AttachOptions {
  vendor?: 'openai' | 'anthropic' | 'bedrock' | 'vertex'
         | 'azure-ai' | 'nvidia-nim' | 'hf-inference'
         | 'openrouter';                                  // Explicit override (required for NIM)
  aiSystemId?: string;                                    // Default aiSystemId on captured DEOs
  emitAiBom?: boolean;                                    // Default true; false is a CAPTURE kill-switch, not just an AI-BOM one
  cacheCapacity?: number;                                 // Declared, not read: the hook cache holds 256 entries
  knownModels?: KnownModelsReference;                     // Declared, not read: the bundled reference is used
}
```

---

## 8. Integrity-event recovery

When the verifier (or the background `ScheduledScanner`) detects an integrity event — chain digest mismatch, descriptor digest mismatch, signature failure — Tzun does not "fix" the chain automatically. Recovery is a human decision routed through one of three first-class tiers.

### Three-tier comparison

**Annotate (Tier 1):**
- Use when: the discrepancy is explainable historical truth — false alarm, known environment issue, benign drift.
- Footprint: point. One annotation row appended to the audit log.
- Audit trail value: "System detected a discrepancy, human reviewed, attributed it to <cause>." Highest-trust outcome for false alarms.
- Example: env clock drift caused the digest mismatch. Reviewer documents, chain extends as normal.

**Re-link (Tier 2):**
- Use when: chain links are broken but the records are intact: each record in and beside the range hashes to its stored digest, and that digest is the one it was captured with.
- Footprint: forward. Links are recomputed from `fromSequence` to the chain head (or `toSequence`) within one chain; no payload or digest is written, and each record whose link changes gets a custody entry naming the re-link.
- Audit trail value: "System detected a broken link, human confirmed the records were intact, links recomputed forward." Shows correction trail.
- Example: a bulk import wrote the link of record 12,400 from the wrong predecessor; every payload still hashes to its stored digest.
- Not for: a record whose content is wrong. Re-link refuses a corrected payload; capture a corrected record, and annotate the incident (Tier 1) or fork (Tier 3).

**Fork (Tier 3):**
- Use when: data is unrecoverable — storage loss, catastrophic corruption.
- Footprint: branch. Old chain sealed; new chain starts at sequence number 1.
- Audit trail value: "System detected catastrophic loss, sealed the impacted chain, started a fresh one with full continuity record."
- Example: a storage event lost records 12,400 to 12,450. Chain unrecoverable; start fresh.

### Decision-tree flowchart

```
                  Integrity event detected
                            │
            ┌───────────────┴───────────────┐
      Is the discrepancy             Are the records intact
      explainable historical          and only the chain
      truth?                          links broken?
            │                                │
          yes                              yes
            │                                │
            ↓                                ↓
      ANNOTATE                          RE-LINK
      (footprint: point)                (footprint: forward)
      chain remains operational         links recomputed forward
      annotation row appended           no record rewritten
            │                                │
            │            no to both          │
            └────────────────┬───────────────┘
                             ↓
                        Is the data
                        unrecoverable?
                             │
                           yes
                             │
                             ↓
                        FORK
                        (footprint: branch)
                        seal old, start new chain
```

### Wiring recovery

The three recovery actions are exposed under `tzun.recovery`:

```typescript
// Tier 1 — annotate
await tzun.recovery.annotate(incidentId, {
  authorizedBy: 'jdoe@example.com',
  notes: 'env clock drift; verified against NTP logs',
});

// Tier 2 — re-link (admin). Recomputes chain LINKS from `fromSequence` to the
// chain head (or `toSequence`). It never rewrites a payload — `correctedPayload`
// is refused — and it refuses a range whose payloads do not hash to their
// stored digests.
await tzun.recovery.relink(incidentId, {
  authorizedBy: 'mchan@example.com',
  chainId: 'default',   // sequences restart per chain, so name the chain
  fromSequence: 12400,  // first record whose link is recomputed
});

// Tier 3 — fork (last resort)
await tzun.recovery.fork(incidentId, {
  authorizedBy: 'lwong@example.com',
  reason: 'storage event 2026-04-12; records 12400-12450 unrecoverable',
  forkAfterSequence: 12399, // last trusted sequence; the new chain starts after it
});
```

`tzun.recovery` itself checks no role: code that holds the Tzun instance can call all three tiers. A service that exposes recovery over HTTP should gate tiers 2 and 3 behind an admin credential; tier 1 can stay open to any authenticated reviewer.

---

## 9. Troubleshooting

The five most common issues integrators hit:

### `descriptor_not_registered` failure on capture

**Symptom:** `tzun.capture(...)` returns `{ stored: false, failure: { failureType: 'descriptor_not_registered' } }`.

**Cause:** The `modelDescriptorDigest` of a contribution step's `aiBom` (`contributions.steps[i].aiBom`) is not in the local catalog. This happens when an application references a digest produced in a different environment, or when registration was skipped.

**Fix (option A — register first):**

```typescript
const { digest } = await tzun.models.register({
  vendor: 'my-co',
  modelName: 'credit-scorer',
  modelVersion: 'v2.3.1',
}, { weightsPath: '/opt/models/credit-scorer-v2.3' });

await tzun.capture({ /* ... */, contributions: singleModel({ modelDescriptorDigest: digest, /* ... */ }) });
```

**Fix (option B — convenience form):**

A step's `aiBom` may carry an inline full descriptor; the SDK registers-if-absent and substitutes the digest:

```typescript
await tzun.capture({
  // ...
  contributions: singleModel({
    modelDescriptor: {  // <-- full ModelDescriptor instead of a digest
      vendor: 'my-co',
      modelName: 'credit-scorer',
      modelVersion: 'v2.3.1',
      // ... remaining fields
    },
    vendorFingerprint: null,
    promptTemplate: null,
    inferenceParameters: null,
    infrastructure: null,
  }),
});
```

This is the `AiBomWithInlineDescriptor` form. The SDK normalizes it to the digest-reference form before envelope assembly, so the wire shape is identical. On the cloud transport it is registered in the hosted service's catalog. A store with no model catalog cannot register it: there (the cloud transport against a service that does not serve `POST /v1/models`, or an adapter without `registerModelDescriptor`) the capture is refused (`validation_failure`, code `invalid_step_ai_bom`), and a pre-built digest the catalog does not hold is refused on every store (`descriptor_not_registered`).

### `descriptor_digest_mismatch` after a manual annotation

**Symptom:** Verifier emits `descriptor_digest_mismatch` shortly after a `tzun models annotate` call.

**Cause:** **Not the annotation.** Annotations don't mutate the canonical descriptor — the digest cannot change because of an annotation. If the verifier reports `descriptor_digest_mismatch`, the catalog row's `canonicalBytes` was tampered with by something other than `tzun.models.annotate`.

**Fix:** Treat this as a real tamper incident. Run the recovery decision tree (§8). The most likely cause is a direct write to the storage backend bypassing the SDK; check audit logs on the storage layer. The annotation log is undisturbed and can be re-applied to a known-good descriptor row.

### Unknown deployment name (Azure OpenAI)

**Symptom:** `tzun.attach()` against an Azure OpenAI endpoint registers a descriptor with a deployment name (e.g., `my-prod-deployment-001`) as the model name instead of the underlying model (`gpt-4o-2024-08-06`).

**Cause:** The Azure deployment name is opaque to the connector by default. Without a hint, the connector falls back to using the deployment name verbatim.

**Fix:** Register the underlying model and name it yourself with `aiBom` inside `tzun_capture`, which takes the place of the AI-BOM the wrapper would have built:

```typescript
const { digest } = await tzun.models.register({
  vendor: 'openai',
  modelName: 'gpt-4o',
  modelVersion: '2024-08-06',
});

await openai.chat.completions.create({
  model: 'my-prod-deployment-001',
  messages,
  tzun_capture: {
    action,
    reason,
    decider,
    aiBom: {
      modelDescriptorDigest: digest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    },
  },
});
```

The connector itself resolves a deployment name only through the bundled known-models reference (`data/known-models.json`, shipped in the package): an `openai` entry that carries an external identifier `{ "scheme": "azure-deployment-name", "value": "<deployment name>" }`. The `knownModels` attach option is declared but not read, so a reference of your own cannot be supplied that way. The wrapper still runs `hook()` on the call, so the deployment-name descriptor it infers is registered in the catalog all the same; the record names only your `aiBom`.

### Capture not firing when `tzun_capture` is present

**Symptom:** A wrapped client carries `tzun_capture` on a call, but no envelope is persisted (or `contributions: null` on the resulting DEO).

**Cause(s) — check in order:**

1. **`emitAiBom: false`** was passed in `AttachOptions`. With the kill-switch active, intercepted calls become pure pass-through — `tzun_capture` is still stripped from the forwarded params, but no capture fires. Despite the name this disables *evidence capture*, not merely the AI-BOM: if you set it to dodge `descriptor_not_registered` on the cloud transport you will lose every record. A call that carried `tzun_capture` while the switch was off emits `capture_skipped { vendor, reason: 'emitAiBom:false' }` on `TzunConfig.onLog`, so grep your telemetry for that event before concluding evidence was never produced.
2. **`tzun_capture` is `null` or `undefined`.** Either form is treated as absent; the call passes through without capture.
3. **No `model` field on the response.** The connector returns `null` when the vendor response doesn't include a model identifier (some streaming-only paths, partial responses). The DEO captures, but with `contributions: null`, and `connector_no_aibom { vendor }` is logged.
4. **Explicit `aiBom: null` inside `tzun_capture`.** The caller can override the wrapper-built AI-BOM; if `tzun_capture.aiBom === null`, that wins.
5. **The cloud transport (`apiKey`) against a service that does not serve the model catalog** (`POST /v1/models` answers 405, 501, or the service's catch-all `404 { error: 'not_found' }`). The wrapper cannot record the model: the DEO captures with `contributions: null`, and `capture_model_not_recordable { vendor, modelName, reason: 'store_has_no_model_catalog' }` is logged. The SDK asks again every 5 minutes (`CATALOG_REPROBE_MS`), so it records models once the service serves the endpoint. Any other failed registration (a 5xx, a 401, a timeout, or a 404 page from the edge during a deploy) costs that one call its model, logs `connector_hook_failure`, and the next call registers it.
6. **A long-running cloud client whose service's catalog was rebuilt.** The process keeps the digests it registered for its lifetime, so it goes on naming descriptors the rebuilt catalog does not hold, and those captures are refused (`descriptor_not_registered`). Restart every cloud-mode client after such a rebuild.

Walk through your attach config and the response shape from the vendor SDK. A connector failure or a failed descriptor registration does not reject the wrapped call: the DEO captures with `contributions: null` and `connector_hook_failure { vendor, errorName }` is logged. A capture that is refused logs `capture_failure { vendor, failureType, … }`; the vendor response is returned either way.

### Scanner load too high

**Symptom:** Scheduled scan passes are consuming significant CPU or hitting your storage adapter aggressively after the AI-BOM rollout.

**Cause:** The scanner walks the parent DAG of every DEO when verifying descriptors.

**Fix:** Disable descriptor verification on the scanner while keeping it on the on-demand verifier:

```typescript
await Tzun.init({
  monitoring: {
    enabled: true,
    scanner: {
      batchSize: 100,
      workers: 2,
      mode: 'interval',
      intervalMs: 15 * 60 * 1000,      // a schedule: Tzun.init() starts the loop
      verifyAttestation: false,
      verifyChainCompleteness: true,
      scannerVerifyDescriptors: false, // <-- skip descriptor + DAG walk on the scanner
    },
  },
});
```

A scanner with a schedule — `mode: 'interval'` with `intervalMs > 0`, or `mode: 'continuous'` — is started by `Tzun.init()` and stopped by `tzun.close()`. Its timer never holds the process open. With `intervalMs: 0`, or `autoStart: false`, nothing scans until you call `tzun.runScan()` — the model to use under serverless or cron, where an in-process timer does not survive between invocations, and when several processes share one store and a single worker should scan it.

On-demand `tzun.verify(evidenceId)` calls still do the full check. The trade-off: descriptor tampering is detected at verification time (or audit time), not by background scan. For most deployments where the catalog is rarely overwritten outside the SDK, that's the right trade-off.

---

## Where to go next

- **Specification:** [spec.tzun.ai](https://spec.tzun.ai) — the DEO record format, including contributions and the step bill of materials ([Record §7](https://spec.tzun.ai/record/1.0/#s7)) and agent descriptors ([Record §6.9](https://spec.tzun.ai/record/1.0/#s6-9)).
- **Types:** `packages/engine/src/types/ai-bom.ts` — the authoritative TypeScript types for `AiBom`, `ModelDescriptor`, `ExportedEvidenceEnvelope`, annotation rows, and catalog rows, published in `@tzun/engine`.
- **Contributing:** [CONTRIBUTING.md](../../CONTRIBUTING.md) — building and testing the SDK itself.
