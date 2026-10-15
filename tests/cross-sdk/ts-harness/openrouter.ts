/**
 * Cross-SDK harness for the OpenRouter connector — Node side.
 *
 * Reads one JSON command from stdin, runs it against the in-repo TS SDK
 * (never a published version), and writes one JSON result to stdout.
 * tests/cross-sdk/test_openrouter_parity.py drives it and compares every
 * answer with `tzun_sdk.ai_bom.connectors`.
 *
 * Every command batches its work, so one Node start answers a whole table.
 *
 *   { action: "helpers", ids: string[], urls: unknown[] }
 *     → { ids: [{ id, author, variantBase, parsed: { modelName, modelVersion } }],
 *         urls: [{ url, endpoint, isOpenRouter }] }
 *     `openRouterAuthor`, `openRouterVariantBase` and `parseModelId('openrouter', id)`
 *     for each id; `openRouterEndpoint` and `isOpenRouterBaseUrl` for each url.
 *
 *   { action: "aibom", cases: [{ request, response }], knownModels?: object }
 *     → { results: [{ skeleton, descriptorCanonical, descriptorDigest,
 *                     aiBomCanonical, aiBomDigest } | { skeleton: null }] }
 *     Runs each pair through the `openrouter` connector with the bundled
 *     known-models catalog (or the one given), then canonicalises the
 *     descriptor (`canonicalSerializeDescriptor`) and the wire `aiBom` the
 *     skeleton becomes once that descriptor's digest replaces it.
 */

import { canonicalSerialize, canonicalSerializeDescriptor } from '@tzun/engine';
import { createHash } from 'node:crypto';
import {
  openRouterConnector,
  openRouterEndpoint,
  isOpenRouterBaseUrl,
} from '../../../src/sdk/connectors/openrouter';
import {
  openRouterAuthor,
  openRouterVariantBase,
  parseModelId,
} from '../../../src/models/import-vendor';
import { loadKnownModels, type KnownModelsReference } from '../../../src/models/known-models';

type Command =
  | { action: 'helpers'; ids: string[]; urls: unknown[] }
  | {
      action: 'aibom';
      cases: Array<{ request: Record<string, unknown>; response: Record<string, unknown> }>;
      knownModels?: KnownModelsReference;
    };

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
  });
}

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

async function main(): Promise<void> {
  const cmd = JSON.parse(await readStdin()) as Command;
  let result: unknown;
  if (cmd.action === 'helpers') {
    result = {
      ids: cmd.ids.map((id) => ({
        id,
        author: openRouterAuthor(id),
        variantBase: openRouterVariantBase(id),
        parsed: parseModelId('openrouter', id),
      })),
      urls: cmd.urls.map((url) => ({
        url,
        endpoint: openRouterEndpoint(url),
        isOpenRouter: isOpenRouterBaseUrl(url),
      })),
    };
  } else if (cmd.action === 'aibom') {
    const knownModels = cmd.knownModels ?? (await loadKnownModels());
    result = {
      results: cmd.cases.map(({ request, response }) => {
        const skeleton = openRouterConnector.buildAiBom(request, response, knownModels);
        if (skeleton === null) return { skeleton: null };
        const descriptorCanonical = canonicalSerializeDescriptor(skeleton.modelDescriptor);
        const descriptorDigest = `sha256:${sha256(descriptorCanonical)}`;
        const aiBom: Record<string, unknown> = {
          modelDescriptorDigest: descriptorDigest,
          vendorFingerprint: skeleton.vendorFingerprint,
          promptTemplate: skeleton.promptTemplate,
          inferenceParameters: skeleton.inferenceParameters,
          infrastructure: skeleton.infrastructure,
        };
        const aiBomCanonical = canonicalSerialize(aiBom, Object.keys(aiBom).sort());
        return {
          skeleton,
          descriptorCanonical,
          descriptorDigest,
          aiBomCanonical,
          aiBomDigest: sha256(aiBomCanonical),
        };
      }),
    };
  } else {
    throw new Error(`Unknown action: ${(cmd as { action: unknown }).action}`);
  }
  process.stdout.write(JSON.stringify(result));
}

main().catch((err) => {
  process.stderr.write(String(err instanceof Error ? err.stack : err));
  process.exit(1);
});
