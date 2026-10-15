/**
 * Connector registry.
 *
 * Single import surface for the eight AI-BOM connectors. The wrapper layer
 * consumes `getConnector(vendor)` to dispatch per-vendor without hard-coding
 * the vendor → module map at every call site.
 *
 * Registry keys are the conventional vendor strings used throughout the
 * AI-BOM stack (matching `SupportedVendor` in `src/models/import-vendor.ts`
 * and the `vendor` field of the bundled known-models entries).
 */

import type { Connector } from './base';
import { openAiConnector } from './openai';
import { anthropicConnector } from './anthropic';
import { bedrockConnector } from './bedrock';
import { vertexConnector } from './vertex';
import { azureAiConnector } from './azure-ai';
import { nimConnector } from './nim';
import { hfInferenceConnector } from './hf-inference';
import { openRouterConnector } from './openrouter';

export const connectorRegistry: Record<string, Connector> = {
  openai: openAiConnector,
  anthropic: anthropicConnector,
  bedrock: bedrockConnector,
  vertex: vertexConnector,
  'azure-ai': azureAiConnector,
  'nvidia-nim': nimConnector,
  'hf-inference': hfInferenceConnector,
  openrouter: openRouterConnector,
};

/**
 * Lookup accessor — returns the registered connector for `vendor`, or
 * `undefined` when the vendor string is not in the registry. The wrapper
 * layer uses `undefined` as the "no connector → capture without aiBom"
 * signal.
 */
export function getConnector(vendor: string): Connector | undefined {
  return connectorRegistry[vendor];
}

export type { Connector, AiBomSkeleton } from './base';
