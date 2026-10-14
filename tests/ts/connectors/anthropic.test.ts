/**
 * Anthropic connector tests.
 *
 * Field mapping (Anthropic row):
 *   - params.temperature      → inferenceParameters.temperature
 *   - params.top_p            → inferenceParameters.topP
 *   - params.max_tokens       → inferenceParameters.maxTokens
 *   - params.stop_sequences   → inferenceParameters.stopSequences
 *                               (Anthropic uses `stop_sequences`, not `stop`)
 *   - response.model          → drives modelName/modelVersion resolution
 *
 * Anthropic does not expose `system_fingerprint` or `seed`; both surface as
 * null in the AiBom skeleton. Infrastructure is null — the Anthropic direct
 * surface is a single SaaS endpoint with no per-call region/endpoint metadata.
 */

import { anthropicConnector } from '../../../src/sdk/connectors/anthropic';
import { AiBomSkeleton } from '../../../src/sdk/connectors/base';
import {
  loadKnownModels,
  KnownModelsReference,
} from '../../../src/models/known-models';

describe('Anthropic connector', () => {
  let known: KnownModelsReference;

  beforeAll(async () => {
    known = await loadKnownModels();
  });

  // ── Happy path ─────────────────────────────────────────────────────

  it('extracts AiBom skeleton from a direct Anthropic messages call', () => {
    // The id is the real `response.model` shape, `claude-3-5-sonnet-20241022`:
    // an undashed date snapshot that splits off as the modelVersion.
    const params = {
      model: 'claude-3-5-sonnet-20241022',
      temperature: 0.3,
      top_p: 0.8,
      max_tokens: 2048,
      stop_sequences: ['END'],
      messages: [{ role: 'user', content: 'hi' }],
    };
    const response = {
      id: 'msg_01abc',
      type: 'message',
      role: 'assistant',
      model: 'claude-3-5-sonnet-20241022',
      content: [{ type: 'text', text: 'hi' }],
    };

    const skel = anthropicConnector.buildAiBom(params, response, known);
    expect(skel).not.toBeNull();
    const s = skel as AiBomSkeleton;

    expect(s.modelDescriptor.vendor).toBe('anthropic');
    expect(s.modelDescriptor.modelName).toBe('claude-3-5-sonnet');
    expect(s.modelDescriptor.modelVersion).toBe('20241022');
    // Enriched from the seeded known-models entry.
    expect(s.modelDescriptor.license).toBe('anthropic-commercial');
    expect(s.modelDescriptor.modelType).toBe('llm');
    expect(s.modelDescriptor.trainedBy).toBe('Anthropic');

    expect(s.vendorFingerprint).toBeNull();
    expect(s.inferenceParameters).toEqual({
      temperature: 0.3,
      topP: 0.8,
      maxTokens: 2048,
      seed: null,
      stopSequences: ['END'],
    });
    expect(s.infrastructure).toBeNull();
    expect(s.promptTemplate).toBeNull();
  });

  // ── Parameter mapping ──────────────────────────────────────────────

  it('uses stop_sequences (not stop) for stopSequences mapping', () => {
    const params = {
      model: 'claude-3-5-sonnet-20241022',
      stop_sequences: ['FIRST', 'SECOND'],
      // OpenAI-style `stop` is intentionally ignored — Anthropic doesn't use it.
      stop: 'ignored',
    };
    const response = { model: 'claude-3-5-sonnet-20241022' };
    const skel = anthropicConnector.buildAiBom(params, response, known);
    expect((skel as AiBomSkeleton).inferenceParameters?.stopSequences).toEqual([
      'FIRST',
      'SECOND',
    ]);
  });

  it('stopSequences is null when stop_sequences is absent', () => {
    const params = { model: 'claude-3-5-sonnet-20241022' };
    const response = { model: 'claude-3-5-sonnet-20241022' };
    const skel = anthropicConnector.buildAiBom(params, response, known);
    expect(
      (skel as AiBomSkeleton).inferenceParameters?.stopSequences,
    ).toBeNull();
  });

  it('handles missing optional params gracefully (all null)', () => {
    const params = { model: 'claude-3-5-sonnet-20241022' };
    const response = { model: 'claude-3-5-sonnet-20241022' };
    const skel = anthropicConnector.buildAiBom(params, response, known);
    expect(skel).not.toBeNull();
    const s = skel as AiBomSkeleton;

    expect(s.inferenceParameters).toEqual({
      temperature: null,
      topP: null,
      maxTokens: null,
      seed: null,
      stopSequences: null,
    });
    expect(s.vendorFingerprint).toBeNull();
    expect(s.infrastructure).toBeNull();
  });

  /**
   * A dashed date (`claude-3-5-sonnet-2024-10-22`) is not an Anthropic
   * snapshot, and the Anthropic API never returns one: the connector must keep
   * the id whole and must not enrich, because a seed key matching it would be
   * one no real response could ever produce.
   */
  it('does NOT split or enrich a synthetic dashed-date id', () => {
    const params = { model: 'claude-3-5-sonnet-2024-10-22' };
    const response = { model: 'claude-3-5-sonnet-2024-10-22' };
    const skel = anthropicConnector.buildAiBom(params, response, known);
    const s = skel as AiBomSkeleton;
    expect(s.modelDescriptor.modelName).toBe('claude-3-5-sonnet-2024-10-22');
    expect(s.modelDescriptor.modelVersion).toBe('unknown');
    expect(s.modelDescriptor.license).toBeNull();
  });

  it('enriches a current-generation id that carries no snapshot suffix', () => {
    const skel = anthropicConnector.buildAiBom(
      { model: 'claude-sonnet-4-6' },
      { model: 'claude-sonnet-4-6' },
      known,
    );
    const s = skel as AiBomSkeleton;
    expect(s.modelDescriptor.modelName).toBe('claude-sonnet-4-6');
    expect(s.modelDescriptor.modelVersion).toBe('unknown');
    expect(s.modelDescriptor.license).toBe('anthropic-commercial');
  });

  // ── Missing-model behavior ────────────────────────────────────────

  it('returns null when response has no model field', () => {
    const params = { model: 'claude-3-5-sonnet-20241022' };
    const response = { id: 'msg_x', type: 'message' };
    const skel = anthropicConnector.buildAiBom(params, response, known);
    expect(skel).toBeNull();
  });

  // ── Connector vendor identity ─────────────────────────────────────

  it('exposes vendor = "anthropic"', () => {
    expect(anthropicConnector.vendor).toBe('anthropic');
  });

  // ── Determinism ────────────────────────────────────────────────────

  it('is a pure transform — same input yields equal AiBom skeletons', () => {
    const params = {
      model: 'claude-3-5-sonnet-20241022',
      temperature: 0.5,
      top_p: 0.95,
      max_tokens: 1024,
      stop_sequences: ['STOP'],
    };
    const response = { model: 'claude-3-5-sonnet-20241022' };
    const a = anthropicConnector.buildAiBom(params, response, known);
    const b = anthropicConnector.buildAiBom(params, response, known);
    expect(a).toEqual(b);
  });
});
