/**
 * GCP Vertex AI connector tests.
 *
 * Vertex has TWO API surfaces; this file exercises both:
 *
 *   1. generateContent: params.model + params.contents + params.generationConfig
 *      (Gemini-family models)
 *   2. predict: params.endpoint + params.instances + params.parameters
 *      (PaLM-family + general publisher models)
 *
 * Dispatch discriminator:
 *   - presence of params.generationConfig → generateContent
 *   - presence of params.instances        → predict
 *
 * Field mapping (Vertex row):
 *   generateContent: generationConfig.{temperature, topP, maxOutputTokens,
 *                                       stopSequences}
 *                    (note `maxOutputTokens`, not `max_tokens`)
 *   predict:         parameters.{temperature, topP, maxOutputTokens,
 *                                 stopSequences}
 */

import { vertexConnector } from '../../../src/sdk/connectors/vertex';
import { AiBomSkeleton } from '../../../src/sdk/connectors/base';
import {
  loadKnownModels,
  KnownModelsReference,
} from '../../../src/models/known-models';

describe('Vertex connector', () => {
  let known: KnownModelsReference;

  beforeAll(async () => {
    known = await loadKnownModels();
  });

  // ── generateContent surface ───────────────────────────────────────

  describe('generateContent surface', () => {
    it('extracts AiBom skeleton from a Vertex generateContent call', () => {
      const params = {
        model: 'gemini-1.5-pro-001',
        contents: [{ role: 'user', parts: [{ text: 'hi' }] }],
        generationConfig: {
          temperature: 0.2,
          topP: 0.9,
          maxOutputTokens: 1024,
          stopSequences: ['END'],
        },
        location: 'us-central1',
      };
      const response = {
        candidates: [{ content: { role: 'model', parts: [{ text: 'hi' }] } }],
      };

      const skel = vertexConnector.buildAiBom(params, response, known);
      expect(skel).not.toBeNull();
      const s = skel as AiBomSkeleton;

      expect(s.modelDescriptor.vendor).toBe('vertex');
      expect(s.modelDescriptor.modelName).toBe('gemini-1.5-pro');
      expect(s.modelDescriptor.modelVersion).toBe('001');
      // Enriched from the seeded known-models entry.
      expect(s.modelDescriptor.license).toBe('google-commercial');
      expect(s.modelDescriptor.trainedBy).toBe('Google');

      expect(s.inferenceParameters).toEqual({
        temperature: 0.2,
        topP: 0.9,
        maxTokens: 1024,
        seed: null,
        stopSequences: ['END'],
      });

      expect(s.infrastructure).toEqual({
        provider: 'gcp-vertex',
        region: 'us-central1',
        apiVersion: null,
        endpoint: null,
      });
      expect(s.vendorFingerprint).toBeNull();
    });

    it('generateContent: region null when params.location absent', () => {
      const params = {
        model: 'gemini-1.5-flash-001',
        generationConfig: { temperature: 0.4 },
      };
      const response = {};
      const skel = vertexConnector.buildAiBom(params, response, known);
      expect((skel as AiBomSkeleton).infrastructure?.region).toBeNull();
      expect((skel as AiBomSkeleton).infrastructure?.provider).toBe(
        'gcp-vertex',
      );
    });
  });

  // ── predict surface ────────────────────────────────────────────────

  describe('predict surface', () => {
    it('extracts AiBom skeleton from a Vertex predict call', () => {
      const params = {
        endpoint:
          'projects/p/locations/us-central1/publishers/google/models/gemini-1.5-pro-001',
        instances: [{ content: 'hi' }],
        parameters: {
          temperature: 0.3,
          topP: 0.85,
          maxOutputTokens: 2048,
          stopSequences: ['STOP', 'END'],
        },
        location: 'us-central1',
      };
      const response = { predictions: [{ content: 'hi' }] };

      const skel = vertexConnector.buildAiBom(params, response, known);
      expect(skel).not.toBeNull();
      const s = skel as AiBomSkeleton;

      expect(s.modelDescriptor.vendor).toBe('vertex');
      // The model id is parsed out of the endpoint resource path.
      expect(s.modelDescriptor.modelName).toBe('gemini-1.5-pro');
      expect(s.modelDescriptor.modelVersion).toBe('001');

      expect(s.inferenceParameters).toEqual({
        temperature: 0.3,
        topP: 0.85,
        maxTokens: 2048,
        seed: null,
        stopSequences: ['STOP', 'END'],
      });
      expect(s.infrastructure?.provider).toBe('gcp-vertex');
    });

    it('predict: extracts model id from endpoint when no separate model field', () => {
      const params = {
        endpoint: 'publishers/google/models/gemini-1.5-flash-001',
        instances: [{ content: 'hi' }],
        parameters: {},
      };
      const response = {};
      const skel = vertexConnector.buildAiBom(params, response, known);
      const s = skel as AiBomSkeleton;
      expect(s.modelDescriptor.modelName).toBe('gemini-1.5-flash');
      expect(s.modelDescriptor.modelVersion).toBe('001');
    });
  });

  // ── Dispatch discrimination ────────────────────────────────────────

  describe('dispatch', () => {
    it('routes to generateContent when params.generationConfig is present', () => {
      const params = {
        model: 'gemini-1.5-pro-001',
        // Both shapes attached — generationConfig wins.
        generationConfig: { temperature: 0.1 },
        instances: [{ content: 'hi' }],
        parameters: { temperature: 0.9 },
      };
      const response = {};
      const skel = vertexConnector.buildAiBom(params, response, known);
      const s = skel as AiBomSkeleton;
      expect(s.inferenceParameters?.temperature).toBe(0.1);
    });

    it('routes to predict when params.instances is present and generationConfig absent', () => {
      const params = {
        endpoint: 'publishers/google/models/gemini-1.5-pro-001',
        instances: [{ content: 'hi' }],
        parameters: { temperature: 0.7 },
      };
      const response = {};
      const skel = vertexConnector.buildAiBom(params, response, known);
      const s = skel as AiBomSkeleton;
      expect(s.inferenceParameters?.temperature).toBe(0.7);
    });
  });

  // ── Missing-model behavior ────────────────────────────────────────

  it('returns null when neither params.model nor params.endpoint identify a model', () => {
    const params = { generationConfig: { temperature: 0.5 } };
    const response = {};
    const skel = vertexConnector.buildAiBom(params, response, known);
    expect(skel).toBeNull();
  });

  // ── Connector vendor identity ─────────────────────────────────────

  it('exposes vendor = "vertex"', () => {
    expect(vertexConnector.vendor).toBe('vertex');
  });
});
