/**
 * What a consumer such as the hosted service would have to copy unless the
 * engine exports it.
 *
 * The type imports are the test: ts-jest type-checks this file, so an export
 * dropped from the index fails the suite at compile time.
 */
import {
  determineAttestationStatus,
  InvalidPaginationError,
  isRetryObtainableComponent,
  missingAttestationComponents,
} from './index';
import type {
  AttestationExpectation,
  ObtainableAttestationComponent,
  RetryObtainableComponent,
} from './index';

describe('the attestation-expectation types', () => {
  it('names the expectation and the components it can leave missing', () => {
    const expected: AttestationExpectation = { timestamp: true, anchor: true };
    const missing: ObtainableAttestationComponent[] = missingAttestationComponents({}, expected);
    expect(missing).toEqual(['timestamp', 'anchor']);
    expect(determineAttestationStatus({}, 'a'.repeat(64), expected)).toBe('pending');
  });

  // The retry lists and obtains the retry-obtainable part only.
  it('splits the components into retry-obtainable and the anchor', () => {
    const missing = missingAttestationComponents({}, { timestamp: true, anchor: true });
    const retry: RetryObtainableComponent[] = missing.filter(isRetryObtainableComponent);
    expect(retry).toEqual(['timestamp']);
  });
});

describe('InvalidPaginationError', () => {
  it('names the refusal of the ListOptions pagination contract, by name and by code', () => {
    const err = new InvalidPaginationError('limit', '10');
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('InvalidPaginationError');
    expect(err.code).toBe('invalid_pagination');
    expect(err.field).toBe('limit');
    expect(err.received).toBe('10');
    expect(err.message).toBe('Invalid limit: expected a non-negative integer, received "10".');
  });
});
