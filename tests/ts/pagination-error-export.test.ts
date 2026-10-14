/**
 * `InvalidPaginationError` is reachable from both packages' entry points, as
 * ONE class.
 *
 * It was declared in `src/storage/pagination-guard.ts` and exported from
 * neither index, so a consumer application kept a local class of the same
 * name whose only purpose was to name the same refusal. The class now lives
 * in the engine, beside the `ListOptions` contract it enforces, and the SDK
 * re-exports it: an `instanceof` against either import catches what any
 * adapter throws.
 */
import { InvalidPaginationError as EngineInvalidPaginationError } from '@tzun/engine';
import { InvalidPaginationError, Tzun } from '../../src/sdk/index';
import { InvalidPaginationError as GuardInvalidPaginationError } from '../../src/storage/pagination-guard';

describe('InvalidPaginationError is exported', () => {
  it('is one class, whichever entry point it is imported from', () => {
    expect(InvalidPaginationError).toBe(EngineInvalidPaginationError);
    expect(GuardInvalidPaginationError).toBe(EngineInvalidPaginationError);
  });

  it.each([
    ['memory', {}],
    ['sqlite', { dbPath: ':memory:' }],
  ])('is what a %s list() throws for a string limit, with its code', async (_label, storage) => {
    const tzun = await Tzun.init({ mode: 'dev', ...storage });
    try {
      const refused = tzun.list({ limit: '10' as unknown as number });
      await expect(refused).rejects.toBeInstanceOf(InvalidPaginationError);
      await expect(refused).rejects.toMatchObject({ code: 'invalid_pagination', field: 'limit' });
    } finally {
      await tzun.close();
    }
  });
});
