/**
 * `tzun.agents` (Record §6.9): register, read and list `tzun-agent/1`
 * descriptors in the store's agent catalog.
 *
 *   - `register(descriptor)` takes a JSON copy of the descriptor, checks the
 *     copy (the grammar, the writer limits, no U+0000 in `name` or
 *     `operator.organization`; `InvalidAgentDescriptorError`, code
 *     `invalid_agent_descriptor`) and hands the copy to the store, which
 *     keeps its canonical bytes under its digest. It answers `{ digest,
 *     alreadyExisted }`, idempotently on identical bytes: the order a set was
 *     assembled in does not change the digest.
 *   - `get(digest)` returns the row as stored (`canonicalBytes` are the bytes
 *     that were hashed), or `null`.
 *   - `list({ name?, organization?, limit?, cursor? })` pages through the
 *     catalog in registration order, at most 200 rows a page (default 100);
 *     pass the returned `cursor` for the next page, which is `null` after the
 *     last. A cursor is the store's own: a decimal string from a local store,
 *     and the platform's cursor, passed back unread, on the cloud transport.
 *     A `limit` or `cursor` the store cannot use is refused
 *     (`InvalidPaginationError`), a lookup value that is not a string with a
 *     `TypeError`.
 *
 * A store without the catalog (an adapter without the methods, or one whose
 * methods answer `agent_not_supported_by_store`, as the cloud transport does
 * against a platform that does not serve the agent endpoints) refuses all
 * three with `AgentCatalogUnsupportedError` (code
 * `agent_not_supported_by_store`).
 */
import type { AgentDescriptor, AgentDescriptorRow, StorageAdapter } from '@tzun/engine';
import { AgentCatalogUnsupportedError, agentListRequest, checkedAgentDescriptor } from '../../storage/agent-sql';
import type { AgentsApi, SdkHost } from '../extension-points';
import { isCatalogUnsupported } from './resolve';

type Catalog = Required<Pick<StorageAdapter, 'putAgentDescriptor' | 'getAgentDescriptor' | 'listAgentDescriptors'>>;

/** The store's catalog methods, or the refusal of a store without them. */
function catalogOf(storage: StorageAdapter, method: keyof Catalog): Catalog {
  if (typeof storage[method] !== 'function') throw new AgentCatalogUnsupportedError();
  return storage as unknown as Catalog;
}

/** A store's own `agent_not_supported_by_store` answer, as the catalog's error. */
async function answered<T>(read: () => Promise<T>): Promise<T> {
  try {
    return await read();
  } catch (error) {
    if (isCatalogUnsupported(error) && !(error instanceof AgentCatalogUnsupportedError)) throw new AgentCatalogUnsupportedError();
    throw error;
  }
}

/** The `tzun.agents` namespace over the instance's store. */
export function agentsApi(host: SdkHost): AgentsApi {
  return {
    async register(descriptor: AgentDescriptor): Promise<{ digest: string; alreadyExisted: boolean }> {
      const catalog = catalogOf(host.storage, 'putAgentDescriptor');
      // Checked here as well as by the adapter, so every store refuses a
      // descriptor with the same error before anything reaches it, and every
      // store is handed the copy that was checked.
      const checked = checkedAgentDescriptor(descriptor);
      const result = await answered(() => catalog.putAgentDescriptor(checked));
      host.log('agent_descriptor_registered', { digest: result.digest, alreadyExisted: result.alreadyExisted });
      return result;
    },
    async get(digest: string): Promise<AgentDescriptorRow | null> {
      const catalog = catalogOf(host.storage, 'getAgentDescriptor');
      if (typeof digest !== 'string') throw new TypeError('An agent descriptor digest is a string: sha256: and 64 lowercase hex.');
      return answered(() => catalog.getAgentDescriptor(digest));
    },
    async list(filter?: { name?: string; organization?: string; limit?: number; cursor?: string }) {
      const catalog = catalogOf(host.storage, 'listAgentDescriptors');
      // The same refusal of a bad filter on every store, whichever adapter
      // answers; the store then reads the cursor as its own.
      agentListRequest(filter);
      return answered(() => catalog.listAgentDescriptors(filter));
    },
  };
}
