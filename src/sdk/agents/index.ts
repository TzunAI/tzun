/**
 * The agent catalog (Record §6.9) as an SDK extension: the `tzun.agents`
 * namespace (`register`, `get`, `list`) and the capture hook that refuses an
 * agent reference the store's catalog does not hold.
 *
 * Installed by `Tzun.init()` from `DEFAULT_SDK_EXTENSIONS`, with
 * `agentsStorageExtension` (`src/storage/ddl/agents.ts`) giving the local
 * adapters the `agent_descriptors` table and the catalog methods. On a store
 * whose adapter has no catalog methods the namespace refuses
 * (`agent_not_supported_by_store`) and capture accepts references as given.
 *
 * `exportAgentDescriptors` builds an export's `resolvedAgentDescriptors`;
 * `exportedAgentCatalog` reads them back for offline verification.
 */
import type { SdkExtensionFactory } from '../extension-points';
import { agentsApi } from './api';
import { agentCaptureHook } from './capture-hook';

/** The agent catalog's SDK extension. */
export const agentsSdkExtension: SdkExtensionFactory = (host) => ({
  name: 'agents',
  agents: { api: agentsApi(host), captureHook: agentCaptureHook() },
});

export { agentsApi } from './api';
export { agentCaptureHook, agentReferenceRefusal } from './capture-hook';
export { resolveAgentDescriptor, readAgentDescriptorRow, type AgentResolution } from './resolve';
export {
  exportAgentDescriptors,
  exportedAgentCatalog,
  recordAgentReferences,
  type ExportedAgentDescriptorEntry,
  type RecordAgentReference,
} from './export';
export {
  AGENT_LIST_DEFAULT_LIMIT,
  AGENT_LIST_MAX_LIMIT,
  AgentCatalogUnsupportedError,
  AgentDescriptorConflictError,
  InvalidAgentDescriptorError,
} from '../../storage/agent-sql';
export { agentsStorageExtension } from '../../storage/ddl/agents';
