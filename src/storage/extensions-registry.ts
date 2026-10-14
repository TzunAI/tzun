/**
 * The storage extensions every local adapter installs unless its constructor
 * is given a list of its own (`extensions`). See `extensions.ts` for the
 * contract.
 */
import type { StorageExtension } from './extensions';
import { agentsStorageExtension } from './ddl/agents';
import { decidersExtension } from './ddl/deciders';
import { linksStorageExtension } from './ddl/links';
import { mandatesExtension } from './ddl/mandates';

export const DEFAULT_STORAGE_EXTENSIONS: readonly StorageExtension[] = Object.freeze([
  decidersExtension,
  agentsStorageExtension,
  linksStorageExtension,
  mandatesExtension,
]);
