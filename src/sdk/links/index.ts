/**
 * The link service (Record §8) as an SDK extension: the capture
 * hook that resolves same-store link targets, `tzun.links` (`relate`, `of`,
 * `to`) and `tzun.decisionGraph` (`walk`).
 *
 * It reads the instance's own store only. `to` and the walk need the link
 * index, which `linksStorageExtension` (`src/storage/ddl/links.ts`) gives the
 * SQLite, Postgres and memory adapters; on a store without it (the cloud
 * transport) they throw `LinksNotSupportedError`, while capture resolution
 * and `of` read records through the store's evidence read.
 */
import type { SdkExtensionFactory } from '../extension-points';
import { decisionGraphService } from '../decision-graph';
import { linkCaptureHook } from './resolve';
import { linksService } from './service';
import { linkStoreReads } from './store-reads';

export { resolveLinkTargets, linkCaptureHook } from './resolve';
export {
  LinksNotSupportedError,
  linksService,
  type HeldTargetPosition,
  type LinkResolution,
  type LinkToRow,
  type LinksService,
  type RelateRequest,
} from './service';
export { isCloudStore, linkStoreReads, recordIntact, type LinkStoreReads } from './store-reads';

/** `tzun.links`, `tzun.decisionGraph` and the link capture hook, for `Tzun.init()`. */
export const linksSdkExtension: SdkExtensionFactory = (host) => {
  const reads = linkStoreReads(host);
  return {
    name: 'links',
    links: {
      api: linksService(host, reads),
      captureHook: linkCaptureHook(reads),
      decisionGraph: decisionGraphService(reads),
    },
  };
};
