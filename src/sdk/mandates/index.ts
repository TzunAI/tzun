/**
 * The mandate service (Record §9.6) as an SDK extension: `tzun.mandates`
 * and the capture hook of `capture(input, { mandate: { mandateId } })`.
 *
 * Installed with its storage extension (`src/storage/ddl/mandates.ts`, the
 * `mandates`, `mandate_totals` and `mandate_events` tables): the namespace
 * and the hook read and write a store through the methods that extension
 * provides, and a store without them (the cloud transport, a custom adapter)
 * refuses every mandate call with `mandate_not_supported_by_store`.
 */
import type { SdkExtensionFactory } from '../extension-points';
import { mandateCaptureHook } from './capture-hook';
import { mandatesApi } from './service';

export const mandatesExtension: SdkExtensionFactory = (host) => ({
  name: 'mandates',
  mandates: { api: mandatesApi(host), captureHook: mandateCaptureHook() },
});

export { MandateError } from './errors';
export { MANDATE_ISSUANCE_REASON, type MandateListApi, type PreparedMandateRevocation } from './service';
export {
  expireEndedMandates,
  expireMandateIfEnded,
  type MandateExpiryOutcome,
  type MandateExpiryPass,
  type MandateListingStore,
} from './expiry';
export { mandateStoreOf, mandatePartsOf, type MandateStore, type MandateParts } from './store';
export { verifyCeremony, type CeremonyResult } from './ceremony';
