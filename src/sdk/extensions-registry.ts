/**
 * The SDK extensions `Tzun.init()` installs unless the internal config member
 * `_sdkExtensions` names a list of its own. See `extension-points.ts`.
 */
import type { SdkExtensionFactory } from './extension-points';
import { agentsSdkExtension } from './agents';
import { linksSdkExtension } from './links';
import { mandatesExtension } from './mandates';

export const DEFAULT_SDK_EXTENSIONS: readonly SdkExtensionFactory[] = Object.freeze([
  agentsSdkExtension,
  linksSdkExtension,
  mandatesExtension,
]);
