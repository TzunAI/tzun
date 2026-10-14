/**
 * The `b1` proof bundle (Bundle §3): its shape, the exporter's anchoring
 * material, and `verifyBundle()` with its report and exit codes (Verification
 * §6).
 */
export * from './bundle-types';
export { bundleAnchoring, type BundleAnchoringMaterial } from './bundle';
export * from './verify-bundle';
