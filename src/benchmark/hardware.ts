import * as os from 'os';
import { HardwareInfo } from './types';

/**
 * Detect hardware info for benchmark reports.
 *
 * Uses Node.js os module. GPU detection is best-effort:
 * returns null in standard environments, would detect via
 * future native bindings in CUDA-enabled builds.
 */
export function detectHardware(): HardwareInfo {
  const cpus = os.cpus();
  const cpuModel = cpus.length > 0 ? cpus[0].model.trim() : 'unknown';

  return {
    cpu: cpuModel,
    cores: cpus.length,
    totalMemoryMB: Math.round(os.totalmem() / (1024 * 1024)),
    platform: os.platform(),
    arch: os.arch(),
    nodeVersion: process.version,
    gpu: null, // GPU detection requires native bindings; null by default
  };
}
