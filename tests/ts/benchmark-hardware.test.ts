import { detectHardware } from '../../src/benchmark/hardware';
import { HardwareInfo } from '../../src/benchmark/types';

describe('detectHardware', () => {
  it('returns HardwareInfo with all required fields', () => {
    const hw = detectHardware();

    expect(hw.cpu).toBeDefined();
    expect(typeof hw.cpu).toBe('string');
    expect(hw.cpu.length).toBeGreaterThan(0);

    expect(hw.cores).toBeDefined();
    expect(typeof hw.cores).toBe('number');
    expect(hw.cores).toBeGreaterThan(0);

    expect(hw.totalMemoryMB).toBeDefined();
    expect(typeof hw.totalMemoryMB).toBe('number');
    expect(hw.totalMemoryMB).toBeGreaterThan(0);

    expect(hw.platform).toBeDefined();
    expect(typeof hw.platform).toBe('string');

    expect(hw.arch).toBeDefined();
    expect(typeof hw.arch).toBe('string');

    expect(hw.nodeVersion).toBeDefined();
    expect(hw.nodeVersion).toMatch(/^v\d+/);
  });

  it('gpu field is null when no GPU is detected', () => {
    const hw = detectHardware();
    // GPU detection is best-effort; in a standard Node.js environment, it's null
    expect(hw.gpu).toBeNull();
  });
});
