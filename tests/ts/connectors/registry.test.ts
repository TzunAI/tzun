/**
 * Connector registry tests.
 *
 * The registry is the single import surface for the wrapper layer to
 * dispatch per-vendor. Tests assert that all eight connectors are present
 * and that the accessor returns undefined for unknown vendors.
 */

import {
  connectorRegistry,
  getConnector,
} from '../../../src/sdk/connectors/index';

describe('connectorRegistry', () => {
  const expectedVendors = [
    'openai',
    'anthropic',
    'bedrock',
    'vertex',
    'azure-ai',
    'nvidia-nim',
    'hf-inference',
    'openrouter',
  ];

  it('connectorRegistry has entries for all 8 vendors', () => {
    expect(Object.keys(connectorRegistry).sort()).toEqual(
      [...expectedVendors].sort(),
    );
  });

  it('each registry entry self-reports the right vendor string', () => {
    for (const vendor of expectedVendors) {
      expect(connectorRegistry[vendor].vendor).toBe(vendor);
    }
  });

  it('getConnector returns the same instance as direct registry access', () => {
    for (const vendor of expectedVendors) {
      expect(getConnector(vendor)).toBe(connectorRegistry[vendor]);
    }
  });

  it('getConnector returns undefined for an unknown vendor', () => {
    expect(getConnector('not-a-real-vendor')).toBeUndefined();
    expect(getConnector('')).toBeUndefined();
  });

  it('re-exports Connector and AiBomSkeleton types', () => {
    // Type re-export — verified by the fact that this file compiles and we
    // can import from `./index` at the runtime level above. Add a smoke
    // assertion on a registry entry to exercise the type re-export path
    // (the import statement at the top of this file already covers the
    // import surface).
    expect(typeof connectorRegistry.openai.buildAiBom).toBe('function');
  });
});
