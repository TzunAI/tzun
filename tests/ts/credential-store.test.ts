import {
  CredentialStore,
  StoredCredential,
} from '../../src/attestation/credential-store';

describe('CredentialStore', () => {
  let store: CredentialStore;

  const cred: StoredCredential = {
    credentialId: 'cred-abc-123',
    publicKey: 'base64-encoded-public-key-data',
    userId: 'user-jane@acme.example',
    algorithm: 'ES256',
    counter: 0,
    status: 'active',
    registeredAt: '2026-03-22T10:00:00.000Z',
  };

  beforeEach(() => {
    store = new CredentialStore();
  });

  it('stores and retrieves a credential by credentialId', () => {
    store.register(cred);
    const retrieved = store.getByCredentialId(cred.credentialId);
    expect(retrieved).toEqual(cred);
  });

  it('returns undefined for unknown credentialId', () => {
    expect(store.getByCredentialId('nonexistent')).toBeUndefined();
  });

  it('retrieves credentials by userId', () => {
    const cred2: StoredCredential = {
      ...cred,
      credentialId: 'cred-def-456',
      registeredAt: '2026-03-22T11:00:00.000Z',
    };
    store.register(cred);
    store.register(cred2);
    const userCreds = store.getByUserId(cred.userId);
    expect(userCreds).toHaveLength(2);
  });

  it('returns empty array for unknown userId', () => {
    expect(store.getByUserId('nobody')).toEqual([]);
  });

  it('revokes a credential', () => {
    store.register(cred);
    store.revoke(cred.credentialId);
    const retrieved = store.getByCredentialId(cred.credentialId);
    expect(retrieved?.status).toBe('revoked');
  });

  it('throws when revoking a nonexistent credential', () => {
    expect(() => store.revoke('nonexistent')).toThrow('not found');
  });

  it('throws when registering a duplicate credentialId', () => {
    store.register(cred);
    expect(() => store.register(cred)).toThrow('already registered');
  });

  it('updates the counter for a credential', () => {
    store.register(cred);
    store.updateCounter(cred.credentialId, 5);
    const retrieved = store.getByCredentialId(cred.credentialId);
    expect(retrieved?.counter).toBe(5);
  });
});
