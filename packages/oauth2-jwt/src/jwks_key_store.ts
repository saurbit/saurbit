import type { JwksKeyStore, JwksRotationTimestampStore } from "./types.ts";

// In-memory key store for testing
export class InMemoryKeyStore implements JwksKeyStore, JwksRotationTimestampStore {
  private privateKey?: object;
  private publicKeys: { key: object; exp: number }[] = [];
  private lastRotation: number = 0;

  async storeKeyPair(
    _kid: string,
    privateKey: object,
    publicKey: object,
    ttl: number,
  ): Promise<void> {
    this.privateKey = privateKey;
    const exp = Date.now() + ttl * 1000;
    this.publicKeys.push({ key: publicKey, exp });
    return await Promise.resolve();
  }

  async getPrivateKey(): Promise<object | undefined> {
    return await Promise.resolve(this.privateKey);
  }

  async getPublicKeys(): Promise<object[]> {
    const now = Date.now();
    this.publicKeys = this.publicKeys.filter((k) => k.exp > now);
    return await Promise.resolve(this.publicKeys.map((k) => k.key));
  }

  async getLastRotationTimestamp(): Promise<number> {
    return await Promise.resolve(this.lastRotation);
  }

  async setLastRotationTimestamp(msDate: number): Promise<void> {
    this.lastRotation = msDate;
    return await Promise.resolve();
  }
}

export function createInMemoryKeyStore(): InMemoryKeyStore {
  return new InMemoryKeyStore();
}
