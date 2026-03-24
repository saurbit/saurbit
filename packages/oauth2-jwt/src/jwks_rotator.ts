import { JwksRotationTimestampStore, KeyGenerator } from "./types.ts";

export interface JwksRotatorOptions {
  keyGenerator: KeyGenerator;
  rotatorKeyStore: JwksRotationTimestampStore;
  rotationIntervalMs: number; // e.g., 180 days
}

export class JwksRotator {
  private readonly keyGenerator: KeyGenerator;
  private readonly rotatorKeyStore: JwksRotationTimestampStore;
  private readonly rotationIntervalMs: number;

  constructor({ keyGenerator, rotationIntervalMs, rotatorKeyStore }: JwksRotatorOptions) {
    this.keyGenerator = keyGenerator;
    this.rotationIntervalMs = rotationIntervalMs;
    this.rotatorKeyStore = rotatorKeyStore;
  }

  /**
   * Checks if rotation is due, and performs rotation if necessary.
   * Should be called at service startup or on a schedule (e.g. every hour).
   */
  public async checkAndRotateKeys(): Promise<void> {
    const now = Date.now();
    const lastRotation = await this.rotatorKeyStore.getLastRotationTimestamp();

    if (isNaN(lastRotation) || now - lastRotation >= this.rotationIntervalMs) {
      //this.logger?.info('[JWKS] Rotating signing keys...');
      await this.rotateKeys();
      await this.rotatorKeyStore.setLastRotationTimestamp(now);
    } else {
      const _nextIn = this.rotationIntervalMs - (now - lastRotation);
      //this.logger?.info(
      //    `[JWKS] Key rotation not needed. Next rotation in ${Math.round(nextIn / 1000 / 60)} minutes`
      //);
    }
  }

  private async rotateKeys(): Promise<void> {
    await this.keyGenerator.generateKeyPair();
  }
}
