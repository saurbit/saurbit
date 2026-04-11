import { JwksRotationTimestampStore, KeyGenerator } from "./types.ts";

/**
 * Configuration options for {@link JwksRotator}.
 */
export interface JwksRotatorOptions {
  /** The key generator used to produce new signing key pairs during rotation. */
  keyGenerator: KeyGenerator;
  /** The store used to read and persist the last rotation timestamp. */
  rotationTimestampStore: JwksRotationTimestampStore;
  /** How often (in milliseconds) new keys should be generated. For example, `7.884e9` for 91 days. */
  rotationIntervalMs: number; // e.g., 180 days
}

/**
 * Manages automatic JWKS key rotation based on a configurable interval.
 *
 * Call {@link JwksRotator.checkAndRotateKeys} at service startup and/or on a
 * recurring schedule (e.g. every hour) to ensure that signing keys are rotated
 * before they expire. During rotation the previous public key remains available
 * in the JWKS until its TTL expires, so in-flight tokens continue to verify correctly.
 */
export class JwksRotator {
  private readonly keyGenerator: KeyGenerator;
  private readonly rotationTimestampStore: JwksRotationTimestampStore;
  private readonly rotationIntervalMs: number;

  /**
   * @param options - Rotation configuration: key generator, timestamp store, and interval.
   */
  constructor({ keyGenerator, rotationIntervalMs, rotationTimestampStore }: JwksRotatorOptions) {
    this.keyGenerator = keyGenerator;
    this.rotationIntervalMs = rotationIntervalMs;
    this.rotationTimestampStore = rotationTimestampStore;
  }

  /**
   * Checks if rotation is due, and performs rotation if necessary.
   * Should be called at service startup or on a schedule (e.g. every hour).
   */
  public async checkAndRotateKeys(): Promise<void> {
    const now = Date.now();
    const lastRotation = await this.rotationTimestampStore.getLastRotationTimestamp();

    if (isNaN(lastRotation) || now - lastRotation >= this.rotationIntervalMs) {
      await this.rotateKeys();
      await this.rotationTimestampStore.setLastRotationTimestamp(now);
    } else {
      const _nextIn = this.rotationIntervalMs - (now - lastRotation);
    }
  }

  private async rotateKeys(): Promise<void> {
    await this.keyGenerator.generateKeyPair();
  }
}
