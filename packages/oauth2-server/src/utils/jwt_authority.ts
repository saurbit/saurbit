export interface JwtPayload {
  iss?: string
  sub?: string
  aud?: string | string[]
  jti?: string
  nbf?: number
  exp?: number
  iat?: number
  [propName: string]: unknown
}

export interface RSA {
    kty: 'RSA';
    e: string;
    n: string;
    d?: string | undefined;
    p?: string | undefined;
    q?: string | undefined;
    dp?: string | undefined;
    dq?: string | undefined;
    qi?: string | undefined;
}

export interface RawKey {
        alg: string;
        kty: string;
        use: "sig" | "enc" | "desc";
        kid: string;

        // e and n make up the public key
        e: string;
        n: string;
    }

export interface JwksKeyStore {
    /**
     * Stores the current active private key and its corresponding public key.
     * The public key will be kept for the duration of the TTL for JWKS purposes.
     */
    storeKeyPair(kid: string, privateKey: object, publicKey: object, ttl: number): void | Promise<void>;
    /**
     * Retrieves the current private key used for signing.
     */
    getPrivateKey(): Promise<object | undefined>;
    /**
     * Retrieves all valid public keys that have not expired.
     * These are used for exposing in JWKS.
     */
    getPublicKeys(): Promise<object[]>;
}

export interface KeyGenerator {
    generateKeyPair(): Promise<void>;
}

export interface JwtVerifier {
    verify<P extends JwtPayload = JwtPayload>(token: string): Promise<P>;
}

export interface JwtSigner {
    sign(payload: JwtPayload): Promise<{ token: string; kid: string }>;
}

export interface JwtAuthority extends JwtVerifier, JwtSigner {
    getPublicKeys(): Promise<{ keys: RawKey[] }>;

    /**
     * Get current kid for observability/debugging
     */
    getCurrentKid(): Promise<string | undefined>;

    /**
     * Helper for JWKS endpoint
     */
    getJwksEndpointResponse(): Promise<{ keys: RawKey[] }>;

    getPublicKey(kid: string): Promise<RSA | undefined>;

    generateKeyPair(): Promise<void>;
}

export interface JwksRotationTimestampStore {
    getLastRotationTimestamp(): Promise<number>;
    setLastRotationTimestamp(rotationTimestamp: number): Promise<void>;
}

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
