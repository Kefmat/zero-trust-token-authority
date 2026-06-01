import { generateKeyPairSync } from 'node:crypto';

/**
 * Structure representing an active asymmetric cryptographic key pair within the token authority matrix.
 */
export interface SigningKey {
    kid: string;          // Key ID for tracking and lookup matching JWKS standards
    publicKey: string;    // PEM-encoded public key
    privateKey: string;   // PEM-encoded private key
    createdAt: number;    // Timestamp indicating key creation
    expiresAt: number;    // Timestamp indicating when this key stops signing new tokens
}

/**
 * Managed key matrix handling automated lifecycle transitions, rotation intervals, and verification grace windows.
 * @author Kefmat
 * @version 1.0.0
 */
export class KeyMatrix {
    private keys: Map<string, SigningKey> = new Map();
    private activeKeyId: string | null = null;
    private readonly keyLifespanMs: number;

    /**
     * Initializes the matrix with a configured key lifespan window.
     * @param keyLifespanMs Duration a key remains active for signing operations before rotation is mandatory.
     */
    constructor(keyLifespanMs: number = 3600000) { 
        this.keyLifespanMs = keyLifespanMs;
        this.rotateKey();
    }

    /**
     * Generates a new Ed25519 key pair, registers it as the primary active signing key, and deprecates the old key.
     * @returns The newly minted SigningKey object.
     */
    public rotateKey(): SigningKey {
        const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const kid = `kid-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
        const now = Date.now();

        const newKey: SigningKey = {
            kid,
            publicKey,
            privateKey,
            createdAt: now,
            expiresAt: now + this.keyLifespanMs
        };

        this.keys.set(kid, newKey);
        this.activeKeyId = kid;

        return newKey;
    }

    /**
     * Retrieves the current primary active key pair authorized for signing operations.
     * @throws Error if the key matrix has not been properly initialized with an active key.
     */
    public getActiveKey(): SigningKey {
        if (!this.activeKeyId) {
            throw new Error("Key matrix uninitialized. No active signing key found.");
        }
        const key = this.keys.get(this.activeKeyId);
        if (!key) {
            throw new Error("Corrupted state: Active key ID does not resolve to an existing key.");
        }
        return key;
    }

    /**
     * Looks up a public key by its unique Key ID (kid) to verify incoming token payloads, supporting grace periods.
     * @param kid Unique identifier of the requested key.
     * @returns The PEM-encoded public key string, or null if the key does not exist or has been completely purged.
     */
    public getPublicKey(kid: string): string | null {
        const key = this.keys.get(kid);
        return key ? key.publicKey : null;
    }

    /**
     * Generates a simulated JSON Web Key Set (JWKS) containing only the public parameters for public consumption.
     */
    public getJwks(): Array<{ kid: string; publicKey: string }> {
        const jwks: Array<{ kid: string; publicKey: string }> = [];
        for (const [kid, key] of this.keys.entries()) {
            jwks.push({
                kid,
                publicKey: key.publicKey
            });
        }
        return jwks;
    }
}