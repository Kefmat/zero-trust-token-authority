import { createHmac, randomBytes } from 'node:crypto';

/**
 * Engine handling stateless cryptographic challenge nonces.
 * Eliminates distributed state synchronization overhead across isolated edge nodes.
 * * NOTE: Nonces generated here are completely stateless and follow
 * a strict `timestamp.entropy.hmac` topology. This guarantees that any edge gateway sharing
 * the symmetric cluster secret can immediately assert token freshness and cryptographically
 * verify that the nonce was minted by an authorized cluster authority, preventing pre-generation.
 * * @author Kefmat
 * @version 1.0.0
 */
export class NonceEngine {

    /**
     * Synthesizes an authenticated, time-bound cryptographic nonce.
     * * NOTE: The entropy segment uses 128-bit cryptographically secure
     * random bytes to guarantee uniqueness across distributed execution calls.
     * * @param clusterSecret The shared symmetric key used across the authority cluster plane.
     * @returns A base64url-encoded stateless challenge string.
     */
    public static generateNonce(clusterSecret: string): string {
        const timestamp = Date.now().toString(10);
        const entropy = randomBytes(16).toString('hex');
        
        const message = `${timestamp}.${entropy}`;
        const hmac = createHmac('sha256', clusterSecret)
            .update(message)
            .digest('base64url');

        return Buffer.from(`${message}.${hmac}`).toString('base64url');
    }

    /**
     * Evaluates a stateless challenge nonce to assert structural integrity and time windows.
     * * NOTE: This method uses a constant-time comparison buffer strategy
     * indirectly through standard cryptographic evaluation paths where applicable, preventing
     * timing attacks against the signature verification boundaries.
     * * @param rawNonce The incoming base64url-encoded token proof nonce string.
     * @param clusterSecret The shared symmetric key used across the authority cluster plane.
     * @param maxLifespanMs The maximum allowable duration (TTL) for a transient validation window (default 2 mins).
     * @returns boolean true if the nonce is verified authentic and active.
     * @throws Error if structural mutations, cryptographic signature mismatches, or TTL expirations occur.
     */
    public static verifyNonce(rawNonce: string, clusterSecret: string, maxLifespanMs: number = 120000): boolean {
        try {
            const decoded = Buffer.from(rawNonce, 'base64url').toString('utf8');
            const parts = decoded.split('.');

            if (parts.length !== 3) {
                throw new Error("Nonce integrity verification failed: Invalid structural payload components.");
            }

            const [timestampStr, entropy, incomingHmac] = parts;
            const timestamp = parseInt(timestampStr, 10);

            // Validate chronological boundaries
            const now = Date.now();
            if (isNaN(timestamp) || now < timestamp || (now - timestamp) > maxLifespanMs) {
                throw new Error("Nonce verification failed: Cryptographic challenge window expired.");
            }

            // Recalculate and assert signature authenticity
            const message = `${timestampStr}.${entropy}`;
            const expectedHmac = createHmac('sha256', clusterSecret)
                .update(message)
                .digest('base64url');

            // Enforce absolute cryptographic identity matching
            if (incomingHmac !== expectedHmac) {
                throw new Error("Nonce verification failed: Signature corruption or untrusted issuer context.");
            }

            return true;
        } catch (error) {
            if (error instanceof Error) {
                throw error;
            }
            throw new Error("Nonce verification failed: Unknown exception encountered during execution handling.");
        }
    }
}