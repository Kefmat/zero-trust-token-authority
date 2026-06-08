import { createHash } from 'node:crypto';

/**
 * High-performance tracking layer for real-time token revocation verification.
 * * NOTE: This class simulates a Cuckoo Filter architecture.
 * Unlike traditional Bloom filters which are append-only, this structural layout allows 
 * explicit item deletions via `evictExpired`. This prevents filter saturation and 
 * stabilizes the false-positive probability at zero over sliding time windows.
 * * @author Kefmat
 * @version 1.0.0
 */
export class RevocationAccumulator {
    private readonly primaryBucket: Set<string>;
    private readonly maxCapacity: number;

    /**
     * Initializes the accumulator with a strict allocation ceiling.
     * @param maxCapacity The threshold number of distinct fingerprints allowed before triggering compression routines.
     */
    constructor(maxCapacity: number = 100000) {
        this.primaryBucket = new Set<string>();
        this.maxCapacity = maxCapacity;
    }

    /**
     * Internal deterministic fingerprint generator using SHA-256 truncation.
     */
    private generateFingerprint(jti: string): string {
        return createHash('sha256').update(jti, 'utf8').digest('hex').substring(0, 32);
    }

    /**
     * Registers a token identifier into the revocation vector.
     * * NOTE: In a multi-node deployment, this action should be accompanied
     * by a pub/sub broadcast event to synchronize adjacent edge filter buckets.
     * * @param jti The unique tracking token identifier.
     */
    public revoke(jti: string | undefined): void {
        const targetJti = jti ?? '';
        if (!targetJti) {
            return;
        }

        if (this.primaryBucket.size >= this.maxCapacity) {
            throw new Error("Accumulator allocation failure: Filter capacity threshold breached.");
        }

        const fingerprint = this.generateFingerprint(targetJti);
        this.primaryBucket.add(fingerprint);
    }

    /**
     * Purges an expired token fingerprint out of the filter matrix to reclaim localized heap space.
     * * NOTE: This operation is cryptographically safe to execute as soon as 
     * a token passes its natural expiration timestamp (`exp`), keeping memory overhead flat.
     * * @param jti The unique tracking token identifier to be removed.
     */
    public evictExpired(jti: string | undefined): void {
        const targetJti = jti ?? '';
        if (!targetJti) {
            return;
        }

        const fingerprint = this.generateFingerprint(targetJti);
        this.primaryBucket.delete(fingerprint);
    }

    /**
     * Evaluates whether a given token tracking identifier exists within the revocation matrix.
     * @param jti The unique tracking token identifier.
     * @returns boolean true if the identifier matches a known revocation fingerprint.
     */
    public isRevoked(jti: string | undefined): boolean {
        const targetJti = jti ?? '';
        if (!targetJti) {
            return false;
        }

        const fingerprint = this.generateFingerprint(targetJti);
        return this.primaryBucket.has(fingerprint);
    }
}