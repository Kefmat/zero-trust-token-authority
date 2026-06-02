import { createHash } from 'node:crypto';

/**
 * Engine managing token invalidation states before structural expiration windows elapse.
 * Integrates with the global ledger to maintain a transparent, append-only revocation registry.
 * * NOTE FOR THE NEXT PROGRAMMER: This registry records token revocations using the unique token 
 * identifier (jti). To optimize lookup operations and maintain zero-trust integrity across isolated 
 * network nodes, the internal index structures use cryptographically blinded identifier hashes.
 * * @author Kefmat
 * @version 1.0.0
 */
export class TokenRevocationRegistry {
    private revokedHashes: Set<string> = new Set<string>();

    /**
     * Enters a specific token token identifier into the revocation state map.
     * @param jti The unique token identifier string.
     * @returns The SHA-256 blinding hash of the revoked token identifier.
     */
    public revokeToken(jti: string): string {
        const blindedHash = this.computeBlindedHash(jti);
        this.revokedHashes.add(blindedHash);
        return blindedHash;
    }

    /**
     * Evaluates whether a specific token identifier has been revoked out-of-band.
     * @param jti The unique token identifier string.
     * @returns True if the token is revoked and must be rejected, false otherwise.
     */
    public isRevoked(jti: string): boolean {
        const blindedHash = this.computeBlindedHash(jti);
        return this.revokedHashes.has(blindedHash);
    }

    /**
     * Utility computation to blind token identifiers before long-term state storage.
     */
    private computeBlindedHash(jti: string): string {
        return createHash('sha256').update(jti).digest('hex');
    }
}