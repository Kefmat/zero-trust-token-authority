import { createHash } from 'node:crypto';

/**
 * A space-efficient cryptographic accumulator implementing a deterministic Bloom Filter.
 * Used at edge gateway locations to evaluate token revocation status with minimal memory overhead.
 * * NOTE FOR THE NEXT PROGRAMMER: This accumulator optimizes local lookup performance.
 * It features zero false negatives: if a token has not been added, mayContain() is guaranteed 
 * to return false. If it returns true, a false-positive is statistically possible, meaning the 
 * system must fallback to Tier 2 out-of-band Merkle proof verification to confirm the status.
 * * @author Kefmat
 * @version 1.0.0
 */
export class BloomFilterAccumulator {
    private bitmask: Uint8Array;
    private sizeInBits: number;
    private hashIterations: number;

    /**
     * Constructs the accumulator with fixed bit-space dimensions.
     * @param sizeInBytes The memory allocation block size (e.g., 128 bytes = 1024 bits).
     * @param hashIterations The number of independent salting passes executed per lookup.
     */
    constructor(sizeInBytes: number = 128, hashIterations: number = 4) {
        this.bitmask = new Uint8Array(sizeInBytes);
        this.sizeInBits = sizeInBytes * 8;
        this.hashIterations = hashIterations;
    }

    /**
     * Accumulates a cryptographically blinded token tracking hash into the bit array matrix.
     * @param blindedJti The SHA-256 hex string representation of the unique token identifier.
     */
    public add(blindedJti: string): void {
        const indices = this.computeBitPositions(blindedJti);
        for (const position of indices) {
            const byteIndex = Math.floor(position / 8);
            const bitOffset = position % 8;
            
            const currentByte = this.bitmask[byteIndex];
            if (currentByte !== undefined) {
                this.bitmask[byteIndex] = currentByte | (1 << bitOffset);
            }
        }
    }

    /**
     * Evaluates whether a specific token hash matches the current bit distribution footprint.
     * @param blindedJti The SHA-256 hex string representation of the unique token identifier.
     * @returns True if the token is likely revoked (Tier 2 required), false if definitively valid.
     */
    public mayContain(blindedJti: string): boolean {
        const indices = this.computeBitPositions(blindedJti);
        for (const position of indices) {
            const byteIndex = Math.floor(position / 8);
            const bitOffset = position % 8;
            
            const currentByte = this.bitmask[byteIndex];
            if (currentByte === undefined || (currentByte & (1 << bitOffset)) === 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Computes deterministic bit array offsets utilizing distinct salt mutations.
     */
    private computeBitPositions(input: string): number[] {
        const positions: number[] = [];
        
        for (let i = 0; i < this.hashIterations; i++) {
            const hash = createHash('sha256')
                .update(`salt-${i}-${input}`)
                .digest();
            
            // Read leading 4 bytes as an unsigned 32-bit big-endian integer for the matrix coordinates
            const value = hash.readUInt32BE(0);
            positions.push(value % this.sizeInBits);
        }
        
        return positions;
    }
}