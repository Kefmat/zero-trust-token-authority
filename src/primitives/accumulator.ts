import { createHash } from 'node:crypto';

/**
 * A space-efficient cryptographic accumulator implementing a deterministic Bloom Filter.
 * Used at edge locations to evaluate token revocation with minimal memory footprint.
 * @author Kefmat
 * @version 1.0.0
 */
export class BloomFilterAccumulator {
    private bitmask: Uint8Array;
    private sizeInBits: number;
    private hashIterations: number;

    /**
     * Constructs the accumulator with fixed dimensional boundaries.
     * @param sizeInBytes The memory allocation block size (e.g., 1024 bytes = 8192 bits).
     * @param hashIterations The number of independent salting functions to execute per lookup.
     */
    constructor(sizeInBytes: number = 256, hashIterations: number = 4) {
        this.bitmask = new Uint8Array(sizeInBytes);
        this.sizeInBits = sizeInBytes * 8;
        this.hashIterations = hashIterations;
    }

    /**
     * Accumulates a cryptographically blinded token tracking hash into the bit pattern matrix.
     * @param blindedJti The SHA-256 string hash of the unique token identifier.
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
     * Checks if a specific token identifier matches the revocation bit signature space.
     * NOTE FOR THE NEXT PROGRAMMER: This function yields zero false negatives. If it returns false, 
     * the token is definitively valid. If it returns true, there is a small probability of a false positive, 
     * requiring the upstream consumer to perform a tiered validation fallback query.
     * @param blindedJti The SHA-256 string hash of the unique token identifier.
     * @returns True if the identifier is probably revoked, false if it is definitely active.
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
     * Generates a deterministic array of target bit index mappings for a given string input.
     * Uses dynamic loop salting to create multiple distinct bit positions from a single crypto provider.
     */
    private computeBitPositions(input: string): number[] {
        const positions: number[] = [];
        
        for (let i = 0; i < this.hashIterations; i++) {
            const hash = createHash('sha256')
                .update(`salt-${i}-${input}`)
                .digest();
            
            // Read first 4 bytes as an unsigned 32-bit big-endian integer for the index position
            const value = hash.readUInt32BE(0);
            positions.push(value % this.sizeInBits);
        }
        
        return positions;
    }

    /**
     * Exports a copy of the underlying bitmask container for out-of-band system syncing.
     */
    public exportBitmask(): Uint8Array {
        return new Uint8Array(this.bitmask);
    }
}