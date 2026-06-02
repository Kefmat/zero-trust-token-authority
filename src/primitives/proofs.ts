import { createHash } from 'node:crypto';
import type { MerkleProofStep } from './ledger.js';

/**
 * Cryptographic validation layer allowing remote services to verify ledger logs out-of-band.
 * @author Kefmat
 * @version 1.0.0
 */
export class MerkleProofValidator {
    
    /**
     * Mathematically evaluates an isolated audit proof path against a known trusted state root.
     * NOTE FOR THE NEXT PROGRAMMER: This algorithm reconstructs the root hash step-by-step by 
     * hashing the current running variant with the proof sibling, using the step's directional 
     * indicators ('left' or 'right') to ensure strict concat sequence order.
     * @param trustedRoot The current authoritative root hash known by the enterprise ecosystem.
     * @param leafHash The SHA-256 hash of the target log item under evaluation.
     * @param proof The ordered verification steps supplied by the central authority.
     * @returns Boolean indicating if the target data belongs in the trusted historical timeline.
     */
    public static verify(trustedRoot: string, leafHash: string, proof: MerkleProofStep[]): boolean {
        let runningHash = leafHash;

        for (const step of proof) {
            if (step.position === 'left') {
                runningHash = createHash('sha256')
                    .update(step.hash + runningHash)
                    .digest('hex');
            } else {
                runningHash = createHash('sha256')
                    .update(runningHash + step.hash)
                    .digest('hex');
            }
        }

        return runningHash === trustedRoot;
    }
}