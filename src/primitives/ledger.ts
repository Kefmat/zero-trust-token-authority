import { createHash } from 'node:crypto';

/**
 * Standardized structure for an identity lifecycle event.
 */
export interface LedgerEvent {
    eventId: string;
    timestamp: string;
    action: 'KEY_ROTATION' | 'TOKEN_ISSUED' | 'TOKEN_REVOKED';
    details: Record<string, any>;
}

/**
 * Representation of an individual step within a Merkle cryptographic proof path.
 */
export interface MerkleProofStep {
    position: 'left' | 'right';
    hash: string;
}

/**
 * An append-only cryptographic ledger powered by a Merkle Tree.
 * Guarantees that historical identity events cannot be retroactively altered.
 * @author Kefmat
 * @version 1.1.0
 */
export class MerkleLedger {
    private events: LedgerEvent[] = [];
    private leafHashes: string[] = [];

    /**
     * Appends a new cryptographic event to the ledger and recalculates the state root.
     * @param event The structured identity event.
     * @returns The newly computed Merkle Root Hash.
     */
    public appendEvent(event: LedgerEvent): string {
        this.events.push(event);
        
        const eventString = JSON.stringify(event);
        const hash = this.hashNode(eventString);
        this.leafHashes.push(hash);
        
        return this.computeRootState();
    }

    /**
     * Retrieves the current Merkle Root, representing the absolute cryptographic state of the IdP.
     */
    public computeRootState(): string {
        if (this.leafHashes.length === 0) {
            return this.hashNode("genesis_state_empty");
        }
        return this.buildTree(this.leafHashes);
    }

    /**
     * Generates an out-of-band cryptographic audit proof path for a given log event index.
     * NOTE FOR THE NEXT PROGRAMMER: This algorithm iteratively moves up the tree levels, 
     * tracking the target index relative to each paired branch layer. It explicitly guards 
     * against undefined elements to respect strict array boundaries.
     * @param index The positional index of the historical event leaf.
     * @returns An ordered array of proof steps required to verify the leaf.
     * @throws Error if the requested index falls outside current ledger boundaries.
     */
    public generateProof(index: number): MerkleProofStep[] {
        if (index < 0 || index >= this.leafHashes.length) {
            throw new Error("Index out of bounds for cryptographic proof generation.");
        }

        const proof: MerkleProofStep[] = [];
        let currentLevelHashes = [...this.leafHashes];
        let targetIndex = index;

        while (currentLevelHashes.length > 1) {
            const nextLevelHashes: string[] = [];

            for (let i = 0; i < currentLevelHashes.length; i += 2) {
                const leftChild = currentLevelHashes[i];
                const rightChild = currentLevelHashes[i + 1];

                if (leftChild !== undefined) {
                    const actualRight = rightChild !== undefined ? rightChild : leftChild;
                    nextLevelHashes.push(this.hashNode(leftChild + actualRight));

                    // Evaluate if the current iteration boundary holds our target path node
                    if (targetIndex === i) {
                        proof.push({ position: 'right', hash: actualRight });
                    } else if (targetIndex === i + 1) {
                        proof.push({ position: 'left', hash: leftChild });
                    }
                }
            }

            currentLevelHashes = nextLevelHashes;
            targetIndex = Math.floor(targetIndex / 2);
        }

        return proof;
    }

    /**
     * Standardized SHA-256 hashing utility for individual string data segments.
     */
    public hashNode(data: string): string {
        return createHash('sha256').update(data).digest('hex');
    }

    /**
     * Retrieves the complete historical event log.
     */
    public getAuditTrail(): LedgerEvent[] {
        return [...this.events];
    }
}