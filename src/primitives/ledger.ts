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
 * An append-only cryptographic ledger powered by a Merkle Tree.
 * Guarantees that historical identity events cannot be retroactively altered.
 * * @author Kefmat
 * @version 1.0.0
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
        
        // Deterministically stringify the event to ensure consistent hashing
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
     * Recursively builds the Merkle Tree upwards from the leaf hashes.
     */
    private buildTree(hashes: string[]): string {
        // Base case: we have reached the root node
        if (hashes.length === 1) return hashes[0];

        const nextLevel: string[] = [];
        
        // Pair up adjacent hashes and hash them together
        for (let i = 0; i < hashes.length; i += 2) {
            const leftChild = hashes[i];
            // If there's an odd number of leaves, duplicate the last node (standard Merkle behavior)
            const rightChild = i + 1 < hashes.length ? hashes[i + 1] : leftChild; 
            
            nextLevel.push(this.hashNode(leftChild + rightChild));
        }

        // Move up one level in the tree
        return this.buildTree(nextLevel);
    }

    /**
     * Standardized SHA-256 hashing utility for tree nodes.
     */
    private hashNode(data: string): string {
        return createHash('sha256').update(data).digest('hex');
    }

    /**
     * Retrieves the complete historical event log.
     */
    public getAuditTrail(): LedgerEvent[] {
        return [...this.events];
    }
}