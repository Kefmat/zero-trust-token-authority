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
 * @author Kefmat
 * @version 1.0.1
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
     * Recursively builds the Merkle Tree upwards from the leaf hashes.
     * Implements strict defensive type guards to satisfy index boundaries.
     */
    private buildTree(hashes: string[]): string {
        const firstElement = hashes[0];

        // Base case: we have reached the root node safely
        if (hashes.length === 1 && firstElement !== undefined) {
            return firstElement;
        }

        const nextLevel: string[] = [];
        
        // Pair up adjacent hashes and hash them together
        for (let i = 0; i < hashes.length; i += 2) {
            const leftChild = hashes[i];
            const rightChild = hashes[i + 1];
            
            // Explicitly assert existence via type guards to bypass noUncheckedIndexedAccess
            if (leftChild !== undefined) {
                const actualRight = rightChild !== undefined ? rightChild : leftChild;
                nextLevel.push(this.hashNode(leftChild + actualRight));
            }
        }

        // Move up one level in the tree recursively
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