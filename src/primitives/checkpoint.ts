import { createHmac } from 'node:crypto';

/**
 * Standard data layout describing a verified state snapshot checkpoint issued by the ledger authority layer.
 */
export interface CheckpointCertificate {
    sequenceId: number;
    targetMerkleRoot: string;
    issuedTimestamp: number;
    authoritySignature: string;
}

/**
 * Enforces strict temporal boundaries on remote edge gateways to neutralize network partition blind spots.
 * If the connection to the core security ledger is lost, this guard triggers defensive self-isolation.
 * @author Kefmat
 * @version 1.0.0
 */
export class StateDriftIsolationGuard {
    private currentCheckpoint: CheckpointCertificate | null = null;
    private maxPermittedDriftMs: number;
    private boundarySecret: string;

    /**
     * @param maxPermittedDriftMs Maximum permissible synchronization gap before forcing network isolation lockout (e.g., 3000ms).
     * @param boundarySecret HMAC signing key configuration used to verify structural identity across systems.
     */
    constructor(maxPermittedDriftMs: number = 3000, boundarySecret: string = 'isolated-boundary-token-secret') {
        this.maxPermittedDriftMs = maxPermittedDriftMs;
        this.boundarySecret = boundarySecret;
    }

    /**
     * Dynamically registers and validates a fresh authoritative synchronization checkpoint.
     * NOTE: Checkpoints must undergo signature validation before 
     * mutation of the internal state cache to prevent parameter injection attacks from spoofed channels.
     * @param certificate The incoming snapshot block envelope.
     * @throws Error if the signature fails authentication tests.
     */
    public synchronizeCheckpoint(certificate: CheckpointCertificate): void {
        const payloadString = `${certificate.sequenceId}:${certificate.targetMerkleRoot}:${certificate.issuedTimestamp}`;
        const calculatedSignature = createHmac('sha256', this.boundarySecret)
            .update(payloadString)
            .digest('hex');

        if (calculatedSignature !== certificate.authoritySignature) {
            throw new Error("BOUNDARY_VIOLATION: Inbound checkpoint verification token signature was invalid.");
        }

        this.currentCheckpoint = certificate;
    }

    /**
     * Evaluates boundary freshness to neutralize state-freeze exploitation tactics.
     * NOTE: This method must execute at the front of the incoming 
     * HTTP middleware processing pipelines. If the age of the certified checkpoint parameters 
     * exceeds maxPermittedDriftMs, the node drops processing immediately and alerts downstream operations.
     * @throws Error if the node has drifted out of bounds or lacks structural configuration data.
     */
    public verifyStateFreshness(): void {
        if (this.currentCheckpoint === null) {
            throw new Error("ISOLATION_LOCKOUT: Gateway component has not completed an initial state sync handshake.");
        }

        const structuralLatencyDelta = Date.now() - this.currentCheckpoint.issuedTimestamp;
        if (structuralLatencyDelta > this.maxPermittedDriftMs) {
            throw new Error(`ISOLATION_LOCKOUT: Edge state synchronization boundary has drifted by ${structuralLatencyDelta}ms. Gateway locked.`);
        }
    }

    /**
     * Helper interface returning the actively locked cryptographic root identifier.
     */
    public getActiveStateRoot(): string {
        if (this.currentCheckpoint === null) {
            return '';
        }
        return this.currentCheckpoint.targetMerkleRoot;
    }
}