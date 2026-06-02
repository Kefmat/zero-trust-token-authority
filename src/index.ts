import { MerkleLedger, type LedgerEvent } from './primitives/ledger.js';
import { KeyMatrix } from './primitives/keys.js';
import { TokenEngine } from './primitives/tokens.js';
import { MerkleProofValidator } from './primitives/proofs.js';

/**
 * AccessOrchestrator manages the end-to-end simulation pipeline for the 
 * Zero-Trust Token Authority, validating defenses against real-time network attack vectors.
 * @author Kefmat
 * @version 1.1.0
 */
class AccessOrchestrator {
    /**
     * Executes the architectural simulation suite.
     */
    public static runSimulation(): void {
        console.log("=================================================");
        console.log("   Zero-Trust Token Authority: Access Engine     ");
        console.log("=================================================\n");

        // 1. Core Infrastructure Initialization
        const ledger = new MerkleLedger();
        const keyMatrix = new KeyMatrix(3600000); // 1-hour lifespan configuration
        
        let initialRoot = ledger.computeRootState();
        console.log(`[Ledger] Genesis State Hash: ${initialRoot}`);

        const initialKey = keyMatrix.getActiveKey();
        const initEvent: LedgerEvent = {
            eventId: `EVT-${Date.now()}-001`,
            timestamp: new Date().toISOString(),
            action: 'KEY_ROTATION',
            details: { kid: initialKey.kid, algorithm: 'Ed25519' }
        };
        let currentRoot = ledger.appendEvent(initEvent);
        console.log(`[Ledger] Key Matrix Initialized. Merkle Root: ${currentRoot}\n`);

        // 2. Client Provisioning
        console.log("[Client] Generating ephemeral cryptographic proof-of-possession keys...");
        const clientKeys = TokenEngine.generateClientKeys();
        
        // 3. Token Request Phase (With authentic DPoP Proof)
        console.log("[Client] Generating DPoP proof for token issuance endpoint...");
        const targetMethod = "POST";
        const targetUrl = "https://authority.enterprise.internal/oauth/token";
        
        const issuanceProof = TokenEngine.createClientDPoPProof(
            clientKeys.privateKey,
            clientKeys.publicKey,
            targetMethod,
            targetUrl
        );

        console.log("[IdP] Processing incoming token request and parsing proof framework...");
        try {
            const clientThumbprint = TokenEngine.verifyClientDPoPProof(issuanceProof, targetMethod, targetUrl);
            console.log(`[IdP] DPoP Proof Authenticated. Client Thumbprint: ${clientThumbprint}`);

            const activeAuthKey = keyMatrix.getActiveKey();
            const accessToken = TokenEngine.issueAccessToken(
                "user-session-9843",
                clientThumbprint,
                activeAuthKey.privateKey,
                activeAuthKey.kid
            );
            console.log("[IdP] Cryptographically bound access token successfully issued.");

            const issueEvent: LedgerEvent = {
                eventId: `EVT-${Date.now()}-002`,
                timestamp: new Date().toISOString(),
                action: 'TOKEN_ISSUED',
                details: { subject: "user-session-9843", jkt: clientThumbprint, authKid: activeAuthKey.kid }
            };
            currentRoot = ledger.appendEvent(issueEvent);
            console.log(`[Ledger] Event committed. Merkle Root updated to: ${currentRoot}\n`);

            // 4. Resource Access Phase (Successful Scenario)
            console.log("[Client] Accessing protected business API with bound token... ");
            const apiMethod = "GET";
            const apiUrl = "https://api.enterprise.internal/v1/metrics";
            
            const apiProof = TokenEngine.createClientDPoPProof(
                clientKeys.privateKey,
                clientKeys.publicKey,
                apiMethod,
                apiUrl
            );

            console.log("[Resource Server] Evaluating token payload and possession signature...");
            const parsedToken = TokenEngine.verifyAccessToken(accessToken, activeAuthKey.publicKey);
            const resourceThumbprint = TokenEngine.verifyClientDPoPProof(apiProof, apiMethod, apiUrl);

            if (parsedToken.cnf.jkt !== resourceThumbprint) {
                throw new Error("Access Denied: Token thumbprint binding mismatch.");
            }
            console.log("[Resource Server] Authorization Successful: Proof-of-Possession confirmed.\n");

            // 5. Adversarial Vector Simulation (Token Replay Attack)
            console.log("[Simulation] Adversary intercepts the bearer access token from network wire...");
            console.log("[Simulation] Adversary attempts to replay token from independent rogue node...");
            
            const rogueKeys = TokenEngine.generateClientKeys();
            const rogueApiProof = TokenEngine.createClientDPoPProof(
                rogueKeys.privateKey,
                rogueKeys.publicKey,
                apiMethod,
                apiUrl
            );

            try {
                console.log("[Resource Server] Processing payload request from adversarial source...");
                const parsedRogueToken = TokenEngine.verifyAccessToken(accessToken, activeAuthKey.publicKey);
                const rogueThumbprint = TokenEngine.verifyClientDPoPProof(rogueApiProof, apiMethod, apiUrl);

                if (parsedRogueToken.cnf.jkt !== rogueThumbprint) {
                    throw new Error("REPLAY_REJECTED: Stolen token is not cryptographically bound to this node's keypair.");
                }
                console.log("[CRITICAL ALERT] Security boundary bypassed. Adversary authorized.");
            } catch (err: any) {
                console.log(`[DEFENSE SUCCESS] Resource Server blocked threat. Reason: ${err.message}\n`);
            }

            // 6. Administrative Automated Key Rotation Event
            console.log("[IdP] Lifetime trigger: Initializing automated authority key rotation routine...");
            const rotatedKey = keyMatrix.rotateKey();
            
            const rotateEvent: LedgerEvent = {
                eventId: `EVT-${Date.now()}-003`,
                timestamp: new Date().toISOString(),
                action: 'KEY_ROTATION',
                details: { kid: rotatedKey.kid, reason: "AUTOMATED_ROTATION_INTERVAL" }
            };
            currentRoot = ledger.appendEvent(rotateEvent);
            console.log(`[Ledger] Rotation committed. Merkle Root locked at: ${currentRoot}\n`);

            // 7. Out-of-Band Audit Trail Verification Routine
            console.log("[Compliance Server] Initiating disconnected historical validation routine...");
            console.log("[Compliance Server] Fetching authorization event info and targeted proof data path...");
            
            // Validate the Token Issuance event (index 1 in the ledger trail)
            const targetEventIndex = 1;
            const targetEvent = ledger.getAuditTrail()[targetEventIndex];
            
            if (targetEvent !== undefined) {
                const computedLeafHash = ledger.hashNode(JSON.stringify(targetEvent));
                const mathematicalProofPath = ledger.generateProof(targetEventIndex);
                
                console.log(`[Compliance Server] Target Event ID to verify: ${targetEvent.eventId}`);
                console.log(`[Compliance Server] Proof Path Node Array Count: ${mathematicalProofPath.length}`);
                
                const isStateValid = MerkleProofValidator.verify(
                    currentRoot,
                    computedLeafHash,
                    mathematicalProofPath
                );

                if (isStateValid) {
                    console.log("[AUDIT SUCCESS] Out-of-band audit verified: Event entry integrity verified.\n");
                } else {
                    console.log("[AUDIT FAILURE] Warning: Mutated ledger transaction detected.\n");
                }
            }

        } catch (error: any) {
            console.error(`[CRITICAL SIMULATION ERROR] Pipeline failed: ${error.message}`);
        }

        // 8. Core Cryptographic Ledger Audit Review
        console.log("=================================================");
        console.log("         Final Cryptographic State Audit         ");
        console.log("=================================================");
        console.log(`Final Merkle State Root: ${ledger.computeRootState()}`);
        console.log(`Total System Events Recorded Immutably: ${ledger.getAuditTrail().length}`);
        console.log("=================================================");
    }
}

// Trigger simulation entry point
AccessOrchestrator.runSimulation();