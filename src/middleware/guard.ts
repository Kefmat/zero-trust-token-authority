import { TokenEngine } from '../primitives/tokens';
import { NonceEngine } from '../primitives/nonce';
import { RevocationAccumulator } from '../primitives/accumulator';

export interface InterceptedRequest {
    headers: Record<string, string | string[] | undefined>;
    method: string;
    url: string;
}

export interface InterceptedResponse {
    setHeader(name: string, value: string): void;
    status(code: number): InterceptedResponse;
    json(body: Record<string, unknown>): void;
}

/**
 * Zero-trust access orchestration middleware for processing DPoP bindings.
 * * NOTE: This pipeline executes structural assertion filtering before parsing 
 * cryptographically heavy signatures. If a request is intercepted due to a missing or invalid nonce, 
 * it directly generates a stateless challenge response, shifting the state tracking cost to the client.
 * * @author Kefmat
 * @version 1.0.0
 */
export class AccessGuardMiddleware {
    private readonly accumulator: RevocationAccumulator;
    private readonly clusterSecret: string;
    private readonly authorityPublicKey: string;

    constructor(accumulator: RevocationAccumulator, clusterSecret: string, authorityPublicKey: string) {
        this.accumulator = accumulator;
        this.clusterSecret = clusterSecret;
        this.authorityPublicKey = authorityPublicKey;
    }

    /**
     * Intercepts incoming execution contexts to certify DPoP bindings and access credentials.
     */
    public async handle(req: InterceptedRequest, res: InterceptedResponse, next: () => void): Promise<void> {
        const dpopHeader = req.headers['dpop'];
        const authHeader = req.headers['authorization'];

        const rawProof = Array.isArray(dpopHeader) ? dpopHeader[0] : dpopHeader;
        const rawToken = Array.isArray(authHeader) ? authHeader[0] : authHeader;

        if (!rawProof) {
            const challengeNonce = NonceEngine.generateNonce(this.clusterSecret);
            res.setHeader('WWW-Authenticate', `DPoP error="invalid_token", nonce="${challengeNonce}"`);
            res.status(401).json({ error: "DPoP proof assertion missing from request header parameters." });
            return;
        }

        // Parse token string from authorization header format: "DPoP <token>"
        let cleanToken: string | undefined = undefined;
        if (rawToken && rawToken.startsWith('DPoP ')) {
            cleanToken = rawToken.substring(5).trim();
        }

        try {
            // Step 1: Decode the proof payload without full verification to isolate the embedded nonce parameter
            const decodedPayloadStr = Buffer.from(rawProof, 'base64url').toString('utf8');
            const parsedEnvelope = JSON.parse(decodedPayloadStr) as { payload: { nonce?: string } };
            const incomingNonce = parsedEnvelope.payload?.nonce;

            // Step 2: Enforce stateless nonce validation checks
            NonceEngine.verifyNonce(incomingNonce, this.clusterSecret);

            // Step 3: Enforce strict architectural validation against the DPoP signature and access token hash
            const clientThumbprint = TokenEngine.verifyClientDPoPProof(
                rawProof,
                req.method,
                req.url,
                incomingNonce,
                cleanToken
            );

            // Step 4: If an access token is presented, evaluate its validity and verify key context bindings
            if (cleanToken) {
                const tokenPayload = TokenEngine.verifyAccessToken(cleanToken, this.authorityPublicKey);

                // Step 5: Check fast-path revocation filter
                if (this.accumulator.isRevoked(tokenPayload.jti)) {
                    res.status(403).json({ error: "Access token validation failed: Token tracking identifier revoked." });
                    return;
                }

                // Step 6: Ensure the thumbprint embedded in the token maps to the active signing key of the proof
                if (tokenPayload.cnf.jkt !== clientThumbprint) {
                    res.status(403).json({ error: "Asymmetric binding verification failed: Key thumbprint mismatch." });
                    return;
                }
            }

            next();
        } catch (error) {
            const challengeNonce = NonceEngine.generateNonce(this.clusterSecret);
            res.setHeader('WWW-Authenticate', `DPoP error="use_dpop_nonce", nonce="${challengeNonce}"`);
            
            const message = error instanceof Error ? error.message : "Cryptographic verification failure.";
            res.status(401).json({ error: message });
        }
    }
}