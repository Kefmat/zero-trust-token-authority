import { generateKeyPairSync, createSign, createVerify, createHash } from 'node:crypto';

/**
 * Standard structure for an internal token envelope payload.
 */
export interface AccessTokenPayload {
    sub: string;       // Subject identifier (e.g., user or service ID)
    iss: string;       // Issuer identifier
    iat: number;       // Issued-at Unix timestamp
    exp: number;       // Expiration Unix timestamp
    kid: string;       // Key ID of the authority signature matrix
    cnf: {
        jkt: string;   // JWK Thumbprint: SHA-256 hash of the client's public key
    };
}

/**
 * Structure representing an incoming client proof of possession assertion.
 */
export interface DPoPProofPayload {
    htm: string;       // Target HTTP Method (e.g., GET, POST)
    htu: string;       // Target HTTP URL string
    iat: number;       // Proof issuance timestamp
    jti: string;       // Unique token token/nonce identifier to prevent replay attacks
    pubKey: string;    // Client public key embedded within the proof header
}

/**
 * Core cryptographic compilation layer managing token issuance and DPoP containment processing.
 * Enforces strict zero-trust validation matrices across distributed systems.
 * @author Kefmat
 * @version 1.0.0
 */
export class TokenEngine {
    
    /**
     * Helper utility mimicking a client generating an ephemeral asymmetric identity keyset.
     */
    public static generateClientKeys(): { publicKey: string; privateKey: string } {
        const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        return { publicKey, privateKey };
    }

    /**
     * Synthesizes and cryptographically signs a client-side DPoP proof envelope.
     */
    public static createClientDPoPProof(
        clientPrivateKey: string,
        clientPublicKey: string,
        htm: string,
        htu: string
    ): string {
        const payload: DPoPProofPayload = {
            htm,
            htu,
            iat: Date.now(),
            jti: Math.random().toString(36).substring(2, 15),
            pubKey: clientPublicKey
        };

        const serializedPayload = JSON.stringify(payload);
        const sign = createSign('RSA-SHA256'); // Using primitive signing mechanisms for raw buffers
        sign.update(serializedPayload);
        const signature = sign.sign(clientPrivateKey, 'hex');

        return Buffer.from(JSON.stringify({ payload, signature })).toString('base64url');
    }

    /**
     * Evaluates a client DPoP proof to certify legitimacy and extract the verification tracking thumbprint.
     * @throws Error if structural mutations, path mismatches, or signature validation failures occur.
     */
    public static verifyClientDPoPProof(
        rawProof: string,
        expectedHtm: string,
        expectedHtu: string
    ): string {
        const decodedString = Buffer.from(rawProof, 'base64url').toString('utf8');
        const parsed = JSON.parse(decodedString) as { payload: DPoPProofPayload; signature: string };
        
        const payload = parsed.payload;
        
        // Assert strict endpoint parameters match expected pathing
        if (payload.htm !== expectedHtm || payload.htu !== expectedHtu) {
            throw new Error("DPoP integrity check failed: HTTP context mismatch.");
        }

        // Verify validity window to prevent long-lived replay opportunities
        if (Date.now() - payload.iat > 60000) {
            throw new Error("DPoP validation failed: Token assertion window expired.");
        }

        const serializedPayload = JSON.stringify(payload);
        const verify = createVerify('RSA-SHA256');
        verify.update(serializedPayload);
        
        const isSignatureValid = verify.verify(payload.pubKey, parsed.signature, 'hex');
        if (!isSignatureValid) {
            throw new Error("DPoP signature validation failed: Untrusted binding signature.");
        }

        // Compute the thumbprint of the verified client public key to serve as the structural binding link
        return createHash('sha256').update(payload.pubKey).digest('hex');
    }

    /**
     * Issues an authority-signed access token bound to a specific client public key thumbprint.
     */
    public static issueAccessToken(
        sub: string,
        clientPublicKeyThumbprint: string,
        authorityPrivateKey: string,
        authorityKid: string
    ): string {
        const now = Date.now();
        const payload: AccessTokenPayload = {
            sub,
            iss: 'zero-trust-token-authority',
            iat: now,
            exp: now + 300000, // 5-minute transient operational window
            kid: authorityKid,
            cnf: {
                jkt: clientPublicKeyThumbprint
            }
        };

        const serializedPayload = JSON.stringify(payload);
        const sign = createSign('RSA-SHA256');
        sign.update(serializedPayload);
        const signature = sign.sign(authorityPrivateKey, 'hex');

        return Buffer.from(JSON.stringify({ payload, signature })).toString('base64url');
    }

    /**
     * Decodes and validates an authority access token token against public key parameters.
     */
    public static verifyAccessToken(token: string, authorityPublicKey: string): AccessTokenPayload {
        const decodedString = Buffer.from(token, 'base64url').toString('utf8');
        const parsed = JSON.parse(decodedString) as { payload: AccessTokenPayload; signature: string };
        
        const payload = parsed.payload;

        if (Date.now() > payload.exp) {
            throw new Error("Access token verification failed: Cryptographic parameter expired.");
        }

        const serializedPayload = JSON.stringify(payload);
        const verify = createVerify('RSA-SHA256');
        verify.update(serializedPayload);

        const isSignatureValid = verify.verify(authorityPublicKey, parsed.signature, 'hex');
        if (!isSignatureValid) {
            throw new Error("Access token validation failed: Corrupted authority signature.");
        }

        return payload;
    }
}