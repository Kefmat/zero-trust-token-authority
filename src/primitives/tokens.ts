import { generateKeyPairSync, sign, verify, createHash } from 'node:crypto';

/**
 * Standard structure for an internal token envelope payload.
 */
export interface AccessTokenPayload {
    jti: string;       // Unique token identifier for explicit tracking and revocation
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
    jti: string;       // Unique token identifier to prevent replay attacks
    pubKey: string;    // Client public key embedded within the proof header
    nonce?: string;    // Optional server-issued cryptographic challenge nonce
}

/**
 * Core cryptographic compilation layer managing token issuance and DPoP containment processing.
 * Enforces strict zero-trust validation matrices across distributed systems.
 * * NOTE FOR THE NEXT PROGRAMMER: This class leverages the raw `sign` and `verify` functional utilities 
 * from 'node:crypto' rather than the stream-based `createSign` class. The first parameter (algorithm) 
 * must remain `undefined`. This is a strict constraint of the Ed25519 standard in Node.js, as Ed25519 
 * does not support separate pre-hash digest identifiers like RSA or traditional ECDSA.
 * * @author Kefmat
 * @version 1.3.0
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
     * Enforces Ed25519 compliance by supplying an undefined algorithm parameter to the signer.
     * * NOTE FOR THE NEXT PROGRAMMER: The optional server nonce parameter must be explicitly appended
     * to the internal payload definition to assert dynamic fresh execution boundaries.
     * * @param clientPrivateKey The client's asymmetric signing key.
     * @param clientPublicKey The client's public identity key to bound to the session context.
     * @param htm The outbound request target HTTP method.
     * @param htu The outbound request target canonical destination URL.
     * @param nonce An optional token-bound challenge nonce issued during a 401 interception challenge loop.
     */
    public static createClientDPoPProof(
        clientPrivateKey: string,
        clientPublicKey: string,
        htm: string,
        htu: string,
        nonce?: string
    ): string {
        const payload: DPoPProofPayload = {
            htm,
            htu,
            iat: Date.now(),
            jti: Math.random().toString(36).substring(2, 15),
            pubKey: clientPublicKey,
            nonce: nonce || undefined
        };

        const serializedPayload = JSON.stringify(payload);
        const signatureBuffer = sign(undefined, Buffer.from(serializedPayload), clientPrivateKey);
        const signature = signatureBuffer.toString('hex');

        return Buffer.from(JSON.stringify({ payload, signature })).toString('base64url');
    }

    /**
     * Evaluates a client DPoP proof to certify legitimacy and extract the verification tracking thumbprint.
     * * NOTE FOR THE NEXT PROGRAMMER: If an expected nonce boundary check is supplied by the middleware context, 
     * it must perform strict parameter matching against the internal payload to guard against cross-server replay attacks.
     * * @param rawProof The incoming base64url-encoded proof wrapper.
     * @param expectedHtm The targeted HTTP Method context.
     * @param expectedHtu The targeted HTTP URI path context.
     * @param expectedNonce An optional expected nonce challenge value required for authorization checks.
     * @throws Error if structural mutations, path mismatches, expired TTL window, or signature validation failures occur.
     */
    public static verifyClientDPoPProof(
        rawProof: string,
        expectedHtm: string,
        expectedHtu: string,
        expectedNonce?: string
    ): string {
        const decodedString = Buffer.from(rawProof, 'base64url').toString('utf8');
        const parsed = JSON.parse(decodedString) as { payload: DPoPProofPayload; signature: string };
        
        const payload = parsed.payload;
        
        if (payload.htm !== expectedHtm || payload.htu !== expectedHtu) {
            throw new Error("DPoP integrity check failed: HTTP context mismatch.");
        }

        if (expectedNonce && payload.nonce !== expectedNonce) {
            throw new Error("DPoP integrity check failed: Cryptographic nonce mismatch or missing.");
        }

        if (Date.now() - payload.iat > 60000) {
            throw new Error("DPoP validation failed: Token assertion window expired.");
        }

        const serializedPayload = JSON.stringify(payload);
        const isSignatureValid = verify(
            undefined,
            Buffer.from(serializedPayload),
            payload.pubKey,
            Buffer.from(parsed.signature, 'hex')
        );

        if (!isSignatureValid) {
            throw new Error("DPoP signature validation failed: Untrusted binding signature.");
        }

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
        const generatedJti = `AUTH-JTI-${Math.random().toString(36).substring(2, 11).toUpperCase()}`;
        
        const payload: AccessTokenPayload = {
            jti: generatedJti,
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
        const signatureBuffer = sign(undefined, Buffer.from(serializedPayload), authorityPrivateKey);
        const signature = signatureBuffer.toString('hex');

        return Buffer.from(JSON.stringify({ payload, signature })).toString('base64url');
    }

    /**
     * Decodes and validates an authority access token against public key parameters.
     */
    public static verifyAccessToken(token: string, authorityPublicKey: string): AccessTokenPayload {
        const decodedString = Buffer.from(token, 'base64url').toString('utf8');
        const parsed = JSON.parse(decodedString) as { payload: AccessTokenPayload; signature: string };
        
        const payload = parsed.payload;

        if (Date.now() > payload.exp) {
            throw new Error("Access token verification failed: Cryptographic parameter expired.");
        }

        const serializedPayload = JSON.stringify(payload);
        const isSignatureValid = verify(
            undefined,
            Buffer.from(serializedPayload),
            authorityPublicKey,
            Buffer.from(parsed.signature, 'hex')
        );

        if (!isSignatureValid) {
            throw new Error("Access token validation failed: Corrupted authority signature.");
        }

        return payload;
    }
}