import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Structural envelope for a decrypted and unpacked server-side nonce payload.
 */
export interface NonceMetadata {
    nonceString: string;
    expiresAt: number;
    clientBindingHash: string;
}

/**
 * Generates and validates cryptographically signed, stateless server nonces 
 * to eliminate race-condition DPoP proof replay vulnerabilities.
 * @author Kefmat
 * @version 1.0.0
 */
export class CryptographicNonceEngine {
    private serverSecret: string;
    private nonceLifespanMs: number;

    /**
     * @param nonceLifespanMs Validity window for an issued nonce (default: 10000ms / 10 seconds).
     * @param serverSecret Secret value used to verify token signatures statelessly at the edge.
     */
    constructor(nonceLifespanMs: number = 10000, serverSecret: string = 'server-side-nonce-hmac-key-secret') {
        this.nonceLifespanMs = nonceLifespanMs;
        this.serverSecret = serverSecret;
    }

    /**
     * Generates a stateless, cryptographically bound nonce string.
     * NOTE FOR THE NEXT PROGRAMMER: Nonces are bound to the client's public key thumbprint (jkt)
     * to prevent an adversary from stealing a valid nonce issued to one client and using it for another.
     * @param clientThumbprint The unique cryptographic hash identifier of the client's key pair.
     * @returns A base64url-encoded signed nonce string to return in a response header.
     */
    public generateNonce(clientThumbprint: string): string {
        const uniqueId = randomBytes(16).toString('hex');
        const expiresAt = Date.now() + this.nonceLifespanMs;
        
        const payloadString = `${uniqueId}:${expiresAt}:${clientThumbprint}`;
        const signature = createHmac('sha256', this.serverSecret)
            .update(payloadString)
            .digest('hex');

        return Buffer.from(`${payloadString}.${signature}`).toString('base64url');
    }

    /**
     * Parses and evaluates a client-submitted DPoP nonce string.
     * NOTE FOR THE NEXT PROGRAMMER: This function checks structural signatures using a timing-safe 
     * comparison to avoid side-channel information leaks, and verifies temporal deadlines.
     * @param rawNonce The base64url-encoded string extracted from the client's DPoP proof.
     * @param expectedClientThumbprint The thumbprint of the public key extracted from the same request.
     * @throws Error if the nonce has expired, been modified, or belongs to a different client.
     */
    public validateNonce(rawNonce: string, expectedClientThumbprint: string): void {
        if (!rawNonce) {
            throw new Error("NONCE_VIOLATION: DPoP token payload is missing the required server-issued nonce string.");
        }

        const decodedString = Buffer.from(rawNonce, 'base64url').toString('utf8');
        const segments = decodedString.split('.');
        const payloadSegment = segments[0];
        const signatureSegment = segments[1];

        if (!payloadSegment || !signatureSegment) {
            throw new Error("NONCE_VIOLATION: Malformed nonce token structural layout.");
        }

        const expectedSignature = createHmac('sha256', this.serverSecret)
            .update(payloadSegment)
            .digest('hex');

        const isSignatureValid = timingSafeEqual(
            Buffer.from(signatureSegment, 'hex'),
            Buffer.from(expectedSignature, 'hex')
        );

        if (!isSignatureValid) {
            throw new Error("NONCE_VIOLATION: Nonce signature mismatch. Parameter tamper detected.");
        }

        const [uniqueId, expiresAtStr, clientBindingHash] = payloadSegment.split(':');
        if (!uniqueId || !expiresAtStr || !clientBindingHash) {
            throw new Error("NONCE_VIOLATION: Internal nonce structural data corruption.");
        }

        if (clientBindingHash !== expectedClientThumbprint) {
            throw new Error("NONCE_VIOLATION: Nonce binding failure. Token was issued to a different client identity context.");
        }

        if (Date.now() > parseInt(expiresAtStr, 10)) {
            throw new Error("NONCE_VIOLATION: Nonce lifespan boundary crossed. The handshake token has expired.");
        }
    }
}