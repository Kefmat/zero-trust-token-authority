# Zero-Trust Token Authority (The Access Engine)

A production-grade Identity Provider (IdP) simulation that enforces automated cryptographic key rotation, issues cryptographically bound access tokens (DPoP), and records lifecycle events in an immutable Merkle Tree ledger.

This engine completely mitigates token theft, replay attacks, and static key compromise vulnerabilities found in standard JWT infrastructures.

## Architectural Scope

1. **Automated Key Matrix Rotation:** Generates and rotates ephemeral asymmetric signing keys (Ed25519/ECDSA), phasing out old keys safely without dropping active sessions.
2. **Cryptographically Bound Tokens (DPoP):** Demonstrating Proof-of-Possession. Tokens are cryptographically bound to a client's specific public key, rendering intercepted or stolen tokens completely useless to an adversary.
3. **Immutable State Ledger:** All token issuances, key rotations, and revocations are appended to a cryptographic Merkle Tree, guaranteeing the historical integrity of the identity state.

## Getting Started

### Prerequisites
- Node.js v20.x or higher
- TypeScript

### Installation
```bash
npm install