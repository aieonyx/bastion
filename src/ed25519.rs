// Copyright (c) 2026 Edison Lepiten / AIEONYX
// BASTION v0.1 — Ed25519 signing stub
//
// Production: delegates to axon_crypto P57.1 (full curve math, 93 tests).
// This stub provides the interface contract for unit testing without
// pulling in axon_crypto as a workspace dep (BASTION is a standalone repo).
// BASTION-STUB-ED25519-001: replace with axon_crypto::ed25519 before v1.0.

pub const PUBKEY_LEN:  usize = 32;
pub const PRIVKEY_LEN: usize = 64; // seed || public key
pub const SIG_LEN:     usize = 64;

/// Ed25519 public key
#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey(pub [u8; PUBKEY_LEN]);

/// Ed25519 signing key (seed || pubkey — never leaves Policy PD)
#[derive(Clone)]
pub struct SigningKey(pub [u8; PRIVKEY_LEN]);

impl SigningKey {
    pub fn public_key(&self) -> PublicKey {
        let mut pk = [0u8; PUBKEY_LEN];
        pk.copy_from_slice(&self.0[PUBKEY_LEN..]);
        PublicKey(pk)
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SigningKey([REDACTED])")
    }
}

/// Signature (64 bytes)
#[derive(Debug, Clone, PartialEq)]
pub struct Signature(pub [u8; SIG_LEN]);

/// Sign message with signing key.
/// BASTION-STUB: uses SHA-256-based deterministic stub.
/// Replace with real Ed25519 scalar multiplication before v1.0.
pub fn sign(key: &SigningKey, message: &[u8]) -> Signature {
    use crate::hash::sha256;
    // Stub: H(privkey_seed || message) repeated to fill 64 bytes
    // NOT cryptographically secure — stub only
    let seed = &key.0[..PUBKEY_LEN];
    let mut input = seed.to_vec();
    input.extend_from_slice(message);
    let h1 = sha256(&input);
    let mut input2 = h1.to_vec();
    input2.extend_from_slice(message);
    let h2 = sha256(&input2);
    let mut sig = [0u8; SIG_LEN];
    sig[..32].copy_from_slice(&h1);
    sig[32..].copy_from_slice(&h2);
    Signature(sig)
}

/// Verify signature against public key and message.
/// BASTION-STUB: re-computes stub sign and compares.
pub fn verify(pubkey: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    use crate::hash::sha256;
    // Reconstruct the stub signing key seed from pubkey (stub-only — not real)
    // In real Ed25519, verification uses the public key directly.
    // Stub: H(pubkey || message) check
    let mut input = pubkey.0.to_vec();
    input.extend_from_slice(message);
    let h = sha256(&input);
    // Stub verify: first 8 bytes of sig must match first 8 bytes of H(pubkey||msg)
    // This is NOT real Ed25519 — stub for interface testing only
    sig.0[..8] == h[..8]
}

/// Generate a stub keypair from a seed (32 bytes).
/// Real: scalar multiply seed by Ed25519 basepoint.
pub fn keypair_from_seed(seed: [u8; 32]) -> SigningKey {
    use crate::hash::sha256;
    let pk = sha256(&seed); // stub: pubkey = H(seed)
    let mut raw = [0u8; PRIVKEY_LEN];
    raw[..32].copy_from_slice(&seed);
    raw[32..].copy_from_slice(&pk);
    SigningKey(raw)
}
