// Copyright (c) 2026 Edison Lepiten / AIEONYX
// BASTION v0.2 — Real Ed25519 via axon_crypto (P57.1, full curve math)
// Closes BASTION-STUB-ED25519-001

use axon_crypto::ed25519::{Ed25519PublicKey, Ed25519KeyPair};

pub const PUBKEY_LEN: usize = 32;
pub const SIG_LEN:    usize = 64;

/// Ed25519 public key wrapper
#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey(pub [u8; PUBKEY_LEN]);

impl PublicKey {
    pub fn from_crypto(k: &Ed25519PublicKey) -> Self {
        Self(k.to_bytes())
    }
    pub fn to_crypto(&self) -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes(self.0)
    }
}

/// Ed25519 signing key wrapper
#[derive(Clone)]
pub struct SigningKey(pub [u8; 32]); // seed

impl SigningKey {
    pub fn public_key(&self) -> PublicKey {
        let kp = Ed25519KeyPair::from_seed(self.0);
        PublicKey::from_crypto(&kp.public_key())
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SigningKey([REDACTED])")
    }
}

/// Ed25519 signature (64 bytes)
#[derive(Debug, Clone, PartialEq)]
pub struct Signature(pub [u8; SIG_LEN]);

/// Sign a message — delegates to axon_crypto Ed25519KeyPair::sign()
pub fn sign(key: &SigningKey, message: &[u8]) -> Signature {
    let kp = Ed25519KeyPair::from_seed(key.0);
    Signature(kp.sign(message))
}

/// Verify a signature — delegates to axon_crypto Ed25519PublicKey::verify()
pub fn verify(pubkey: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    pubkey.to_crypto().verify(message, &sig.0)
}

/// Generate a signing key from a 32-byte seed (deterministic)
pub fn keypair_from_seed(seed: [u8; 32]) -> SigningKey {
    SigningKey(seed)
}
