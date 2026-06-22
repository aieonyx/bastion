// Copyright (c) 2026 Edison Lepiten / AIEONYX
// BASTION v0.1 — Policy Protection Domain
// Holds the node trust list and seen-nonce ledger.
// In production: runs in seL4 isolated PD; private key never leaves.

use std::collections::HashSet;
use crate::ed25519::{PublicKey, SigningKey, keypair_from_seed, PUBKEY_LEN};

/// Policy Protection Domain — node's trust authority
pub struct PolicyPD {
    /// Node signing key (NEVER leaves this PD in production)
    node_key: SigningKey,
    /// Trusted signer public keys (node key + any delegated keys)
    trusted_keys: Vec<[u8; PUBKEY_LEN]>,
    /// Seen nonces (replay protection)
    seen_nonces: HashSet<u64>,
    /// Whether this node has been commissioned
    pub commissioned: bool,
    /// Node identity string
    pub node_id: String,
}

impl PolicyPD {
    /// Create a new Policy PD from a seed (commissioning step).
    /// In production: seed comes from hardware RNG inside seL4 PD.
    pub fn commission(node_id: &str, seed: [u8; 32]) -> Self {
        let node_key = keypair_from_seed(seed);
        let pubkey = node_key.public_key();
        Self {
            node_key,
            trusted_keys: vec![pubkey.0],
            seen_nonces: HashSet::new(),
            commissioned: true,
            node_id: node_id.to_string(),
        }
    }

    /// Get the node's public key (safe to export — public only).
    pub fn node_pubkey(&self) -> PublicKey {
        self.node_key.public_key()
    }

    /// Sign a message with the node key.
    pub fn sign(&self, message: &[u8]) -> crate::ed25519::Signature {
        crate::ed25519::sign(&self.node_key, message)
    }

    /// Add a trusted public key (delegation).
    pub fn trust_key(&mut self, pubkey: PublicKey) {
        if !self.trusted_keys.contains(&pubkey.0) {
            self.trusted_keys.push(pubkey.0);
        }
    }

    /// Revoke a trusted public key.
    pub fn revoke_key(&mut self, pubkey: &PublicKey) {
        let node_pk = self.node_key.public_key();
        // Cannot revoke the node's own key
        if pubkey.0 == node_pk.0 { return; }
        self.trusted_keys.retain(|k| k != &pubkey.0);
    }

    /// Check if a public key is trusted.
    pub fn is_trusted(&self, pubkey: &PublicKey) -> bool {
        self.trusted_keys.contains(&pubkey.0)
    }

    /// Record a nonce as seen. Returns false if already seen (replay).
    pub fn record_nonce(&mut self, nonce: u64) -> bool {
        self.seen_nonces.insert(nonce)
    }

    /// Check if a nonce has been seen before.
    pub fn is_nonce_seen(&self, nonce: u64) -> bool {
        self.seen_nonces.contains(&nonce)
    }

    pub fn trusted_key_count(&self) -> usize {
        self.trusted_keys.len()
    }
}
