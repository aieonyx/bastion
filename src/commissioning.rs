// Copyright (c) 2026 Edison Lepiten / AIEONYX
// BASTION v0.1 — Node Commissioning Ceremony
// One-time physical setup before node enters any profile.

use crate::policy_pd::PolicyPD;
use crate::hash::sha256;

/// Commissioning result
#[derive(Debug)]
pub struct CommissioningResult {
    pub node_id: String,
    pub pubkey_hex: String,
    pub commissioned_at: u64,
}

/// Commission a BASTION node from a seed and node ID.
/// In production: seed comes from hardware RNG inside seL4 isolated PD.
/// The seed must be 32 bytes of high-entropy random data.
pub fn commission_node(node_id: &str, seed: [u8; 32]) -> (PolicyPD, CommissioningResult) {
    let policy = PolicyPD::commission(node_id, seed);
    let pubkey_hex = policy.node_pubkey().0.iter()
        .map(|b| format!("{:02x}", b)).collect();
    let result = CommissioningResult {
        node_id: node_id.to_string(),
        pubkey_hex,
        commissioned_at: now_secs(),
    };
    (policy, result)
}

/// Validate that a seed has sufficient entropy (not all zeros, not all same byte).
pub fn validate_seed(seed: &[u8; 32]) -> bool {
    if seed.iter().all(|&b| b == 0) { return false; }
    if seed.iter().all(|&b| b == seed[0]) { return false; }
    // Check at least 8 distinct byte values
    let distinct: std::collections::HashSet<u8> = seed.iter().cloned().collect();
    distinct.len() >= 8
}

/// Derive a deterministic test seed from a string (for testing only — NOT production).
pub fn test_seed(input: &str) -> [u8; 32] {
    sha256(input.as_bytes())
}

fn now_secs() -> u64 {
    // Stub: returns 0 in no_std context
    // Production: seL4 hardware timer
    0
}
