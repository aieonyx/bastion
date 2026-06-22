// Copyright (c) 2026 Edison Lepiten / AIEONYX
// BASTION v0.1 tests (20 tests)

use bastion::commissioning::{commission_node, validate_seed, test_seed};
use bastion::manifest::{BastionManifest, ProfileTag, CapabilityDecl, MANIFEST_VERSION};
use bastion::verifier::{BastionVerifier, VerifyResult, RejectReason};
use bastion::policy_pd::PolicyPD;
use bastion::ed25519::{keypair_from_seed, PublicKey};
use bastion::hash::{sha256, sha256_hex};

fn node() -> PolicyPD {
    PolicyPD::commission("test-node-01", test_seed("test-node-01"))
}

fn make_manifest(policy: &PolicyPD, profile: ProfileTag, content: &[u8]) -> BastionManifest {
    let signing_key = bastion::ed25519::keypair_from_seed(test_seed("test-node-01"));
    BastionManifest::new(
        "test-binary", "0.1.0", profile, content,
        vec![CapabilityDecl::required("IPC")], 1, &signing_key,
    )
}

// ── T1: SHA-256 known vector ──────────────────────────────────────────────────
#[test]
fn t1_sha256_empty() {
    let h = sha256_hex(b"");
    assert_eq!(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

// ── T2: ProfileTag acceptance ─────────────────────────────────────────────────
#[test]
fn t2_profile_acceptance() {
    assert!(ProfileTag::SeL4Strict.is_accepted());
    assert!(ProfileTag::SovereignOffline.is_accepted());
    assert!(ProfileTag::MeshNode.is_accepted());
    assert!(!ProfileTag::DevMode.is_accepted(), "DevMode MUST be rejected");
}

// ── T3: ProfileTag from_str roundtrip ─────────────────────────────────────────
#[test]
fn t3_profile_roundtrip() {
    for s in ["sel4-strict","sovereign-offline","mesh-node","dev-mode"] {
        let p = ProfileTag::from_str(s).unwrap();
        assert_eq!(p.as_str(), s);
    }
}

// ── T4: validate_seed rejects all-zeros ───────────────────────────────────────
#[test]
fn t4_seed_zero_rejected() {
    assert!(!validate_seed(&[0u8; 32]));
}

// ── T5: validate_seed rejects low-entropy ────────────────────────────────────
#[test]
fn t5_seed_low_entropy_rejected() {
    assert!(!validate_seed(&[0xABu8; 32]));
}

// ── T6: validate_seed accepts good seed ───────────────────────────────────────
#[test]
fn t6_seed_good_accepted() {
    let seed = test_seed("sovereign-node-entropy-source");
    assert!(validate_seed(&seed));
}

// ── T7: commission_node produces commissioned PolicyPD ────────────────────────
#[test]
fn t7_commission_node() {
    let seed = test_seed("node-alpha");
    let (policy, result) = commission_node("node-alpha", seed);
    assert!(policy.commissioned);
    assert_eq!(result.node_id, "node-alpha");
    assert_eq!(result.pubkey_hex.len(), 64); // 32 bytes hex
}

// ── T8: PolicyPD node pubkey is trusted ───────────────────────────────────────
#[test]
fn t8_node_pubkey_trusted() {
    let policy = node();
    let pk = policy.node_pubkey();
    assert!(policy.is_trusted(&pk));
}

// ── T9: PolicyPD trust/revoke delegation ──────────────────────────────────────
#[test]
fn t9_trust_revoke() {
    let mut policy = node();
    let other_key = keypair_from_seed(test_seed("delegate"));
    let other_pk = other_key.public_key();
    assert!(!policy.is_trusted(&other_pk));
    policy.trust_key(other_pk.clone());
    assert!(policy.is_trusted(&other_pk));
    policy.revoke_key(&other_pk);
    assert!(!policy.is_trusted(&other_pk));
}

// ── T10: PolicyPD cannot revoke own key ───────────────────────────────────────
#[test]
fn t10_cannot_revoke_node_key() {
    let mut policy = node();
    let pk = policy.node_pubkey();
    policy.revoke_key(&pk);
    assert!(policy.is_trusted(&pk), "node key must never be revoked");
}

// ── T11: PolicyPD nonce tracking ─────────────────────────────────────────────
#[test]
fn t11_nonce_tracking() {
    let mut policy = node();
    assert!(!policy.is_nonce_seen(42));
    assert!(policy.record_nonce(42));  // first time: ok
    assert!(policy.is_nonce_seen(42));
    assert!(!policy.record_nonce(42)); // second time: replay
}

// ── T12: manifest signing + verify_signature ─────────────────────────────────
#[test]
fn t12_manifest_sign_verify() {
    let policy = node();
    let m = make_manifest(&policy, ProfileTag::SeL4Strict, b"binary content");
    assert!(m.verify_signature(), "fresh manifest must verify");
}

// ── T13: manifest content hash ───────────────────────────────────────────────
#[test]
fn t13_manifest_content_hash() {
    let policy = node();
    let content = b"sovereign binary";
    let m = make_manifest(&policy, ProfileTag::SeL4Strict, content);
    assert!(m.verify_content(content));
    assert!(!m.verify_content(b"tampered"));
}

// ── T14: manifest JSON roundtrip ─────────────────────────────────────────────
#[test]
fn t14_manifest_json_roundtrip() {
    let policy = node();
    let m = make_manifest(&policy, ProfileTag::SovereignOffline, b"data");
    let json = m.to_json();
    let m2 = BastionManifest::from_json(&json).unwrap();
    assert_eq!(m2.name, m.name);
    assert_eq!(m2.content_hash, m.content_hash);
}

// ── T15: verifier accepts valid binary ───────────────────────────────────────
#[test]
fn t15_verifier_accepts_valid() {
    let policy = node();
    let content = b"sovereign binary";
    let m = make_manifest(&policy, ProfileTag::SeL4Strict, content);
    let v = BastionVerifier::new(&policy);
    assert_eq!(v.verify(&m, content), VerifyResult::Accepted);
}

// ── T16: verifier rejects dev-mode (hard invariant) ──────────────────────────
#[test]
fn t16_verifier_rejects_devmode() {
    let policy = node();
    let content = b"dev binary";
    let m = make_manifest(&policy, ProfileTag::DevMode, content);
    let v = BastionVerifier::new(&policy);
    assert_eq!(
        v.verify(&m, content),
        VerifyResult::Rejected(RejectReason::DevModeRejected)
    );
}

// ── T17: verifier rejects content tamper ─────────────────────────────────────
#[test]
fn t17_verifier_rejects_tampered_content() {
    let policy = node();
    let content = b"original binary";
    let m = make_manifest(&policy, ProfileTag::SeL4Strict, content);
    let v = BastionVerifier::new(&policy);
    assert_eq!(
        v.verify(&m, b"tampered binary"),
        VerifyResult::Rejected(RejectReason::ContentHashMismatch)
    );
}

// ── T18: verifier rejects unknown signer ─────────────────────────────────────
#[test]
fn t18_verifier_rejects_unknown_signer() {
    let policy = node();
    // Sign with a different key
    let other_key = keypair_from_seed(test_seed("attacker"));
    let content = b"binary";
    let m = BastionManifest::new(
        "evil", "0.0.1", ProfileTag::SeL4Strict, content, vec![], 2, &other_key,
    );
    let v = BastionVerifier::new(&policy);
    assert_eq!(
        v.verify(&m, content),
        VerifyResult::Rejected(RejectReason::UnknownSigner)
    );
}

// ── T19: verifier rejects nonce replay ───────────────────────────────────────
#[test]
fn t19_verifier_rejects_nonce_replay() {
    let mut policy = node();
    policy.record_nonce(1); // mark nonce 1 as seen
    let signing_key = keypair_from_seed(test_seed("test-node-01"));
    let content = b"binary";
    let m = BastionManifest::new(
        "test", "0.1.0", ProfileTag::SeL4Strict, content, vec![], 1, &signing_key,
    );
    let v = BastionVerifier::new(&policy);
    assert_eq!(
        v.verify(&m, content),
        VerifyResult::Rejected(RejectReason::NonceReplay(1))
    );
}

// ── T20: full commissioning + sign + verify pipeline ─────────────────────────
#[test]
fn t20_full_pipeline() {
    // Commission node
    let seed = test_seed("production-node-prague-01");
    assert!(validate_seed(&seed));
    let (policy, result) = commission_node("prague-01", seed);
    assert!(policy.commissioned);
    assert_eq!(result.node_id, "prague-01");

    // Build and sign a binary manifest
    let signing_key = keypair_from_seed(seed);
    let content = b"axon_main sovereign binary v0.1.0";
    let manifest = BastionManifest::new(
        "axon_main", "0.1.0",
        ProfileTag::SovereignOffline,
        content,
        vec![
            CapabilityDecl::required("IPC"),
            CapabilityDecl::optional("GPU"),
        ],
        100,
        &signing_key,
    );

    // Verify
    let verifier = BastionVerifier::new(&policy);
    assert_eq!(verifier.verify(&manifest, content), VerifyResult::Accepted);

    // Dev-mode binary from same node is still rejected
    let dev_manifest = BastionManifest::new(
        "dev_tool", "0.0.1", ProfileTag::DevMode,
        content, vec![], 101, &signing_key,
    );
    assert_eq!(
        verifier.verify(&dev_manifest, content),
        VerifyResult::Rejected(RejectReason::DevModeRejected)
    );
}
