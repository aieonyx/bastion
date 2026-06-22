// Copyright (c) 2026 Edison Lepiten / AIEONYX
// BASTION v0.1 — Binary verifier: signature check, dev-mode rejection, policy gate

use crate::manifest::{BastionManifest, ProfileTag, BASTION_MAGIC};
use crate::ed25519::PublicKey;
use crate::policy_pd::PolicyPD;

/// Verification result
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyResult {
    Accepted,
    Rejected(RejectReason),
}

impl VerifyResult {
    pub fn is_accepted(&self) -> bool { matches!(self, Self::Accepted) }
    pub fn is_rejected(&self) -> bool { matches!(self, Self::Rejected(_)) }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RejectReason {
    DevModeRejected,           // hard invariant — no override
    InvalidSignature,
    ContentHashMismatch,
    UnknownSigner,             // pubkey not in node's trust list
    ManifestVersionUnsupported(u32),
    InvalidMagic,
    NonceReplay(u64),
    PolicyViolation(String),
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::DevModeRejected             => write!(f, "BASTION: dev-mode binary rejected (hard invariant)"),
            Self::InvalidSignature            => write!(f, "BASTION: invalid Ed25519 signature"),
            Self::ContentHashMismatch         => write!(f, "BASTION: content hash mismatch"),
            Self::UnknownSigner               => write!(f, "BASTION: unknown signer pubkey"),
            Self::ManifestVersionUnsupported(v) => write!(f, "BASTION: manifest version {} unsupported", v),
            Self::InvalidMagic                => write!(f, "BASTION: invalid magic bytes"),
            Self::NonceReplay(n)              => write!(f, "BASTION: nonce replay detected: {}", n),
            Self::PolicyViolation(s)          => write!(f, "BASTION: policy violation: {}", s),
        }
    }
}

/// BASTION binary verifier
pub struct BastionVerifier<'a> {
    policy: &'a PolicyPD,
}

impl<'a> BastionVerifier<'a> {
    pub fn new(policy: &'a PolicyPD) -> Self {
        Self { policy }
    }

    /// Verify a binary given its manifest and content bytes.
    /// Evaluation order:
    ///   1. Magic bytes check
    ///   2. Manifest version check
    ///   3. Dev-mode hard rejection (CANNOT be overridden)
    ///   4. Signature verification
    ///   5. Content hash verification
    ///   6. Signer trust check (pubkey in policy)
    ///   7. Nonce replay check
    pub fn verify(&self, manifest: &BastionManifest, content: &[u8]) -> VerifyResult {
        // 1. Version check
        if manifest.version != crate::manifest::MANIFEST_VERSION {
            return VerifyResult::Rejected(
                RejectReason::ManifestVersionUnsupported(manifest.version)
            );
        }

        // 2. Dev-mode hard rejection — BASTION architectural invariant
        if !manifest.profile.is_accepted() {
            return VerifyResult::Rejected(RejectReason::DevModeRejected);
        }

        // 3. Signature verification
        if !manifest.verify_signature() {
            return VerifyResult::Rejected(RejectReason::InvalidSignature);
        }

        // 4. Content hash
        if !manifest.verify_content(content) {
            return VerifyResult::Rejected(RejectReason::ContentHashMismatch);
        }

        // 5. Signer trust
        let pubkey = PublicKey(manifest.signer_pubkey);
        if !self.policy.is_trusted(&pubkey) {
            return VerifyResult::Rejected(RejectReason::UnknownSigner);
        }

        // 6. Nonce replay
        if self.policy.is_nonce_seen(manifest.nonce) {
            return VerifyResult::Rejected(RejectReason::NonceReplay(manifest.nonce));
        }

        VerifyResult::Accepted
    }
}
