// Copyright (c) 2026 Edison Lepiten / AIEONYX
// BASTION v0.1 — Binary manifest: signed header, capability declarations, profile tag

use serde::{Deserialize, Serialize};
use crate::ed25519::{PublicKey, Signature, SIG_LEN, PUBKEY_LEN};
use crate::hash::sha256;

pub const MANIFEST_VERSION: u32 = 1;
pub const BASTION_MAGIC: [u8; 4] = [0x42, 0x53, 0x54, 0x4E]; // "BSTN"

/// Compilation profile tag — determines acceptance policy
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProfileTag {
    SeL4Strict,       // production seL4 — accepted by default
    SovereignOffline, // offline sovereign — accepted by default
    MeshNode,         // mesh network node — accepted by default
    DevMode,          // REJECTED by BASTION in production (hard invariant)
}

impl ProfileTag {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SeL4Strict       => "sel4-strict",
            Self::SovereignOffline => "sovereign-offline",
            Self::MeshNode         => "mesh-node",
            Self::DevMode          => "dev-mode",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "sel4-strict"       => Some(Self::SeL4Strict),
            "sovereign-offline" => Some(Self::SovereignOffline),
            "mesh-node"         => Some(Self::MeshNode),
            "dev-mode"          => Some(Self::DevMode),
            _                   => None,
        }
    }

    /// BASTION hard invariant: dev-mode binaries are ALWAYS rejected.
    pub fn is_accepted(&self) -> bool {
        !matches!(self, Self::DevMode)
    }
}

/// Capability declaration — what the binary requests from seL4
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityDecl {
    pub name: String,
    pub required: bool,
}

impl CapabilityDecl {
    pub fn required(name: &str) -> Self {
        Self { name: name.into(), required: true }
    }
    pub fn optional(name: &str) -> Self {
        Self { name: name.into(), required: false }
    }
}

/// Binary manifest — signed attestation of a BASTION binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BastionManifest {
    pub version: u32,
    /// Binary name
    pub name: String,
    /// Semver
    pub semver: String,
    /// Compilation profile
    pub profile: ProfileTag,
    /// SHA-256 of the binary content
    pub content_hash: [u8; 32],
    /// Node public key that signed this manifest
    pub signer_pubkey: [u8; PUBKEY_LEN],
    /// Ed25519 signature over (version|name|semver|profile|content_hash|signer_pubkey)
    pub signature: [u8; SIG_LEN],
    /// Declared capabilities
    pub capabilities: Vec<CapabilityDecl>,
    /// Monotonic counter (replay protection)
    pub nonce: u64,
}

impl BastionManifest {
    /// Build and sign a manifest.
    pub fn new(
        name: &str,
        semver: &str,
        profile: ProfileTag,
        content: &[u8],
        capabilities: Vec<CapabilityDecl>,
        nonce: u64,
        signing_key: &crate::ed25519::SigningKey,
    ) -> Self {
        let content_hash = sha256(content);
        let pubkey = signing_key.public_key();
        let mut m = Self {
            version: MANIFEST_VERSION,
            name: name.to_string(),
            semver: semver.to_string(),
            profile,
            content_hash,
            signer_pubkey: pubkey.0,
            signature: [0u8; SIG_LEN],
            capabilities,
            nonce,
        };
        let msg = m.signing_message();
        let sig = crate::ed25519::sign(signing_key, &msg);
        m.signature = sig.0;
        m
    }

    /// The message that is signed: deterministic serialization of all fields
    /// except the signature itself.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.version.to_le_bytes());
        msg.extend_from_slice(self.name.as_bytes());
        msg.push(0); // null separator
        msg.extend_from_slice(self.semver.as_bytes());
        msg.push(0);
        msg.extend_from_slice(self.profile.as_str().as_bytes());
        msg.push(0);
        msg.extend_from_slice(&self.content_hash);
        msg.extend_from_slice(&self.signer_pubkey);
        msg.extend_from_slice(&self.nonce.to_le_bytes());
        msg
    }

    /// Verify the manifest signature.
    pub fn verify_signature(&self) -> bool {
        let msg = self.signing_message();
        let pubkey = PublicKey(self.signer_pubkey);
        let sig = Signature(self.signature);
        crate::ed25519::verify(&pubkey, &msg, &sig)
    }

    /// Verify content hash matches provided bytes.
    pub fn verify_content(&self, content: &[u8]) -> bool {
        sha256(content) == self.content_hash
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| e.to_string())
    }
}
