// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Software ECDSA P-256 signing backend.

use crate::key_storage::{self, SoftwareConfig};
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::{validate_label, AccessPolicy, KeyType};
use enclaveapp_core::{Error, Result};

/// Software-based ECDSA P-256 signer.
///
/// Private keys are stored as files on disk (not hardware-backed).
#[derive(Debug)]
pub struct SoftwareSigner {
    config: SoftwareConfig,
}

impl SoftwareSigner {
    pub fn new(app_name: &str) -> Self {
        Self {
            config: SoftwareConfig::new(app_name),
        }
    }

    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        Self {
            config: SoftwareConfig::with_keys_dir(app_name, keys_dir),
        }
    }

    /// Disable keyring-based key encryption (for testing or environments
    /// without a keyring daemon).
    ///
    /// When the `keyring-storage` feature is not enabled this is a no-op
    /// because keyring support is already absent.
    pub fn without_keyring(mut self) -> Self {
        self.config.use_keyring = false;
        self
    }
}

impl EnclaveKeyManager for SoftwareSigner {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Signing {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "SoftwareSigner only supports signing keys".into(),
            });
        }
        key_storage::generate_and_save(&self.config, label, key_type, policy)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        key_storage::load_public_key(&self.config, label)
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        key_storage::list_labels(&self.config)
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        validate_label(label)?;
        key_storage::delete_key(&self.config, label)
    }

    fn rename_key(&self, old_label: &str, new_label: &str) -> Result<()> {
        key_storage::rename_key(&self.config, old_label, new_label)
    }

    fn is_available(&self) -> bool {
        true
    }
}

impl EnclaveSigner for SoftwareSigner {
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::{signature::Signer, SigningKey};

        // AccessPolicy is stored in key metadata but is not enforced here.
        // The private key is loaded from the keyring and signs without any
        // user prompt, regardless of the policy recorded at generation time.
        validate_label(label)?;
        let secret = key_storage::load_secret_key(&self.config, label)?;
        let signing_key = SigningKey::from(&secret);

        let signature: p256::ecdsa::DerSignature = signing_key.sign(data);
        Ok(signature.as_bytes().to_vec())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-sw-sign-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn generate_and_sign_produces_valid_der() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("sign-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let sig = signer.sign("sign-key", b"hello world").unwrap();

        // DER signature starts with SEQUENCE tag 0x30
        assert_eq!(sig[0], 0x30);
        // Typical P-256 DER signature is 70-72 bytes
        assert!(
            sig.len() >= 68 && sig.len() <= 73,
            "sig len = {}",
            sig.len()
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sign_produces_different_output_for_different_data() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("diff-data", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let sig1 = signer.sign("diff-data", b"data one").unwrap();
        let sig2 = signer.sign("diff-data", b"data two").unwrap();
        assert_ne!(sig1, sig2);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sign_fails_for_nonexistent_key() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let err = signer.sign("ghost", b"data").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_rejects_encryption_key_type() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let err = signer
            .generate("enc-key", KeyType::Encryption, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::KeyOperation { .. } => {}
            other => panic!("expected KeyOperation, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn public_key_matches_generated() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let generated = signer
            .generate("pk-test", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let retrieved = signer.public_key("pk-test").unwrap();
        assert_eq!(generated, retrieved);
        assert_eq!(retrieved.len(), 65);
        assert_eq!(retrieved[0], 0x04);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_and_delete_lifecycle() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        assert!(signer.list_keys().unwrap().is_empty());

        signer
            .generate("key-a", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        signer
            .generate("key-b", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        assert_eq!(signer.list_keys().unwrap(), vec!["key-a", "key-b"]);

        signer.delete_key("key-a").unwrap();
        assert_eq!(signer.list_keys().unwrap(), vec!["key-b"]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn is_available_returns_true() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();
        assert!(signer.is_available());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn software_signer_rejects_invalid_labels_across_operations() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let err = signer.public_key("../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = signer.delete_key("../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = signer.sign("../escape", b"payload").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn signature_can_be_verified_with_public_key() {
        use p256::ecdsa::{signature::Verifier, VerifyingKey};

        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let pub_bytes = signer
            .generate("verify-test", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let data = b"test message for verification";
        let sig_bytes = signer.sign("verify-test", data).unwrap();

        // Reconstruct the verifying key from the public key bytes
        let point = p256::EncodedPoint::from_bytes(&pub_bytes).unwrap();
        let verifying_key = VerifyingKey::from_encoded_point(&point).unwrap();
        let signature = p256::ecdsa::DerSignature::from_bytes(&sig_bytes).unwrap();
        verifying_key.verify(data, &signature).unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_returns_valid_65_byte_pubkey() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let pub_bytes = signer
            .generate("gen-pubkey", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04, "SEC1 uncompressed point prefix");

        // Verify it's a valid P-256 point
        let pk = p256::PublicKey::from_sec1_bytes(&pub_bytes);
        assert!(pk.is_ok(), "must be a valid P-256 point");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sign_is_deterministic_for_same_key_and_data() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("det-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();

        // RFC 6979 deterministic signatures: same key + same data = same signature
        let sig1 = signer.sign("det-key", b"deterministic data").unwrap();
        let sig2 = signer.sign("det-key", b"deterministic data").unwrap();
        assert_eq!(sig1, sig2, "RFC 6979 signatures should be deterministic");

        // Different data should produce different signatures
        let sig3 = signer.sign("det-key", b"different data").unwrap();
        assert_ne!(sig1, sig3);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_keys_after_generate_includes_label() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("listed-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();

        let keys = signer.list_keys().unwrap();
        assert!(
            keys.contains(&"listed-key".to_string()),
            "list_keys should include the generated label"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_then_sign_returns_key_not_found() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("del-then-sign", KeyType::Signing, AccessPolicy::None)
            .unwrap();

        // Sign succeeds before deletion
        signer.sign("del-then-sign", b"data").unwrap();

        // Delete the key
        signer.delete_key("del-then-sign").unwrap();

        // Sign should now fail
        let err = signer.sign("del-then-sign", b"data").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "del-then-sign"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn with_keys_dir_uses_custom_directory() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("custom-dir-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();

        // Key files should be in our custom directory
        assert!(dir.join("custom-dir-key.key").exists());
        assert!(dir.join("custom-dir-key.pub").exists());
        assert!(dir.join("custom-dir-key.meta").exists());

        // Should NOT be in the default directory
        let default_dir = enclaveapp_core::metadata::keys_dir("test");
        assert!(!default_dir.join("custom-dir-key.key").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_with_invalid_label_returns_error() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        // Empty label
        let err = signer
            .generate("", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::InvalidLabel { .. } => {}
            other => panic!("expected InvalidLabel for empty label, got: {other}"),
        }

        // Label with special characters
        let err = signer
            .generate("bad/label", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::InvalidLabel { .. } => {}
            other => panic!("expected InvalidLabel for label with slash, got: {other}"),
        }

        // Label with spaces
        let err = signer
            .generate("bad label", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::InvalidLabel { .. } => {}
            other => panic!("expected InvalidLabel for label with space, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
