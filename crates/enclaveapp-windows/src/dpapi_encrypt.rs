// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows DPAPI-backed software ECIES encryption backend.
//!
//! This is intentionally not the normal Windows backend. It exists only
//! for VM hosts where TPM 2.0 is unavailable. The private P-256 key
//! is stored on disk encrypted by per-user DPAPI, and the public ECIES
//! wire format matches the software/keyring backend.

use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use enclaveapp_core::metadata::{self, KeyMeta};
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::{validate_label, AccessPolicy, KeyType};
use enclaveapp_core::{Error, Result};
use p256::SecretKey;
use zeroize::Zeroizing;

const ECIES_VERSION: u8 = 0x01;
const GCM_NONCE_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;
const UNCOMPRESSED_POINT_SIZE: usize = 65;
const RAW_KEY_SIZE: usize = 32;
const MIN_CIPHERTEXT_LEN: usize = 1 + UNCOMPRESSED_POINT_SIZE + GCM_NONCE_SIZE + GCM_TAG_SIZE;

#[derive(Debug)]
pub struct DpapiEncryptor {
    app_name: String,
    keys_dir_override: Option<std::path::PathBuf>,
}

impl DpapiEncryptor {
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: None,
        }
    }

    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
        }
    }

    fn keys_dir(&self) -> std::path::PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }

    fn key_path(&self, label: &str) -> std::path::PathBuf {
        self.keys_dir().join(format!("{label}.key"))
    }
}

impl EnclaveKeyManager for DpapiEncryptor {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Encryption {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "DpapiEncryptor only supports encryption keys".into(),
            });
        }
        let dir = self.keys_dir();
        metadata::ensure_dir(&dir)?;
        let _lock = metadata::DirLock::acquire(&dir)?;
        let key_path = self.key_path(label);
        if key_path.exists() || metadata::key_files_exist(&dir, label)? {
            return Err(Error::DuplicateLabel {
                label: label.to_string(),
            });
        }

        let secret_key = SecretKey::random(&mut elliptic_curve::rand_core::OsRng);
        let public_key = secret_key.public_key();
        let pub_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
        let secret_bytes = Zeroizing::new(secret_key.to_bytes().to_vec());
        let protected = crate::dpapi::protect(&secret_bytes, "dpapi_encrypt_key")?;
        metadata::atomic_write(&key_path, &protected)?;
        metadata::restrict_file_permissions(&key_path)?;
        metadata::save_pub_key(&dir, label, &pub_bytes)?;

        let meta = KeyMeta::new(label, key_type, policy);
        match crate::meta_hmac::load_or_create(&self.app_name)? {
            Some(hmac_key) => {
                metadata::save_meta_with_hmac(&dir, label, &meta, hmac_key.as_slice())?;
            }
            None => metadata::save_meta(&dir, label, &meta)?,
        }

        Ok(pub_bytes)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        let dir = self.keys_dir();
        match metadata::load_pub_key(&dir, label) {
            Ok(pub_key) => Ok(pub_key),
            Err(_) => {
                let secret = load_secret_key(&self.key_path(label), label)?;
                Ok(secret
                    .public_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec())
            }
        }
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        metadata::list_labels(&self.keys_dir())
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        validate_label(label)?;
        let dir = self.keys_dir();
        let key_path = self.key_path(label);
        let key_exists = key_path.exists() || metadata::key_files_exist(&dir, label)?;
        if !key_exists {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        let _lock = metadata::DirLock::acquire(&dir)?;
        if key_path.exists() {
            std::fs::remove_file(&key_path)?;
        }
        match metadata::delete_key_files(&dir, label) {
            Ok(()) | Err(Error::KeyNotFound { .. }) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn is_available(&self) -> bool {
        true
    }
}

impl EnclaveEncryptor for DpapiEncryptor {
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use p256::ecdh::diffie_hellman;
        use rand::RngCore;

        validate_label(label)?;
        let pub_bytes = self.public_key(label)?;
        let stored_point =
            p256::EncodedPoint::from_bytes(&pub_bytes).map_err(|e| Error::EncryptFailed {
                detail: format!("invalid public key: {e}"),
            })?;
        let stored_pub = p256::PublicKey::from_encoded_point(&stored_point)
            .into_option()
            .ok_or_else(|| Error::EncryptFailed {
                detail: "invalid public key point".into(),
            })?;

        let eph_secret = SecretKey::random(&mut elliptic_curve::rand_core::OsRng);
        let eph_pub = eph_secret.public_key();
        let eph_pub_bytes = eph_pub.to_encoded_point(false).as_bytes().to_vec();
        let shared_secret = diffie_hellman(eph_secret.to_nonzero_scalar(), stored_pub.as_affine());
        let derived_key = derive_key(&shared_secret, &eph_pub_bytes);
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_slice()).map_err(|e| {
            Error::EncryptFailed {
                detail: format!("AES init: {e}"),
            }
        })?;
        let mut nonce_bytes = [0_u8; GCM_NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let encrypted = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| Error::EncryptFailed {
                detail: format!("AES-GCM: {e}"),
            })?;

        let mut output =
            Vec::with_capacity(1 + UNCOMPRESSED_POINT_SIZE + GCM_NONCE_SIZE + encrypted.len());
        output.push(ECIES_VERSION);
        output.extend_from_slice(&eph_pub_bytes);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&encrypted);
        Ok(output)
    }

    fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use p256::ecdh::diffie_hellman;

        validate_label(label)?;
        if ciphertext.len() < MIN_CIPHERTEXT_LEN {
            return Err(Error::DecryptFailed {
                detail: "ciphertext too short".into(),
            });
        }
        if ciphertext[0] != ECIES_VERSION {
            return Err(Error::DecryptFailed {
                detail: format!("unsupported version: 0x{:02x}", ciphertext[0]),
            });
        }
        let eph_pub_bytes = &ciphertext[1..66];
        let nonce_bytes = &ciphertext[66..78];
        let encrypted = &ciphertext[78..];
        let secret = load_secret_key(&self.key_path(label), label)?;
        let eph_point =
            p256::EncodedPoint::from_bytes(eph_pub_bytes).map_err(|e| Error::DecryptFailed {
                detail: format!("invalid ephemeral key: {e}"),
            })?;
        let eph_pub = p256::PublicKey::from_encoded_point(&eph_point)
            .into_option()
            .ok_or_else(|| Error::DecryptFailed {
                detail: "invalid ephemeral key point".into(),
            })?;
        let shared_secret = diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
        let derived_key = derive_key(&shared_secret, eph_pub_bytes);
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_slice()).map_err(|e| {
            Error::DecryptFailed {
                detail: format!("AES init: {e}"),
            }
        })?;
        let nonce_array: [u8; GCM_NONCE_SIZE] =
            nonce_bytes.try_into().map_err(|_| Error::DecryptFailed {
                detail: "invalid nonce length".into(),
            })?;
        let nonce = Nonce::from(nonce_array);
        cipher
            .decrypt(&nonce, encrypted)
            .map_err(|e| Error::DecryptFailed {
                detail: format!("AES-GCM: {e}"),
            })
    }
}

fn load_secret_key(key_path: &std::path::Path, label: &str) -> Result<SecretKey> {
    let protected = match metadata::read_no_follow(key_path) {
        Ok(bytes) => bytes,
        Err(err) if matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::NotFound) => {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        Err(err) => return Err(err),
    };
    let plaintext = Zeroizing::new(crate::dpapi::unprotect(&protected, "dpapi_decrypt_key")?);
    if plaintext.len() != RAW_KEY_SIZE {
        return Err(Error::KeyOperation {
            operation: "dpapi_decrypt_key".into(),
            detail: format!(
                "decrypted key has unexpected length {}, expected {RAW_KEY_SIZE}",
                plaintext.len()
            ),
        });
    }
    SecretKey::from_slice(&plaintext).map_err(|e| Error::KeyOperation {
        operation: "load_secret_key".into(),
        detail: e.to_string(),
    })
}

fn derive_key(
    shared_secret: &p256::ecdh::SharedSecret,
    eph_pub_bytes: &[u8],
) -> Zeroizing<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.raw_secret_bytes());
    hasher.update([0x00, 0x00, 0x00, 0x01]);
    hasher.update(eph_pub_bytes);
    let result = hasher.finalize();
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&result);
    key
}
