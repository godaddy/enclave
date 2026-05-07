// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `TpmSigner` — ECDSA P-256 signing backend using the Windows TPM.

// This module wraps NCrypt C APIs which require unsafe FFI calls.
#![allow(unsafe_code, unused_qualifications, let_underscore_drop)]

use crate::convert::p1363_to_der;
use crate::export::export_public_key;
use crate::key;
use crate::provider;
use crate::state;
use enclaveapp_core::metadata;
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::validate_label;
use enclaveapp_core::{AccessPolicy, Error, KeyMeta, KeyType, Result};
use sha2::{Digest, Sha256};
use windows::Win32::Security::Cryptography::*;

/// ECDSA P-256 algorithm identifier for CNG.
const ECDSA_P256_ALGORITHM: &str = "ECDSA_P256";

/// Windows TPM-backed ECDSA P-256 signer.
#[derive(Debug)]
pub struct TpmSigner {
    app_name: String,
    keys_dir_override: Option<std::path::PathBuf>,
}

impl TpmSigner {
    /// Create a new signer for the given application.
    pub fn new(app_name: &str) -> Self {
        TpmSigner {
            app_name: app_name.to_string(),
            keys_dir_override: None,
        }
    }

    /// Create a signer with a custom keys directory path.
    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        TpmSigner {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
        }
    }

    fn keys_dir(&self) -> std::path::PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }
}

impl EnclaveKeyManager for TpmSigner {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Signing {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "TpmSigner only supports signing keys".into(),
            });
        }

        let dir = self.keys_dir();
        let provider = provider::open_provider()?;
        let state = state::KeyMaterialState::acquire(&dir)?;
        state.ensure_label_available(label, || {
            match key::open_key(&provider, &self.app_name, label) {
                Ok(_key) => Ok(state::AuthoritativeKeyState::Present),
                Err(Error::KeyNotFound { .. }) => Ok(state::AuthoritativeKeyState::Missing),
                Err(error) => Err(error),
            }
        })?;
        let (_key_handle, pub_key) = key::create_key(
            &provider,
            &self.app_name,
            label,
            ECDSA_P256_ALGORITHM,
            policy,
        )?;

        state.persist_generated_key(label, key_type, policy, &pub_key, || {
            key::delete_key(&self.app_name, label)
        })?;

        // Layer the meta-integrity tag onto the CNG key. This is
        // the trust anchor for `<label>.meta` going forward — the
        // on-disk `<label>.meta.hmac` sidecar is a derivable cache,
        // not the authority. See
        // `docs/design-meta-hmac-trust-anchor.md`.
        //
        // Two failure modes (mirroring macOS keychain.rs):
        //   - meta-HMAC key unavailable (DPAPI rare path): fail-open,
        //     log a warning. Match pre-trust-anchor behavior; the
        //     user can run migrate-meta once DPAPI recovers.
        //   - meta-HMAC key available but the per-key tag write
        //     fails: hard error, roll back the entire keygen so the
        //     label is free to retry cleanly.
        let hmac_key_opt = crate::meta_hmac::load_or_create(&self.app_name)
            .ok()
            .flatten();
        if let Some(hk) = hmac_key_opt {
            let meta = KeyMeta::new(label, key_type, policy);
            if let Err(e) = metadata::save_meta_with_hmac(state.dir(), label, &meta, hk.as_slice())
            {
                rollback_after_persist(state.dir(), &self.app_name, label);
                return Err(e);
            }
            let meta_path = state.dir().join(format!("{label}.meta"));
            let meta_bytes = match std::fs::read(&meta_path) {
                Ok(b) => b,
                Err(e) => {
                    rollback_after_persist(state.dir(), &self.app_name, label);
                    return Err(Error::KeyOperation {
                        operation: "post_persist_meta_read".into(),
                        detail: format!("read {}: {e}", meta_path.display()),
                    });
                }
            };
            let tag = metadata::compute_meta_hmac_bytes(hk.as_slice(), &meta_bytes);
            if let Err(e) = crate::meta_tag::store(&self.app_name, label, &tag) {
                rollback_after_persist(state.dir(), &self.app_name, label);
                return Err(e);
            }
        } else {
            tracing::warn!(
                label = label,
                "meta-HMAC key unavailable at keygen; key persisted without integrity tag. \
                 Run `<app> migrate-meta` once DPAPI is reachable."
            );
        }

        Ok(pub_key)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        let dir = self.keys_dir();
        let state = state::KeyMaterialState::acquire(&dir)?;
        let provider = provider::open_provider()?;
        let key_handle = key::open_key(&provider, &self.app_name, label)?;
        let pub_key = export_public_key(&key_handle)?;
        metadata::sync_pub_key(state.dir(), label, &pub_key)
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        let provider = provider::open_provider()?;
        key::enumerate_keys(&provider, &self.app_name)
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        validate_label(label)?;
        let dir = self.keys_dir();
        let state = state::KeyMaterialState::acquire(&dir)?;
        state.reconcile_deleted_key(label, || match key::delete_key(&self.app_name, label) {
            Ok(()) => Ok(state::AuthoritativeKeyState::Present),
            Err(Error::KeyNotFound { .. }) => Ok(state::AuthoritativeKeyState::Missing),
            Err(error) => Err(error),
        })
    }

    fn rename_key(&self, old_label: &str, new_label: &str) -> Result<()> {
        // Windows CNG persisted keys are immutable by name: renaming the
        // CNG container requires exporting (not possible for
        // hardware-bound keys) and re-importing under a new name. A
        // consistent rename is therefore not achievable on this backend.
        // Callers (e.g. sshenc's `default` promotion) already gate this
        // operation off on Windows.
        let _ = (old_label, new_label);
        Err(Error::KeyOperation {
            operation: "rename_key".into(),
            detail: "renaming is not supported on the Windows TPM backend: \
                     CNG keys are immutable by name. Create a new key with \
                     the desired label and migrate authorized_keys instead."
                .into(),
        })
    }

    fn is_available(&self) -> bool {
        provider::is_available()
    }
}

/// Roll back a half-completed keygen *after* the on-disk material has
/// been persisted, when a subsequent step (meta-HMAC sidecar or
/// meta-tag store) failed. Each step is best-effort; we log warnings
/// and continue so partial cleanup doesn't strand resources.
///
/// Order matters: clear the CNG meta-tag property first (cheap, no
/// effect if already missing), remove on-disk artifacts, then delete
/// the CNG key itself. Deleting the key would orphan the property
/// anyway, but doing the property delete first avoids a tag that
/// outlives a later-recreated key with the same label.
fn rollback_after_persist(dir: &std::path::Path, app_name: &str, label: &str) {
    if let Err(e) = crate::meta_tag::delete(app_name, label) {
        tracing::warn!(label = label, error = %e, "rollback: meta_tag::delete failed");
    }
    match metadata::delete_key_files(dir, label) {
        Ok(()) | Err(Error::KeyNotFound { .. }) => {}
        Err(e) => tracing::warn!(label = label, error = %e, "rollback: file cleanup failed"),
    }
    if let Err(e) = key::delete_key(app_name, label) {
        tracing::warn!(label = label, error = %e, "rollback: CNG key delete failed");
    }
}

/// Run the per-op meta-integrity check against the CNG-stored tag.
/// Returns `Ok(())` on a clean verify, on a missing meta file
/// (`NoMeta` — caller's key-not-found flow handles it downstream),
/// and on `KeychainUnavailable` (fail-open; the CNG load below will
/// fail with its own clearer error if the provider is truly
/// unreachable).
///
/// Returns `Err` on **tamper** (CNG tag exists but doesn't match the
/// on-disk meta) and on **legacy** (no CNG tag — pre-migration key or
/// attacker-induced state). Error messages mirror the macOS
/// `keychain.rs::ensure_meta_integrity` wording so the user-facing UX
/// is identical across platforms.
fn ensure_meta_integrity(app_name: &str, label: &str, dir: &std::path::Path) -> Result<()> {
    // CRITICAL: do not touch the platform secure store unless an
    // on-disk `.meta` actually exists. Without this guard, every
    // synthetic call site (tests, fresh-install probes) would call
    // into `meta_hmac::load_existing` — which still touches DPAPI,
    // even read-only, and on a stripped-down host without a usable
    // user profile that surfaces as confusing noise.
    let meta_path = dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return Ok(());
    }

    // Read-only lookup. We must NOT trigger `CryptProtectData` here —
    // creation belongs on the keygen path. Without this distinction
    // a runner without an interactive user session can hang on the
    // implicit DPAPI prompt.
    let hmac_key = match crate::meta_hmac::load_existing(app_name) {
        Ok(Some(k)) => k,
        Ok(None) | Err(_) => return Ok(()),
    };

    match crate::meta_tag::verify(app_name, label, dir, hmac_key.as_slice())? {
        crate::meta_tag::VerifyOutcome::Match
        | crate::meta_tag::VerifyOutcome::NoMeta
        | crate::meta_tag::VerifyOutcome::KeychainUnavailable => Ok(()),
        crate::meta_tag::VerifyOutcome::Tamper => Err(Error::KeyOperation {
            operation: "meta_tag_verify".into(),
            detail: format!(
                "key '{label}': metadata integrity check failed. The on-disk meta \
                 does not match the keychain-stored tag — meta may have been \
                 tampered with. Refusing to proceed. Regenerate the key to restore \
                 a known-good state."
            ),
        }),
        crate::meta_tag::VerifyOutcome::Legacy => {
            // Strong-tamper variant when the migrate-meta marker is
            // already set; gentle one-time-cutover variant otherwise.
            // Treat any Credential-Manager failure on the marker
            // check as "marker not set" so the gentle message wins on
            // a flaky-store host.
            let marker_set = crate::meta_migration_marker::is_set(app_name).unwrap_or(false);
            if marker_set {
                Err(Error::KeyOperation {
                    operation: "meta_tag_legacy_post_migration".into(),
                    detail: format!(
                        "key '{label}' has no integrity tag, but `{app_name} migrate-meta` \
                         has already completed on this install. This is a strong tamper \
                         signal — legitimate operation should not produce a missing tag \
                         after the marker is set. Recommended: regenerate the affected \
                         key with `{app_name} keygen`. Do NOT run migrate-meta again \
                         unless you can independently explain why this key's tag is \
                         missing (e.g., manual restore from a backup of an unrelated \
                         machine), in which case pass \
                         `--force-rerun-i-understand` to override."
                    ),
                })
            } else {
                Err(Error::KeyOperation {
                    operation: "meta_tag_legacy".into(),
                    detail: format!(
                        "key '{label}' has no integrity tag. This is the one-time \
                         migration required by upgrading to a build that introduces meta \
                         integrity tags, and is not something future upgrades will repeat. \
                         Before migrating, verify the key's current policy looks correct: \
                         `{app_name} inspect {label}`. To migrate: `{app_name} \
                         migrate-meta`."
                    ),
                })
            }
        }
    }
}

impl EnclaveSigner for TpmSigner {
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        validate_label(label)?;
        let provider = provider::open_provider()?;
        let key_handle = key::open_key(&provider, &self.app_name, label)?;

        // Per-op trust-anchor check before any signing UI is
        // surfaced. Refuses to proceed on a tamper / legacy state so
        // the TPM is never asked to sign over policy-bearing meta
        // that doesn't match what the user originally agreed to.
        ensure_meta_integrity(&self.app_name, label, &self.keys_dir())?;

        // Re-verify the key's NCRYPT_UI_POLICY matches the metadata's
        // AccessPolicy before signing. Without this check, a same-user
        // attacker who pre-planted a TPM key with the expected CNG
        // name (but without UI_PROTECT_KEY_FLAG) could get sshenc to
        // sign without triggering a UI prompt — the hardware enforces
        // the policy that's actually set on the key, not what the app
        // thinks was set.
        //
        // With the `windows-hello-ui` feature on, `key::create_key`
        // skips the flag *only* when Hello was enrolled at keygen
        // time. So a key without the flag is the expected
        // configuration on a Hello host — we verify it explicitly
        // below: if Hello is no longer available now, refuse the
        // signature rather than falling through to silent TPM use.
        let dir = self.keys_dir();
        let expected_policy = match metadata::load_meta(&dir, label) {
            Ok(meta) => meta.access_policy,
            Err(Error::KeyNotFound { .. }) => AccessPolicy::None,
            Err(err) => return Err(err),
        };
        // Verify the on-disk metadata's access policy matches the
        // TPM key's actual `NCRYPT_UI_POLICY` flag. Catches an
        // attacker-planted key that has the expected CNG name but
        // a different (or missing) UI flag -- without this check
        // the agent might sign through a key that has no
        // hardware-enforced UI gate. The hardware itself fires the
        // CryptUI password dialog at the TPM call below if the
        // flag is set; we don't issue any user-mode prompts here.
        crate::ui_policy::verify_ui_policy_matches(&key_handle, expected_policy)?;

        // Pre-hash with SHA-256.
        let digest = Sha256::digest(data);

        // Query signature size.
        let mut sig_size: u32 = 0;
        unsafe {
            NCryptSignHash(
                key_handle.as_key(),
                None,
                &digest,
                None,
                &mut sig_size,
                NCRYPT_FLAGS::default(),
            )
            .map_err(|e| Error::SignFailed {
                detail: format!("NCryptSignHash size query: {e}"),
            })?;
        }

        // Produce the P1363 signature.
        let mut sig = vec![0_u8; sig_size as usize];
        unsafe {
            NCryptSignHash(
                key_handle.as_key(),
                None,
                &digest,
                Some(&mut sig),
                &mut sig_size,
                NCRYPT_FLAGS::default(),
            )
            .map_err(|e| Error::SignFailed {
                detail: format!("NCryptSignHash: {e}"),
            })?;
        }
        sig.truncate(sig_size as usize);

        // CNG returns P1363 (r || s); convert to DER.
        Ok(p1363_to_der(&sig))
    }
}
