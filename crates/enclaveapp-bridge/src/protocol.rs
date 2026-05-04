// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! JSON-RPC protocol types shared between server and client.

use base64::Engine;
use enclaveapp_core::AccessPolicy;
use serde::{Deserialize, Serialize};

/// Bridge request sent from WSL client to Windows server.
#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeRequest {
    /// Method: "init", "encrypt", "decrypt", "destroy"
    pub method: String,
    /// Parameters.
    pub params: BridgeParams,
}

/// Bridge request parameters.
///
/// The legacy `biometric: bool` field from earlier releases has been
/// removed. `access_policy` is now the only accepted encoding of the
/// key's access policy on the wire. See THREAT_MODEL.md T5 — the
/// legacy field opened a silent-downgrade path for a malicious bridge
/// peer that honored `biometric` and ignored `access_policy`.
///
/// The `webauthn_*` fields are populated only by the
/// `webauthn_make_credential` / `webauthn_get_assertion` /
/// `webauthn_delete_platform_credential` methods (used to give WSL
/// callers parity with native-Windows SK keygen / sign by routing
/// through `webauthn.dll` on the Windows host). Other methods leave
/// them empty and the server ignores them.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BridgeParams {
    /// Base64-encoded data (plaintext for encrypt, ciphertext for decrypt).
    #[serde(default)]
    pub data: String,
    /// Access policy to enforce on key use.
    #[serde(default)]
    pub access_policy: AccessPolicy,
    /// Application name (determines TPM key name).
    #[serde(default)]
    pub app_name: String,
    /// Key label within the application namespace.
    #[serde(default)]
    pub key_label: String,

    // --- WebAuthn / SK fields ---
    //
    // All optional; populated only by the `webauthn_*` methods.
    // Skipped on serialize when `None` so non-SK requests stay on
    // the existing wire shape.
    /// FIDO2 Relying-Party identifier (e.g. `sshenc-<keyhash>.local`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    /// Human-readable RP name surfaced in the Hello prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    /// Per-user opaque ID (base64). Used at make-credential time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id_b64: Option<String>,
    /// Username surfaced in the Hello prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    /// Display name surfaced in the Hello prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
    /// Credential identifier (base64). Required for
    /// `webauthn_get_assertion` and `webauthn_delete_platform_credential`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id_b64: Option<String>,
    /// Bytes that webauthn.dll hashes with SHA-256 and signs as the
    /// `clientDataHash`. For SSH-SK signing this is the raw SSH
    /// session-binding payload (we exploit the bytes-of-JSON
    /// contract -- see `enclaveapp-windows-webauthn` for the
    /// brittleness note). Base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_data_b64: Option<String>,
    /// Hello prompt timeout in milliseconds (default 60_000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u32>,
}

impl BridgeParams {
    /// Access policy requested by this message. Kept as a method for
    /// source-compatibility with the legacy `effective_access_policy()`
    /// call sites that used to reconcile `access_policy` vs a legacy
    /// `biometric: bool` flag.
    #[must_use]
    pub fn effective_access_policy(&self) -> AccessPolicy {
        self.access_policy
    }

    /// Build a new `BridgeParams` for the legacy (TPM/CNG) methods.
    /// The WebAuthn-side fields are left `None`.
    #[must_use]
    pub fn new(
        data: String,
        access_policy: AccessPolicy,
        app_name: String,
        key_label: String,
    ) -> Self {
        Self {
            data,
            access_policy,
            app_name,
            key_label,
            rp_id: None,
            rp_name: None,
            user_id_b64: None,
            user_name: None,
            user_display_name: None,
            credential_id_b64: None,
            client_data_b64: None,
            timeout_ms: None,
        }
    }
}

/// JSON payload returned in `BridgeResponse::result` for a successful
/// `webauthn_make_credential` call. Caller `serde_json::from_str`s
/// the result string to recover the structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct WebauthnMakeCredentialResult {
    /// Base64 of the platform-authenticator credential identifier.
    pub credential_id_b64: String,
    /// Hex-encoded ECDSA P-256 public-key X coordinate (32 bytes).
    pub public_key_x_hex: String,
    /// Hex-encoded ECDSA P-256 public-key Y coordinate (32 bytes).
    pub public_key_y_hex: String,
    /// Base64 of the raw `authenticator_data` from the make-credential
    /// response. Caller can use it for audit / debugging; not
    /// required for downstream signing.
    pub authenticator_data_b64: String,
    /// Whether the platform authenticator made the credential
    /// resident (Win11 26200+ forces resident regardless of the
    /// `bRequireResidentKey` hint).
    pub resident: bool,
}

/// JSON payload returned in `BridgeResponse::result` for a successful
/// `webauthn_get_assertion` call.
#[derive(Debug, Serialize, Deserialize)]
pub struct WebauthnAssertionResult {
    /// Base64 of the DER-encoded ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`).
    pub signature_der_b64: String,
    /// Base64 of the `authenticator_data` blob (32-byte rpIdHash + flags + counter, possibly + extensions).
    pub authenticator_data_b64: String,
    /// `authenticator_data[32]`. Bit 0 = User Present, bit 2 = User Verified.
    pub flags: u8,
    /// Big-endian u32 from `authenticator_data[33..37]`. The TPM
    /// increments this on every assertion.
    pub counter: u32,
}

/// Bridge response from Windows server to WSL client.
#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeResponse {
    /// Base64-encoded result data (on success).
    pub result: Option<String>,
    /// Error message (on failure).
    pub error: Option<String>,
}

impl BridgeResponse {
    /// Create a successful response with data.
    pub fn success(data: &str) -> Self {
        BridgeResponse {
            result: Some(data.to_string()),
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(msg: &str) -> Self {
        BridgeResponse {
            result: None,
            error: Some(msg.to_string()),
        }
    }

    /// Create a successful response with no data.
    pub fn ok() -> Self {
        BridgeResponse {
            result: Some(String::new()),
            error: None,
        }
    }

    /// Require that the response contains a success result payload.
    pub fn require_result(&self, operation: &str) -> enclaveapp_core::Result<&str> {
        if let Some(error) = &self.error {
            return Err(enclaveapp_core::Error::KeyOperation {
                operation: operation.into(),
                detail: error.clone(),
            });
        }
        self.result
            .as_deref()
            .ok_or_else(|| enclaveapp_core::Error::KeyOperation {
                operation: operation.into(),
                detail: "bridge response missing result payload".into(),
            })
    }

    /// Require an acknowledged success response.
    pub fn require_ok(&self, operation: &str) -> enclaveapp_core::Result<()> {
        let _unused = self.require_result(operation)?;
        Ok(())
    }

    /// Decode a base64-encoded success payload.
    pub fn decode_result(&self, operation: &str) -> enclaveapp_core::Result<Vec<u8>> {
        decode_data(self.require_result(operation)?)
    }
}

/// Encode binary data as base64 for the bridge protocol.
pub fn encode_data(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decode base64 data from the bridge protocol.
pub fn decode_data(encoded: &str) -> enclaveapp_core::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| enclaveapp_core::Error::Serialization(format!("base64 decode: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn bridge_request_serde_roundtrip() {
        let request = BridgeRequest {
            method: "encrypt".to_string(),
            params: BridgeParams::new(
                "aGVsbG8=".to_string(),
                AccessPolicy::BiometricOnly,
                "test-app".to_string(),
                "cache-key".to_string(),
            ),
        };
        let json = serde_json::to_string(&request).unwrap();
        let parsed: BridgeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method, "encrypt");
        assert_eq!(parsed.params.data, "aGVsbG8=");
        assert_eq!(parsed.params.access_policy, AccessPolicy::BiometricOnly);
        assert_eq!(parsed.params.app_name, "test-app");
        assert_eq!(parsed.params.key_label, "cache-key");
    }

    #[test]
    fn bridge_request_defaults_for_missing_fields() {
        let json = r#"{"method":"init","params":{}}"#;
        let parsed: BridgeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.method, "init");
        assert_eq!(parsed.params.data, "");
        assert_eq!(parsed.params.access_policy, AccessPolicy::None);
        assert_eq!(parsed.params.app_name, "");
        assert_eq!(parsed.params.key_label, "");
    }

    #[test]
    fn bridge_request_ignores_legacy_biometric_field() {
        // Older callers may still include `biometric: true` on the wire.
        // We must not silently honor it — access_policy is authoritative.
        // Unknown fields are ignored by serde's default, so the legacy
        // flag simply has no effect.
        let json = r#"{"method":"encrypt","params":{"biometric":true,"access_policy":"none","app_name":"a","key_label":"k"}}"#;
        let parsed: BridgeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.params.access_policy, AccessPolicy::None);
        assert_eq!(parsed.params.effective_access_policy(), AccessPolicy::None);
    }

    #[test]
    fn bridge_response_success_construction() {
        let resp = BridgeResponse::success("c29tZSBkYXRh");
        assert_eq!(resp.result, Some("c29tZSBkYXRh".to_string()));
        assert!(resp.error.is_none());
    }

    #[test]
    fn bridge_response_error_construction() {
        let resp = BridgeResponse::error("something went wrong");
        assert!(resp.result.is_none());
        assert_eq!(resp.error, Some("something went wrong".to_string()));
    }

    #[test]
    fn bridge_response_ok_construction() {
        let resp = BridgeResponse::ok();
        assert_eq!(resp.result, Some(String::new()));
        assert!(resp.error.is_none());
    }

    #[test]
    fn bridge_response_serde_roundtrip() {
        let resp = BridgeResponse::success("dGVzdA==");
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: BridgeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.result, Some("dGVzdA==".to_string()));
        assert!(parsed.error.is_none());
    }

    #[test]
    fn encode_decode_roundtrip_empty() {
        let data = b"";
        let encoded = encode_data(data);
        let decoded = decode_data(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_decode_roundtrip_small() {
        let data = b"hello, world!";
        let encoded = encode_data(data);
        let decoded = decode_data(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_decode_roundtrip_large() {
        let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let encoded = encode_data(&data);
        let decoded = decode_data(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_data_rejects_invalid_base64() {
        let result = decode_data("not valid base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn bridge_request_all_methods() {
        for method in &["init", "encrypt", "decrypt", "destroy", "delete"] {
            let request = BridgeRequest {
                method: (*method).to_string(),
                params: BridgeParams::new(
                    String::new(),
                    AccessPolicy::None,
                    "test".to_string(),
                    "default".to_string(),
                ),
            };
            let json = serde_json::to_string(&request).unwrap();
            let parsed: BridgeRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.method, *method);
        }
    }

    #[test]
    fn bridge_response_success_with_empty_result() {
        let resp = BridgeResponse::ok();
        assert_eq!(resp.result, Some(String::new()));
        assert!(resp.error.is_none());

        // Verify it roundtrips through JSON
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: BridgeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.result, Some(String::new()));
    }

    #[test]
    fn bridge_response_error_preserves_message() {
        let msg = "TPM device not found: error code 0x8028000F";
        let resp = BridgeResponse::error(msg);
        assert_eq!(resp.error.as_deref(), Some(msg));
        assert!(resp.result.is_none());

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: BridgeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.error.as_deref(), Some(msg));
    }

    #[test]
    fn encode_decode_binary_data_with_null_bytes() {
        let data: Vec<u8> = vec![0x00, 0x01, 0x00, 0xFF, 0x00, 0xFE];
        let encoded = encode_data(&data);
        let decoded = decode_data(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_decode_large_data_1mb() {
        let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let encoded = encode_data(&data);
        let decoded = decode_data(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_data_invalid_base64_returns_error() {
        let result = decode_data("!!!not-base64!!!");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("base64"));
    }

    #[test]
    fn decode_data_empty_string_returns_empty_vec() {
        let result = decode_data("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn bridge_params_default_values() {
        let json = r#"{}"#;
        let params: BridgeParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.data, "");
        assert_eq!(params.access_policy, AccessPolicy::None);
        assert_eq!(params.app_name, "");
        assert_eq!(params.key_label, "");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn find_bridge_returns_none_on_macos() {
        // On macOS there's no /mnt/c/ and no bridge binary
        let result = crate::find_bridge("sshenc");
        assert!(result.is_none());
    }

    #[test]
    fn bridge_params_biometric_only_access_policy() {
        let json = r#"{"access_policy":"biometric_only","app_name":"t","key_label":"k"}"#;
        let params: BridgeParams = serde_json::from_str(json).unwrap();
        assert_eq!(
            params.effective_access_policy(),
            AccessPolicy::BiometricOnly
        );
    }

    #[test]
    fn bridge_params_any_access_policy() {
        let json = r#"{"access_policy":"any","app_name":"t","key_label":"k"}"#;
        let params: BridgeParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.effective_access_policy(), AccessPolicy::Any);
    }

    #[test]
    fn bridge_params_wire_format_omits_biometric_field() {
        // We must not serialize a `biometric` field on the wire — old
        // servers that preferred it over `access_policy` would observe
        // a false value and silently downgrade. Note: the
        // `biometric_only` access-policy enum variant string contains
        // the substring `biometric`, so the assertion must check for
        // the quoted JSON key specifically.
        let params = BridgeParams::new(
            String::new(),
            AccessPolicy::BiometricOnly,
            "app".into(),
            "key".into(),
        );
        let json = serde_json::to_string(&params).unwrap();
        assert!(!json.contains("\"biometric\""));
        assert!(json.contains("\"access_policy\":\"biometric_only\""));
    }

    #[test]
    fn bridge_response_require_result_rejects_null() {
        let resp = BridgeResponse {
            result: None,
            error: None,
        };
        let err = resp.require_result("test_op").unwrap_err();
        assert!(err.to_string().contains("missing result payload"));
    }

    #[test]
    fn bridge_response_require_result_rejects_error() {
        let resp = BridgeResponse::error("boom");
        let err = resp.require_result("test_op").unwrap_err();
        assert!(err.to_string().contains("boom"));
    }

    #[test]
    fn bridge_response_decode_result_works() {
        let resp = BridgeResponse::success("aGVsbG8=");
        let data = resp.decode_result("test_op").unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn bridge_response_require_ok_succeeds_on_ok() {
        let resp = BridgeResponse::ok();
        assert!(resp.require_ok("test").is_ok());
    }

    #[test]
    fn bridge_response_require_ok_rejects_null() {
        let resp = BridgeResponse {
            result: None,
            error: None,
        };
        let err = resp.require_ok("test").unwrap_err();
        assert!(err.to_string().contains("missing result payload"));
    }

    #[test]
    fn bridge_response_require_ok_rejects_error() {
        let resp = BridgeResponse::error("fail");
        let err = resp.require_ok("test").unwrap_err();
        assert!(err.to_string().contains("fail"));
    }

    #[test]
    fn bridge_response_decode_result_empty_string() {
        let resp = BridgeResponse::ok();
        let data = resp.decode_result("test").unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn bridge_response_decode_result_rejects_invalid_base64() {
        let resp = BridgeResponse::success("not-valid-base64!!!");
        let err = resp.decode_result("test").unwrap_err();
        assert!(err.to_string().contains("base64"));
    }

    #[test]
    fn effective_access_policy_with_all_variants() {
        let params = BridgeParams::new(String::new(), AccessPolicy::Any, "a".into(), "k".into());
        assert_eq!(params.effective_access_policy(), AccessPolicy::Any);

        let params = BridgeParams::new(
            String::new(),
            AccessPolicy::PasswordOnly,
            "a".into(),
            "k".into(),
        );
        assert_eq!(params.effective_access_policy(), AccessPolicy::PasswordOnly);

        let params = BridgeParams::new(String::new(), AccessPolicy::None, "a".into(), "k".into());
        assert_eq!(params.effective_access_policy(), AccessPolicy::None);
    }

    #[test]
    fn bridge_params_roundtrip_preserves_all_fields() {
        let original = BridgeParams::new(
            "dGVzdA==".into(),
            AccessPolicy::BiometricOnly,
            "my-app".into(),
            "my-key".into(),
        );
        let json = serde_json::to_string(&original).unwrap();
        let parsed: BridgeParams = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.data, "dGVzdA==");
        assert_eq!(parsed.access_policy, AccessPolicy::BiometricOnly);
        assert_eq!(
            parsed.effective_access_policy(),
            AccessPolicy::BiometricOnly
        );
        assert_eq!(parsed.app_name, "my-app");
        assert_eq!(parsed.key_label, "my-key");
    }
}
