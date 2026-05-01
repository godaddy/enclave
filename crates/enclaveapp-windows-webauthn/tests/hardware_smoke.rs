// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Hardware-touching smoke tests for the WebAuthn wrapper.
//!
//! These tests fire real Hello prompts and only pass on a Windows
//! host with an enrolled platform authenticator. They are
//! `#[ignore]`'d by default so a normal `cargo test` run doesn't
//! pop dialogs in CI / unattended builds. To run:
//!
//! ```bash
//! cargo test -p enclaveapp-windows-webauthn -- --ignored
//! ```

#![cfg(target_os = "windows")]
#![allow(clippy::print_stdout, clippy::unwrap_used)]

use enclaveapp_windows_webauthn::{
    get_assertion, is_platform_authenticator_available, make_credential, GetAssertionParams,
    MakeCredentialParams,
};

#[test]
#[ignore]
fn hardware_make_then_sign() {
    assert!(
        is_platform_authenticator_available(),
        "platform authenticator must be available; enroll Windows Hello first"
    );

    let user_id = b"sshenc-wrapper-smoke";
    let cred = make_credential(MakeCredentialParams {
        rp_id: "sshenc.local",
        rp_name: "sshenc",
        user_id,
        user_name: "smoke-test",
        user_display_name: "Smoke Test",
        timeout_ms: 60_000,
        hwnd: None,
    })
    .expect("make_credential should succeed when user verifies");

    println!("credential_id: {} bytes", cred.credential_id.len());
    println!("public_key_x:  {}", hex(&cred.public_key_x));
    println!("public_key_y:  {}", hex(&cred.public_key_y));
    println!("resident:      {}", cred.resident);
    assert_eq!(cred.public_key_x.len(), 32);
    assert_eq!(cred.public_key_y.len(), 32);
    assert!(!cred.credential_id.is_empty());

    // Verifying the second leg right after the first means the
    // user only gets one Hello prompt session for the whole test.
    let challenge = b"sshenc-wrapper-smoke-test-challenge-32-bytes-pad";
    let asn = get_assertion(GetAssertionParams {
        rp_id: "sshenc.local",
        credential_id: &cred.credential_id,
        client_data: challenge,
        timeout_ms: 60_000,
        hwnd: None,
    })
    .expect("get_assertion should succeed");

    println!("signature_der: {} bytes", asn.signature_der.len());
    println!("authData:      {} bytes", asn.authenticator_data.len());
    println!("flags:         0b{:08b}", asn.flags);
    println!("counter:       {}", asn.counter);

    assert!(
        asn.signature_der.first() == Some(&0x30),
        "DER ECDSA signature must start with SEQUENCE tag 0x30"
    );
    // UV bit (bit 2) must be set -- we asked for UV=REQUIRED.
    assert!(asn.flags & 0x04 != 0, "UV flag must be set");
    // Counter must have advanced past whatever it was at make-time.
    assert!(asn.counter >= 1, "counter should have incremented");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
