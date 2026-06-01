# enclave Interface Redesign

## Motivation

The library was developed agenically and the current public API has accumulated several rough edges that would make FFI language bindings painful to author and maintain:

- `Box<dyn Trait>` is opaque to FFI; callers need concrete opaque handle types
- `serde_json::Value` in `KeyMeta` is not C-compatible
- Platform-specific types (`KeychainConfig`, `DpapiEncryptorConfig`) leak into the call sites of consuming apps
- Scattered `#[cfg(target_os)]` gates mean bindings must handle missing symbols per platform
- Two separate error hierarchies (`enclaveapp_core::Error` and `StorageError`) with overlapping variants
- `sign_with_presence()` has a default impl that silently ignores the presence parameters on every platform except macOS — cross-platform drift hidden behind a default
- `AccessPolicy` is stored in metadata but unenforced on Linux TPM (silent contract violation)
- Protected memory for decrypted secrets relies entirely on `zeroize` drop impls — no guard pages, no mlock beyond the existing `mlock_buffer()` utility

Before adding FFI bindings, the goal is to establish four clean, stable interfaces that:
1. Are amenable to C FFI wrapping (flat functions, opaque handles, no trait objects at the boundary)
2. Abstract platform differences as completely as possible
3. Provide escape hatches for genuinely platform-specific behavior without polluting the common path
4. Include protected memory backed by guard pages and mlock (ported from [asherah-ffi](https://github.com/godaddy/asherah-ffi))

Existing crates and their internal traits remain intact. Consuming Rust apps are ported incrementally. The old interfaces are never removed — they just aren't published via FFI.

---

## Proposed Structure

A new top-level crate `enclaveapp` becomes the single public surface. It re-exports the four interface modules and provides factory functions. All existing platform crates remain as private implementation dependencies.

```
crates/
  enclaveapp/                    ← NEW: the public API crate
    src/
      lib.rs
      signing.rs                 ← Interface 1
      encryption.rs              ← Interface 2
      auth.rs                    ← Interface 3 (UI / user presence)
      core.rs                    ← Interface 4 (process hardening + protected memory)
      memory/
        mod.rs
        memcall.rs               ← OS primitives (ported from asherah-ffi)
        secure_buffer.rs         ← Page-guarded buffer  (ported from asherah-ffi)
        locked_buffer.rs         ← Arc-wrapped buffer   (ported from asherah-ffi)
      config.rs                  ← EnclaveConfig + PlatformConfig escape hatches
      error.rs                   ← Single unified error type
      factory.rs                 ← create_signer() / create_encryptor()
  enclaveapp-core/               ← unchanged (internal)
  enclaveapp-apple/              ← unchanged (internal)
  enclaveapp-windows/            ← unchanged (internal)
  enclaveapp-keyring/            ← unchanged (internal)
  enclaveapp-app-storage/        ← unchanged (internal, powers factory)
  ...                            ← all other existing crates unchanged
```

---

## Interface 1 — Signing

```rust
// enclave::signing

/// Handle to a signing backend. Opaque to callers; obtained from create_signer().
pub struct SignerHandle(Box<dyn enclaveapp_core::EnclaveSigner>);

pub struct PresenceOptions {
    pub mode: PresenceMode,
    pub cache_ttl_secs: u64,
    pub reason: String,
}

impl SignerHandle {
    /// Generate a new P-256 signing key. Returns the uncompressed SEC1 public key.
    pub fn generate_key(&self, label: &str, policy: AccessPolicy) -> Result<Vec<u8>>;

    /// Return the uncompressed SEC1 public key for an existing key.
    pub fn public_key(&self, label: &str) -> Result<Vec<u8>>;

    /// Sign `data` (SHA-256 is applied internally). Returns DER-encoded ECDSA signature.
    pub fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>>;

    /// Sign with optional user-presence prompt. On platforms that don't support
    /// presence caching the options are honored best-effort; callers should check
    /// presence_available() first if they need a hard guarantee.
    pub fn sign_with_presence(
        &self, label: &str, data: &[u8], opts: &PresenceOptions,
    ) -> Result<Vec<u8>>;

    /// True when the current platform supports presence prompting.
    pub fn presence_available(&self) -> bool;

    pub fn list_keys(&self) -> Result<Vec<KeyInfo>>;
    pub fn delete_key(&self, label: &str) -> Result<()>;
    pub fn key_exists(&self, label: &str) -> Result<bool>;
    pub fn rename_key(&self, old_label: &str, new_label: &str) -> Result<()>;
    pub fn backend_kind(&self) -> BackendKind;
}
```

**Design notes:**
- `sign_with_presence` is no longer a default-impl on the core trait. The `SignerHandle` wrapper inspects `BackendKind` and transparently falls back to a plain sign on platforms without presence support, but the fallback is explicit code, not a silently swallowed default.
- The handle owns a `Box<dyn EnclaveSigner>` internally; callers never touch that trait object.

---

## Interface 2 — ECIES Encryption

```rust
// enclave::encryption

/// Handle to an encryption backend. Opaque; obtained from create_encryptor().
pub struct EncryptorHandle(Box<dyn enclaveapp_core::EnclaveEncryptor>);

impl EncryptorHandle {
    /// Generate a new P-256 key pair for ECIES. Returns the uncompressed SEC1 public key.
    pub fn generate_key(&self, label: &str, policy: AccessPolicy) -> Result<Vec<u8>>;

    /// Return the uncompressed SEC1 public key for an existing key.
    pub fn public_key(&self, label: &str) -> Result<Vec<u8>>;

    /// ECIES encrypt. Wire format: [0x01 version][65B pubkey][12B nonce][ciphertext][16B tag].
    pub fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// ECIES decrypt. Returns plaintext in a Zeroizing<Vec<u8>>.
    pub fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;

    pub fn list_keys(&self) -> Result<Vec<KeyInfo>>;
    pub fn delete_key(&self, label: &str) -> Result<()>;
    pub fn key_exists(&self, label: &str) -> Result<bool>;
    pub fn rename_key(&self, old_label: &str, new_label: &str) -> Result<()>;
    pub fn backend_kind(&self) -> BackendKind;
}
```

**Design notes:**
- `decrypt` now returns `Zeroizing<Vec<u8>>` rather than bare `Vec<u8>` to make the caller's zeroization responsibility visible at the type level.
- Wire format is unchanged (maintains ciphertext compatibility with all existing data).

---

## Interface 3 — Auth / UI

This interface abstracts the user-presence and authentication UI differences across platforms.

```rust
// enclave::auth

pub struct AuthHandle(Box<dyn PlatformAuth>);

/// What this platform's auth subsystem can do.
pub struct AuthCapabilities {
    /// Platform has a biometric authenticator (Touch ID, Windows Hello fingerprint).
    pub biometric_available: bool,
    /// Platform supports password / PIN fallback in the same auth flow.
    pub password_available: bool,
    /// Platform supports LAContext / presence caching across multiple ops.
    pub presence_caching: bool,
    /// Name of the authenticator shown to users (e.g. "Touch ID", "Windows Hello").
    pub authenticator_name: Option<String>,
}

impl AuthHandle {
    pub fn capabilities(&self) -> AuthCapabilities;

    /// Request a user-presence verification. Returns Ok(()) if granted.
    /// `reason` is the human-readable string shown in the OS prompt.
    pub fn request_presence(&self, reason: &str) -> Result<()>;

    /// Evict any cached presence token (e.g. LAContext on macOS).
    /// No-op on platforms without caching.
    pub fn evict_presence_cache(&self);

    pub fn backend_kind(&self) -> BackendKind;
}

/// Standalone helper — no handle required.
pub fn platform_auth_capabilities() -> AuthCapabilities;
```

**Design notes:**
- On macOS the handle wraps an `LAContext` and exposes the TTL-based caching already in the Apple backend.
- On Windows the handle wraps `UserConsentVerifier` (Windows Hello) plus the password gate.
- On Linux the handle is a stub that returns `biometric_available: false`. This is an honest capability report rather than silent no-ops.
- `AuthHandle` is intentionally separable from `SignerHandle` / `EncryptorHandle` so that a long-running agent can acquire presence once, then sign/encrypt many times, without coupling the auth lifecycle to each operation.

---

## Interface 4 — Core (Process Hardening + Protected Memory)

### 4a. Process Hardening

No change to the existing API. Re-export from `enclaveapp_core::process`:

```rust
pub use enclaveapp_core::process::{harden_process, mlock_buffer, munlock_buffer};
```

### 4b. Protected Memory (new — ported from asherah-ffi)

Port the `memcall` and `memguard` layers from asherah-ffi into `enclave::memory`. We take the minimum viable subset: `SecureBuffer` (guard pages + mlock) and `LockedBuffer` (Arc-wrapped for sharing). We skip the Enclave/Coffer/SecureSlab layers for now — those are only needed if we want in-memory re-encryption of long-lived secrets, which is a separate conversation.

```rust
// enclave::memory

/// A page-guarded, mlock'd buffer.
///
/// Layout: [PROT_NONE guard page] [inner region, mlock'd] [PROT_NONE guard page]
///
/// The guard pages are filled with random canary bytes on construction. On drop,
/// canaries are verified (overflow detection), inner region is zeroized, and all
/// pages are unmapped.
///
/// Access to the inner region flips between PROT_READ (frozen) and
/// PROT_READ|PROT_WRITE (mutable). The buffer starts mutable.
pub struct SecureBuffer { /* private */ }

impl SecureBuffer {
    pub fn new(size: usize) -> Result<Self>;
    pub fn bytes(&mut self) -> &mut [u8];      // requires mutable state
    pub fn as_slice(&self) -> &[u8];           // requires non-NONE state
    pub fn size(&self) -> usize;
    pub fn freeze(&mut self) -> Result<()>;    // PROT_READ
    pub fn melt(&mut self) -> Result<()>;      // PROT_READ|WRITE
    pub fn scramble(&mut self) -> Result<()>;  // fill with OsRng, stays mutable
    pub fn is_alive(&self) -> bool;
    pub fn is_mutable(&self) -> bool;
}

impl Drop for SecureBuffer { /* verify canaries, zeroize, unmap */ }

/// Arc-wrapped, Mutex-guarded SecureBuffer for sharing across threads.
///
/// All mutations go through the Mutex. bytes_zeroizing() copies the content
/// into a Zeroizing<Vec<u8>> for callers that need to hand the plaintext
/// somewhere (e.g., write to stdout, pass to a child process).
pub struct LockedBuffer(Arc<Mutex<SecureBuffer>>);

impl LockedBuffer {
    pub fn new(size: usize) -> Result<Self>;
    pub fn random(size: usize) -> Result<Self>;                // OsRng-filled
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self>;
    pub fn freeze(&self) -> Result<()>;
    pub fn melt(&self) -> Result<()>;
    pub fn scramble(&self) -> Result<()>;
    pub fn wipe(&self);
    /// Copy contents to a Zeroizing heap allocation.
    pub fn bytes_zeroizing(&self) -> Zeroizing<Vec<u8>>;
    pub fn size(&self) -> usize;
}
```

**Platform implementations (in `memcall.rs`):**

| Operation | Unix | Windows |
|-----------|------|---------|
| Allocate | `mmap(MAP_PRIVATE\|MAP_ANON)` | `VirtualAlloc(MEM_RESERVE\|MEM_COMMIT)` |
| Lock | `mlock` + `madvise(MADV_DONTDUMP)` | `VirtualLock` |
| Protect | `mprotect` | `VirtualProtect` |
| Free | `munmap` (after mprotect RW + zeroize + munlock) | `VirtualFree` |

---

## Binary Identity & Security Capabilities

Most consumers will ship unsigned binaries. The library must be fully functional for unsigned callers while being honest about what security tier they're operating in, and must guarantee namespace isolation so unsigned development builds can never clobber signed production keys.

### Signing detection (already implemented in `enclaveapp_core::signing`)

```rust
// enclaveapp (re-exported at crate root)

/// True iff the running binary is considered signed for identity purposes.
///
/// Detection (cached for the process lifetime):
/// - Path contains `/target/` or `\target\` → cargo build → false
/// - macOS: `codesign --verify --no-strict` exit 0 → true
/// - Other platforms: not in `/target/` → true (no ACL coupling on non-Apple)
pub fn is_binary_signed() -> bool;

/// True iff the running binary has the named keychain-access-groups entitlement.
/// On macOS: runs `codesign -d --entitlements -` and checks for the group string.
/// On other platforms: always returns false (concept doesn't exist).
/// Result is cached per group string for the process lifetime.
///
/// Use this rather than is_binary_signed() for feature gating — what matters
/// is whether the binary has the *specific entitlement* for the access group
/// you're trying to use, not just whether it's signed at all.
pub fn has_keychain_entitlement(group: &str) -> bool;
```

### Security capabilities

```rust
// enclave::capabilities

/// Full description of what security tier the current binary+platform provides.
pub struct SecurityCapabilities {
    /// The binary is code-signed. When false, the app_name namespace is
    /// automatically suffixed with `-unsigned` to prevent key conflicts.
    pub binary_signed: bool,

    /// The hardware security backend in use.
    pub backend: BackendKind,

    /// The keychain access group the factory resolved to, if any.
    /// Some(group) means the entitlement was verified and the Data Protection
    /// keychain is in use. None means the legacy keychain is in use.
    pub effective_keychain_group: Option<String>,

    /// Whether the platform can bind secure-store entries to this binary's code
    /// signature, so other processes cannot read them even with the same
    /// user identity. True only on macOS when effective_keychain_group is Some.
    pub code_signature_binding: bool,

    /// Whether user-presence (Touch ID / Windows Hello) gates Keychain access.
    /// True only when effective_keychain_group is Some AND wrapping_key_user_presence
    /// was requested. When the access group falls back to legacy, this is false
    /// even if user_presence was requested — the fallback doesn't support it.
    pub keychain_user_presence: bool,

    /// Whether the platform can enforce user-presence at the
    /// hardware/OS level (Touch ID, Windows Hello).
    pub hardware_presence: bool,

    /// Whether presence prompts can be cached across multiple operations
    /// within a TTL (LAContext on macOS). False on Windows and Linux.
    pub presence_caching: bool,

    /// The effective app_name after namespace isolation is applied.
    /// Unsigned binaries get `-unsigned` appended automatically.
    /// Use this value — not the raw config app_name — for logging and
    /// diagnostics so the identity is unambiguous.
    pub effective_app_name: String,

    /// Features that were requested in the config but downgraded because the
    /// binary lacks the necessary entitlements. Empty means no downgrade occurred.
    /// Callers can log these or surface them to users as security posture info.
    pub downgraded_features: Vec<String>,
}

/// Query capabilities without creating any handles. Safe to call any time
/// after harden_process(). The result reflects the current binary's
/// signing state and the platform's detected hardware.
pub fn security_capabilities(app_name: &str) -> SecurityCapabilities;
```

**Intended use:** callers that need to inform users about their security posture, or that want to conditionally enable features (e.g., skip presence prompting on platforms where `hardware_presence` is false), call `security_capabilities()` first rather than probing `BackendKind` + `is_binary_signed()` separately.

### What works unsigned vs signed

The library is fully functional for unsigned callers with the default config. Unsigned is not a degraded edge case — most consumers will be unsigned.

| Feature | Unsigned | Signed | Notes |
|---------|----------|--------|---------|
| Key generation (SE/TPM) | ✅ | ✅ | CryptoKit doesn't require provisioning profiles |
| Sign / Encrypt / Decrypt | ✅ | ✅ | |
| Legacy Keychain storage (default) | ✅ | ✅ | Ad-hoc signed binary prompts once per binary hash on macOS |
| `keychain_access_group` | ❌ error | ✅ | Requires `keychain-access-groups` entitlement |
| `wrapping_key_user_presence: true` (no access group) | ❌ error | ❌ error | Requires Data Protection keychain; needs access group + entitlement |
| `wrapping_key_user_presence: true` (with access group) | ❌ error | ✅ | Signed + entitlement required |
| Keychain ACL bound to binary identity | ⚠️ weak | ✅ | Unsigned: per-binary-hash ACL; any rebuild = new prompt |
| `-unsigned` namespace isolation | automatic | n/a | Applied transparently |
| HMAC tamper-evident files | ✅ | ✅ | HMAC key stored in Keychain without access group |
| Protected memory (`SecureBuffer`, `LockedBuffer`) | ✅ | ✅ | Pure OS memory calls, no signing dependency |
| Windows Hello / TPM | ✅ | ✅ | No code signature concept on Windows |
| Linux keyring / TPM | ✅ | ✅ | No code signature concept on Linux |

**Graceful downgrade vs hard error:**

The real-world apps (gocode-dev, sshenc) reveal that the right model is **downgrade + report**, not fail-fast, for most cases. Apps should be able to set their desired config and get the best achievable result:

- `keychain_access_group: Some(G)` + no entitlement for G → downgrade to legacy keychain silently; record `"keychain_access_group"` in `downgraded_features`. Matches sshenc's actual behavior today (bridge catches `errSecMissingEntitlement` and falls back).
- `wrapping_key_user_presence: true` + `keychain_access_group: None` → **hard error** (`Error::RequiresSigning { feature: "wrapping_key_user_presence" }`). There is no valid fallback for this combination: the legacy keychain rejects the userPresence ACL with `errSecParam`. Currently surfaces as an opaque Swift bridge error code.
- `wrapping_key_user_presence: true` + `keychain_access_group: Some(G)` + no entitlement → downgrade (lose user_presence, use legacy keychain); record both in `downgraded_features`.

**`AccessPolicy` and signing status:**

gocode-dev's pattern reveals an important insight: the right `AccessPolicy` differs by signing tier.
- **Signed** (entitlement ACL is the gate): `AccessPolicy::None` is fine. The keychain ACL enforces that only this binary can read the wrapping key. Biometric on the SE key adds friction without adding meaningful security over the ACL.
- **Unsigned** (no entitlement gate): `AccessPolicy::Any` is appropriate. With no code-signature binding, the SE key's own access control is the only hardware-enforced barrier. Without it, any same-UID process could use the key.

The factory should document this recommendation clearly. Apps can override it, but the default for `EnclaveConfig` when `access_policy` is not set should be `AccessPolicy::Any` for unsigned binaries and `AccessPolicy::None` for signed ones with an effective keychain group.

---

## Configuration & Factory

### Namespace isolation guarantee

`EnclaveConfig` calls `ensure_safe_app_name(app_name)` internally on construction. This is the same function already in `enclaveapp_core::signing`:

- Signed binary → `app_name` used as-is.
- Unsigned binary → `-unsigned` appended if not already present.
- The function is idempotent (never double-suffixes).

Callers never need to do this themselves. The raw `app_name` field in the config struct is the *requested* name; the *effective* name (post-suffix) is available via `SecurityCapabilities::effective_app_name` and is what gets used for all storage operations.

### EnclaveConfig

```rust
// enclave::config

pub struct EnclaveConfig {
    /// Requested app identifier. Unsigned binaries get `-unsigned` appended
    /// automatically before any storage operation.
    pub app_name: String,
    /// Default label used when the caller doesn't supply one.
    pub default_key_label: String,
    /// Default access policy for new keys.
    pub access_policy: AccessPolicy,
    /// Override key storage directory (default: platform default).
    pub keys_dir: Option<PathBuf>,
    /// Platform-specific overrides. Default is PlatformConfig::Default.
    pub platform: PlatformConfig,
}

/// Escape hatches for platform-specific behavior.
/// PlatformConfig::Default covers all common cases.
pub enum PlatformConfig {
    Default,
    MacOs(MacOsConfig),
    Windows(WindowsConfig),
    Linux(LinuxConfig),
}

pub struct MacOsConfig {
    pub wrapping_key_user_presence: bool,
    pub wrapping_key_cache_ttl: Duration,
    pub keychain_access_group: Option<String>,
    pub extra_bridge_paths: Vec<String>,  // WSL bridge discovery
}

pub struct WindowsConfig {
    pub prefer_windows_hello_ux: bool,
    pub software_fallback: WindowsSoftwareFallback,
    pub dpapi_app_key: Option<[u8; 32]>,
}

pub struct LinuxConfig {
    pub force_keyring: bool,
    pub extra_bridge_paths: Vec<String>,  // WSL bridge discovery
}
```

### Factory Functions

```rust
// enclave::factory

/// Create a signing handle for the current platform.
pub fn create_signer(config: &EnclaveConfig) -> Result<SignerHandle>;

/// Create an encryption handle for the current platform.
pub fn create_encryptor(config: &EnclaveConfig) -> Result<EncryptorHandle>;

/// Create an auth handle for the current platform.
pub fn create_auth(config: &EnclaveConfig) -> Result<AuthHandle>;

/// Create a tamper-evident handle for the given app.
pub fn create_tamper_evident(app_name: &str) -> Result<TamperEvidentHandle>;

---

## Unified Error Type

Collapse `enclaveapp_core::Error` and `StorageError` into one:

```rust
// enclave::error

#[non_exhaustive]
pub enum Error {
    NotAvailable,
    KeyNotFound { label: String },
    DuplicateLabel { label: String },
    InvalidLabel { reason: String },
    SignFailed { detail: String },
    EncryptFailed { detail: String },
    DecryptFailed { detail: String },
    AuthDenied { label: String },
    AuthRequired { label: String },        // was KeychainInteractionRequired
    UserCancelled { label: String },
    KeyOperation { operation: String, detail: String },
    TamperDetected { path: String },       // tamper-evident file mismatch
    /// The requested configuration or operation requires a code-signed binary.
    /// `feature` names the specific option (e.g. "keychain_access_group",
    /// "wrapping_key_user_presence"). Returned at factory construction time,
    /// never buried in a later operation.
    RequiresSigning { feature: String },
    Config(String),
    Io(std::io::Error),
}
```

`#[non_exhaustive]` so FFI bindings can add a catch-all arm without recompilation when we add variants.

---

## Shared Types

```rust
// enclave::types (re-exported at crate root)

pub struct KeyInfo {
    pub label: String,
    pub key_type: KeyType,
    pub access_policy: AccessPolicy,
    pub public_key: Vec<u8>,   // uncompressed SEC1
}

// Existing enums kept as-is (already clean):
pub use enclaveapp_core::{AccessPolicy, KeyType, PresenceMode, BackendKind};
```

`KeyMeta` with its `serde_json::Value` app_specific field stays in `enclaveapp_core` as an implementation detail. `KeyInfo` is the clean public projection.

---

## Interface 6 — Application Delivery Tiers

The `enclave` crate defines four integration types for how secrets reach a target process. The new interface must surface clean APIs for each tier. The implementation already exists in `enclaveapp-app-adapter`; this section defines what gets re-exported and what changes shape.

### Tier overview

| Type | Name | Secret boundary | Mechanism |
|------|------|----------------|-----------|
| **1** | HelperTool | Never leaves process | SSH agent, `credential_process`, RPC |
| **2** | EnvInterpolation | Env vars via `execve()`, zeroized after | `.npmrc` `${NPM_TOKEN}`, similar |
| **3** | TempMaterializedConfig | Temp file, shredded on drop | Apps with no env/plugin support |
| **4** | CredentialSource | Consumer controls; no delivery guardrail | `sso-jwt`, token providers |

### Type 1 — HelperTool

No generic interface. Type 1 apps use `SignerHandle` and `EncryptorHandle` directly and implement the application protocol themselves (SSH agent wire format, AWS `credential_process` JSON, git credential helper lines, etc.). The library provides the crypto; the app provides the protocol.

### Type 2 — EnvInterpolation and Type 3 — TempMaterializedConfig

Both types deliver secrets to a child process; the difference is the channel (env vars vs file path). A single `SecureProcess` builder covers both.

```rust
// enclave::exec

/// Launch a child process with hardware-backed secrets injected.
///
/// Secret values are mlocked before spawn and zeroized after the child exits.
/// The child inherits RLIMIT_CORE=0 on Unix, preventing crash dumps that
/// would capture the secret-laden environment.
///
/// Build with the builder methods, then call run() or exec().
pub struct SecureProcess { /* private */ }

impl SecureProcess {
    pub fn new(program: impl Into<PathBuf>) -> Self;

    /// Append a positional argument.
    pub fn arg(self, a: impl Into<OsString>) -> Self;
    pub fn args(self, args: impl IntoIterator<Item = impl Into<OsString>>) -> Self;

    /// Inject a secret as an environment variable (Type 2).
    /// The value is mlocked, and zeroized after the child exits.
    pub fn secret_env(self, key: impl Into<String>, value: impl Into<String>) -> Self;

    /// Add a non-secret environment variable (e.g. a config file path).
    pub fn env(self, key: impl Into<String>, value: impl Into<String>) -> Self;

    /// Remove an environment variable from the child's environment.
    pub fn env_remove(self, key: impl Into<String>) -> Self;

    /// Scrub inherited env vars matching this pattern before spawning.
    /// Exact names or prefix patterns ending in `*` (e.g. `"NPM_TOKEN_*"`).
    /// Removes from both the child command and the parent's own env block.
    pub fn scrub(self, pattern: impl Into<String>) -> Self;

    /// Spawn the child and wait for it to exit. Returns the exit status.
    /// Zeroizes secret env var values after the child returns.
    pub fn run(self) -> Result<ExitStatus>;

    /// Replace the current process image (Unix execve). Never returns on success.
    /// Note: secret env var zeroization is NOT possible after exec() because
    /// the current process no longer exists. Prefer run() when zeroization
    /// matters (typical for Type 2 wrappers). Use exec() only for Type 1
    /// patterns where the current process itself becomes the target (e.g.
    /// exec into ssh with agent forwarding already established).
    /// On Windows, falls back to run() since CreateProcess cannot replace
    /// the calling image.
    pub fn exec(self) -> Result<std::convert::Infallible>;
}
```

### Type 3 — TempSecretFile

```rust
// enclave::exec

/// A temporary file containing secret content, shredded (zeroed) on drop.
///
/// Platform selection is automatic via create():
/// - Linux / WSL2: `memfd_create` — anonymous in-memory file, no filesystem path.
///   Target receives `/proc/self/fd/{N}`. Secret never touches disk.
/// - macOS: 0o600 temp file in a 0o700 temp directory, shredded on drop.
/// - Windows: temp file in a restricted-permission temp directory, shredded on drop.
///
/// The file is sealed read-only on Linux (memfd SEAL_WRITE) after writing so the
/// target cannot modify it.
pub struct TempSecretFile { /* private */ }

impl TempSecretFile {
    /// Write text content to a platform-appropriate secret temp location.
    pub fn create(content: &str) -> Result<Self>;

    /// Write binary content.
    pub fn create_bytes(content: &[u8]) -> Result<Self>;

    /// The path string to pass to the target process.
    /// On Linux this is `/proc/self/fd/{N}`; elsewhere a real filesystem path.
    pub fn path(&self) -> &str;
}

impl Drop for TempSecretFile {
    // Shreds (zeros) the file content before the directory is removed.
}
```

### Type 4 — CredentialSource

Type 4 apps obtain credentials externally and cache them with hardware-backed encryption. The interface surfaces the lifecycle state machine.

```rust
// enclave::credential

/// Lifecycle state of a cached credential.
pub enum CredentialState {
    /// Within primary validity window. Serve from cache.
    Fresh,
    /// Aging — attempt background refresh, but serve stale if refresh fails.
    RefreshWindow,
    /// Past refresh window but within grace period. Serve stale; warn.
    Grace,
    /// Fully expired. Must re-acquire from the external source.
    Expired,
}

/// Maps risk levels (0–255) to credential expiration thresholds.
/// Higher risk level = shorter durations.
pub trait LifecyclePolicy: Send + Sync {
    /// Maximum age before entering the RefreshWindow.
    fn max_age_secs(&self, risk_level: u8) -> u64;
    /// Duration of the refresh window before Grace.
    fn refresh_window_secs(&self, risk_level: u8) -> u64;
    /// Duration of the grace period before Expired.
    fn grace_period_secs(&self, risk_level: u8) -> u64;
}

/// Classify a cached credential's lifecycle state without decrypting it.
/// Call this before deciding whether to decrypt+serve or re-acquire,
/// so the hardware operation is only triggered when actually needed.
pub fn classify_credential(
    issued_at: SystemTime,
    session_start: Option<SystemTime>,
    now: SystemTime,
    policy: &dyn LifecyclePolicy,
    risk_level: u8,
) -> CredentialState;
```

### Integration type enum

```rust
// enclave::exec

pub enum IntegrationType {
    HelperTool,
    EnvInterpolation,
    TempMaterializedConfig,
    CredentialSource,
}
```

---

## What This Means for FFI

With this design, a C FFI crate (`enclaveapp-ffi`, a future work item) wraps the four handles with `extern "C"` functions:

```c
// Future enclaveapp-ffi surface — illustrative only
typedef struct SignerHandle SignerHandle;  // opaque

SignerHandle* enclaveapp_signer_create(const EnclaveConfig* config, char** err_out);
void          enclaveapp_signer_destroy(SignerHandle* h);
int           enclaveapp_signer_sign(SignerHandle* h,
                  const char* label, const uint8_t* data, size_t data_len,
                  uint8_t** sig_out, size_t* sig_len_out, char** err_out);
void          enclaveapp_free_bytes(uint8_t* ptr, size_t len);
void          enclaveapp_free_string(char* ptr);
```

All the ugly `Box<dyn Trait>`, `PathBuf`, `Duration`, and `serde_json::Value` complexity is invisible to language bindings because it never appears in the public types of `enclaveapp`.

---

## Migration Plan

### Phase 1 — New crate + interface (this PR / design)
1. Create `crates/enclave/` with the six interfaces, config, factory, error, and memory modules.
2. Port the protected memory code from asherah-ffi into `enclave::memory`.
3. Factory functions delegate to `enclaveapp-app-storage` unchanged.
4. All existing consuming apps continue to build — nothing is removed.

### Phase 2 — Port consuming apps
Update `awsenc`, `sshenc`, `sso-jwt`, and `npmenc` to use `enclave::*` instead of the internal crates directly. This can be done app-by-app.

### Phase 3 — FFI bindings
Add `crates/enclaveapp-ffi/` with `extern "C"` wrappers around the Phase 1 API. Build C header via `cbindgen`. From there, language bindings (Python, Node, Go, etc.) are straightforward.

---

## Interface 5 — Tamper-Evident Files

This interface provides plaintext files on disk that are HMAC-protected against undetected tampering. It currently exists as an implementation detail inside the key metadata system but deserves its own clean surface because it is useful independently (sshenc uses it for key metadata, gitenc uses it for config files).

### How the existing system works (context)

- Each file gets a `.hmac` sidecar containing a hex-encoded HMAC-SHA256 of the file's bytes.
- The HMAC key is a random 32-byte key stored in the platform secure store (Keychain on macOS, DPAPI blob on Windows, D-Bus Secret Service on Linux) under a per-app name. No user-presence ACL — agents must be able to read it silently.
- A second per-label **trust anchor** (the authoritative HMAC value itself) lives in the secure store. The sidecar is forensic; the trust anchor is what verification checks. Deleting the sidecar does not bypass verification.
- All file writes are atomic (write to `.tmp`, rename into place, sync parent dir on Unix).
- Symlink reads are rejected via `O_NOFOLLOW` / pre-check to close TOCTOU attacks on attacker-controlled label paths.

### Clean interface

```rust
// enclave::integrity

/// Handle to the tamper-evident file subsystem for one app.
/// The HMAC key is loaded from the platform secure store on construction
/// and held in memory for the handle's lifetime.
pub struct TamperEvidentHandle { /* private */ }

/// Result of a verification check.
pub enum VerifyOutcome {
    /// File matches its stored trust anchor. Content is trustworthy.
    Match,
    /// HMAC mismatch — file has been modified outside the API.
    Tamper,
    /// No trust anchor exists yet (pre-migration or newly created path).
    Legacy,
    /// File does not exist.
    NotFound,
    /// Secure store is unreachable; verification was skipped (fail-open).
    StoreUnavailable,
}

impl TamperEvidentHandle {
    /// Write `content` to `path` atomically, update the HMAC sidecar,
    /// and refresh the trust anchor in the platform secure store.
    /// Existing content is overwritten; the sidecar and trust anchor are
    /// always consistent after a successful write.
    pub fn write(&self, path: &Path, content: &[u8]) -> Result<()>;

    /// Read `path`, verify its HMAC against the trust anchor, and return
    /// the content. Returns `Error::TamperDetected` if verification fails.
    pub fn read(&self, path: &Path) -> Result<Vec<u8>>;

    /// Verify `path` without returning content. Cheap — no content copy.
    pub fn verify(&self, path: &Path) -> Result<VerifyOutcome>;

    /// Migrate a file that was written before this API existed:
    /// compute the HMAC, write the sidecar, and store the trust anchor.
    /// Idempotent — safe to call even if a sidecar already exists.
    pub fn migrate(&self, path: &Path) -> Result<()>;

    /// Delete the sidecar and trust anchor for `path`.
    /// Does not delete the file itself.
    pub fn remove_integrity_data(&self, path: &Path) -> Result<()>;
}
```

### Factory

```rust
// enclave::factory

/// Create a tamper-evident handle for the given app. Loads (or generates)
/// the per-app HMAC key from the platform secure store.
pub fn create_tamper_evident(app_name: &str) -> Result<TamperEvidentHandle>;
```

**Design notes:**
- `TamperEvidentHandle` is intentionally scoped to an `app_name`, not a single file or directory. Multiple files for the same app share one HMAC key, consistent with existing behavior.
- The trust-anchor layer means the API is honest about security: deleting or replacing the sidecar file does not bypass verification, because the authoritative HMAC is in the platform secure store, not on disk.
- `VerifyOutcome::StoreUnavailable` (fail-open) matches existing behavior on Linux when D-Bus is absent. If you need fail-closed, check the outcome and treat `StoreUnavailable` as `Tamper` in your call site.
- The `.hmac` sidecar is kept for forensics and compatibility with existing tooling that inspects it. It is not the verification source of truth.
- `Error::TamperDetected` is added to the unified error type from Interface 4.

---

## Decisions

1. **Crate name:** `enclave` — confirmed free on crates.io. The `lib` prefix is a C convention; published Rust crates don't use it (`serde`, `tokio`, `zeroize` — never `libserde`). The repo was named `libenclaveapp`; it is now renamed to `enclave` on GitHub.

2. **`LockedBuffer` registry:** Include it. Centralized shutdown zeroization is worth the complexity, especially once FFI bindings exist and callers may not cleanly drop all handles.

3. **Enclave / Coffer layer:** Defer to Phase 3. Phase 1 scope is `SecureBuffer` + `LockedBuffer` only. The Coffer/Enclave heap re-encryption layer is added before FFI bindings ship.

4. **`AccessPolicy` enforcement on Linux:** Return `Error::PolicyNotSupported` from `generate_key()` when the backend cannot enforce the requested policy (e.g. `BiometricOnly` on Linux keyring/TPM). The interface must not lie.

5. **`sign_with_presence` with `PresenceMode::Strict` on unsupported platform:** Return `Error::PresenceNotAvailable`. Callers who pass `Strict` mean it; silent downgrade is surprising.
