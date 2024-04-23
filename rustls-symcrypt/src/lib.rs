//! # SymCrypt Provider for Rustls
//!
//! This crate provides integration for using `SymCrypt` cryptographic functionalities with the `rustls` crate, by implementing the required traits specified by `rustls`.
//!
//! ## Platform Support
//!
//! - Windows AMD64: Full support.
//! - Azure Linux: Full support.
//! - Ubuntu: Partial support. While tested, full compatibility and optimal performance on all Ubuntu environments cannot be guaranteed
//!
//! ## Limitations
//!
//! - QUIC Protocol: Not supported.
//! - Integration Efforts: Ongoing integration with rustls-cng and rustls-platform-verifier.
//!
//! ## Supported Ciphers
//!
//! Supported cipher suites are listed below, ordered by preference. IE: The default configuration prioritizes `TLS13_AES_256_GCM_SHA384` over `TLS13_AES_128_GCM_SHA256`.
//!
//! ### TLS 1.3
//!
//! ```ignore
//! TLS13_AES_256_GCM_SHA384
//! TLS13_AES_128_GCM_SHA256
//! TLS13_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
//! ```
//!
//! **Note:** `TLS13_CHACHA20_POLY1305_SHA256` is disabled by default. Enable the `chacha` feature in your `Cargo.toml` to use this cipher suite.
//!
//! ### TLS 1.2
//!
//! ```ignore
//! TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
//! TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
//! TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
//! TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
//! TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
//! TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
//! ```
//!**Note:** `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` and `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` is disabled by default. Enable the `chacha` feature in your `Cargo.toml` to use this cipher suite.
//!
//! ## Supported Key Exchanges
//!
//! Key exchanges are listed below, ordered by preference. IE: `SECP384R1` is preferred over `SECP256R1`.
//!
//! ```ignore
//! SECP384R1
//! SECP256R1
//! X25519 // Enabled with the `x25519` feature
//! ```
//!
//! **Note:** `X25519` is disabled by default. To enable, add `x25519` feature in your `Cargo.toml`.
//!
//! ## Dependencies
//!
//! This crate depends on the [symcrypt](https://github.com/microsoft/rust-symcrypt) crate and requires you have the necessary `symcrypt` binaries for your architecture.
//! Refer to the [rust-symcrypt Quick Start Guide](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt#quick-start-guide) to download the required binaries.
//!
//! ## Usage
//!
//! Add `rustls-symcrypt` to your `Cargo.toml`:
//!
//! **Note:** If you wish to enable `x25519` or `chacha` you may add it as a feature at this time.
//!
//! ```toml
//! [dependencies]
//! rustls = { version = "0.23.0", features = ["ring", "tls12", "std"], default-features = false }
//! # Disabling aws-lc as it slows down build times and is not needed.
//! rustls_symcrypt = "0.1.0"
//! # To enable the chacha feature:
//! # rustls_symcrypt = {version = "0.1.0", features = ["chacha"]}
//! ```
//!
//! ### Default Configuration
//!
//! Use `default_symcrypt_provider()` for a `ClientConfig` that utilizes the default cipher suites and key exchange groups listed above:
//!
//! ```rust
//! use rustls::{ClientConfig, RootCertStore};
//! use rustls_symcrypt::default_symcrypt_provider;
//! use std::sync::Arc;
//! use webpki_roots;
//!
//! fn main() {
//!     let mut root_store = RootCertStore {
//!         roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
//!     };
//!
//!     let mut config =
//!         ClientConfig::builder_with_provider(Arc::new(default_symcrypt_provider()))
//!             .with_safe_default_protocol_versions()
//!             .unwrap()
//!             .with_root_certificates(root_store)
//!             .with_no_client_auth();
//!
//!     // Rest of the connection setup
//! }
//! ```
//!
//! ### Custom Configuration
//!
//! To modify or change the order of negotiated cipher suites for `ClientConfig`, use `custom_symcrypt_provider()`.
//!
//! ```rust
//! use rustls::{ClientConfig, RootCertStore};
//! use rustls_symcrypt::{custom_symcrypt_provider, TLS13_AES_128_GCM_SHA256, SECP256R1};
//! use std::sync::Arc;
//! use webpki_roots;
//!
//! fn main() {
//!     let mut root_store = RootCertStore {
//!         roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
//!     };
//!      
//!     // Set custom config of cipher suites that have been imported from rustls_symcrypt.
//!     let cipher_suites = vec![TLS13_AES_128_GCM_SHA256];
//!     let kx_group = vec![SECP256R1];
//!
//!     let mut config =
//!         ClientConfig::builder_with_provider(Arc::new(custom_symcrypt_provider(
//!             Some(cipher_suites), Some(kx_group))))
//!                 .with_safe_default_protocol_versions()
//!                 .unwrap()
//!                 .with_root_certificates(root_store)
//!                 .with_no_client_auth();
//!
//!     // Rest of the connection setup
//! }
//! ```

use rustls::crypto::{
    CryptoProvider, GetRandomFailed, SecureRandom, SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::{SignatureScheme, SupportedCipherSuite};
use symcrypt::symcrypt_random;
use webpki::ring as webpki_algs;

mod cipher_suites;
mod ecdh;
mod hash;
mod hmac;
mod signer;
mod tls12;
mod tls13;

/// Exporting default cipher suites for TLS 1.3
pub use cipher_suites::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384};

/// Exporting default cipher suites for TLS 1.2
pub use cipher_suites::{
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};

/// Exporting ChaCha suites for TLS 1.2 and TLS 1.3
#[cfg(feature = "chacha")]
pub use cipher_suites::{
    TLS13_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};

/// Exporting default key exchange groups
pub use ecdh::{SECP256R1, SECP384R1};

/// Exporting X25519 key exchange group
#[cfg(feature = "x25519")]
pub use ecdh::X25519;

/// `default_symcrypt_provider` returns a `CryptoProvider` using the default `SymCrypt` configuration and cipher suites.
/// To see the default cipher suites, please take a look at [`DEFAULT_CIPHER_SUITES`].
///
/// Sample usage:
/// ```rust
/// use rustls::{ClientConfig, RootCertStore};
/// use rustls_symcrypt::default_symcrypt_provider;
/// use std::sync::Arc;
/// use webpki_roots;
///
/// fn main() {
///     let mut root_store = RootCertStore {
///         roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
///     };
///
///     let mut config =
///         ClientConfig::builder_with_provider(Arc::new(default_symcrypt_provider()))
///            .with_safe_default_protocol_versions()
///             .unwrap()
///             .with_root_certificates(root_store)
///             .with_no_client_auth();
///
///     // Rest of the connection setup
/// }
/// ```
pub fn default_symcrypt_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
        kx_groups: ecdh::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SymCrypt,
        key_provider: &signer::Ring,
    }
}

/// `custom_symcrypt_provider` provides a way to set up an custom config using a `symcrypt` crypto backend.
///
/// `provided_cipher_suites` takes in an optional `Vec<>` of `SupportedCipherSuites`
/// The supplied arguments for `provided_cipher_suite` will be used when when negotiating the TLS cipher suite;
/// and should be placed in preference order, where the first element has highest priority.
/// If `None` or an empty `Vec<>` is provided the [`DEFAULT_CIPHER_SUITES`] will be used instead.
///
/// `provided_kx_group` takes in an optional `Vec<>` of `SupportedKxGroup`
/// The supplied arguments for `provided_kx_group` will be used when when negotiating the TLS key exchange;
/// and should be placed in preference order, where the first element has highest priority.
/// If `None` or an empty `Vec<>` is provided the default will be used instead.
///
/// This call cannot fail.
///
/// Sample usage:
/// ```rust
/// use rustls::{ClientConfig, RootCertStore};
/// use rustls_symcrypt::{custom_symcrypt_provider, TLS13_AES_128_GCM_SHA256, SECP256R1};
/// use std::sync::Arc;
/// use webpki_roots;
///
/// fn main() {
///     let mut root_store = RootCertStore {
///         roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
///     };
///      
///     // Set custom config of cipher suites that have been imported from rustls_symcrypt.
///     let cipher_suites = vec![TLS13_AES_128_GCM_SHA256];
///     let kx_group = vec![SECP256R1];
///
///     let mut config =
///         ClientConfig::builder_with_provider(Arc::new(custom_symcrypt_provider(
///             Some(cipher_suites), Some(kx_group))))
///                 .with_safe_default_protocol_versions()
///                 .unwrap()
///                 .with_root_certificates(root_store)
///                 .with_no_client_auth();
///
///     // Rest of the connection setup
/// }
/// ```
pub fn custom_symcrypt_provider(
    provided_cipher_suites: Option<Vec<SupportedCipherSuite>>,
    provided_kx_group: Option<Vec<&'static dyn SupportedKxGroup>>,
) -> CryptoProvider {
    let cipher_suites = match provided_cipher_suites {
        Some(suites) if !suites.is_empty() => suites, // Use provided non-empty suites
        _ => DEFAULT_CIPHER_SUITES.to_vec(),          // Use default suites if None or empty
    };

    let kx_group = match provided_kx_group {
        Some(groups) if !groups.is_empty() => groups, // Use provided non-empty groups
        _ => ecdh::ALL_KX_GROUPS.to_vec(),            // Use default groups if None or empty
    };

    CryptoProvider {
        cipher_suites,
        kx_groups: kx_group,
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SymCrypt,
        key_provider: &signer::Ring,
    }
}

/// List of SymCrypt supported cipher suites in a preference order.
/// The first element has highest priority when negotiating cipher suites.
/// ```ignore
/// // TLS 1.3 suites
/// TLS13_AES_256_GCM_SHA384
/// TLS13_AES_128_GCM_SHA256
/// TLS13_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
/// // TLS 1.2 suites
/// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
/// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
/// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
/// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
/// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
/// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
/// ```
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = ALL_CIPHER_SUITES;

static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS 1.3 suites
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    #[cfg(feature = "chacha")]
    TLS13_CHACHA20_POLY1305_SHA256,
    // TLS 1.2 suites
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "chacha")]
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "chacha")]
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

// TODO: Switch to symcrypt for verification
static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512,
        webpki_algs::RSA_PKCS1_3072_8192_SHA384,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ECDSA_P256_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};

#[derive(Debug)]
struct SymCrypt;

impl SecureRandom for SymCrypt {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        symcrypt_random(buf);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_secure_random() {
        let random = SymCrypt;
        let mut buff_1 = [0u8; 10];
        let mut buff_2 = [0u8; 10];

        let _ = random.fill(&mut buff_1);
        let _ = random.fill(&mut buff_2);

        assert_ne!(buff_1, buff_2);
    }
}
