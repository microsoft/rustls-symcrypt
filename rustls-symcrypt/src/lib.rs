#![doc = include_str!("../README.md")]
use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom, SupportedKxGroup};

use rustls::SupportedCipherSuite;
use symcrypt::symcrypt_random;

mod cipher_suites;
mod ecdh;
mod hash;
mod hmac;
mod signer;
mod tls12;
mod tls13;
mod verify;
use crate::verify::SUPPORTED_SIG_ALGS;

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
/// let mut root_store = RootCertStore {
///     roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
/// };
///
/// let mut config =
/// ClientConfig::builder_with_provider(Arc::new(default_symcrypt_provider()))
///     .with_safe_default_protocol_versions()
///     .unwrap()
///     .with_root_certificates(root_store)
///     .with_no_client_auth();
/// // Rest of the connection setup
///
/// ```
pub fn default_symcrypt_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
        kx_groups: ecdh::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SymCrypt,
        key_provider: &signer::SymCryptProvider,
    }
}

/// `custom_symcrypt_provider` provides a way to set up an custom config using a `symcrypt` crypto backend.
///
/// `provided_cipher_suites` takes in an optional `Vec<>` of `SupportedCipherSuites`.
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
/// let mut root_store = RootCertStore {
///     roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
/// };
///
/// // Set custom config of cipher suites that have been imported from rustls_symcrypt.
/// let cipher_suites = vec![TLS13_AES_128_GCM_SHA256];
/// let kx_group = vec![SECP256R1];
///
/// let mut config =
///     ClientConfig::builder_with_provider(Arc::new(custom_symcrypt_provider(
///         Some(cipher_suites), Some(kx_group))))
///             .with_safe_default_protocol_versions()
///             .unwrap()
///             .with_root_certificates(root_store)
///             .with_no_client_auth();
///     // Rest of the connection setup
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
        key_provider: &signer::SymCryptProvider,
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
