//! Cipher Suites supported for TLS 1.3 and TLS 1.2
use crate::hash::{Sha256, Sha384};
use crate::hmac::{HmacSha256, HmacSha384};
use rustls::crypto::{CipherSuiteCommon, KeyExchangeAlgorithm};
use rustls::{
    CipherSuite, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite,
};

use crate::tls12::Tls12Gcm;
use crate::tls13::Tls13Gcm;

#[cfg(feature = "chacha")]
use crate::tls12::Tls12ChaCha;
#[cfg(feature = "chacha")]
use crate::tls13::Tls13ChaCha;

use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::tls13::HkdfUsingHmac;

/// Algo types for GCM TLS 1.3 and TLS 1.2
pub enum AesGcm {
    Aes128Gcm,
    Aes256Gcm,
}

impl AesGcm {
    pub fn key_size(&self) -> usize {
        match self {
            AesGcm::Aes128Gcm => 16,
            AesGcm::Aes256Gcm => 32,
        }
    }
}

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
#[cfg(feature = "chacha")]
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &Sha256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(&HmacSha256),
        aead_alg: &Tls13ChaCha,
        quic: None,
    });

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &Sha384,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &HkdfUsingHmac(&HmacSha384),
        aead_alg: &Tls13Gcm {
            algo_type: AesGcm::Aes256Gcm,
        },
        quic: None,
    });

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &Sha256,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &HkdfUsingHmac(&HmacSha256),
        aead_alg: &Tls13Gcm {
            algo_type: AesGcm::Aes128Gcm,
        },
        quic: None,
    });

/// TLS 1.2

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
#[cfg(feature = "chacha")]
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &Sha256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &Tls12ChaCha,
        prf_provider: &PrfUsingHmac(&HmacSha256),
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
#[cfg(feature = "chacha")]
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &Sha256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &Tls12ChaCha,
        prf_provider: &PrfUsingHmac(&HmacSha256),
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &Sha256,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &Tls12Gcm {
            algo_type: AesGcm::Aes128Gcm,
        },
        prf_provider: &PrfUsingHmac(&HmacSha256),
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &Sha384,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &Tls12Gcm {
            algo_type: AesGcm::Aes256Gcm,
        },
        prf_provider: &PrfUsingHmac(&HmacSha384),
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &Sha256,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &Tls12Gcm {
            algo_type: AesGcm::Aes128Gcm,
        },
        prf_provider: &PrfUsingHmac(&HmacSha256),
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &Sha384,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &Tls12Gcm {
            algo_type: AesGcm::Aes256Gcm,
        },
        prf_provider: &PrfUsingHmac(&HmacSha384),
    });

static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];
