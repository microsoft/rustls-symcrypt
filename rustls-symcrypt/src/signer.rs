/// function used are defined here
/// https://github.com/microsoft/rust-symcrypt/blob/main/rust-symcrypt/src/ecc/mod.rs
/// https://github.com/microsoft/rust-symcrypt/blob/main/rust-symcrypt/src/rsa/mod.rs
/// https://docs.rs/pkcs8/latest/pkcs8/trait.DecodePrivateKey.html#tymethod.from_pkcs8_der
/// https://docs.rs/pkcs1/latest/pkcs1/trait.DecodeRsaPrivateKey.html#tymethod.from_pkcs1_der
/// 
///use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;
///use rustls::sign::SigningKey;
use rustls::Error;
use rustls::SignatureScheme;
use rustls::sign::Signer;
use symcrypt::{
    rsa::{RsaKey, RsaKeyUsage},
    ecc::{EcKey, CurveType, EcKeyUsage},
    hash::{HashAlgorithm, sha256, sha384, sha512},
};

use std::sync::Arc;
use std::fmt::Debug;
use pkcs1::RsaPrivateKey;
use pkcs8::PrivateKeyInfo;
use pkcs1::der::Decode;


/* 
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    match der {
        PrivateKeyDer::Pkcs1(pkcs1) => {
            // For PKCS#1 RSA keys
            let rsa_key = RsaSigningKey::new(pkcs1)?;
            Ok(Arc::new(rsa_key) as Arc<dyn SigningKey>)
        }
        PrivateKeyDer::Pkcs8(pkcs8) => {
            // Attempt to determine if it's RSA or ECDSA
            let private_key_blob = pkcs8.secret_pkcs8_der(); // returns &[u8] that is DER encoded

            // Check the algorithm OID to determine the key type
            if is_rsa(private_key_blob) {
                let rsa_key = RsaSigningKey::new(pkcs8)?;
                Ok(Arc::new(rsa_key) as Arc<dyn SigningKey>)
            } else if is_ecdsa(private_key_blob) {
                let ecdsa_key = EcDsaSigningKey::new(pkcs8)?;
                Ok(Arc::new(ecdsa_key) as Arc<dyn SigningKey>)
            } else {
                Err(Error::General("Unsupported key format".into()))
            }
        }
        PrivateKeyDer::Sec1(sec1) => {
            let ecdsa_key = EcDsaSigningKey::new(sec1)?;
            Ok(Arc::new(ecdsa_key) as Arc<dyn SigningKey>)
        }
        _ => Err(Error::General("Unsupported key format".into())),
    }
}

fn is_rsa(blob: &[u8]) -> bool {
    // The OID for RSA is typically 1.2.840.113549.1.1.1
    const RSA_OID_PREFIX: &[u8] = &[0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    
    blob.starts_with(RSA_OID_PREFIX)
}

fn is_ecdsa(blob: &[u8]) -> bool {
    // The OID for ECDSA is typically 1.2.840.10045.3.1.7
    const ECDSA_OID_PREFIX: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    blob.starts_with(ECDSA_OID_PREFIX)
}
*/


pub struct RsaSigningKey { 
    key: Arc<RsaKey>
}

static ALL_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

impl RsaSigningKey {
    pub fn new(der: &PrivateKeyDer<'_>) -> Result<Self, Error> {
        let key = match der {
            PrivateKeyDer::Pkcs1(pkcs1) => {
                // Get the DER-encoded private key blob
                let private_key_blob = pkcs1.secret_pkcs1_der(); // returns &[u8] that is DER encoded

                // Parse the DER-encoded RSA private key
                let private_key = RsaPrivateKey::from_der(private_key_blob)
                    .map_err(|_| Error::General("Failed to parse PKCS#1 DER".into()))?;

                // Extract the components and set the key pair
                RsaKey::set_key_pair(
                    private_key.modulus.as_bytes(),
                    private_key.public_exponent.as_bytes(),
                    private_key.prime1.as_bytes(),
                    private_key.prime2.as_bytes(),
                    RsaKeyUsage::Sign,
                ).map_err(|_| Error::General("Failed to set RsaKey from PKCS#1".into()))?
            }

            PrivateKeyDer::Pkcs8(pkcs8) => {
                let private_key_blob = pkcs8.secret_pkcs8_der(); // DER-encoded &[u8]

                // Parse the DER-encoded private key
                let private_key_info = PrivateKeyInfo::from_der(private_key_blob)
                    .map_err(|_| Error::General("Failed to parse PKCS#8 DER".into()))?;
                let private_key = RsaPrivateKey::from_der(&private_key_info.private_key)
                    .map_err(|_| Error::General("Failed to parse PKCS#8 DER".into()))?;

                // Extract the components and set the key pair
                RsaKey::set_key_pair(
                    private_key.modulus.as_bytes(),
                    private_key.public_exponent.as_bytes(),
                    private_key.prime1.as_bytes(),
                    private_key.prime2.as_bytes(),
                    RsaKeyUsage::Sign,
                ).map_err(|_| Error::General("Failed to set RsaKey from PKCS#8".into()))?
            }
            _ => {
                return Err(Error::General("Failed to parse RSA private key as either PKCS#1 or PKCS#8".into()));
            }
        };

        Ok(Self {
            key: Arc::new(key),
        })
    }
}

#[derive(Debug)]
struct RsaSigner {
    key: Arc<RsaKey>,
    scheme: SignatureScheme,
}

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // from Ring, do we need to add padding??? 

        // Sign msg. msg is digested using the digest algorithm from padding_alg and the digest is then padded using the padding algorithm from padding_alg. 
        // The signature it written into signature; signature's length must be exactly the length returned by public_modulus_len().
        // Many other crypto libraries have signing functions that takes a precomputed digest as input, 
        // instead of the message to digest. This function does not take a precomputed digest; instead, sign calculates the digest itself.

        match self.scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => {
                let hashed_message = sha256(message);
                match self.key.pkcs1_sign(&hashed_message, HashAlgorithm::Sha256) {
                    Ok(signature) => Ok(signature),
                    Err(e) => Err(Error::General(format!("failed to sign message: {}", e))),
                }
            }
            SignatureScheme::RSA_PKCS1_SHA384 => {
                let hashed_message = sha384(message);
                match self.key.pkcs1_sign(&hashed_message, HashAlgorithm::Sha384) {
                    Ok(signature) => Ok(signature),
                    Err(e) => Err(Error::General(format!("failed to sign message: {}", e))),
                }
            }
            SignatureScheme::RSA_PKCS1_SHA512 => {
                let hashed_message = sha512(message);
                match self.key.pkcs1_sign(&hashed_message, HashAlgorithm::Sha512) {
                    Ok(signature) => Ok(signature),
                    Err(e) => Err(Error::General(format!("failed to sign message: {}", e))),
                }
            }
            SignatureScheme::RSA_PSS_SHA256 => {
                let hashed_message = sha256(message);
                match self.key.pss_sign(&hashed_message, HashAlgorithm::Sha256, 32) {
                    Ok(signature) => Ok(signature),
                    Err(e) => Err(Error::General(format!("failed to sign message: {}", e))),
                }
            }
            SignatureScheme::RSA_PSS_SHA384 => {
                let hashed_message = sha384(message);
                match self.key.pss_sign(&hashed_message, HashAlgorithm::Sha384, 48) {
                    Ok(signature) => Ok(signature),
                    Err(e) => Err(Error::General(format!("failed to sign message: {}", e))),
                }
            }
            SignatureScheme::RSA_PSS_SHA512 => {
                let hashed_message = sha512(message);
                match self.key.pss_sign(&hashed_message, HashAlgorithm::Sha512, 64) {
                    Ok(signature) => Ok(signature),
                    Err(e) => Err(Error::General(format!("failed to sign message: {}", e))),
                }
            }
            _ => {
                return Err(Error::General("unsupported RSA-PKCS1 signature scheme".into()));
            }
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}



pub struct EcDsaSigningKey {
    key: Arc<EcKey>, 
    scheme: SignatureScheme
}


impl EcDsaSigningKey {
    pub fn new(der: &PrivateKeyDer<'_>, scheme: SignatureScheme) -> Result<Self, Box<dyn std::error::Error>> {
        let key = match der {
            PrivateKeyDer::Pkcs1(pkcs1) => {
                // Get the DER-encoded private key blob
                let private_key_blob = pkcs1.secret_pkcs1_der(); // returns &[u8] that is DER encoded

                // Determine the curve type for PKCS#1

                let curve_type = match private_key_blob {
                    blob if blob.starts_with(&[0x30, 0x81]) => CurveType::NistP256, // Example check for NistP256
                    blob if blob.starts_with(&[0x30, 0x82]) => CurveType::NistP384, // Example check for NistP384
                    blob if blob.starts_with(&[0x30, 0x83]) => CurveType::NistP521, // Example check for NistP521
                    blob if blob.starts_with(&[0x30, 0x84]) => CurveType::Curve25519, // Example check for Curve25519
                    _ => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Unsupported curve type"))),
                };

                // Parse the DER-encoded EC private key
                EcKey::set_key_pair(
                    curve_type,
                    private_key_blob,
                    None, 
                    EcKeyUsage::EcDsa,
                ).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Failed to parse PKCS#1 DER"))?
            }
            PrivateKeyDer::Pkcs8(pkcs8) => {
                // Get the DER-encoded private key blob
                let private_key_blob = pkcs8.secret_pkcs8_der(); // returns &[u8] that is DER encoded

                let curve_type = match private_key_blob {
                    blob if blob.starts_with(&[0x30, 0x81]) => CurveType::NistP256, // Example check for NistP256
                    blob if blob.starts_with(&[0x30, 0x82]) => CurveType::NistP384, // Example check for NistP384
                    blob if blob.starts_with(&[0x30, 0x83]) => CurveType::NistP521, // Example check for NistP521
                    blob if blob.starts_with(&[0x30, 0x84]) => CurveType::Curve25519, // Example check for Curve25519
                    _ => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Unsupported curve type"))),
                };

                EcKey::set_key_pair(
                    curve_type,
                    private_key_blob,
                    None, 
                    EcKeyUsage::EcDsa,
                ).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Failed to parse PKCS#8 DER"))?
            }
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Failed to parse EC private key as either PKCS#1 or PKCS#8",
                )));
            }
        };

        Ok(Self {
            key: Arc::new(key),
            scheme,
        })
    }
}

#[derive(Debug)]
struct EcdsaSigner {
    key: Arc<EcKey>,
    scheme: SignatureScheme,
}


impl Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        match self.scheme { 
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                let hashed_message = sha256(message);
                match self.key.ecdsa_sign(&hashed_message) {
                    Ok(signature) => Ok(signature),
                    Err(e) => Err(Error::General(format!("failed to sign message: {}", e))),
                }
            }
            SignatureScheme::ECDSA_NISTP384_SHA384 => {
                let hashed_message = sha384(message);
                match self.key.ecdsa_sign(&hashed_message) {
                    Ok(signature) => Ok(signature),
                    Err(e) => Err(Error::General(format!("failed to sign message: {}", e))),
                }
            }
            SignatureScheme::ECDSA_NISTP521_SHA512 => {
                let hashed_message = sha512(message);
                match self.key.ecdsa_sign(&hashed_message) {
                    Ok(signature) => Ok(signature),
                    Err(e) => Err(Error::General(format!("failed to sign message: {}", e))),
                }
            }
            _ => {
                return Err(Error::General("unsupported ECDSA signature scheme".into()));
            }
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/* 
#[derive(Debug)]
pub struct SymCryptProvider;

impl KeyProvider for SymCryptProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        sign::any_supported_type(&key_der)
    }
}
*/