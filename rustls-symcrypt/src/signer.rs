//! Implementation of `KeyProvider` for rustls-symcrypt
use rustls::crypto::ring::sign;
use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::Error;
use std::{f32::consts::E, sync::Arc};
use symcrypt::{rsa::RsaKey, ecc::EcKey, hash::HashAlgorithm, hash::{sha256, sha384, sha512}};
use rustls::{SignatureAlgorithm, SignatureScheme};
use rustls::sign::Signer;
#[derive(Debug)]
pub(crate) struct Ring;

// this will be called by the keyprovider trait, when you load a new private key. It will return the corresponding singin key.
pub fn parse_der(der: &PrivateKeyDer<'_>) -> Result<SigningKey, Error> {
    // call new function on Rsa pcks1, rsa pss, ecc
    // if result is OK that means that its the key type, if not then we'll check the other one.
    // if both fail, return error.
    // If EDD is passed, we can make a new error saying that ED is not supported
}

// This key is for pkcs1 only.
pub struct RsaSigningKey { 
    key: Arc<RsaKey>
}

// Supported RSA schemes
static PKCS1_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

// must handle pcks1 and pkcs8. 
// need to check if its pcks1 or pss, if pss return error right away, handle later in the parse_cert func.
impl RsaSigningKey { 
    pub fn new(der: &PrivateKeyDer<'_>) -> Result<Self, Error> {
        let key_pair = match der {
            PrivateKeyDer::Pkcs1(pcks1) => {
                let private_key_blob = pcks1.secret_pkcs1_der(); // returns &[u8] that is der encoded. 
                // use intern code to return this as an RsaKeyPair. 
                // RsaKey::set_key_pair(modulus_buffer, pub_exp, p, q, rsa_key_usage)
            }
            PrivateKeyDer::Pkcs8(pkcs8) => {
                let private_key_blob = pkcs8.secret_pkcs8_der(); // Parses an unencrypted PKCS#8-encoded RSA private key
                // use intern code to return this as an RsaKeyPair.
            }
            _ => {
                return Err(Error::General(
                    "failed to parse RSA private key as either PKCS#1 or PKCS#8".into(),
                ));
            }
        }
        .map_err(|key_rejected| {
            Error::General(format!("failed to parse RSA private key: {}", key_rejected))
        })?;

        Ok(Self {
            key: Arc::new(key_pair)
        })
    }
}

impl SigningKey for RsaSigningKey 
{
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        PKCS1_SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme))
            .map(|scheme| RsaSigner{key: Arc::clone(&self.key), scheme: *scheme})
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

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
    fn new (der: &PrivateKeyDer<'_>, scheme: SignatureScheme) -> Result<Self, ()> {
        let key_pair = match der {
            PrivateKeyDer::Sec1(sec1) => {
                // asn1 decode the sec1 key, use info to get ecc object
            }
            PrivateKeyDer::Pkcs8(pkcs8) => {
                // asn1 decode the pkcs8 key, use info to get ecc object
                // need to check if this will be rsa or ecc 
            }
            _ => {
                return Err(());
            }
        };

        Ok(Self {
            key: Arc::new(key_pair),
            scheme,
        })
    }
}

impl SigningKey for EcDsaSigningKey 
{
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(EcdsaSigner {
                key: Arc::clone(&self.key),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

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

// Key provider for Ring
impl KeyProvider for Ring {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        sign::any_supported_type(&key_der)
    }
}
