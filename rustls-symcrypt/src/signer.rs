/// function used are defined here
/// https://github.com/microsoft/rust-symcrypt/blob/main/rust-symcrypt/src/ecc/mod.rs
/// https://github.com/microsoft/rust-symcrypt/blob/main/rust-symcrypt/src/rsa/mod.rs
/// https://docs.rs/pkcs8/latest/pkcs8/trait.DecodePrivateKey.html#tymethod.from_pkcs8_der
/// https://docs.rs/pkcs1/latest/pkcs1/trait.DecodeRsaPrivateKey.html#tymethod.from_pkcs1_der
/// 
use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::Error;
use rustls::{SignatureAlgorithm, SignatureScheme};
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
use sec1::der::Decodable;
use sec1::EcPrivateKey;


pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(rsa) = RsaSigningKey::new(der) {
        return Ok(Arc::new(rsa));
    }

    if let Ok(ecdsa) = any_ecdsa_type(der) {
        return Ok(ecdsa);
    }
    
    Err(Error::General(
        "failed to parse private key as RSA or ECDSA ".into(),
    ))
}

pub fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<EcdsaSigningKey>, Error> {
    if let Ok(ecdsa_p256) = EcdsaSigningKey::new(
        der,
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
    ) {
        return Ok(Arc::new(ecdsa_p256));
    }
    
    if let Ok(ecdsa_p384) = EcdsaSigningKey::new(
        der,
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
    ) {
        return Ok(Arc::new(ecdsa_p384));
    }
    
    if let Ok(ecdsa_p521) = EcdsaSigningKey::new(
        der,
        rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
    ) {
        return Ok(Arc::new(ecdsa_p521));
    }
    
    Err(Error::General(
        "Failed to parse ECDSA private key as PKCS#8 or SEC1".into(),
    ))
}


#[derive(Debug)]
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

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        ALL_RSA_SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme))
            .map(|&scheme| Box::new(RsaSigner {
                key: Arc::clone(&self.key),
                scheme,
            }) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
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

static ALL_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
];

#[derive(Debug)]
pub struct EcdsaSigningKey {
    key: Arc<EcKey>, 
}


impl EcdsaSigningKey {
    /// Creates a new `ECDSASigningKey` from DER encoding in either PKCS#8 or SEC1
    /// format, ensuring compatibility with the specified signature scheme.
    fn new(
        der: &PrivateKeyDer<'_>,
        scheme: SignatureScheme,
    ) -> Result<Self, Error> {
        // Map the signature scheme to rust-symcrypt's CurveType
        let curve_type = match scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => CurveType::NistP256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => CurveType::NistP384,
            SignatureScheme::ECDSA_NISTP521_SHA512 => CurveType::NistP521, // Assuming NistP521 exists in rust-symcrypt
            _ => return Err(Error::General("Unsupported signature scheme".into())),
        };

        // Initialize the key based on the DER encoding format
        let key = match der {
            PrivateKeyDer::Pkcs1(pkcs1) => {
                // Extract DER-encoded private key blob for PKCS#1
                let private_key_blob = pkcs1.secret_pkcs1_der();
                
                // Parse the PKCS#1 DER-encoded EC private key
                let private_key = EcPrivateKey::from_der(private_key_blob)
                    .map_err(|_| Error::General("Failed to parse PKCS#1 DER".into()))?;
                
                // Use EcPrivateKey's private_key to set up the ECDSA key
                EcKey::set_key_pair(curve_type, &private_key.private_key, None, EcKeyUsage::EcDsa)
                    .map_err(|_| Error::General("Failed to set ECDSA key from PKCS#1".into()))?
            }
            PrivateKeyDer::Pkcs8(pkcs8) => {
                // Extract DER-encoded private key blob for PKCS#8
                let private_key_blob = pkcs8.secret_pkcs8_der();

                // Parse the PKCS#8 DER-encoded EC private key
                let private_key = EcPrivateKey::from_der(private_key_blob)
                    .map_err(|_| Error::General("Failed to parse PKCS#8 DER".into()))?;
                
                // Use EcPrivateKey's private_key to set up the ECDSA key
                EcKey::set_key_pair(curve_type, &private_key.private_key, None, EcKeyUsage::EcDsa)
                    .map_err(|_| Error::General("Failed to set ECDSA key from PKCS#8".into()))?
            }
            _ => return Err(Error::General("Invalid key format: must be PKCS#1 or PKCS#8".into())),
        };

        // Return the ECDSASigningKey with Arc-wrapped key_pair and scheme
        Ok(Self {
            key: Arc::new(key),
        })
    }
}


impl SigningKey for EcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        ALL_ECDSA_SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme))
            .map(|&scheme| Box::new(EcdsaSigner {
                key: Arc::clone(&self.key),
                scheme,
            }) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
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


#[derive(Debug)]
pub struct SymCryptProvider;

impl KeyProvider for SymCryptProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        any_supported_type(&key_der)
    }
}
