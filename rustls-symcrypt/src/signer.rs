
use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::Signer;
use rustls::sign::SigningKey;
use rustls::Error;
use rustls::{SignatureAlgorithm, SignatureScheme};
use symcrypt::{
    ecc::{CurveType, EcKey, EcKeyUsage},
    hash::{sha256, sha384, sha512, HashAlgorithm},
    rsa::{RsaKey, RsaKeyUsage},
};

use pkcs1::der::Decode;
use pkcs1::RsaPrivateKey;
use pkcs8::PrivateKeyInfo;
use sec1::der::Decodable;
use sec1::EcPrivateKey;
use std::fmt::Debug;
use std::sync::Arc;

use pkcs1::RsaPublicKey as ECSignatureData;
use der::Encode;
use pkcs1::UintRef;
use symcrypt::hash::{SHA256_RESULT_SIZE, SHA384_RESULT_SIZE, SHA512_RESULT_SIZE};

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
        SignatureScheme::ECDSA_NISTP256_SHA256,
    ) {
        Ok(Arc::new(ecdsa_p256))
    } else if let Ok(ecdsa_p384) = EcdsaSigningKey::new(
        der,
        SignatureScheme::ECDSA_NISTP384_SHA384,
    ) {
        Ok(Arc::new(ecdsa_p384))
    } else if let Ok(ecdsa_p521) = EcdsaSigningKey::new(
        der,
        SignatureScheme::ECDSA_NISTP521_SHA512,
    ) {
        Ok(Arc::new(ecdsa_p521))
    } else {
        Err(Error::General(
            "failed to parse ECDSA private key as PKCS#8 or SEC1".into(),
        ))
    }
}

#[derive(Debug)]
pub struct RsaSigningKey {
    key: Arc<RsaKey>,
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
                )
                .map_err(|_| Error::General("Failed to set RsaKey from PKCS#1".into()))?
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
                )
                .map_err(|_| Error::General("Failed to set RsaKey from PKCS#8".into()))?
            }
            _ => {
                return Err(Error::General(
                    "Failed to parse RSA private key as either PKCS#1 or PKCS#8".into(),
                ));
            }
        };

        Ok(Self { key: Arc::new(key) })
    }
}

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        ALL_RSA_SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme))
            .map(|&scheme| {
                Box::new(RsaSigner {
                    key: Arc::clone(&self.key),
                    scheme,
                }) as Box<dyn Signer>
            })
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
                match self
                    .key
                    .pss_sign(&hashed_message, HashAlgorithm::Sha256, SHA256_RESULT_SIZE)
                {
                    Ok(signature) => Ok(signature),
                    Err(e) => Err(Error::General(format!("failed to sign message: {}", e))),
                }
            }
            SignatureScheme::RSA_PSS_SHA384 => {
                let hashed_message = sha384(message);
                match self
                    .key
                    .pss_sign(&hashed_message, HashAlgorithm::Sha384, SHA384_RESULT_SIZE)
                {
                    Ok(signature) => Ok(signature),
                    Err(e) => Err(Error::General(format!("failed to sign message: {}", e))),
                }
            }
            SignatureScheme::RSA_PSS_SHA512 => {
                let hashed_message = sha512(message);
                match self
                    .key
                    .pss_sign(&hashed_message, HashAlgorithm::Sha512, SHA512_RESULT_SIZE)
                {
                    Ok(signature) => Ok(signature),
                    Err(e) => Err(Error::General(format!("failed to sign message: {}", e))),
                }
            }
            _ => {
                return Err(Error::General(
                    "unsupported RSA-PKCS1 signature scheme".into(),
                ));
            }
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct EcdsaSigningKey {
    key: Arc<EcKey>,
    scheme: SignatureScheme,
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
            PrivateKeyDer::Sec1(sec1) => {
                // Extract DER-encoded private key blob for SEC1
                let private_key_blob = sec1.secret_sec1_der();

                // Parse the SEC1 DER-encoded EC private key
                let private_key = EcPrivateKey::from_der(private_key_blob)
                    .map_err(|_| Error::General("Failed to parse SEC1 DER".into()))?;

                // Use EcPrivateKey's private_key to set up the ECDSA key
                EcKey::set_key_pair(
                    curve_type,
                    &private_key.private_key,
                    None,
                    EcKeyUsage::EcDsa,
                )
                .map_err(|_| Error::General("Failed to set ECDSA key from SEC1".into()))?
            }
            PrivateKeyDer::Pkcs8(pkcs8) => {
                // Extract DER-encoded private key blob for PKCS#8
                let private_key_blob = pkcs8.secret_pkcs8_der();
                
                // Parse the DER-encoded private key
                let private_key_info = match PrivateKeyInfo::from_der(private_key_blob) {
                    Ok(info) => info,
                    Err(_) => return Err(Error::General("Failed to parse private key info from DER".into())),
                };
                
                // Parse the PKCS#8 DER-encoded EC private key
                let private_key = EcPrivateKey::from_der(&private_key_info.private_key)
                    .map_err(|_| Error::General("Failed to parse PKCS#8 DER".into()))?;
                
                // Use EcPrivateKey's private_key to set up the ECDSA key
                EcKey::set_key_pair(
                    curve_type,
                    &private_key.private_key,
                    None,
                    EcKeyUsage::EcDsa,
                )
                .map_err(|_| Error::General("Failed to set ECDSA key from PKCS#8".into()))?
            }
            _ => {
                return Err(Error::General(
                    "Invalid key format: must be PKCS#1 or PKCS#8".into(),
                ))
            }
        };

        // Return the ECDSASigningKey with Arc-wrapped key_pair and scheme
        Ok(Self {
            key: Arc::new(key),
            scheme,
        })
    }
}

impl SigningKey for EcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
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

#[derive(Debug)]
struct EcdsaSigner {
    key: Arc<EcKey>,
    scheme: SignatureScheme,
}


impl Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // Step 1: Hash the message based on the scheme
        let hash_value = match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => sha256(message).to_vec(),
            SignatureScheme::ECDSA_NISTP384_SHA384 => sha384(message).to_vec(),
            SignatureScheme::ECDSA_NISTP521_SHA512 => sha512(message).to_vec(),
            _ => return Err(Error::General("unsupported ECDSA signature scheme".into())),
        };

        // Step 2: Sign the hashed message
        let signature = self
            .key
            .ecdsa_sign(&hash_value)
            .map_err(|e| Error::General(format!("failed to sign message: {}", e)))?;

        // Step 3: Split the signature into r and s components
        let (r, s) = signature.split_at(signature.len() / 2);

        // Step 4: Create an RsaPublicKey structure which contains the signature r and s
        // ECSignatureData is encoded as sequence of two integers. RsaPublicKey is also encoded as sequence of two integers.
        // Will use RsaPublicKey to enode where modulus contains r and public_exponent contains s
        let modulus = match UintRef::new(r) {
            Ok(value) => value,
            Err(_) => return Err(Error::General("Failed to create UintRef for modulus".into())),
        };
        
        let public_exponent = match UintRef::new(s) {
            Ok(value) => value,
            Err(_) => return Err(Error::General("Failed to create UintRef for public exponent".into())),
        };
        
        let ec_sig_data = ECSignatureData {
            modulus,
            public_exponent,
        };

        // Step 5: Encode the RsaPublicKey using the Encode trait
        let mut encoded_signature = Vec::new();
        ec_sig_data
            .encode_to_vec(&mut encoded_signature)
            .map_err(|e| Error::General(format!("failed to encode signature: {}", e)))?;

        Ok(encoded_signature)
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
