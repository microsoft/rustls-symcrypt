use pkcs1::RsaPublicKey as AsnRsaPublicKey;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};
use symcrypt::hash::{sha256, sha384, sha512, HashAlgorithm};
use symcrypt::rsa::{RsaKey, RsaKeyUsage};
use webpki::alg_id::{self};

/// Rsa signatures from the wire will come in the following ASN1 format:
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
fn extract_rsa_public_key(pub_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), InvalidSignature> {
    let key = AsnRsaPublicKey::try_from(pub_key).map_err(|_| InvalidSignature)?;

    let modulus = key.modulus.as_bytes().to_vec();
    let exponent = key.public_exponent.as_bytes().to_vec();

    Ok((modulus, exponent))
}

// NistP256, NistP384, and NistP521 have a prepended Legacy byte that needs to be removed.
// This call will return InvalidSignature if the public key is P256, P384, or P21 and does not have the legacy byte.
fn extract_ecc_public_key(
    pub_key: &[u8],
    curve_type: CurveType,
) -> Result<Vec<u8>, InvalidSignature> {
    match curve_type {
        CurveType::NistP256 | CurveType::NistP384 | CurveType::NistP521 => {
            if pub_key.starts_with(&[0x04]) {
                Ok(pub_key[1..].to_vec())
            } else {
                Err(InvalidSignature) // Propagate InvalidSignature error back to caller
            }
        }
        CurveType::Curve25519 => {
            // Curve25519 is not supported for ECC signatures
            Err(InvalidSignature)
        }
    }
}

/// Ecc signatures from the wire will come in the following ASN1 format:
/// ECDSASignature ::= SEQUENCE {
///     r INTEGER,
///     s INTEGER
/// }
/// SymCrypt expects a concatenated r+s with leading padding and leading 0's for both r and s to be removed
fn extract_ecc_signature(signature: &[u8], curve: CurveType) -> Result<Vec<u8>, InvalidSignature> {
    // We use pkcs1::RsaPublicKey because the underlying ASN1 format between an RSA public key and
    // an ECC signature is the same.
    let signature = AsnRsaPublicKey::try_from(signature).map_err(|_| InvalidSignature)?;

    let component_length = curve.get_size() as usize;

    // Leading 0's are stripped when using as_bytes()
    // https://docs.rs/pkcs1/0.7.5/pkcs1/struct.UintRef.html
    let r = signature.modulus.as_bytes(); // cast name from `modulus` to `r`
    let s = signature.public_exponent.as_bytes(); // cast name from `public_exponent` to `s`

    // SymCrypt takes in a concatenated r+s. with the individual r and s components having a size of curve / 2.
    // If for example the curve is P256, the r and s components must individually 32 bytes long.
    // as_bytes() removes all leading 0s, which covers the case if r or s is 33 bytes long for example.
    // as_bytes() may remove ALL 0's even if one was randomly generated as part of the signature.
    // So after we remove the 0's we prepend 0's that were removed until the lengths are 32.
    // Majority of the time this will not happen but this is to cover corner cases where it does.

    // Ensure r and s are the correct length (pad with leading zeros if necessary).
    let mut r_padded = Vec::with_capacity(component_length);
    let mut s_padded = Vec::with_capacity(component_length);

    // In the scenario where there are too many bytes after the leading 0's are removed, return an error.
    if r.len() > component_length || s.len() > component_length {
        return Err(InvalidSignature);
    }

    // Prepend zeros if r is smaller than component_length.
    if r.len() < component_length {
        r_padded.extend(std::iter::repeat(0).take(component_length - r.len()));
    }
    r_padded.extend_from_slice(r); // Add the actual r bytes.

    // Prepend zeros if s is smaller than component_length.
    if s.len() < component_length {
        s_padded.extend(std::iter::repeat(0).take(component_length - s.len()));
    }
    s_padded.extend_from_slice(s); // Add the actual s bytes.

    // Concatenate the padded r and s components.
    Ok([r_padded, s_padded].concat())
}

pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ECDSA_P521_SHA256,
        ECDSA_P521_SHA384,
        ECDSA_P521_SHA512,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384, ECDSA_P521_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256, ECDSA_P521_SHA256],
        ),
        (SignatureScheme::ECDSA_NISTP521_SHA512, &[ECDSA_P521_SHA512]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

fn hash_sha256(data: &[u8]) -> Vec<u8> {
    sha256(data).to_vec()
}

fn hash_sha384(data: &[u8]) -> Vec<u8> {
    sha384(data).to_vec()
}

fn hash_sha512(data: &[u8]) -> Vec<u8> {
    sha512(data).to_vec()
}

#[derive(Debug)]
enum KeyType {
    RsaPkcs1(RsaPkcs1),
    RsaPss(RsaPss),
    Ecc(Ecc),
}

#[derive(Debug)]
struct RsaPkcs1 {
    hash_algorithm: HashAlgorithm,
}

#[derive(Debug)]
struct RsaPss {
    hash_algorithm: HashAlgorithm,
    salt_length: u32,
}

#[derive(Debug)]
struct Ecc {
    curve: CurveType,
}

/// ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    hasher: hash_sha256,
    key_type: KeyType::Ecc(Ecc {
        curve: CurveType::NistP256,
    }),
};

/// ECDSA signatures using the P-256 curve and SHA-384.
pub static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    hasher: hash_sha384,
    key_type: KeyType::Ecc(Ecc {
        curve: CurveType::NistP256,
    }),
};

/// ECDSA signatures using the P-384 curve and SHA-256.
pub static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    hasher: hash_sha256,
    key_type: KeyType::Ecc(Ecc {
        curve: CurveType::NistP384,
    }),
};

/// ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    hasher: hash_sha384,
    key_type: KeyType::Ecc(Ecc {
        curve: CurveType::NistP384,
    }),
};

/// ECDSA signatures using the P-521 curve and SHA-256.
pub static ECDSA_P521_SHA256: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA256,
    hasher: hash_sha256,
    key_type: KeyType::Ecc(Ecc {
        curve: CurveType::NistP521,
    }),
};

/// ECDSA signatures using the P-521 curve and SHA-384.
pub static ECDSA_P521_SHA384: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA384,
    hasher: hash_sha384,
    key_type: KeyType::Ecc(Ecc {
        curve: CurveType::NistP521,
    }),
};

/// ECDSA signatures using the P-521 curve and SHA-512.
pub static ECDSA_P521_SHA512: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA512,
    hasher: hash_sha512,
    key_type: KeyType::Ecc(Ecc {
        curve: CurveType::NistP521,
    }),
};

/// RSA PKCS1 signatures using SHA-256.
pub static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
    hasher: hash_sha256,
    key_type: KeyType::RsaPkcs1(RsaPkcs1 {
        hash_algorithm: HashAlgorithm::Sha256,
    }),
};

/// RSA PKCS1 signatures using SHA-384.
pub static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    hasher: hash_sha384,
    key_type: KeyType::RsaPkcs1(RsaPkcs1 {
        hash_algorithm: HashAlgorithm::Sha384,
    }),
};

/// RSA PKCS1 signatures using SHA-512.
pub static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
    hasher: hash_sha512,
    key_type: KeyType::RsaPkcs1(RsaPkcs1 {
        hash_algorithm: HashAlgorithm::Sha512,
    }),
};

/// RSA PSS signatures using SHA-256.
pub static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
    hasher: hash_sha256,
    key_type: KeyType::RsaPss(RsaPss {
        hash_algorithm: HashAlgorithm::Sha256,
        salt_length: 32,
    }),
};

/// RSA PSS signatures using SHA-384.
pub static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
    hasher: hash_sha384,
    key_type: KeyType::RsaPss(RsaPss {
        hash_algorithm: HashAlgorithm::Sha384,
        salt_length: 48,
    }),
};

/// RSA PSS signatures using SHA-256.
pub static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
    hasher: hash_sha512,
    key_type: KeyType::RsaPss(RsaPss {
        hash_algorithm: HashAlgorithm::Sha512,
        salt_length: 64,
    }),
};

#[derive(Debug)]
/// SymCryptAlgorithm holds the following fields
/// `public_key_alg_id`: The public key algorithm identifier, this is tied to the
/// rustls::pki_types::AlgorithmIdentifier and is used to match the public key
///
/// `signature_alg_id`: The signature algorithm identifier, this is tied to the
/// rustls::pki_types::AlgorithmIdentifier and is used to match the signature
///
/// `hasher`: A function that takes a slice of bytes and returns a vector of bytes
/// that have been hashed
///
/// `key_type`: A enum that holds the type of key that is being used, this is used to store
/// the info needed to create a public key on the SymCrypt side.
///
/// Each SymCryptAlgorithm has already been matched for the necessary fields for creating
/// public keys on the SymCrypt side through the fields in this struct.
struct SymCryptAlgorithm {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    hasher: fn(&[u8]) -> Vec<u8>,
    key_type: KeyType,
}

/// [`SignatureVerificationAlgorithm`] for SymCryptAlgorithm.
/// Creates either a RSA or ECC key depending on the SymCryptAlgorithm then does a verify based on the
/// provided `public_key` bytes, `message` bytes and the `signature` bytes.
impl SignatureVerificationAlgorithm for SymCryptAlgorithm {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        match &self.key_type {
            KeyType::Ecc(ecc) => {
                // the pub_key passed will have a 0x04 legacy byte prepended to the key for the case of
                // NistP256, NistP384, NistP521.
                let key = extract_ecc_public_key(public_key, ecc.curve)?;

                // the signature will be in ASN.1 DER format, with separated `r` and `s` components, need to remove padding
                // and concatenate the two components.
                let sig = extract_ecc_signature(signature, ecc.curve)?;

                let ec_key = EcKey::set_public_key(ecc.curve, &key, EcKeyUsage::EcDsa)
                    .map_err(|_| InvalidSignature)?;
                let hashed_message = (self.hasher)(message);
                ec_key
                    .ecdsa_verify(&sig, &hashed_message)
                    .map_err(|_| InvalidSignature)
            }
            KeyType::RsaPkcs1(rsa_pkcs1) => {
                // extract the modulus and exponent from the public key
                let (modulus, exponent) = extract_rsa_public_key(public_key)?;
                let rsa_key = RsaKey::set_public_key(&modulus, &exponent, RsaKeyUsage::Sign)
                    .map_err(|_| InvalidSignature)?;
                let hashed_message = (self.hasher)(message);
                rsa_key
                    .pkcs1_verify(&hashed_message, signature, rsa_pkcs1.hash_algorithm)
                    .map_err(|_| InvalidSignature)
            }
            KeyType::RsaPss(rsa_pss) => {
                // extract the modulus and exponent from the public key
                let (modulus, exponent) = extract_rsa_public_key(public_key)?;
                let rsa_key = RsaKey::set_public_key(&modulus, &exponent, RsaKeyUsage::Sign)
                    .map_err(|_| InvalidSignature)?;
                let hashed_message = (self.hasher)(message);
                rsa_key
                    .pss_verify(
                        &hashed_message,
                        signature,
                        rsa_pss.hash_algorithm,
                        rsa_pss.salt_length as usize,
                    )
                    .map_err(|_| InvalidSignature)
            }
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn fips(&self) -> bool {
        true
    }
}
