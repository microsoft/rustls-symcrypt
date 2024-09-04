use core::hash;

use rustls::crypto::hmac::Key;
use symcrypt::ecc::{EcKey, EcKeyUsage, CurveType};
use symcrypt::hash::{sha256, sha384, sha512, HashAlgorithm};
use webpki::alg_id::{self};
use webpki::ring as webpki_algs;
use rustls::{SignatureScheme, SupportedCipherSuite};
use rustls::crypto::{
    CryptoProvider, GetRandomFailed, SecureRandom, SupportedKxGroup, WebPkiSupportedAlgorithms
};
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use symcrypt::rsa::RsaKey;
use symcrypt::rsa::RsaKeyUsage;


use rasn::der;
use rasn::types::Integer;
use rasn::AsnType;
use num_bigint::BigUint;


#[derive(Debug, AsnType, rasn::Decode)]
struct RsaPublicKey {
    modulus: Integer,
    exponent: Integer,
}


fn extract_rsa_components(encoded: &[u8]) -> (Integer, Integer) {
    // Decode the DER-encoded RSA public key
    let rsa_public_key: RsaPublicKey = der::decode(encoded).unwrap();

    // Extract modulus and exponent
    let modulus = rsa_public_key.modulus;
    let exponent = rsa_public_key.exponent;

    (modulus, exponent)
}

// fn integer_to_be_bytes(integer: Integer) -> Vec<u8> {
//     // Convert `rasn::types::Integer` to `num_bigint::BigUint`
//     let biguint = BigUint::from_bytes_be(&integer.to_bytes_be());

//     // Convert `BigUint` to big-endian byte array
//     biguint.to_bytes_be()
// }



/// Review
// 
// if our P1 is microsoft customers, we should want to have it disabled to comply with SDL.
// If not we should enable it since it's much faster than NIstP256 and NistP384.
// Most people will high prio 25519 in their list of supported curves, by disabling we are forcing hello retry request
// we should move 25519 higher than p256 and p384 and disable by default for msft SDL. Make documentation to note that it's 
// disabled by default for SDL compliance, and opensource should enable it for higher speeds.


// TODO: Switch to symcrypt for verification
pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        // webpki_algs::ECDSA_P256_SHA256,
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384, 
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        // ED25519,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                ECDSA_P384_SHA384,
                ECDSA_P256_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                ECDSA_P256_SHA256,
                ECDSA_P384_SHA256,
            ],
        ),
        // (SignatureScheme::ED25519, &[webpki_algs::ED25519]), // Disable this since we dont support ED25519. 
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[RSA_PSS_SHA512]
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[RSA_PSS_SHA384],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[RSA_PSS_SHA256],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[RSA_PKCS1_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[RSA_PKCS1_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[RSA_PKCS1_SHA256],
        ),
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
    hash_algorithm: HashAlgorithm
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
    key_type: KeyType::Ecc(Ecc{curve: CurveType::NistP256}),
};

/// ECDSA signatures using the P-256 curve and SHA-384.
pub static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    hasher: hash_sha384,
    key_type: KeyType::Ecc(Ecc{curve: CurveType::NistP256}),
};

/// ECDSA signatures using the P-384 curve and SHA-256.
pub static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    hasher: hash_sha256,
    key_type: KeyType::Ecc(Ecc{curve: CurveType::NistP384}),
};

/// ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    hasher: hash_sha384,
    key_type: KeyType::Ecc(Ecc{curve: CurveType::NistP384}),
};

/// RSA PKCS1 signatures using SHA-256.
pub static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
    hasher: hash_sha256,
    key_type: KeyType::RsaPkcs1(RsaPkcs1{hash_algorithm: HashAlgorithm::Sha256}),
};

/// RSA PKCS1 signatures using SHA-384.
pub static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    hasher: hash_sha384,
    key_type: KeyType::RsaPkcs1(RsaPkcs1{hash_algorithm: HashAlgorithm::Sha384}),
};

/// RSA PKCS1 signatures using SHA-512.
pub static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
    hasher: hash_sha512,
    key_type: KeyType::RsaPkcs1(RsaPkcs1{hash_algorithm: HashAlgorithm::Sha512}),
};

/// RSA PSS signatures using SHA-256.
pub static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
    hasher: hash_sha256,
    key_type: KeyType::RsaPss(RsaPss{hash_algorithm: HashAlgorithm::Sha256, salt_length: 32}),
};

/// RSA PSS signatures using SHA-384.
pub static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
    hasher: hash_sha384,
    key_type: KeyType::RsaPss(RsaPss{hash_algorithm: HashAlgorithm::Sha384, salt_length: 48}),
};

/// RSA PSS signatures using SHA-256.
pub static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &SymCryptAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
    hasher: hash_sha512,
    key_type: KeyType::RsaPss(RsaPss{hash_algorithm: HashAlgorithm::Sha512, salt_length: 64}),
};


#[derive(Debug)]
struct SymCryptAlgorithm {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    hasher: fn(&[u8]) -> Vec<u8>,
    key_type: KeyType,
}

impl SignatureVerificationAlgorithm for SymCryptAlgorithm {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        match &self.key_type {
            KeyType::Ecc(ecc) => {

                println!("ECC");
                // parse the public key to get the required decoding 
                // decode the signature? 
                let ec_key = EcKey::set_public_key(ecc.curve, public_key, EcKeyUsage::EcDsa).unwrap();
                let hashed_message = (self.hasher)(message);
                ec_key.ecdsa_verify(&signature, &hashed_message).map_err(|_| InvalidSignature)
            }
            KeyType::RsaPkcs1(rsa_pkcs1) => {

                println!("PKCS1");
                let (modulus, exponent) = extract_rsa_components(public_key);
                // let be_modulus = integer_to_be_bytes(modulus);
                // let be_exponent = integer_to_be_bytes(exponent);

                let rsa_key = RsaKey::set_public_key(&(modulus.to_bytes_be()).1, &(exponent.to_bytes_be()).1, RsaKeyUsage::SignAndEncrypt).unwrap();
                let hashed_message = (self.hasher)(message);
                rsa_key.pkcs1_verify(&hashed_message, signature, rsa_pkcs1.hash_algorithm).map_err(|_| InvalidSignature)
            }
            KeyType::RsaPss(rsa_pss) => {
                // parse the public key to get the required decoding 
                println!("PSS");
                let (modulus, exponent) = extract_rsa_components(public_key);
                // let be_modulus = integer_to_be_bytes(modulus);
                // let be_exponent = integer_to_be_bytes(exponent);

                let rsa_key = RsaKey::set_public_key(&(modulus.to_bytes_be()).1, &(exponent.to_bytes_be()).1, RsaKeyUsage::SignAndEncrypt).unwrap();
                let hashed_message = (self.hasher)(message);
                rsa_key.pss_verify(&hashed_message, signature, rsa_pss.hash_algorithm, rsa_pss.salt_length as usize).map_err(|_| InvalidSignature)
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
        // For now, leave fips return as always false. 
        // TODO: investigate fips flag in symcrypt.
        false
    }
}
