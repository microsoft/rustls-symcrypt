use symcrypt::ecc::{EcKey, EcKeyUsage};
use symcrypt::rsa::{RsaKey, RsaKeyUsage};



/// decode fns. 

/// ecdsa::from_pcks8
/// ecdsa::from_sec1
/// ecdsa::from_der
/// ecdsa::decode_public_key


/// rsa_decode_public_key
/// rsa::from_pcks8
/// rsa::from_pkcs1
/// rsa::from_der


pub struct RustlsEcKey(EcKey);

impl RustlsEcKey {
    pub fn from_pcks8(pcks8: &[u8]) -> Result<Self, ()> {
        // asn1 decode the pkcs8 key, use info to get ecc object
        Ok(Self::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap())
    }

    pub fn from_sec1(sec1: &[u8]) -> Result<Self, ()> {
        // asn1 decode the sec1 key, use info to get ecc object
        Ok(Self::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap())
    }

    pub fn from_der(der: &[u8]) -> Result<Self, ()> {
        // asn1 decode the der key, use info to get ecc object
        Ok(Self::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap())
    }

    pub fn decode_public_key(public_key: &[u8]) -> Result<Self, ()> {
        // asn1 decode the public key, use info to get ecc object
        Ok(Self::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap())
    }
}

pub struct RustlsRsaKey(RsaKey);

impl RustlsRsaKey {
    pub fn from_pcks8(pcks8: &[u8]) -> Result<Self, ()> {
        // asn1 decode the pkcs8 key, use info to get ecc object
        Ok(Self::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap())
    }

    pub fn from_pkcs1(pkcs1: &[u8]) -> Result<Self, ()> {
        // asn1 decode the pkcs1 key, use info to get ecc object
        Ok(Self::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap())
    }

    pub fn from_der(der: &[u8]) -> Result<Self, ()> {
        // asn1 decode the der key, use info to get ecc object
        Ok(Self::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap())
    }

    pub fn decode_public_key(public_key: &[u8]) -> Result<Self, ()> {
        // asn1 decode the public key, use info to get ecc object
        Ok(Self::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap())
    }
}


/// encode fns.
/// might have to encode ecdsa and rsa to der for the sign. 
