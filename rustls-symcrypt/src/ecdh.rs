//! EcDh functions. For further documentation please refer to rust_symcrypt::ecdh
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};

use symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};

/// KxGroup is a struct that easily ties `rustls::NamedGroup` to the `symcrypt_sys::ecurve::CurveType`.
///
/// This outlines the supported key exchange groups that are exposed by Rustls and implemented by SymCrypt.
/// Currently the only supported key exchange groups are `X25519`, `NistP38`, and `Nist256`.
#[derive(Debug)]
pub struct KxGroup {
    name: NamedGroup,
    curve_type: CurveType,
}

/// KeyExchange is a struct that defines the state for EcDh operations
///
/// the `state` field is tied to the [`EcDh`] struct from symcrypt_sys.
///
/// the `name` and `curve_type` provide access to the `rustls::NamedGroup`
/// and `symcrypt_sys::ecurve::CurveType` respectively
///
/// `pub_key` is a `Vec<u8>` that represents the public key that is tied to the [`EcDh`] state.
/// The `private_key` is not exposed.
pub struct KeyExchange {
    state: EcKey,
    name: NamedGroup,
    curve_type: CurveType,
    pub_key: Vec<u8>,
}

/// All supported KeyExchange groups.
/// ```ignore
/// SECP384R1
/// SECP256R1
/// X25519 // Enabled with the `x25519` feature
/// ```
pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    SECP384R1,
    SECP256R1,
    #[cfg(feature = "x25519")]
    X25519,
];

// Since the type trait size cannot be determined at compile time, we must use trait objects, hence the `&dyn SupportedKxGroup`
// annotation. Similarly, `KxGroup` must then also be taken as a reference.
#[cfg(feature = "x25519")]
pub const X25519: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::X25519,
    curve_type: CurveType::Curve25519,
};

pub const SECP256R1: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::secp256r1,
    curve_type: CurveType::NistP256,
};

pub const SECP384R1: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::secp384r1,
    curve_type: CurveType::NistP384,
};

/// Impl for the trait SupportedKxGroup
///
/// `start()` creates a new `symcrypt::ecc::EcKey` struct and subsequently, a new [`KeyExchange`] struct.
///
/// `name()` returns the `NamedGroup` of the current [`KeyExchange`] group.
impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange)>, Error> {
        let ec_key = EcKey::generate_key_pair(self.curve_type, EcKeyUsage::EcDh)
            .map_err(|e| Error::General(format!("SymCrypt key generation failed: {:?}", e)))?;
        let mut pub_key = ec_key
            .export_public_key()
            .map_err(|e| Error::General(format!("SymCrypt public key export failed: {:?}", e)))?;

        // Based on RFC 8446 https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2.
        // struct {
        //     uint8 legacy_form = 4;
        //     opaque X[coordinate_length];
        //     opaque Y[coordinate_length];
        // } UncompressedPointRepresentation;

        // Have to pre-append 0x04 to the first element of the vec since SymCrypt expects the caller to do so,
        // and Rustls expects the crypto library to append the 0x04.
        // X25519 does not have the legacy form requirement.
        match ec_key.get_curve_type() {
            CurveType::NistP256 | CurveType::NistP384 => {
                pub_key.insert(0, 0x04); // Prepend legacy byte to public key
            }

            CurveType::Curve25519 => {
                // Curve25519 curve does not require public key prepending
            }

            // Not possible to reach this branch since NistP521 struct is not implemented for key exchange
            CurveType::NistP521 => {
                return Err(Error::General(
                    "NistP521 is not supported for key exchange".to_string(),
                ));
            }
        }

        Ok(Box::new(KeyExchange {
            state: ec_key,
            name: self.name,
            curve_type: self.curve_type,
            pub_key,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.name
    }
}

/// Impl for the trait for `ActiveKeyExchange` in order to do stateful operations on the [`EcDh`] state.
///
/// `complete()` takes in a `peer_pub_key` and creates a secondary [`EcDh`] struct in order to generate the secret agreement.
///
/// Errors from SymCrypt will be propagated back to the user as a `rustls::Error::GeneralError`.
///
/// `pub_key()` will return a ref to the `Vec<u8>` that holds the public key.
///
/// `group()` will return the [`NamedGroup`] of the [`KeyExchange`]
impl ActiveKeyExchange for KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let new_peer_pub_key = match self.curve_type {
            CurveType::NistP256 | CurveType::NistP384 => {
                // If curve type is NistP256 or NistP384 or NistP521 remove the first byte
                // Based on RFC 8446 https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2.
                // struct {
                //     uint8 legacy_form = 4;
                //     opaque X[coordinate_length];
                //     opaque Y[coordinate_length];
                // } UncompressedPointRepresentation;

                // Have to remove the legacy_form 0x04. Rustls does not do this for us, and SymCrypt
                // only expects the X and Y coordinates.

                if peer_pub_key.starts_with(&[0x04]) {
                    &peer_pub_key[1..] // Return a slice starting from the second byte
                } else {
                    return Err(Error::General("Invalid public key".to_string()));
                }
            }

            CurveType::Curve25519 => {
                // Do not remove first byte for Curve22519, since Curve25519 only has the x and y coordinates.
                peer_pub_key
            }

            CurveType::NistP521 => {
                return Err(Error::General(
                    "NistP521 is not supported for key exchange".to_string(),
                ));
            }
        };

        let peer_ecdh =
            match EcKey::set_public_key(self.curve_type, new_peer_pub_key, EcKeyUsage::EcDh) {
                Ok(peer_ecdh) => peer_ecdh,
                Err(symcrypt_error) => {
                    let custom_error_message = format!(
                        "SymCryptError: {}",
                        symcrypt_error // Using general error to propagate the SymCrypt error back to the caller
                    );
                    return Err(Error::General(custom_error_message));
                }
            };

        let secret_agreement = match EcKey::ecdh_secret_agreement(&self.state, peer_ecdh) {
            Ok(secret_agreement) => secret_agreement,
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error // Using general error to propagate the SymCrypt error back to the caller
                );
                return Err(Error::General(custom_error_message));
            }
        };
        Ok(SharedSecret::from(secret_agreement.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}
