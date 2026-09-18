//! ML-KEM key encapsulation as a `rustls` key exchange group.
//!
//! For further documentation please refer to `symcrypt::mlkem`.
//!
//! This module is not part of the public API. ML-KEM on its own is not offered as a TLS key
//! exchange group by this provider; it exists as the post-quantum half of the hybrid groups in
//! [`crate::hybrid`]. Standalone `MLKEM768` / `MLKEM1024` groups are deferred.
//!
//! # Why this is not shaped like `ecdh`
//!
//! ML-KEM is a key encapsulation mechanism, not a Diffie-Hellman key agreement, so the two peers do
//! different things:
//!
//! - The client calls [`SupportedKxGroup::start`] and sends its **encapsulation key**.
//! - The server calls [`SupportedKxGroup::start_and_complete`] and **encapsulates** to the client's
//!   key, sending back a **ciphertext**.
//! - The client calls [`ActiveKeyExchange::complete`] on that ciphertext and **decapsulates**.
//!
//! The `peer_pub_key` argument of `complete` is therefore a ciphertext, not a public key.
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, ProtocolVersion};

use symcrypt::errors::SymCryptError;
use symcrypt::mlkem::{MlKemKey, MlKemParams};

use crate::INVALID_KEY_SHARE;

/// `MlKem` ties a `rustls::NamedGroup` to a `symcrypt::mlkem::MlKemParams`.
#[derive(Debug)]
pub(crate) struct MlKem {
    pub(crate) params: MlKemParams,
    pub(crate) group: NamedGroup,
}

/// The post-quantum half of `X25519MLKEM768` and `SECP256R1MLKEM768`.
pub(crate) static MLKEM768: &dyn SupportedKxGroup = &MlKem {
    params: MlKemParams::MlKem768,
    group: NamedGroup::MLKEM768,
};

impl SupportedKxGroup for MlKem {
    /// The client path. Generates a key pair and offers the encapsulation key as the key share.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let key = MlKemKey::generate_key_pair(self.params)
            .map_err(|e| Error::General(format!("SymCrypt ML-KEM key generation failed: {}", e)))?;
        let encapsulation_key = key.export_encapsulation_key().map_err(|e| {
            Error::General(format!(
                "SymCrypt ML-KEM encapsulation key export failed: {}",
                e
            ))
        })?;

        Ok(Box::new(KeyExchange {
            key,
            encapsulation_key,
            group: self.group,
        }))
    }

    /// The server path. `client_share` is the client's encapsulation key; encapsulate to it and
    /// return the ciphertext as this side's key share.
    ///
    /// Overriding this is mandatory, not an optimization. The default implementation in
    /// `rustls::crypto` calls `start()` then `complete()`, which is the Diffie-Hellman shape: both
    /// peers derive from each other's public keys. A KEM server must encapsulate instead. Leaving
    /// the default in place compiles cleanly and fails at runtime with mismatched secrets.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let peer_key = MlKemKey::from_encapsulation_key(self.params, client_share)
            .map_err(map_key_import_error)?;
        // Importing the client's key can fail on bad input, so that is peer misbehavior. Failing to
        // encapsulate to an already-validated key cannot be, so it must not be reported as such.
        let encapsulation = peer_key
            .encapsulate()
            .map_err(|e| Error::General(format!("SymCrypt ML-KEM encapsulation failed: {}", e)))?;

        Ok(CompletedKeyExchange {
            group: self.group,
            pub_key: encapsulation.ciphertext,
            secret: SharedSecret::from(encapsulation.shared_secret.as_bytes().as_slice()),
        })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        self.group
    }

    fn fips(&self) -> bool {
        // AUDITORS:
        // aws-lc-rs reads "FIPS-pending" as approved, on the basis that some regulatory regimes
        // (for example FedRAMP rev 5 SC-13) permit implementations in that state. We take the
        // conservative reading instead and report false until SymCrypt's CMVP status for ML-KEM is
        // confirmed.
        //
        // This costs nothing today: all key exchange groups in this provider report false, so
        // `CryptoProvider::fips()` is already false and has been since the crate shipped.
        false
    }

    /// ML-KEM is only defined for TLS 1.3 key shares.
    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// The client-side state of an in-progress ML-KEM exchange.
///
/// Holds the decapsulation key until the server's ciphertext arrives. The private key is never
/// exposed; `pub_key()` returns only the encapsulation key.
struct KeyExchange {
    key: MlKemKey,
    encapsulation_key: Vec<u8>,
    group: NamedGroup,
}

impl ActiveKeyExchange for KeyExchange {
    /// `peer_pub_key` is the server's ML-KEM **ciphertext**, not a public key. Decapsulating it
    /// with the key held here yields the shared secret.
    ///
    /// A tampered but correctly sized ciphertext does not fail here. FIPS 203 requires implicit
    /// rejection, so decapsulation succeeds with a pseudo-random secret and the handshake fails
    /// later at the transcript MAC. That is the intended behavior, not a missing check.
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let shared_secret = self.key.decapsulate(peer_pub_key).map_err(|e| match e {
            // A wrong-length ciphertext is the peer's mistake. Anything else is local (allocation,
            // or a key that cannot decapsulate, which cannot happen for a key we just generated)
            // and must not be attributed to the peer.
            SymCryptError::InvalidArgument => INVALID_KEY_SHARE,
            e => Error::General(format!("SymCrypt ML-KEM decapsulation failed: {}", e)),
        })?;

        Ok(SharedSecret::from(shared_secret.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.encapsulation_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

fn map_key_import_error(error: SymCryptError) -> Error {
    match error {
        SymCryptError::WrongKeySize | SymCryptError::InvalidBlob => INVALID_KEY_SHARE,
        error => Error::General(format!("SymCrypt ML-KEM key import failed: {}", error)),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mlkem768_round_trip() {
        // Drives the client and server paths against each other in the order rustls uses them.
        let client = MLKEM768.start().unwrap();
        assert_eq!(client.group(), NamedGroup::MLKEM768);
        assert_eq!(
            client.pub_key().len(),
            MlKemParams::MlKem768.encapsulation_key_len()
        );

        let server = MLKEM768.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(server.group, NamedGroup::MLKEM768);
        assert_eq!(server.pub_key.len(), MlKemParams::MlKem768.ciphertext_len());

        let client_secret = client.complete(&server.pub_key).unwrap();
        assert_eq!(
            client_secret.secret_bytes(),
            server.secret.secret_bytes(),
            "client and server must agree on the ML-KEM shared secret"
        );
    }

    #[test]
    fn test_mlkem768_rejects_malformed_client_share() {
        let valid_len = MlKemParams::MlKem768.encapsulation_key_len();

        for bad in [
            vec![0u8; 0],
            vec![0u8; valid_len - 1],
            vec![0u8; valid_len + 1],
        ] {
            assert_eq!(
                MLKEM768.start_and_complete(&bad).err().unwrap(),
                INVALID_KEY_SHARE,
                "a malformed client share must be reported as peer misbehavior"
            );
        }
    }

    #[test]
    fn test_mlkem_key_import_error_mapping() {
        assert_eq!(
            map_key_import_error(SymCryptError::WrongKeySize),
            INVALID_KEY_SHARE
        );
        assert_eq!(
            map_key_import_error(SymCryptError::InvalidBlob),
            INVALID_KEY_SHARE
        );
        assert!(matches!(
            map_key_import_error(SymCryptError::MemoryAllocationFailure),
            Error::General(_)
        ));
    }

    #[test]
    fn test_mlkem768_rejects_malformed_ciphertext() {
        let valid_len = MlKemParams::MlKem768.ciphertext_len();

        for bad in [
            vec![0u8; 0],
            vec![0u8; valid_len - 1],
            vec![0u8; valid_len + 1],
        ] {
            let client = MLKEM768.start().unwrap();
            assert_eq!(
                client.complete(&bad).err().unwrap(),
                INVALID_KEY_SHARE,
                "a malformed server ciphertext must be reported as peer misbehavior"
            );
        }
    }

    #[test]
    fn test_mlkem768_is_tls13_only() {
        assert!(MLKEM768.usable_for_version(ProtocolVersion::TLSv1_3));
        assert!(!MLKEM768.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(MLKEM768.ffdhe_group().is_none());
    }
}
