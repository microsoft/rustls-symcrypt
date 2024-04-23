//! Implementation of `KeyProvider` for rustls-symcrypt
use rustls::crypto::ring::sign;
use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::Error;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct Ring;

// TODO: Connect rustls-cng for the signing operation. For now use ring impl.

// Key provider for Ring
impl KeyProvider for Ring {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        sign::any_supported_type(&key_der)
    }
}
