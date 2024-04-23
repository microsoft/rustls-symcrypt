//! GCM and ChaCha functions for TLS 1.2. For further documentation please refer to rust_symcrypt::gcm and symcrypt::chacha
use crate::cipher_suites::AesGcm;
use rustls::crypto::cipher::{
    make_tls12_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape,
    MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage,
    PrefixedPayload, Tls12AeadAlgorithm, UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, Error};
use symcrypt::block_ciphers::BlockCipherType;

use symcrypt::gcm::GcmExpandedKey;
const GCM_FULL_NONCE_LENGTH: usize = 12;
const GCM_EXPLICIT_NONCE_LENGTH: usize = 8;
const GCM_IMPLICIT_NONCE_LENGTH: usize = 4;
const GCM_TAG_LENGTH: usize = 16;

#[cfg(feature = "chacha")]
use symcrypt::chacha::{chacha20_poly1305_decrypt_in_place, chacha20_poly1305_encrypt_in_place};
#[cfg(feature = "chacha")]
const CHACHA_TAG_LENGTH: usize = 16;
#[cfg(feature = "chacha")]
const CHAHCA_NONCE_LENGTH: usize = 12;
#[cfg(feature = "chacha")]
const CHACHA_KEY_LENGTH: usize = 32;

/// ChaCha for TLS 1.2
/// ChaCha functionality will be disabled by default, in order to enable ChaCha functionality,
/// user must pass the "chacha" feature via `Cargo.toml`

/// `Tls12ChaCha` impls `Tls12AeadAlgorithm`.
#[cfg(feature = "chacha")]
pub struct Tls12ChaCha;

/// `TLs12ChaCha20Poly1305` impls `MessageEncrypter` and `MessageDecrypter`
/// `key` is a ChaCha key and must be 32 bytes long.
/// `iv` is an initialization vector that is needed to create the unique nonce.
#[cfg(feature = "chacha")]
pub struct Tls12ChaCha20Poly1305 {
    key: [u8; CHACHA_KEY_LENGTH],
    iv: Iv,
}

#[cfg(feature = "chacha")]
impl Tls12AeadAlgorithm for Tls12ChaCha {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        assert_eq!(key.as_ref().len(), CHACHA_KEY_LENGTH); // ChaCha key length must be 32 bytes.

        let mut chacha_key = [0u8; CHACHA_KEY_LENGTH];
        chacha_key[..CHACHA_KEY_LENGTH].copy_from_slice(key.as_ref());

        Box::new(Tls12ChaCha20Poly1305 {
            key: chacha_key,
            iv: Iv::copy(iv),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        assert_eq!(key.as_ref().len(), CHACHA_KEY_LENGTH); // ChaCha key length must be 32 bytes.

        let mut chacha_key = [0u8; CHACHA_KEY_LENGTH];
        chacha_key[..CHACHA_KEY_LENGTH].copy_from_slice(key.as_ref());

        Box::new(Tls12ChaCha20Poly1305 {
            key: chacha_key,
            iv: Iv::copy(iv),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: CHACHA_KEY_LENGTH, // ChaCha key must be 32 bytes.
            fixed_iv_len: CHAHCA_NONCE_LENGTH,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        assert_eq!(CHAHCA_NONCE_LENGTH, iv.len()); // Nonce length must be 12 for ChaCha
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv[..].try_into().unwrap()),
        })
    }
}

/// `MessageEncrypter` for ChaCha 1.2
/// the `payload` field that comes from the `OutboundPlainMessage` is structured to include the message which is an arbitrary length,
/// and  the tag which is 16 bytes.
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                        ^  ^                                                   ^
///      Message (N bytes)                              Tag (16 bytes)
#[cfg(feature = "chacha")]
impl MessageEncrypter for Tls12ChaCha20Poly1305 {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        // Adding the size of message, the tag and encoding type to the capacity of payload vector.
        // Must create the payload this way. There is a header of 5 bytes at the front of the payload.
        // Using overridden with_capacity() will return a new payload with the header of 5 bytes set to 0 and accounted for.
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // payload will be appended do via extend_from_chunks() starting after the 5 byte buffer.
        payload.extend_from_chunks(&msg.payload);

        // Set up needed parameters for ChaCha encrypt.
        let mut tag = [0u8; CHACHA_TAG_LENGTH];
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        // ChaCha Encrypt in place, only the message from the payload will be encrypted.
        // payload.as_mut() returns the slice that is indexed by 5 bytes to avoid encrypting the header.
        match chacha20_poly1305_encrypt_in_place(
            &self.key,
            &nonce.0,
            &auth_data,
            &mut payload.as_mut()[..msg.payload.len()],
            &mut tag,
        ) {
            Ok(_) => {
                payload.extend_from_slice(&tag); // Add tag to the end of the payload.
                Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error.to_string() // Using general error to propagate the SymCrypt error back to the caller.
                );
                return Err(Error::General(custom_error_message));
            }
        }
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHA_TAG_LENGTH
    }
}

/// `MessageDecrypter` for ChaCha 1.2
/// the `payload` field that comes from the `InboundOpaqueMessage` is structured to include the message which is an arbitrary length,
/// and  the tag which is 16 bytes.
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                        ^  ^                                                   ^
///      Message (N bytes)                              Tag (16 bytes)
#[cfg(feature = "chacha")]
impl MessageDecrypter for Tls12ChaCha20Poly1305 {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload; // payload is already mutable since it is a reference to [`BorrowedPayload`]
        let payload_len = payload.len(); // This length includes the message and the tag.
        if payload_len < CHACHA_TAG_LENGTH {
            return Err(Error::DecryptError);
        }
        let message_len = payload_len - CHACHA_TAG_LENGTH; // This length is only the message and does not include tag.

        // Set up needed parameters for ChaCha decrypt
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls12_aad(seq, msg.typ, msg.version, message_len);
        let mut tag = [0u8; CHACHA_TAG_LENGTH];
        tag.copy_from_slice(&payload[message_len..]); // get the tag

        // Decrypting the payload in place, only the message from the payload will be decrypted.
        match chacha20_poly1305_decrypt_in_place(
            &self.key,
            &nonce.0,
            &auth_data,
            &mut payload[..message_len],
            &tag,
        ) {
            Ok(_) => {
                payload.truncate(message_len);
                Ok(msg.into_plain_message())
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error.to_string() // Using general error to propagate the SymCrypt error back to the caller
                );
                return Err(Error::General(custom_error_message));
            }
        }
    }
}

/// GCM 1.2
/// Tls12Gcm impls [`Tls12AeadAlgorithm`].

/// `algo_type` represents either `Aes128Gcm` or `Aes256Gcm` which corresponds to a 16 and 32 byte key respectively.
pub struct Tls12Gcm {
    pub(crate) algo_type: AesGcm,
}

/// Gcm12Decrypt impls [`MessageDecrypter`]
/// `key` is a [`GcmExpandedKey`] which takes in a key, and block type to return a Pin<Box<>>'d expanded key.
/// The only supported block type is AES.
/// `iv` is an implicit Iv that must be 4 bytes.
pub struct Gcm12Decrypt {
    key: GcmExpandedKey,
    iv: [u8; GCM_IMPLICIT_NONCE_LENGTH],
}

/// Gcm12Encrypt impls [`MessageEncrypter`]
/// `key` is a [`GcmExpandedKey`] which takes in a key, and block type to return a Pin<Box<>>'d expanded key.
/// The only supported block type is AES.
/// `full_iv` includes both the implicit and the explicit iv.
pub struct Gcm12Encrypt {
    key: GcmExpandedKey,
    full_iv: [u8; GCM_FULL_NONCE_LENGTH],
}

impl Tls12AeadAlgorithm for Tls12Gcm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        assert_eq!(iv.len(), GCM_IMPLICIT_NONCE_LENGTH);
        assert_eq!(extra.len(), GCM_EXPLICIT_NONCE_LENGTH);
        let mut full_iv = [0u8; GCM_FULL_NONCE_LENGTH];
        full_iv[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(iv);
        full_iv[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(extra);

        // Unwrapping here, since rustls does not expect this to fail.
        // In the scenarios that GcmExpandKey would fail should result in a panic, ie: Not enough memory.
        Box::new(Gcm12Encrypt {
            key: GcmExpandedKey::new(key.as_ref(), BlockCipherType::AesBlock).unwrap(),
            full_iv: full_iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        assert_eq!(iv.len(), GCM_IMPLICIT_NONCE_LENGTH);
        let mut implicit_iv = [0u8; GCM_IMPLICIT_NONCE_LENGTH];
        implicit_iv.copy_from_slice(iv);

        // Unwrapping here, since rustls does not expect this to fail.
        // In the scenarios that GcmExpandKey would fail should result in a panic, ie: Not enough memory.
        Box::new(Gcm12Decrypt {
            key: GcmExpandedKey::new(key.as_ref(), BlockCipherType::AesBlock).unwrap(),
            iv: implicit_iv,
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.algo_type.key_size(), // Can be either 16 or 32
            fixed_iv_len: GCM_IMPLICIT_NONCE_LENGTH,
            explicit_nonce_len: GCM_EXPLICIT_NONCE_LENGTH,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let mut gcm_iv = [0; GCM_FULL_NONCE_LENGTH];
        gcm_iv[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(iv);
        gcm_iv[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(explicit);

        match self.algo_type.key_size() {
            16 => Ok(ConnectionTrafficSecrets::Aes128Gcm {
                key: key,
                iv: Iv::new(gcm_iv),
            }),
            32 => Ok(ConnectionTrafficSecrets::Aes256Gcm {
                key: key,
                iv: Iv::new(gcm_iv),
            }),
            _ => Err(UnsupportedOperationError),
        }
    }
}

/// [`MessageEncrypter`] for  Gcm 1.2
/// the `payload` field that comes from the [`OutboundPlainMessage`] is structured to include the explicit iv which is 8 bytes,
/// the message which is an arbitrary length, and  the tag which is 16 bytes.
/// ex : [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                    ^  ^                        ^  ^                                                   ^
///       Explicit Iv (8 bytes)       Message (N bytes)                                  Tag (16 bytes)
impl MessageEncrypter for Gcm12Encrypt {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        // Adding the size of message, the tag and encoding type to the capacity of payload vector.
        // Must create the payload this way. There is a header of 5 bytes at the front of the payload.
        // Using overridden with_capacity() will return a new payload with the header of 5 bytes set to 0 and accounted for.
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // Construct the payload
        let nonce = Nonce::new(&Iv::copy(&self.full_iv), seq);
        payload.extend_from_slice(&nonce.0[GCM_IMPLICIT_NONCE_LENGTH..]);
        payload.extend_from_chunks(&msg.payload);

        let mut tag = [0u8; GCM_TAG_LENGTH];
        let auth_data = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        // Encrypting the payload in place, only the message from the payload will be encrypted, explicit iv will not be encrypted.
        // This call cannot fail.
        self.key.encrypt_in_place(
            &nonce.0,
            &auth_data,
            &mut payload.as_mut()
                [GCM_EXPLICIT_NONCE_LENGTH..(msg.payload.len() + GCM_EXPLICIT_NONCE_LENGTH)],
            // adding the gcm_explicit_nonce_length to account for shifting 8 bytes
            &mut tag,
        );
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LENGTH + GCM_TAG_LENGTH
    }
}

/// [`MessageDecrypter`] for  Gcm 1.2
/// the `payload` field that comes from the [`InboundOpaqueMessage`] is structured to include the explicit iv which is 8 bytes,
/// the message which is an arbitrary length, and  the tag which is 16 bytes.
/// ex : [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                    ^  ^                        ^  ^                                                   ^
///       Explicit Iv (8 bytes)       Message (N bytes)                                  Tag (16 bytes)
impl MessageDecrypter for Gcm12Decrypt {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload; // payload is already mutable since it is a reference to [`BorrowedPayload`]
        let payload_len = payload.len(); // This length includes the explicit iv, message and tag
        if payload_len < GCM_TAG_LENGTH + GCM_EXPLICIT_NONCE_LENGTH {
            return Err(Error::DecryptError);
        }

        // Construct nonce, the first 4 bytes of nonce will be the the implicit iv, the last 8 bytes will be the explicit iv. The explicit
        // iv is taken from the first 8 bytes of the payload. The explicit iv will not be encrypted.
        let mut nonce = [0u8; GCM_FULL_NONCE_LENGTH];
        nonce[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(&self.iv);
        nonce[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(&payload[..GCM_EXPLICIT_NONCE_LENGTH]);

        // Set up needed parameters for Gcm decrypt
        let mut tag = [0u8; GCM_TAG_LENGTH];
        tag.copy_from_slice(&payload[payload_len - GCM_TAG_LENGTH..]);
        let auth_data = make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            payload_len - GCM_TAG_LENGTH - GCM_EXPLICIT_NONCE_LENGTH,
        );

        // Decrypting the payload in place, only the message from the payload will be decrypted, explicit iv will not be decrypted.
        match self.key.decrypt_in_place(
            &nonce,
            &auth_data,
            &mut payload[GCM_EXPLICIT_NONCE_LENGTH..payload_len - GCM_TAG_LENGTH],
            &tag,
        ) {
            Ok(()) => {
                // copy bytes from the [GCM_EXPLICIT_NONCE_LENTH..] to end of array, starting destination is 0 index.
                // This overwrites the the first 8 bytes that were previously the explicit nonce.
                payload.copy_within(GCM_EXPLICIT_NONCE_LENGTH..(payload_len - GCM_TAG_LENGTH), 0);

                // Remove the last 8 bytes since they are now garbage.
                // This work around is needed because rustls wraps the payload ( which is just an array ) behind
                // a BorrowedPayload type, which only exposes truncate as a field, and hides many methods like new() pop() etc.
                payload.truncate(payload_len - (GCM_EXPLICIT_NONCE_LENGTH + GCM_TAG_LENGTH));

                Ok(msg.into_plain_message())
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error.to_string() // Using general error to propagate the SymCrypt error back to the caller
                );
                return Err(Error::General(custom_error_message));
            }
        }
    }
}
