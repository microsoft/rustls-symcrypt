//! GCM and ChaCha functions for TLS 1.3. For further documentation please refer to rust_symcrypt::gcm and symcrypt::chacha
use crate::cipher_suites::AesGcm;
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::ConnectionTrafficSecrets;
use symcrypt::cipher::BlockCipherType;

use symcrypt::gcm::GcmExpandedKey;
const GCM_TAG_LENGTH: usize = 16;

#[cfg(feature = "chacha")]
use symcrypt::chacha::{chacha20_poly1305_decrypt_in_place, chacha20_poly1305_encrypt_in_place};
#[cfg(feature = "chacha")]
const CHACHA_TAG_LENGTH: usize = 16;
#[cfg(feature = "chacha")]
const CHACHA_KEY_LENGTH: usize = 32;

/// ChaCha for TLS 1.3.
/// ChaCha functionality will be disabled by default, in order to enable ChaCha functionality,
/// user must pass the "chacha" feature via `Cargo.toml`

/// [`Tls13ChaCha`] impls [`Tls13AeadAlgorithm`]
#[cfg(feature = "chacha")]
pub struct Tls13ChaCha;

/// [`Tls13ChaCha20Poly1305`] impls [`MessageEncrypter`] and [`MessageDecrypter`].
/// `key` is a ChaCha key and must be 32 bytes.
/// `iv` is an initialization vector that is needed to create the unique nonce.
#[cfg(feature = "chacha")]
pub struct Tls13ChaCha20Poly1305 {
    key: [u8; CHACHA_KEY_LENGTH],
    iv: Iv,
}

#[cfg(feature = "chacha")]
impl Tls13AeadAlgorithm for Tls13ChaCha {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        assert_eq!(key.as_ref().len(), CHACHA_KEY_LENGTH); // ChaCha key length must be 32 bytes.
        let mut chacha_key = [0u8; CHACHA_KEY_LENGTH];
        chacha_key[..CHACHA_KEY_LENGTH].copy_from_slice(key.as_ref());

        Box::new(Tls13ChaCha20Poly1305 {
            key: chacha_key,
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        assert_eq!(key.as_ref().len(), CHACHA_KEY_LENGTH); // ChaCha key length must be 32 bytes.
        let mut chacha_key = [0u8; CHACHA_KEY_LENGTH];
        chacha_key[..CHACHA_KEY_LENGTH].copy_from_slice(key.as_ref());

        Box::new(Tls13ChaCha20Poly1305 {
            key: chacha_key,
            iv,
        })
    }

    fn key_len(&self) -> usize {
        CHACHA_KEY_LENGTH // ChaCha key must be 32 bytes.
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

/// [`MessageEncrypter`] for ChaCha 1.3
/// the `payload` field that comes from the [`OutboundPlainMessage`] is structured to include the message which is an arbitrary length,
/// an encoding type that is 1 byte and then finally the tag which is 16 bytes.
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                       ^   ^  ^                                                   ^
///            Message (N bytes)   Encoding (1 byte)              Tag (16 bytes)
#[cfg(feature = "chacha")]
impl MessageEncrypter for Tls13ChaCha20Poly1305 {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        // Adding the size of message, the tag and encoding type to the capacity of payload vector.
        // Must create the payload this way. There is a header of 5 bytes at the front of the payload.
        // Using overridden with_capacity() will return a new payload with the header of 5 bytes set to 0 and accounted for.
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // payload will be appended via extend_from_chunks() and extend_from_slice() starting after the 5 byte buffer.
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        // Set up needed parameters for ChaCha encrypt. Must use total length of message, not including the length of
        // the 5 byte header, since that is not included in the message to be encrypted.
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls13_aad(total_len);
        let mut tag = [0u8; CHACHA_TAG_LENGTH];

        // Encrypting the payload in place. +1 is added to account for encoding type that must also be encrypted.
        // payload.as_mut() returns the slice that is indexed by 5 bytes to avoid encrypting the header.
        match chacha20_poly1305_encrypt_in_place(
            &self.key,
            &nonce.0,
            &auth_data,
            &mut payload.as_mut()[..msg.payload.len() + 1],
            &mut tag,
        ) {
            Ok(_) => {
                payload.extend_from_slice(&tag); // Add tag to the end of the payload.
                Ok(OutboundOpaqueMessage::new(
                    // Note: all TLS 1.3 application data records use TLSv1_2 (0x0303) as the legacy record
                    // protocol version, see https://www.rfc-editor.org/rfc/rfc8446#section-5.1
                    rustls::ContentType::ApplicationData,
                    rustls::ProtocolVersion::TLSv1_2,
                    payload,
                ))
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error // Using general error to propagate the SymCrypt error back to the caller
                );
                Err(rustls::Error::General(custom_error_message))
            }
        }
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHA_TAG_LENGTH
    }
}

/// [`MessageDecrypter`] for ChaCha 1.3
/// the `payload` field that comes from the [`InboundOpaqueMessage`] is structured to include the message which is an arbitrary length,
/// an encoding type that is 1 byte and then finally the tag which is 16 bytes.
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                       ^   ^  ^                                                   ^
///            Message (N bytes)   Encoding (1 byte)              Tag (16 bytes)
#[cfg(feature = "chacha")]
impl MessageDecrypter for Tls13ChaCha20Poly1305 {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut msg.payload; // This is mutable since it is a reference of BorrowedPayload
        let payload_len = payload.len(); // This length includes the message, encoding, and tag.

        // Ensure that the length is over 16 bytes or there is a decryption error.
        if payload_len < CHACHA_TAG_LENGTH {
            return Err(rustls::Error::DecryptError);
        }
        let message_length = payload_len - CHACHA_TAG_LENGTH; // getting message length, this includes the message length and the encoding type.

        // Set up needed parameters for ChaCha decrypt
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls13_aad(payload_len); // The total message including tag and encoding byte must be used for auth_data.
        let mut tag = [0u8; GCM_TAG_LENGTH];
        tag.copy_from_slice(&payload[message_length..]); // get tag

        // Decrypting the payload in place, there is no +1 here since message_length accounts for the extra byte for encoding type.
        match chacha20_poly1305_decrypt_in_place(
            &self.key,
            &nonce.0,
            &auth_data,
            &mut payload[..message_length],
            &tag,
        ) {
            Ok(_) => {
                payload.truncate(message_length);
                msg.into_tls13_unpadded_message() // Removes the optional padding of zero bytes.
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error // Using general error to propagate the SymCrypt error back to the caller
                );
                Err(rustls::Error::General(custom_error_message))
            }
        }
    }
}

/// GCM for TLS 1.3

/// [`Tls13Gcm`] impls [`Tls13AeadAlgorithm`].

/// `algo_type` represents either `Aes128Gcm` or `Aes256Gcm` which corresponds to a 16 and 32 byte key respectively.
pub struct Tls13Gcm {
    pub(crate) algo_type: AesGcm,
}

/// [`Tls13GcmState`] impls [`MessageEncrypter`] and [`MessageDecrypter`]
///
/// `key` is a rust-symcrypt::GcmExpandedKey that has expands the provided key
/// `iv` is an initialization vector that is needed to create the unique nonce.
pub struct Tls13GcmState {
    key: GcmExpandedKey,
    iv: Iv,
}

impl Tls13AeadAlgorithm for Tls13Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        // Unwrapping here, since rustls does not expect this to fail.
        // In the scenarios that GcmExpandKey would fail should result in a panic, ie: Not enough memory.
        Box::new(Tls13GcmState {
            key: GcmExpandedKey::new(key.as_ref(), BlockCipherType::AesBlock).unwrap(),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        // Unwrapping here, since rustls does not expect this to fail.
        // In the scenarios that GcmExpandKey would fail should result in a panic, ie: Not enough memory.
        Box::new(Tls13GcmState {
            key: GcmExpandedKey::new(key.as_ref(), BlockCipherType::AesBlock).unwrap(),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.algo_type.key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        match self.key_len() {
            16 => Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv }),
            32 => Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv }),
            _ => Err(UnsupportedOperationError),
        }
    }
}

/// [`MessageEncrypter`] for GCM 1.3
/// the `payload` field that comes from the [`OutboundPlainMessage`] is structured to include the message which is an arbitrary length,
/// an encoding type that is 1 byte and then finally the tag which is 16 bytes.
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                       ^   ^  ^                                                   ^
///            Message (N bytes)   Encoding (1 byte)              Tag (16 bytes)
impl MessageEncrypter for Tls13GcmState {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        // Adding the size of message, the tag and encoding type to the capacity of payload vector.
        // Must create the payload this way. There is a header of 5 bytes at the front of the payload.
        // Using overridden with_capacity() will return a new payload with the header of 5 bytes set to 0 and accounted for.
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // payload will be appended do via extend_from_chunks() and extend_from_slice() starting after the 5 byte buffer.
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        // Set up needed parameters for ChaCha encrypt, Must use total length of message, not including the length of
        // the 5 byte header, since that is not included in the message to be encrypted.
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls13_aad(total_len);
        let mut tag = [0u8; GCM_TAG_LENGTH];

        // Encrypting the payload in place. +1 is added to account for encoding type that must also be encrypted.
        // payload.as_mut() returns the slice that is indexed by 5 bytes to avoid encrypting the header. This call cannot fail.
        self.key.encrypt_in_place(
            &nonce.0,
            &auth_data,
            &mut payload.as_mut()[..msg.payload.len() + 1],
            &mut tag,
        );

        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            // Note: all TLS 1.3 application data records use TLSv1_2 (0x0303) as the legacy record
            // protocol version, see https://www.rfc-editor.org/rfc/rfc8446#section-5.1
            rustls::ContentType::ApplicationData,
            rustls::ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + GCM_TAG_LENGTH
    }
}

/// [`MessageDecrypter`] for GCM 1.3
/// the `payload` field that comes from the [`InboundOpaqueMessage`] is structured to include the message which is an arbitrary length,
/// an encoding type that is 1 byte. After the encoding byte there can be a padding of 0 or more zero bytes, and finally the tag which is 16 bytes.
/// ex : [1, 2, 3, 5, 6, 7, 8, 9, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16]
///       ^                       ^   ^  ^                                                   ^
///            Message (N bytes)   Encoding (1 byte)              Tag (16 bytes)
impl MessageDecrypter for Tls13GcmState {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut msg.payload; // payload is already mutable since it is a reference to BorrowedPayload
        let payload_len = payload.len(); // This length includes the message, encoding, and tag.
        if payload_len < GCM_TAG_LENGTH {
            return Err(rustls::Error::DecryptError);
        }
        let message_length = payload_len - GCM_TAG_LENGTH; // This includes the message length and the encoding type.

        // Set up needed parameters for GCM decrypt.
        let nonce = Nonce::new(&self.iv, seq);
        let auth_data = make_tls13_aad(payload_len); // The whole message, including encoding type and tag should be used.
        let mut tag = [0u8; GCM_TAG_LENGTH];
        tag.copy_from_slice(&payload[message_length..]); // get tag

        // Decrypting the payload in place, there is no +1 here since message_length accounts for the extra byte for encoding type.
        match self
            .key
            .decrypt_in_place(&nonce.0, &auth_data, &mut payload[..message_length], &tag)
        {
            Ok(()) => {
                payload.truncate(message_length);
                msg.into_tls13_unpadded_message() // This removes the optional padding of zero bytes.
            }
            Err(symcrypt_error) => {
                let custom_error_message = format!(
                    "SymCryptError: {}",
                    symcrypt_error // Using general error to propagate the SymCrypt error back to the caller
                );
                Err(rustls::Error::General(custom_error_message))
            }
        }
    }
}
