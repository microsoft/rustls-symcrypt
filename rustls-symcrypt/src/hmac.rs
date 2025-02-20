//! Hmac functions. For further documentation please refer to rust_symcrypt::hmac
use rustls::crypto::hmac::{Hmac, Key, Tag};
use symcrypt::hmac::{HmacSha256State, HmacSha384State, HmacState};

// HmacShaXXX is a struct that represents either HmacSha256 or HmacSha384
//
// HmacShaXXXKey is a wrapper around HmacShaXXXState This is what needs to
// be initialized in order to run stateful operations on the SymCrypt HmacShaXXXState
//
//
//
// Impl's for the Hash trait for both HmacSha256 and HmacSha384 implement the Ruslts traits for hashing
//
// `with_key()` creates a new `Box<>'d` HmacShaXXXState via its wrapper HmacShaXXXKey. This state is needed in order to
// run stateful operations.
//
// `hash_output_len()` returns the hash output length based on the hash algorithm.
//
//
//
// Impl's for the Key trait for both HmacSha256Key and HmacSha384Key implement the Rustls trait for
// Key which is called state on the SymCrypt side.
//
// `sign()` returns a tag based on the data that is passed in.
//
// `sign_concat()` returns a tag based on the set of first, middle and last data that is passed in.
// The passed data will be appended sequentially to the HmacShaXXXState.
//
// `tag_len()` returns the tag length associated wit Hmac algorithm.

/// Structs related to HmacSha256
pub struct HmacSha256;
pub struct HmacSha256Key(HmacSha256State);

/// Structs related to HmacSha384
pub struct HmacSha384;
pub struct HmacSha384Key(HmacSha384State);

/// Impl's related to HmacSha256
impl Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        // unwrap here since rustls::hmac does not accept errors.
        Box::new(HmacSha256Key(HmacSha256State::new(key).unwrap()))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

impl Key for HmacSha256Key {
    fn sign(&self, data: &[&[u8]]) -> Tag {
        self.sign_concat(&[], data, &[])
    }

    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut new_state = self.0.clone();
        new_state.append(first);
        for d in middle {
            new_state.append(d);
        }
        new_state.append(last);

        let result = new_state.result();
        Tag::new(&result)
    }

    fn tag_len(&self) -> usize {
        32
    }
}

/// Impl's related to HmacSha384
impl Hmac for HmacSha384 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        // unwrap here since rustls::Hmac does not accept errors.
        Box::new(HmacSha384Key(HmacSha384State::new(key).unwrap()))
    }

    fn hash_output_len(&self) -> usize {
        48
    }
}

impl Key for HmacSha384Key {
    fn sign(&self, data: &[&[u8]]) -> Tag {
        self.sign_concat(&[], data, &[])
    }

    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut new_state = self.0.clone();
        new_state.append(first);
        for d in middle {
            new_state.append(d);
        }
        new_state.append(last);

        let result = new_state.result();
        Tag::new(&result)
    }

    fn tag_len(&self) -> usize {
        48
    }
}
