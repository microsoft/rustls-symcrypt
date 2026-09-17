//! Hybrid post-quantum key exchange groups.
//!
//! A hybrid group runs a classical exchange and a post-quantum KEM in parallel and concatenates
//! both key shares and both secrets. TLS then derives from the concatenation, so the connection is
//! secure if *either* half is.
//!
//! The layout logic here mirrors `rustls::crypto::aws_lc_rs::pq::hybrid`, which is `pub(crate)`
//! upstream and therefore cannot be reused by an out-of-tree provider. Keeping it byte-compatible
//! matters: a provider that concatenates in a different order still handshakes with itself and
//! fails only against real peers.
use crate::ecdh::{SECP256R1, X25519};
use crate::mlkem::MLKEM768;
use crate::INVALID_KEY_SHARE;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, ProtocolVersion};

/// Length of an X25519 public key.
const X25519_LEN: usize = 32;
/// Length of an uncompressed secp256r1 point, including the `0x04` legacy byte.
const SECP256R1_LEN: usize = 65;
/// Length of an ML-KEM-768 ciphertext, which is the server's post-quantum share.
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// Length of an ML-KEM-768 encapsulation key, which is the client's post-quantum share.
const MLKEM768_ENCAP_LEN: usize = 1184;

/// This is the [X25519MLKEM768] key exchange, code point `0x11ec`.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
pub static X25519MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    classical: X25519,
    post_quantum: MLKEM768,
    name: NamedGroup::X25519MLKEM768,
    layout: Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

/// This is the [SECP256R1MLKEM768] key exchange, code point `0x11eb`.
///
/// [SECP256R1MLKEM768]: <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
pub static SECP256R1MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    classical: SECP256R1,
    post_quantum: MLKEM768,
    name: NamedGroup::secp256r1MLKEM768,
    layout: Layout {
        classical_share_len: SECP256R1_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        // Not a copy-paste slip. SECP256R1MLKEM768 puts the classical element first while
        // X25519MLKEM768 puts it second; the two drafts simply disagree. Getting this wrong
        // produces silently wrong key material that only shows up as a decrypt failure against a
        // real peer, which is why each group has its own layout test below.
        post_quantum_first: false,
    },
};

/// A generalization of hybrid key exchange, pairing a classical group with a post-quantum KEM.
#[derive(Debug)]
struct Hybrid {
    classical: &'static dyn SupportedKxGroup,
    post_quantum: &'static dyn SupportedKxGroup,
    name: NamedGroup,
    layout: Layout,
}

impl SupportedKxGroup for Hybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = self.classical.start()?;
        let post_quantum = self.post_quantum.start()?;

        let combined_pub_key = self
            .layout
            .concat(post_quantum.pub_key(), classical.pub_key());

        Ok(Box::new(ActiveHybrid {
            classical,
            post_quantum,
            name: self.name,
            layout: self.layout,
            combined_pub_key,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (post_quantum_share, classical_share) = self
            .layout
            .split_received_client_share(client_share)
            .ok_or(INVALID_KEY_SHARE)?;

        let classical = self.classical.start_and_complete(classical_share)?;
        let post_quantum = self.post_quantum.start_and_complete(post_quantum_share)?;

        let combined_pub_key = self
            .layout
            .concat(&post_quantum.pub_key, &classical.pub_key);
        let secret = self.layout.concat(
            post_quantum.secret.secret_bytes(),
            classical.secret.secret_bytes(),
        );

        Ok(CompletedKeyExchange {
            group: self.name,
            pub_key: combined_pub_key,
            secret: SharedSecret::from(secret),
        })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn fips(&self) -> bool {
        // Per SP800-56C rev 2, a hybrid secret Z' = Z || T is approved on the strength of the
        // element that appears *first*, which is exactly what `post_quantum_first` encodes. NIST
        // plans to allow both orders (<https://csrc.nist.gov/pubs/sp/800/227/ipd>), but until then
        // we follow the current text.
        //
        // Both arms return false today: the ML-KEM group reports false by decision (see
        // `crate::mlkem`), and no classical group in this provider overrides the rustls default of
        // false either.
        match self.layout.post_quantum_first {
            true => self.post_quantum.fips(),
            false => self.classical.fips(),
        }
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// The state of an in-progress hybrid exchange, holding both halves.
struct ActiveHybrid {
    classical: Box<dyn ActiveKeyExchange>,
    post_quantum: Box<dyn ActiveKeyExchange>,
    name: NamedGroup,
    layout: Layout,
    combined_pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveHybrid {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let (post_quantum_share, classical_share) = self
            .layout
            .split_received_server_share(peer_pub_key)
            .ok_or(INVALID_KEY_SHARE)?;

        let classical = self.classical.complete(classical_share)?;
        let post_quantum = self.post_quantum.complete(post_quantum_share)?;

        let secret = self
            .layout
            .concat(post_quantum.secret_bytes(), classical.secret_bytes());
        Ok(SharedSecret::from(secret))
    }

    /// Lets the classical half be offered and selected on its own.
    ///
    /// This is an optimization, not a correctness requirement: rustls states that "There is no
    /// requirement [to implement this]. It only enables an optimization". Without it a
    /// classical-only server sends a HelloRetryRequest and the handshake still completes, one round
    /// trip slower. Implemented for parity with aws-lc-rs.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    /// Called when the server selected the classical component alone, so only that half completes.
    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

/// How a hybrid group lays its two components out on the wire and in the derived secret.
#[derive(Clone, Copy, Debug)]
struct Layout {
    /// Length of the classical key share.
    classical_share_len: usize,

    /// Length of the post-quantum key share sent by the client, an encapsulation key.
    post_quantum_client_share_len: usize,

    /// Length of the post-quantum key share sent by the server, a ciphertext.
    post_quantum_server_share_len: usize,

    /// Whether the post-quantum element comes first in shares and secrets.
    ///
    /// True for `X25519MLKEM768`, false for `SECP256R1MLKEM768`.
    post_quantum_first: bool,
}

impl Layout {
    fn split_received_client_share<'a>(&self, share: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        self.split(share, self.post_quantum_client_share_len)
    }

    fn split_received_server_share<'a>(&self, share: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        self.split(share, self.post_quantum_server_share_len)
    }

    /// Returns the post-quantum and classical components of a key share, in that order,
    /// or `None` if the share is not exactly the expected length.
    fn split<'a>(
        &self,
        share: &'a [u8],
        post_quantum_share_len: usize,
    ) -> Option<(&'a [u8], &'a [u8])> {
        if share.len() != self.classical_share_len + post_quantum_share_len {
            return None;
        }

        Some(match self.post_quantum_first {
            true => share.split_at(post_quantum_share_len),
            false => {
                let (classical, post_quantum) = share.split_at(self.classical_share_len);
                (post_quantum, classical)
            }
        })
    }

    fn concat(&self, post_quantum: &[u8], classical: &[u8]) -> Vec<u8> {
        match self.post_quantum_first {
            true => [post_quantum, classical].concat(),
            false => [classical, post_quantum].concat(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use symcrypt::mlkem::SHARED_SECRET_LEN;

    /// Drives a full client/server hybrid exchange through the same calls rustls makes.
    fn round_trip(group: &'static dyn SupportedKxGroup, expected_classical: NamedGroup) {
        let client = group.start().unwrap();
        assert_eq!(client.group(), group.name());

        // The client offers the classical half separately so a classical-only server can pick it
        // without a HelloRetryRequest.
        let (classical_group, classical_share) = client.hybrid_component().unwrap();
        assert_eq!(classical_group, expected_classical);
        assert!(
            client.pub_key().ends_with(classical_share)
                || client.pub_key().starts_with(classical_share)
        );

        let server = group.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(server.group, group.name());

        let client_secret = client.complete(&server.pub_key).unwrap();
        assert_eq!(
            client_secret.secret_bytes(),
            server.secret.secret_bytes(),
            "client and server must agree on the hybrid secret"
        );
        assert_eq!(
            client_secret.secret_bytes().len(),
            SHARED_SECRET_LEN + 32,
            "the hybrid secret is the ML-KEM secret concatenated with the classical one"
        );
    }

    #[test]
    fn test_x25519_mlkem768_round_trip() {
        round_trip(X25519MLKEM768, NamedGroup::X25519);
    }

    #[test]
    fn test_secp256r1_mlkem768_round_trip() {
        round_trip(SECP256R1MLKEM768, NamedGroup::secp256r1);
    }

    /// The wire-format trap from the draft: the two groups order their components differently.
    /// Asserting the concrete byte offsets is the only way to catch a copied layout.
    #[test]
    fn test_share_layouts_differ_between_groups() {
        let x25519 = X25519MLKEM768.start().unwrap();
        let (_, classical) = x25519.hybrid_component().unwrap();
        assert_eq!(x25519.pub_key().len(), MLKEM768_ENCAP_LEN + X25519_LEN);
        assert_eq!(
            &x25519.pub_key()[MLKEM768_ENCAP_LEN..],
            classical,
            "X25519MLKEM768 puts the post-quantum share first"
        );

        let p256 = SECP256R1MLKEM768.start().unwrap();
        let (_, classical) = p256.hybrid_component().unwrap();
        assert_eq!(p256.pub_key().len(), MLKEM768_ENCAP_LEN + SECP256R1_LEN);
        assert_eq!(
            &p256.pub_key()[..SECP256R1_LEN],
            classical,
            "SECP256R1MLKEM768 puts the classical share first"
        );
        assert_eq!(
            p256.pub_key()[0],
            0x04,
            "the secp256r1 share keeps its uncompressed-point legacy byte"
        );
    }

    /// The server may select only the classical component, in which case the client must complete
    /// through `complete_hybrid_component` rather than `complete`.
    #[test]
    fn test_server_chooses_classical_component() {
        for (group, classical) in [(X25519MLKEM768, X25519), (SECP256R1MLKEM768, SECP256R1)] {
            let client = group.start().unwrap();
            let (offered_group, offered_share) = client.hybrid_component().unwrap();
            assert_eq!(offered_group, classical.name());

            // A classical-only server sees just the hybrid_component share.
            let server = classical.start_and_complete(offered_share).unwrap();

            let client_secret = client.complete_hybrid_component(&server.pub_key).unwrap();
            assert_eq!(
                client_secret.secret_bytes(),
                server.secret.secret_bytes(),
                "the classical-only fallback must still agree"
            );
        }
    }

    #[test]
    fn test_malformed_client_share_is_peer_misbehavior() {
        for group in [X25519MLKEM768, SECP256R1MLKEM768] {
            let valid_len = group.start().unwrap().pub_key().len();

            for bad in [
                vec![0u8; 0],
                vec![0u8; valid_len - 1],
                vec![0u8; valid_len + 1],
            ] {
                assert_eq!(
                    group.start_and_complete(&bad).err().unwrap(),
                    INVALID_KEY_SHARE
                );
            }
        }
    }

    #[test]
    fn test_malformed_server_share_is_peer_misbehavior() {
        for group in [X25519MLKEM768, SECP256R1MLKEM768] {
            // The server's share is a ciphertext plus a classical share, which is shorter than the
            // client's share, so lengths cannot be reused between directions.
            let client = group.start().unwrap();
            let valid_len = group
                .start_and_complete(client.pub_key())
                .unwrap()
                .pub_key
                .len();

            for bad in [
                vec![0u8; 0],
                vec![0u8; valid_len - 1],
                vec![0u8; valid_len + 1],
            ] {
                let client = group.start().unwrap();
                assert_eq!(client.complete(&bad).err().unwrap(), INVALID_KEY_SHARE);
            }
        }
    }

    #[test]
    fn test_malformed_classical_components_are_peer_misbehavior() {
        for group in [X25519MLKEM768, SECP256R1MLKEM768] {
            let client = group.start().unwrap();
            let mut malformed_client_share = client.pub_key().to_vec();
            match group.name() {
                NamedGroup::X25519MLKEM768 => {
                    malformed_client_share[MLKEM768_ENCAP_LEN..].fill(0);
                }
                NamedGroup::secp256r1MLKEM768 => {
                    malformed_client_share[..SECP256R1_LEN].fill(0);
                    malformed_client_share[0] = 0x04;
                }
                _ => unreachable!(),
            }
            assert_eq!(
                group
                    .start_and_complete(&malformed_client_share)
                    .err()
                    .unwrap(),
                INVALID_KEY_SHARE
            );

            let client = group.start().unwrap();
            let mut malformed_server_share =
                group.start_and_complete(client.pub_key()).unwrap().pub_key;
            match group.name() {
                NamedGroup::X25519MLKEM768 => {
                    malformed_server_share[MLKEM768_CIPHERTEXT_LEN..].fill(0);
                }
                NamedGroup::secp256r1MLKEM768 => {
                    malformed_server_share[..SECP256R1_LEN].fill(0);
                    malformed_server_share[0] = 0x04;
                }
                _ => unreachable!(),
            }
            assert_eq!(
                client.complete(&malformed_server_share).err().unwrap(),
                INVALID_KEY_SHARE
            );
        }
    }

    #[test]
    fn test_hybrid_groups_are_tls13_only() {
        for group in [X25519MLKEM768, SECP256R1MLKEM768] {
            assert!(group.usable_for_version(ProtocolVersion::TLSv1_3));
            assert!(!group.usable_for_version(ProtocolVersion::TLSv1_2));
            assert!(group.ffdhe_group().is_none());
        }
    }

    #[test]
    fn test_named_group_code_points() {
        // Guards against a group being wired to the wrong code point, which would look like a
        // peer that never offers PQ.
        assert_eq!(u16::from(X25519MLKEM768.name()), 0x11ec);
        assert_eq!(u16::from(SECP256R1MLKEM768.name()), 0x11eb);
    }
}
