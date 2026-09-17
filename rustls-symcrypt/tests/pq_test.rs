//! Post-quantum hybrid key exchange integration tests.
//!
//! These drive a real rustls client and server against each other entirely in memory, so unlike
//! `full_test.rs` they need no `openssl s_server` and no network. Both peers use the SymCrypt
//! provider, which proves the two halves of each hybrid group agree with each other but not that
//! they match the wire format of an independent implementation.
//!
//! Wire-format interop against an aws-lc-rs-backed peer is the real proof of correctness for the
//! layouts in `hybrid.rs`, and it is deliberately not attempted here: pulling aws-lc-rs into
//! dev-dependencies means a second crypto backend, a C toolchain, and a NASM dependency in CI. The
//! byte-offset assertions in `hybrid.rs` guard the layout instead.

use std::fs::File;
use std::io::{BufReader, Cursor};
use std::sync::Arc;

use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{
    ClientConfig, ClientConnection, Connection, HandshakeKind, NamedGroup, RootCertStore,
    ServerConfig, ServerConnection,
};

use rustls_symcrypt::{
    custom_symcrypt_provider, default_symcrypt_provider, ALL_KX_GROUPS, DEFAULT_KX_GROUPS,
    SECP256R1, SECP256R1MLKEM768, SECP384R1, X25519, X25519MLKEM768,
};

const SERVER_NAME: &str = "localhost";

fn cert_path(file: &str) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("certs");
    path.push(file);
    path
}

fn server_config(kx_groups: Vec<&'static dyn SupportedKxGroup>) -> ServerConfig {
    let certs = rustls_pemfile::certs(&mut BufReader::new(
        File::open(cert_path("localhost.pem")).unwrap(),
    ))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let key = PrivateKeyDer::from_pem_file(cert_path("localhost.key")).unwrap();

    ServerConfig::builder_with_provider(Arc::new(custom_symcrypt_provider(None, Some(kx_groups))))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap()
}

fn client_config(kx_groups: Vec<&'static dyn SupportedKxGroup>) -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(cert_path("RootCA.pem"))
            .unwrap()
            .map(|cert| cert.unwrap()),
    );

    ClientConfig::builder_with_provider(Arc::new(custom_symcrypt_provider(None, Some(kx_groups))))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Moves every byte one side wants to write into the other side, then processes them.
fn transfer(from: &mut Connection, to: &mut Connection) -> Result<(), rustls::Error> {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf).unwrap();
    }
    if buf.is_empty() {
        return Ok(());
    }

    let mut cursor = Cursor::new(buf);
    while cursor.position() < cursor.get_ref().len() as u64 {
        to.read_tls(&mut cursor).unwrap();
    }
    to.process_new_packets().map(|_| ())
}

/// Runs a complete handshake in memory and returns both sides for inspection.
fn try_handshake(
    client_groups: Vec<&'static dyn SupportedKxGroup>,
    server_groups: Vec<&'static dyn SupportedKxGroup>,
) -> Result<(Connection, Connection), rustls::Error> {
    let mut client = Connection::Client(
        ClientConnection::new(
            Arc::new(client_config(client_groups)),
            SERVER_NAME.try_into().unwrap(),
        )
        .unwrap(),
    );
    let mut server =
        Connection::Server(ServerConnection::new(Arc::new(server_config(server_groups))).unwrap());

    // Bounded so a stalled handshake fails the test instead of hanging CI.
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok((client, server));
        }
        transfer(&mut client, &mut server)?;
        transfer(&mut server, &mut client)?;
    }

    panic!("handshake did not complete within the flight budget");
}

fn handshake(
    client_groups: Vec<&'static dyn SupportedKxGroup>,
    server_groups: Vec<&'static dyn SupportedKxGroup>,
) -> (Connection, Connection) {
    try_handshake(client_groups, server_groups).unwrap()
}

#[test]
fn test_x25519_mlkem768_handshake() {
    let (client, server) = handshake(vec![X25519MLKEM768], vec![X25519MLKEM768]);

    for conn in [&client, &server] {
        assert_eq!(
            conn.negotiated_key_exchange_group().map(|g| g.name()),
            Some(NamedGroup::X25519MLKEM768)
        );
    }
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
}

#[test]
fn test_secp256r1_mlkem768_handshake() {
    let (client, server) = handshake(vec![SECP256R1MLKEM768], vec![SECP256R1MLKEM768]);

    for conn in [&client, &server] {
        assert_eq!(
            conn.negotiated_key_exchange_group().map(|g| g.name()),
            Some(NamedGroup::secp256r1MLKEM768)
        );
    }
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
}

/// The default provider must actually offer a hybrid group as its first choice, otherwise the whole
/// point of this work is lost: two SymCrypt peers with no explicit configuration should negotiate
/// post-quantum.
#[test]
fn test_default_provider_negotiates_post_quantum() {
    let mut client = Connection::Client(
        ClientConnection::new(
            Arc::new(
                ClientConfig::builder_with_provider(Arc::new(default_symcrypt_provider()))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates({
                        let mut roots = RootCertStore::empty();
                        roots.add_parsable_certificates(
                            CertificateDer::pem_file_iter(cert_path("RootCA.pem"))
                                .unwrap()
                                .map(|cert| cert.unwrap()),
                        );
                        roots
                    })
                    .with_no_client_auth(),
            ),
            SERVER_NAME.try_into().unwrap(),
        )
        .unwrap(),
    );
    let mut server = Connection::Server(
        ServerConnection::new(Arc::new(server_config(DEFAULT_KX_GROUPS.to_vec()))).unwrap(),
    );

    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        transfer(&mut client, &mut server).unwrap();
        transfer(&mut server, &mut client).unwrap();
    }

    assert_eq!(
        client.negotiated_key_exchange_group().map(|g| g.name()),
        Some(NamedGroup::X25519MLKEM768),
        "the default provider must negotiate post-quantum without configuration"
    );
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
}

/// A server that only knows the classical half must be able to select it out of the client's
/// hybrid share, with no extra round trip. This is what `hybrid_component` buys.
///
/// rustls only sends the separate classical share when the classical group also appears in the
/// client's own `kx_groups`, after the hybrid, so the client list here mirrors the shape of
/// [`DEFAULT_KX_GROUPS`].
#[test]
fn test_server_selects_classical_component_without_retry() {
    for (hybrid, classical, expected) in [
        (X25519MLKEM768, X25519, NamedGroup::X25519),
        (SECP256R1MLKEM768, SECP256R1, NamedGroup::secp256r1),
    ] {
        let (client, server) = handshake(vec![hybrid, classical], vec![classical]);

        for conn in [&client, &server] {
            assert_eq!(
                conn.negotiated_key_exchange_group().map(|g| g.name()),
                Some(expected)
            );
        }
        assert_eq!(
            client.handshake_kind(),
            Some(HandshakeKind::Full),
            "selecting the classical component must not cost a HelloRetryRequest"
        );
    }
}

/// The mirror image: with the hybrid group alone in the client's list, there is no separate
/// classical share and no classical entry in `supported_groups`, so a classical-only server has
/// nothing to select and the handshake fails outright rather than retrying.
///
/// This is the concrete reason [`DEFAULT_KX_GROUPS`] lists `X25519` separately after the hybrid.
#[test]
fn test_hybrid_only_client_cannot_talk_to_classical_only_server() {
    assert_eq!(
        try_handshake(vec![X25519MLKEM768], vec![X25519]).unwrap_err(),
        rustls::Error::PeerIncompatible(rustls::PeerIncompatible::NoKxGroupsInCommon)
    );
}

/// When the server supports none of the groups the client sent a share for, it asks for one it does
/// support. The client has to re-offer, and the hybrid group must survive that path.
#[test]
fn test_hello_retry_request() {
    // The client sends a share only for its first group, so a SECP384R1-only server must retry.
    let (client, server) = handshake(vec![X25519MLKEM768, SECP384R1], vec![SECP384R1]);

    for conn in [&client, &server] {
        assert_eq!(
            conn.negotiated_key_exchange_group().map(|g| g.name()),
            Some(NamedGroup::secp384r1)
        );
    }
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );

    // The reverse direction: a hybrid-only server retries a classical-first client's share.
    let (client, _) = handshake(vec![SECP384R1, X25519MLKEM768], vec![X25519MLKEM768]);
    assert_eq!(
        client.negotiated_key_exchange_group().map(|g| g.name()),
        Some(NamedGroup::X25519MLKEM768)
    );
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
}

/// Locks in the group lists. Missing a wiring site ships a provider that compiles but never offers
/// post-quantum, which is exactly the silent failure this work exists to remove.
#[test]
fn test_provider_kx_group_wiring() {
    let expected_default = [
        NamedGroup::X25519MLKEM768,
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
    ];
    let expected_all = [
        NamedGroup::X25519MLKEM768,
        NamedGroup::secp256r1MLKEM768,
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
    ];

    let names = |groups: &[&'static dyn SupportedKxGroup]| {
        groups.iter().map(|g| g.name()).collect::<Vec<_>>()
    };

    assert_eq!(names(DEFAULT_KX_GROUPS), expected_default);
    assert_eq!(names(ALL_KX_GROUPS), expected_all);

    // Both provider constructors, including the fallback path when no groups are supplied.
    assert_eq!(
        names(&default_symcrypt_provider().kx_groups),
        expected_default
    );
    assert_eq!(
        names(&custom_symcrypt_provider(None, None).kx_groups),
        expected_default
    );
    assert_eq!(
        names(&custom_symcrypt_provider(None, Some(vec![])).kx_groups),
        expected_default
    );
}

/// Pins the conservative FIPS decision so it cannot regress unnoticed in either direction.
///
/// `CryptoProvider::fips()` is already false for this provider and always has been: no key exchange
/// group overrides the rustls default. Adding post-quantum groups that report false changes
/// nothing. If this ever starts failing, someone has made a compliance claim that needs a real
/// conversation behind it.
#[test]
fn test_fips_reporting() {
    assert!(!X25519MLKEM768.fips());
    assert!(!SECP256R1MLKEM768.fips());

    let provider: CryptoProvider = default_symcrypt_provider();
    assert!(!provider.fips());
}

/// X25519 is no longer behind a cargo feature. A post-quantum default that silently disappears
/// unless the consumer opts in would defeat the purpose of enabling it by default.
#[test]
fn test_x25519_is_unconditional() {
    assert_eq!(X25519.name(), NamedGroup::X25519);
    assert!(DEFAULT_KX_GROUPS
        .iter()
        .any(|g| g.name() == NamedGroup::X25519));

    let (client, _) = handshake(vec![X25519], vec![X25519]);
    assert_eq!(
        client.negotiated_key_exchange_group().map(|g| g.name()),
        Some(NamedGroup::X25519)
    );
}
