use rustls_symcrypt::{
    custom_symcrypt_provider, SECP256R1, TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384,
};

use std::fs::File;
use std::io::BufReader;
use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;

static TEST_CERT_PATH: once_cell::sync::Lazy<PathBuf> = once_cell::sync::Lazy::new(|| {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("bin");
    path.push("certs");
    path
});

// Note this assumes that you are connecting to a localhost server that has the included localhost.crt and localhost.key
// set up for the server configuration, to run this in openssl, you can use the following command:

// openssl s_server -accept 4444 -cert localhost.crt  -key localhost.key -debug

/// Usage
/// This program provides a simple localhost client using rustls-symcrypt.
/// It uses the provided RootCA.pem to set up the client config.
/// To run this program you can use the following command in your terminal:
/// cargo run --bin sample_local_client
fn main() {
    let cert_path = TEST_CERT_PATH
        .join("RootCA.pem")
        .into_os_string()
        .into_string()
        .unwrap();
    let certs = rustls_pemfile::certs(&mut BufReader::new(&mut File::open(cert_path).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_parsable_certificates(certs);

    let cipher_suites = vec![TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384];
    let kx_group = vec![SECP256R1];

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(custom_symcrypt_provider(
        Some(cipher_suites),
        Some(kx_group),
    )))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let server_name = "localhost".try_into().unwrap();
    let mut sock = TcpStream::connect("localhost:4444").unwrap();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    println!("Connecting to localhost using a the custom_symcrypt_provider.");
    println!("To get your own localhost server you can use the following openssl command:");
    println!("openssl s_server -accept 4444 -cert localhost.crt  -key localhost.key -debug");

    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: localhost\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();

    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();

    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();

    println!("Connection established");
}
