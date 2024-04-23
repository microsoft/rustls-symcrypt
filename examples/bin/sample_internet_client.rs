use rustls_symcrypt::default_symcrypt_provider;

use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

/// Usage
/// This program provides a simple internet client using rustls-symcrypt to connect to rust-lang.org
/// It uses the provided RootCA.pem to set up the client config.
/// To run this program you can use the following command in your terminal:
/// cargo run --bin sample_internet_client
fn main() {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
    };

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(default_symcrypt_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = "www.rust-lang.org".try_into().unwrap();
    let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    println!("Connecting to rust-lang.org, using the default_symcrypt_provider()");

    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: rust-lang.org\r\n",
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
