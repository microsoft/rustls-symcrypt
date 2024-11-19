use rustls_symcrypt::{
    custom_symcrypt_provider, SECP256R1, TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384,
};
use rustls::RootCertStore;
use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use rustls_cng::store::CertStore;

const CLIENT_PFX: &[u8] = include_bytes!("certs/RootCA.pfx");
const PASSWORD: &str = "enspwd";

// Note this assumes that you are connecting to a localhost server that has the included localhost.crt and localhost.key
// set up for the server configuration, to run this in openssl, you can use the following command:

// openssl s_server -accept 4444 -cert localhost.crt  -key localhost.key -debug

/// Usage
/// This program provides a simple localhost client using rustls-symcrypt.
/// It uses the provided RootCA.pem to set up the client config.
/// To run this program you can use the following command in your terminal:
/// cargo run --bin sample_local_client_cng
fn main() -> Result<(), Box<dyn std::error::Error>> {

    let store = CertStore::from_pkcs12(CLIENT_PFX, PASSWORD)?;
    let sha1 = [
        0xAD, 0xA0, 0xBA, 0xB0, 0xF4, 0x64, 0x79, 0xD4,
        0x16, 0x9A, 0x1F, 0x66, 0xB4, 0xF7, 0xE8, 0xD1,
        0x37, 0x77, 0xE3, 0x3C,
    ];
    // Find the CA certificate by SHA-1 hash
    let ca_cert_context = store.find_by_sha1(sha1)?;
    let ca_cert = ca_cert_context.first().unwrap();
    println!("#####found cert by sha1.");

    // Initialize the root store and add the CA certificate
    let mut root_store = RootCertStore::empty();
    root_store.add(ca_cert.as_der().into())?;

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
    let mut sock = TcpStream::connect("localhost:4444")?;

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    println!("Connecting to localhost using the custom_symcrypt_provider.");
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
    )?;

    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )?;

    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext)?;
    stdout().write_all(&plaintext)?;

    println!("Connection established");

    Ok(())
}