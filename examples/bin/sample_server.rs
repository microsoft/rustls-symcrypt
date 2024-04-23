use std::io::Write;
use std::sync::Arc;

use rustls::server::Acceptor;
use rustls::ServerConfig;

use rustls_symcrypt::{
    custom_symcrypt_provider, SECP256R1, TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384,
};

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

static TEST_CERT_PATH: once_cell::sync::Lazy<PathBuf> = once_cell::sync::Lazy::new(|| {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("bin");
    path.push("certs");
    path
});

/// Usage
/// This program provides a simple localhost server using rustls-symcrypt.
/// It uses the provided localhost.pem and localhost.key to set up the server config.
/// To run this program you can use the following command in your terminal:
/// cargo run --bin sample_server
fn main() {
    // This code is similar to running the following command in openssl.
    // openssl s_server -accept 4444 -cert localhost.crt  -key localhost.key -debug

    // Get file path and parse cert and key
    let cert_path = TEST_CERT_PATH
        .join("localhost.pem")
        .into_os_string()
        .into_string()
        .unwrap();
    let key_path = TEST_CERT_PATH
        .join("localhost.key")
        .into_os_string()
        .into_string()
        .unwrap();

    let certs = rustls_pemfile::certs(&mut BufReader::new(&mut File::open(cert_path).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let private_key =
        rustls_pemfile::private_key(&mut BufReader::new(&mut File::open(key_path).unwrap()))
            .unwrap()
            .unwrap();

    // Set what cipher suites are going to be accepted by the server.
    let cipher_suites = vec![TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384];
    let kx_group = vec![SECP256R1];

    // Set up custom server config.
    let server_config = ServerConfig::builder_with_provider(Arc::new(custom_symcrypt_provider(
        Some(cipher_suites),
        Some(kx_group),
    )))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, private_key)
    .unwrap();

    let server_config = Arc::new(server_config);
    let listener = std::net::TcpListener::bind(format!("[::]:{}", 4444)).unwrap();

    println!("Staring server with custom_symcrypt_provider()");

    // Handle incomming connections
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };

        match accepted.into_connection(server_config.clone()) {
            Ok(mut conn) => {
                println!("Connection established");

                let msg = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Connection: Closed\r\n",
                    "Content-Type: text/html\r\n",
                    "\r\n",
                    "<h1>Hello World! From your own RUSTLS server</h1>\r\n"
                )
                .as_bytes();

                // Note: do not use `unwrap()` on IO in real programs!
                conn.writer().write_all(msg).unwrap();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();

                conn.send_close_notify();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();
            }
            Err(_) => {
                // error here
            }
        }
    }
}
