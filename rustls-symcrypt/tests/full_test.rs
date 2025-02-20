use std::env;
use std::fs::File;
use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustls::crypto::SupportedKxGroup;
use rustls::{CipherSuite, SupportedCipherSuite};

use rustls_symcrypt::{
    custom_symcrypt_provider, default_symcrypt_provider, SECP256R1, SECP384R1,
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};

#[cfg(feature = "x25519")]
use rustls_symcrypt::X25519;

#[cfg(feature = "chacha")]
use rustls_symcrypt::{
    TLS13_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};

static TEST_CERT_PATH: once_cell::sync::Lazy<PathBuf> = once_cell::sync::Lazy::new(|| {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("certs");
    path
});

struct OpenSSLServer(Child);

impl Drop for OpenSSLServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn start_openssl_server() -> OpenSSLServer {
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

    let child = Command::new("openssl")
        .arg("s_server")
        .arg("-accept")
        .arg("4443")
        .arg("-cert")
        .arg(cert_path)
        .arg("-key")
        .arg(key_path)
        .stdout(std::process::Stdio::null()) // Suppress standard output
        .stderr(std::process::Stdio::null()) // Suppress standard error
        .spawn()
        .expect("Failed to start OpenSSL server.");

    // wait for openssl server
    thread::sleep(Duration::from_secs(2));

    OpenSSLServer(child)
}

fn test_with_config(
    suite: SupportedCipherSuite,
    group: &'static dyn SupportedKxGroup,
) -> CipherSuite {
    let cipher_suites = vec![suite];
    let kx_group = vec![group];

    // Add default webpki roots to the root store
    let mut root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let cert_path = TEST_CERT_PATH
        .join("RootCA.pem")
        .into_os_string()
        .into_string()
        .unwrap();

    let certs = rustls_pemfile::certs(&mut BufReader::new(&mut File::open(cert_path).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    root_store.add_parsable_certificates(certs);

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(custom_symcrypt_provider(
        Some(cipher_suites),
        Some(kx_group),
    )))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let server_name = "localhost".try_into().unwrap();

    let mut sock = TcpStream::connect("localhost:4443").unwrap();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
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

    let mut exit_buffer: [u8; 1] = [0]; // Size 1 because "Q" is a single byte command
    exit_buffer[0] = b'Q'; // Assign the ASCII value of "Q" to the buffer

    // Write the "Q" command to the TLS connection stream
    tls.write_all(&exit_buffer).unwrap();
    ciphersuite.suite()
}

fn test_with_custom_config_to_internet(
    suite: SupportedCipherSuite,
    group: &'static dyn SupportedKxGroup,
    host_name: String,
) -> CipherSuite {
    let cipher_suites = vec![suite];
    let kx_group = vec![group];

    // Add default webpki roots to the root store
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(custom_symcrypt_provider(
        Some(cipher_suites),
        Some(kx_group),
    )))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let server_name = host_name.clone().try_into().unwrap();
    let addr = format!("{}:443", host_name);
    let mut sock = TcpStream::connect(&addr).unwrap();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        format!(
            "GET / HTTP/1.1\r\n\
            Host: {}\r\n\
            Connection: close\r\n\
            Accept-Encoding: identity\r\n\
            \r\n",
            host_name
        )
        .as_bytes(),
    )
    .unwrap();

    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

    let mut exit_buffer: [u8; 1] = [0]; // Size 1 because "Q" is a single byte command
    exit_buffer[0] = b'Q'; // Assign the ASCII value of "Q" to the buffer

    // Write the "Q" command to the TLS connection stream
    tls.write_all(&exit_buffer).unwrap();
    ciphersuite.suite()
}

// Test TLS 1.3 Cipher Suites

#[test]
fn test_tls13_aes_128_256() {
    let server_thread = {
        let openssl_server = Arc::new(Mutex::new(start_openssl_server()));
        thread::spawn(move || {
            openssl_server
                .lock()
                .unwrap()
                .0
                .wait()
                .expect("OpenSSL server crashed unexpectedly");
        })
    };

    // Wait for the server to start
    thread::sleep(std::time::Duration::from_secs(5));

    let expected_suite = test_with_config(TLS13_AES_128_GCM_SHA256, SECP384R1);
    assert_eq!(expected_suite, CipherSuite::TLS13_AES_128_GCM_SHA256);
    drop(server_thread);
}

#[test]
fn test_tls13_aes_256_384() {
    let server_thread = {
        let openssl_server = Arc::new(Mutex::new(start_openssl_server()));
        thread::spawn(move || {
            openssl_server
                .lock()
                .unwrap()
                .0
                .wait()
                .expect("OpenSSL server crashed unexpectedly");
        })
    };

    // Wait for the server to start
    thread::sleep(std::time::Duration::from_secs(5));

    let expected_suite = test_with_config(TLS13_AES_256_GCM_SHA384, SECP256R1);
    assert_eq!(expected_suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
    drop(server_thread);
}

#[cfg(feature = "chacha")]
#[test]
fn test_tls13_chacha_1305() {
    let server_thread = {
        let openssl_server = Arc::new(Mutex::new(start_openssl_server()));
        thread::spawn(move || {
            openssl_server
                .lock()
                .unwrap()
                .0
                .wait()
                .expect("OpenSSL server crashed unexpectedly");
        })
    };

    // Wait for the server to start
    thread::sleep(std::time::Duration::from_secs(5));

    let expected_suite = test_with_config(TLS13_CHACHA20_POLY1305_SHA256, SECP256R1);
    assert_eq!(expected_suite, CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
    drop(server_thread);
}

// Test TLS 1.2 Cipher Suites

#[test]
fn test_tls12_rsa_256_384() {
    let server_thread = {
        let openssl_server = Arc::new(Mutex::new(start_openssl_server()));
        thread::spawn(move || {
            openssl_server
                .lock()
                .unwrap()
                .0
                .wait()
                .expect("OpenSSL server crashed unexpectedly");
        })
    };

    // Wait for the server to start
    thread::sleep(std::time::Duration::from_secs(5));

    let expected_suite = test_with_config(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, SECP256R1);
    assert_eq!(
        expected_suite,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    );
    drop(server_thread);
}

#[test]
fn test_tls12_rsa_128_256() {
    let server_thread = {
        let openssl_server = Arc::new(Mutex::new(start_openssl_server()));
        thread::spawn(move || {
            openssl_server
                .lock()
                .unwrap()
                .0
                .wait()
                .expect("OpenSSL server crashed unexpectedly");
        })
    };

    // Wait for the server to start
    thread::sleep(std::time::Duration::from_secs(5));

    let expected_suite = test_with_config(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, SECP256R1);
    assert_eq!(
        expected_suite,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    );
    drop(server_thread);
}

#[cfg(feature = "x25519")]
#[test]
fn test_tls13_256_384_with_25519() {
    let server_thread = {
        let openssl_server = Arc::new(Mutex::new(start_openssl_server()));
        thread::spawn(move || {
            openssl_server
                .lock()
                .unwrap()
                .0
                .wait()
                .expect("OpenSSL server crashed unexpectedly");
        })
    };

    // Wait for the server to start
    thread::sleep(std::time::Duration::from_secs(5));

    let expected_suite = test_with_config(TLS13_AES_256_GCM_SHA384, X25519);
    assert_eq!(expected_suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
    drop(server_thread);
}

#[test]
fn test_tls13_256_384_with_nist384() {
    let server_thread = {
        let openssl_server = Arc::new(Mutex::new(start_openssl_server()));
        thread::spawn(move || {
            openssl_server
                .lock()
                .unwrap()
                .0
                .wait()
                .expect("OpenSSL server crashed unexpectedly");
        })
    };

    // Wait for the server to start
    thread::sleep(std::time::Duration::from_secs(5));

    let expected_suite = test_with_config(TLS13_AES_256_GCM_SHA384, SECP384R1);
    assert_eq!(expected_suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
    drop(server_thread);
}

// Test TLS connection to internet
#[cfg(feature = "chacha")]
#[test]
fn test_chacha_to_internet() {
    let expected_suite = test_with_custom_config_to_internet(
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        SECP384R1,
        "www.rust-lang.org".to_string(),
    );
    assert_eq!(
        expected_suite,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    );
}

#[test]
fn test_tls12_rsa_128_256_to_internet() {
    let expected_suite = test_with_custom_config_to_internet(
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        SECP256R1,
        "www.rust-lang.org".to_string(),
    );
    assert_eq!(
        expected_suite,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    );
}

#[test]
fn test_tls12_rsa_256_384_to_internet() {
    let expected_suite = test_with_custom_config_to_internet(
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        SECP384R1,
        "rust-lang.org".to_string(),
    );
    assert_eq!(
        expected_suite,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    );
}

#[test]
fn test_tls12_ecdsa_128_256_to_internet() {
    let expected_suite = test_with_custom_config_to_internet(
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        SECP256R1,
        "www.ssl.org".to_string(),
    );
    assert_eq!(
        expected_suite,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    );
}

#[test]
fn test_tls12_ecdsa_256_384_to_internet() {
    let expected_suite = test_with_custom_config_to_internet(
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        SECP256R1,
        "www.ssl.org".to_string(),
    );
    assert_eq!(
        expected_suite,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    );
}

#[test]
#[cfg(feature = "chacha")]
fn test_tls12_ecdsa_poly_1305_to_internet() {
    let expected_suite = test_with_custom_config_to_internet(
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        SECP256R1,
        "www.ssl.org".to_string(),
    );
    assert_eq!(
        expected_suite,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    );
}

// #[test]
// fn test_default_client() {
//     // Spawn a concurrent thread that starts the server
//     let server_thread = {
//         let openssl_server = Arc::new(Mutex::new(start_openssl_server()));
//         thread::spawn(move || {
//             openssl_server
//                 .lock()
//                 .unwrap()
//                 .0
//                 .wait()
//                 .expect("OpenSSL server crashed unexpectedly");
//         })
//     };

//     // Wait for the server to start
//     thread::sleep(std::time::Duration::from_secs(5));

//     // Add default webpki roots to the root store
//     let mut root_store = rustls::RootCertStore {
//         roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
//     };

//     let cert_path = TEST_CERT_PATH
//         .join("RootCA.pem")
//         .into_os_string()
//         .into_string()
//         .unwrap();

//     let certs = rustls_pemfile::certs(&mut BufReader::new(&mut File::open(cert_path).unwrap()))
//         .collect::<Result<Vec<_>, _>>()
//         .unwrap();

//     root_store.add_parsable_certificates(certs);

//     let config = rustls::ClientConfig::builder_with_provider(Arc::new(default_symcrypt_provider()))
//         .with_safe_default_protocol_versions()
//         .unwrap()
//         .with_root_certificates(root_store)
//         .with_no_client_auth();

//     let server_name = "localhost".try_into().unwrap();

//     let mut sock = TcpStream::connect("localhost:4443").unwrap();

//     let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
//     let mut tls = rustls::Stream::new(&mut conn, &mut sock);
//     tls.write_all(
//         concat!(
//             "GET / HTTP/1.1\r\n",
//             "Host: localhost\r\n",
//             "Connection: close\r\n",
//             "Accept-Encoding: identity\r\n",
//             "\r\n"
//         )
//         .as_bytes(),
//     )
//     .unwrap();

//     let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

//     let mut exit_buffer: [u8; 1] = [0]; // Size 1 because "Q" is a single byte command
//     exit_buffer[0] = b'Q'; // Assign the ASCII value of "Q" to the buffer

//     // Write the "Q" command to the TLS connection stream
//     tls.write_all(&exit_buffer).unwrap();

//     assert_eq!(ciphersuite.suite(), CipherSuite::TLS13_AES_256_GCM_SHA384);
//     drop(server_thread);
// }
