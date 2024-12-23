/// This program provides a simple client-server application using rustls-symcrypt and rustls-cng.
/// It uses rustls-platform-verifier to utilize your machine's certificate validation for TLS communication.
/// Both the client and server retrieve certificates from the "CurrentUser" "my" store.
/// Please install rustls-client.pfx and rustls-server.pfx if you want to test it.
/// Usage: cargo run --bin test_client_server
//  The reference for this program is https://github.com/rustls/rustls-cng/blob/dev/tests/test_client_server.rs

mod client {

    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpStream},
        sync::Arc,
    };

    use anyhow::Result;
    use rustls::{
        client::ResolvesClientCert, sign::CertifiedKey, ClientConfig, ClientConnection,
        SignatureScheme, Stream,
    };
    use rustls_cng::{
        signer::CngSigningKey,
        store::{CertStore, CertStoreType},
    };
    use rustls_pki_types::CertificateDer;
    use rustls_platform_verifier::BuilderVerifierExt;
    use rustls_symcrypt::default_symcrypt_provider;

    #[derive(Debug)]
    pub struct ClientCertResolver(String);

    fn get_chain(hex_thumbprint: &str) -> Result<(Vec<CertificateDer<'static>>, CngSigningKey)> {
        let store = CertStore::open(CertStoreType::CurrentUser, "My")?;
        let thumbprint = hex::decode(hex_thumbprint)?;
        // depend on version of rustls-cng that supports. can use find_by_sha256() when rustls-cng in new version
        let contexts = store.find_by_sha1(thumbprint)?;
        let context = contexts
            .first()
            .ok_or_else(|| anyhow::Error::msg("Client: No client cert"))?;
        let key = context.acquire_key()?;
        let signing_key = CngSigningKey::new(key)?;
        let chain = context
            .as_chain_der()?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok((chain, signing_key))
    }

    impl ResolvesClientCert for ClientCertResolver {
        fn resolve(
            &self,
            _acceptable_issuers: &[&[u8]],
            sigschemes: &[SignatureScheme],
        ) -> Option<Arc<CertifiedKey>> {
            println!("Client sig schemes: {:#?}", sigschemes);
            let (chain, signing_key) = get_chain(&self.0).ok()?;
            for scheme in signing_key.supported_schemes() {
                if sigschemes.contains(scheme) {
                    return Some(Arc::new(CertifiedKey {
                        cert: chain,
                        key: Arc::new(signing_key),
                        ocsp: None,
                    }));
                }
            }
            None
        }

        fn has_certs(&self) -> bool {
            true
        }
    }

    pub fn run_client(port: u16) -> Result<()> {
        let hex_thumbprint = "a508d75eac3f646de59e406a5382ae2a40037d97";

        let client_config =
            ClientConfig::builder_with_provider(Arc::new(default_symcrypt_provider()))
                .with_safe_default_protocol_versions()?
                .with_platform_verifier()
                .with_client_cert_resolver(Arc::new(ClientCertResolver(
                    hex_thumbprint.to_string(),
                )));

        let mut connection =
            ClientConnection::new(Arc::new(client_config), "rustls-server".try_into()?)?;
        println!("start a new connection");
        let mut client = TcpStream::connect(format!("localhost:{}", port))?;
        let mut tls_stream = Stream::new(&mut connection, &mut client);
        println!("write to tls stream");
        tls_stream.write_all(b"ping")?;
        println!("shut down socket");
        tls_stream.sock.shutdown(Shutdown::Write)?;

        let mut buf = [0u8; 4];
        tls_stream.read_exact(&mut buf)?;
        assert_eq!(&buf, b"pong");

        tls_stream.sock.shutdown(Shutdown::Read)?;

        Ok(())
    }
}

mod server {
    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        sync::{mpsc::Sender, Arc},
    };

    use anyhow::Result;
    use rustls::{
        server::{ClientHello, ResolvesServerCert, ServerConfig, ServerConnection},
        sign::CertifiedKey,
        Stream,
    };
    use rustls_cng::{
        signer::CngSigningKey,
        store::{CertStore, CertStoreType},
    };
    use rustls_pki_types::CertificateDer;

    #[derive(Debug)]
    pub struct CachedServerCertResolver(Arc<CertifiedKey>);

    impl CachedServerCertResolver {
        pub fn new(chain: Vec<CertificateDer<'static>>, signing_key: CngSigningKey) -> Self {
            let certified_key = CertifiedKey {
                cert: chain,
                key: Arc::new(signing_key),
                ocsp: None,
            };
            CachedServerCertResolver(Arc::new(certified_key))
        }
    }

    impl ResolvesServerCert for CachedServerCertResolver {
        fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    fn get_chain(hex_thumbprint: &str) -> Result<(Vec<CertificateDer<'static>>, CngSigningKey)> {
        let store = CertStore::open(CertStoreType::CurrentUser, "My")?;
        let thumbprint = hex::decode(hex_thumbprint)?;
        // depend on version of rustls-cng that supports. can use find_by_sha256() when rustls-cng in new version
        let context = store
            .find_by_sha1(thumbprint)
            .unwrap()
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::Error::msg("Server: No client certificate found"))?;
        let key = context.acquire_key()?;
        let signing_key = CngSigningKey::new(key)?;

        let chain = context
            .as_chain_der()?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok((chain, signing_key))
    }

    fn handle_connection(mut stream: TcpStream, config: Arc<ServerConfig>) -> Result<()> {
        let mut connection = ServerConnection::new(config)?;
        let mut tls_stream = Stream::new(&mut connection, &mut stream);

        let mut buf = [0u8; 4];
        tls_stream.read_exact(&mut buf)?;
        assert_eq!(&buf, b"ping");
        tls_stream.sock.shutdown(Shutdown::Read)?;
        tls_stream.write_all(b"pong")?;
        tls_stream.sock.shutdown(Shutdown::Write)?;

        Ok(())
    }

    pub fn run_server(sender: Sender<u16>) -> Result<()> {
        let hex_thumbprint = "7772f5739ffab1777c83f158d44bba49e84b5b54";
        let (chain, signing_key) = get_chain(hex_thumbprint)?;
        // Build the server configuration
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CachedServerCertResolver::new(chain, signing_key)));

        let server = TcpListener::bind("127.0.0.1:0")?;
        let _ = sender.send(server.local_addr()?.port());
        let stream = server.incoming().next().unwrap()?;
        let config = Arc::new(server_config);
        handle_connection(stream, config)?;

        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        if let Err(e) = server::run_server(tx) {
            eprintln!("Server error: {:?}", e);
        }
    });
    println!("Server is running");
    if let Ok(port) = rx.recv() {
        if let Err(e) = client::run_client(port) {
            eprintln!("Client error: {:?}", e);
        }
    }

    Ok(())
}
