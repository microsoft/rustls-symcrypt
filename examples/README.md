# Rust TLS Examples

This README provides an overview and usage instructions for three Rust programs that demonstrate the use of `rustls` and `rustls_symcrypt`. These examples include an internet client, an internet client with platform certificate verification, a local client, and a local server.


`sample_local_client` and `sample_server` both require certs and/or keys for proper functionality. These sample certs have been provided in the `bin/certs` path. 

## 1. Sample Internet Client (`sample_internet_client`)

This example establishes a TLS connection to `rust-lang.org` using `default_symcrypt_provider()`. This program does not take in any certs or keys and instead relies on `webpki_roots::TLS_SERVER_ROOTS`.

### Usage
`cargo run --bin sample_internet_client`

## 2. Sample Internet Client with Platform Verifier (`sample_internet_client_platform`)

This example establishes a TLS connection to `rust-lang.org` using `default_symcrypt_provider()`. and [rustls-platform-verifier](https://github.com/rustls/rustls-platform-verifier). This program does not take in any certs or keys and instead relies the roots that are managed by your platform.

### Usage
`cargo run --bin sample_internet_client`

## 3. Sample Local Client (`sample_local_client`)

This example shows how to connect to a local server on `localhost:4444` using `custom_symcrypt_provider()`. This program requires the usage of a sample Root CA which has been provided and is named `RootCA.pem`. To get the client to connect, you can either start the `sample_server` in a separate terminal window, or you can start a simple openssl server in a separate terminal window.

To spin up a simple openssl server please use the following from the `bin/certs` folder:

`openssl s_server -accept 4444 -cert localhost.crt  -key localhost.key -debug`

### Usage
`cargo run --bin sample_local_client`.

## 4. Sample Server (`sample_server`)

This example shows how to set up a server application that listens on `localhost:4444` for incoming TLS connections. This program requires the usage of an end cert and it's key which have been provided and is named `localhost.crt` and `localhost.pem` respectively. To get a client to connect to your server, you can either start `sample_local_client` in a separate terminal window, or you can start a simple openssl client in a separate terminal window.

To spin up a simple openssl client please use the following from the `bin/certs` folder:

`openssl s_client -connect localhost:4444 -CAfile RootCA.pem`

### Usage
`cargo run --bin sample_server`.

