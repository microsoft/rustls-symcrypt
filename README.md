# SymCrypt Provider for Rustls

This crate provides integration for using [rust-symcrypt](https://github.com/microsoft/rust-symcrypt) cryptographic functionalities with  [rustls](https://github.com/rustls/rustls), by implementing the required traits specified by `rustls`.


### Supported Configurations

| Operating Environment | Architecture      | Dynamic Linking |
| --------------------- | ----------------- | ----------- |
| Windows user mode     | AMD64, ARM64      | ✅          | 
| Ubuntu (Tested via WSL)       | AMD64, ARM64      | ✅          | 
| Azure Linux 3         | AMD64, ARM64      | ✅          |
| Azure Linux 2         | AMD64, ARM64      | ❌          |

## Dependencies

This crate depends on the [symcrypt](https://github.com/microsoft/rust-symcrypt) crate and requires you have the necessary `symcrypt` binaries for your architecture.
Refer to the [rust-symcrypt Quick Start Guide](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt#quick-start-guide) to download the required binaries.

## Usage

Add `rustls-symcrypt` to your `Cargo.toml`:
**Note:** If you wish to enable `x25519` or `chacha` you may add it as a feature at this time.

```toml
[dependencies]
rustls = { version = "0.23.0", features = ["ring", "tls12", "std"], default-features = false }
# Disabling aws-lc as it slows down build times and is not needed.
rustls_symcrypt = "0.1.0"
# To enable the chacha feature:
# rustls_symcrypt = {version = "0.1.0", features = ["chacha"]}
```

## Supported Ciphers

Supported cipher suites are listed below, ordered by preference. IE: The default configuration prioritizes `TLS13_AES_256_GCM_SHA384` over `TLS13_AES_128_GCM_SHA256`.

### TLS 1.3

```ignore
TLS13_AES_256_GCM_SHA384
TLS13_AES_128_GCM_SHA256
TLS13_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
```

**Note:** `TLS13_CHACHA20_POLY1305_SHA256` is disabled by default. Enable the `chacha` feature in your `Cargo.toml` to use this cipher suite.

### TLS 1.2

```ignore
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 // Enabled with the `chacha` feature
```

## Supported Key Exchanges

Key exchanges are listed below, ordered by preference. IE: `SECP384R1` is preferred over `SECP256R1`.

```ignore
SECP384R1
SECP256R1
X25519 // Enabled with the `x25519` feature
```

**Note:** `X25519` is disabled by default. To enable, add `x25519` feature in your `Cargo.toml`.

## Example Code

The `examples` directory showcases how to use the `rustls-symcrypt` provider with `rustls` for both a client configuration and a server configuration by taking advantage of `rustls::ClientConfig::builder_with_provider()`.
