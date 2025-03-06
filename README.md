# SymCrypt Provider for Rustls

This crate provides integration for using [rust-symcrypt](https://github.com/microsoft/rust-symcrypt) cryptographic functionalities with  [rustls](https://github.com/rustls/rustls), by implementing the required traits specified by `rustls`.


### Supported Configurations

| Operating Environment | Architecture      | Dynamic Linking  | Static Linking  |
| --------------------- | ----------------- | ---------------- | --------------- |
| Windows user mode     | AMD64, ARM64      | ✅              | ✅ ⚠️           |
| Ubuntu                | AMD64, ARM64      | ✅              | ✅ ⚠️           |
| Azure Linux 3         | AMD64, ARM64      | ✅              | ✅ ⚠️           |

**Note:** ⚠️ Static linking does not offer FIPS and is **not to be used in Microsoft production or release builds.** For more information please see the `Dependencies` below.

---

## Dependencies

By default, `rustls-symcrypt` requires no additional dependencies. It will automatically build `SymCrypt` from source, and static link during build time. If you wish to static link you can continue to the `Usage` section.

If you enable the `dynamic` feature, `rustls-symcrypt` will try to dynamically link to the `SymCrypt` shared object on your machine. Dynamic linking will provide FIPS and will but will require you to pull down the required `SymCrypt` binaries for your architecture, for more info please refer to the [rust-symcrypt Quick Start Guide](https://github.com/microsoft/rust-symcrypt/tree/main/rust-symcrypt#quick-start-guide) to download the required binaries.

---

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

---

## Supported Key Exchanges

Key exchanges are listed below, ordered by preference. IE: `SECP384R1` is preferred over `SECP256R1`.

```ignore
SECP384R1
SECP256R1
X25519 // Enabled with the `x25519` feature
```

**Note:** `X25519` is disabled by default. To enable, add `x25519` feature in your `Cargo.toml`.

--- 

## Usage

Add `rustls-symcrypt` to your `Cargo.toml`:


Static Linking: 
```toml
[dependencies]
rustls = { version = "0.23.0", features = ["tls12", "std", "custom-provider"], default-features = false }
rustls_symcrypt = "0.3.0"
```

Dynamic Linking:
```toml
[dependencies]
rustls = { version = "0.23.0", features = ["tls12", "std", "custom-provider"], default-features = false }
rustls_symcrypt = {version = "0.3.0", features = "dynamic"}
```

**Note:** If you wish to enable `x25519` or `chacha` you may add it as a feature at this time.


### Default Configuration

Use `default_symcrypt_provider()` for a `ClientConfig` that utilizes the default cipher suites and key exchange groups listed above:

```rust
use rustls::{ClientConfig, RootCertStore};
use rustls_symcrypt::default_symcrypt_provider;
use std::sync::Arc;
use webpki_roots;

let mut root_store = RootCertStore {
    roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
};
let mut config =
    ClientConfig::builder_with_provider(Arc::new(default_symcrypt_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

// Rest of the connection setup

```

### Custom Configuration

To modify or change the order of negotiated cipher suites for `ClientConfig`, use `custom_symcrypt_provider()`.

```rust
use rustls::{ClientConfig, RootCertStore};
use rustls_symcrypt::{custom_symcrypt_provider, TLS13_AES_128_GCM_SHA256, SECP256R1};
use std::sync::Arc;
use webpki_roots;

let mut root_store = RootCertStore {
    roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
};

// Set custom config of cipher suites that have been imported from rustls_symcrypt.
let cipher_suites = vec![TLS13_AES_128_GCM_SHA256];
let kx_group = vec![SECP256R1];

let mut config =
    ClientConfig::builder_with_provider(Arc::new(custom_symcrypt_provider(
        Some(cipher_suites), Some(kx_group))))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

// Rest of the connection setup

```

In addition, the `examples` directory showcases how to use the `rustls-symcrypt` provider with `rustls` for both a client configuration and a server configuration by taking advantage of `rustls::ClientConfig::builder_with_provider()`.
