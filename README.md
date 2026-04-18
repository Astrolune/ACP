# ACP (Astrolune Cipher Protocol)

[![CI](https://github.com/Astrolune/ACP/workflows/CI/badge.svg)](https://github.com/Astrolune/ACP/actions)
[![Security Audit](https://github.com/Astrolune/ACP/workflows/Security%20Audit/badge.svg)](https://github.com/Astrolune/ACP/actions)
[![License](https://img.shields.io/badge/Apache--2.0-blue.svg)](LICENSE)

A secure, transport-agnostic cryptographic library with multi-language support.

## Features

- **Proven Cryptography**: Only NIST-approved algorithms (AES-256-GCM, ChaCha20-Poly1305)
- **Multi-Language Support**: Native Rust, C, C#, and C++ bindings
- **Clean API**: Simple, intuitive interfaces for encryption, key management, and sessions
- **Transport-Agnostic**: Works with any communication layer
- **Memory Safe**: Built in Rust with automatic key zeroing
- **Well-Tested**: Comprehensive unit, integration, and fuzz tests

## Quick Start

### Rust

```toml
[dependencies]
acp-core = "0.1"
```

```rust
use acp_core::{Algorithm, Key, Session};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a key
    let key = Key::generate(Algorithm::Aes256Gcm)?;
    
    // Create a session
    let session = Session::new(&key, "my-session".to_string())?;
    
    // Encrypt
    let plaintext = b"Hello, ACP!";
    let ciphertext = session.encrypt(plaintext)?;
    
    // Decrypt
    let decrypted = session.decrypt(&ciphertext)?;
    assert_eq!(plaintext, decrypted.as_slice());
    
    Ok(())
}
```

### C

```c
#include <acp.h>

int main() {
    AcpKey* key = NULL;
    acp_key_generate(ACP_ALGORITHM_AES_256_GCM, &key);
    
    AcpSession* session = NULL;
    acp_session_new(key, "my-session", &session);
    
    const char* plaintext = "Hello, ACP!";
    uint8_t* ciphertext = NULL;
    size_t ciphertext_len = 0;
    acp_session_encrypt(session, plaintext, strlen(plaintext), 
                        &ciphertext, &ciphertext_len);
    
    // Cleanup
    acp_free_buffer(ciphertext);
    acp_session_free(session);
    acp_key_free(key);
    
    return 0;
}
```

### C#

```csharp
using Astrolune.Cipher;

var key = Key.Generate(Algorithm.Aes256Gcm);
using var session = new Session(key, Algorithm.Aes256Gcm);

var plaintext = Encoding.UTF8.GetBytes("Hello, ACP!");
var ciphertext = session.Encrypt(plaintext);
var decrypted = session.Decrypt(ciphertext);
```

## Architecture

ACP is organized as a Rust workspace with multiple crates:

- **acp-core**: Core Rust library with cryptographic primitives
- **acp-ffi**: C ABI layer for FFI
- **acp-csharp**: C# bindings and NuGet package
- **acp-cpp**: Modern C++ wrapper

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

## Building

### Prerequisites

- Rust 1.75+ (install from [rustup.rs](https://rustup.rs))
- CMake 3.15+ (for C/C++ examples)
- .NET 8.0+ (for C# bindings)

### Build All

```bash
# Clone with submodules
git clone --recursive https://github.com/Astrolune/ACP.git
cd ACP

# Build all crates
cargo build --release --all-features

# Run tests
cargo test --all-features

# Build examples
cargo build --examples
```

### Build FFI Library

```bash
cargo build --release -p acp-ffi
```

This generates:
- **Linux**: `target/release/libacp.so`
- **Windows**: `target/release/acp.dll`
- **macOS**: `target/release/libacp.dylib`
- **Headers**: `crates/acp-ffi/include/acp.h`

## Examples

See the [examples](examples/) directory:

- **Rust**: `cargo run --example basic_encryption`
- **C**: Build with CMake in `examples/c/`
- **C#**: See `examples/csharp/`
- **C++**: Build with CMake in `examples/cpp/`

## Security

ACP follows security best practices:

- No custom cryptography - only proven primitives
- Constant-time operations
- Automatic key zeroing with `zeroize`
- Memory-safe Rust implementation
- Regular security audits with `cargo-audit`
- Fuzz testing for robustness

**Reporting vulnerabilities**: Please email security@astrolune.dev

## AVM Integration

ACP supports optional integration with [AVM](https://github.com/Astrolune/AVM) via git submodule:

```bash
git submodule update --init --recursive
cargo build --features avm
```

## Documentation

- [Architecture Design](ARCHITECTURE.md)
- [API Documentation](https://docs.rs/acp-core)
- [Security Policy](SECURITY.md)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `cargo test` and `cargo clippy` pass
5. Submit a pull request

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE](LICENSE))

## Acknowledgments

Built with:
- [RustCrypto](https://github.com/RustCrypto) - Cryptographic primitives
- [cbindgen](https://github.com/mozilla/cbindgen) - C header generation
- [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize) - Secure memory clearing
