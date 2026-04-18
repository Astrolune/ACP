# ACP (Astrolune Cipher Protocol) - Architecture Design

## 1. Repository Structure

```
ACP/
├── Cargo.toml                    # Workspace root
├── README.md
├── LICENSE
├── ARCHITECTURE.md
├── SECURITY.md
├── .gitmodules                   # AVM submodule reference
├── AVM/                          # Git submodule (optional extension)
│
├── crates/
│   ├── acp-core/                 # Core Rust library
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── cipher.rs         # Encryption/decryption traits
│   │   │   ├── key.rs            # Key management
│   │   │   ├── session.rs        # Session abstractions
│   │   │   ├── error.rs          # Typed error handling
│   │   │   └── primitives/       # Crypto primitives wrappers
│   │   │       ├── mod.rs
│   │   │       ├── aead.rs       # AEAD ciphers (AES-GCM, ChaCha20-Poly1305)
│   │   │       └── kdf.rs        # Key derivation (HKDF, Argon2)
│   │   ├── tests/
│   │   └── benches/
│   │
│   ├── acp-ffi/                  # C ABI layer
│   │   ├── Cargo.toml
│   │   ├── build.rs              # cbindgen integration
│   │   ├── cbindgen.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── cipher.rs         # C API for cipher operations
│   │   │   ├── key.rs            # C API for key management
│   │   │   ├── session.rs        # C API for sessions
│   │   │   ├── error.rs          # C error codes
│   │   │   └── types.rs          # Opaque pointer types
│   │   ├── include/              # Generated C headers
│   │   │   └── acp.h
│   │   └── tests/
│   │
│   ├── acp-csharp/               # C# bindings
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   └── lib.rs            # P/Invoke helpers if needed
│   │   ├── dotnet/
│   │   │   ├── ACP.csproj
│   │   │   ├── ACP.cs            # Main C# wrapper
│   │   │   ├── Cipher.cs
│   │   │   ├── KeyManager.cs
│   │   │   ├── Session.cs
│   │   │   ├── Errors.cs
│   │   │   └── Native.cs         # P/Invoke declarations
│   │   └── tests/
│   │
│   └── acp-cpp/                  # C++ bindings
│       ├── Cargo.toml
│       ├── include/
│       │   ├── acp.hpp           # Main C++ header
│       │   ├── cipher.hpp
│       │   ├── key.hpp
│       │   ├── session.hpp
│       │   └── error.hpp
│       ├── src/
│       │   └── acp.cpp           # C++ wrapper implementation
│       └── tests/
│
├── examples/
│   ├── rust/
│   │   ├── basic_encryption.rs
│   │   ├── session_management.rs
│   │   └── key_derivation.rs
│   ├── c/
│   │   ├── basic_encryption.c
│   │   └── CMakeLists.txt
│   ├── csharp/
│   │   ├── BasicEncryption.cs
│   │   └── BasicEncryption.csproj
│   └── cpp/
│       ├── basic_encryption.cpp
│       └── CMakeLists.txt
│
├── tests/
│   ├── integration/              # Cross-language integration tests
│   │   ├── rust_to_c.rs
│   │   ├── interop_test.sh
│   │   └── vectors/              # Test vectors
│   └── fuzz/
│       ├── Cargo.toml
│       └── fuzz_targets/
│           ├── fuzz_cipher.rs
│           └── fuzz_key.rs
│
├── ci/
│   ├── build.sh
│   ├── test.sh
│   └── release.sh
│
└── .github/
    └── workflows/
        ├── ci.yml
        ├── security.yml
        └── release.yml
```

## 2. Crate Breakdown

### acp-core
**Purpose**: Core Rust library with clean, idiomatic API  
**Dependencies**: 
- `aes-gcm` (RustCrypto AEAD)
- `chacha20poly1305` (RustCrypto AEAD)
- `hkdf` (Key derivation)
- `argon2` (Password hashing)
- `zeroize` (Secure memory clearing)
- `thiserror` (Error handling)

**Features**:
- `default = ["std"]`
- `std` - Standard library support
- `alloc` - Allocation without std
- `avm` - Optional AVM submodule integration

### acp-ffi
**Purpose**: C ABI layer for FFI  
**Dependencies**: 
- `acp-core`
- `libc`

**Build**: Uses `cbindgen` in `build.rs` to generate `acp.h`

### acp-csharp
**Purpose**: C# bindings and NuGet package  
**Structure**: 
- Rust crate for native library compilation
- .NET project for managed wrapper

**Target Frameworks**: `net6.0`, `net8.0`

### acp-cpp
**Purpose**: Modern C++ (C++17) wrapper  
**Structure**: Header-only wrapper around C ABI

## 3. Public API Design

### Core Traits (Rust)

```rust
// acp-core/src/cipher.rs
pub trait Cipher: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;
    
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

pub trait CipherFactory {
    type Cipher: Cipher;
    type Error: std::error::Error + Send + Sync + 'static;
    
    fn create(&self, key: &Key) -> Result<Self::Cipher, Self::Error>;
}

// acp-core/src/key.rs
pub struct Key {
    bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl Key {
    pub fn generate(algorithm: Algorithm) -> Result<Self, KeyError>;
    pub fn from_bytes(bytes: Vec<u8>) -> Self;
    pub fn derive(password: &[u8], salt: &[u8], params: &KdfParams) -> Result<Self, KeyError>;
}

pub trait KeyManager: Send + Sync {
    fn generate_key(&mut self, id: &str, algorithm: Algorithm) -> Result<(), KeyError>;
    fn get_key(&self, id: &str) -> Result<Key, KeyError>;
    fn delete_key(&mut self, id: &str) -> Result<(), KeyError>;
}

// acp-core/src/session.rs
pub struct Session {
    cipher: Box<dyn Cipher<Error = CipherError>>,
    metadata: SessionMetadata,
}

impl Session {
    pub fn new(key: &Key, algorithm: Algorithm) -> Result<Self, SessionError>;
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError>;
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError>;
}

// acp-core/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum AcpError {
    #[error("Cipher error: {0}")]
    Cipher(#[from] CipherError),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error("Session error: {0}")]
    Session(#[from] SessionError),
}

#[derive(Debug, thiserror::Error)]
pub enum CipherError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid key size")]
    InvalidKeySize,
}
```

### C API (FFI)

```c
// acp-ffi/include/acp.h (generated by cbindgen)

typedef struct AcpCipher AcpCipher;
typedef struct AcpKey AcpKey;
typedef struct AcpSession AcpSession;

typedef enum {
    ACP_OK = 0,
    ACP_ERR_ENCRYPTION_FAILED = 1,
    ACP_ERR_DECRYPTION_FAILED = 2,
    ACP_ERR_INVALID_KEY = 3,
    ACP_ERR_NULL_POINTER = 4,
} AcpErrorCode;

typedef enum {
    ACP_ALGORITHM_AES_256_GCM = 0,
    ACP_ALGORITHM_CHACHA20_POLY1305 = 1,
} AcpAlgorithm;

// Key management
AcpErrorCode acp_key_generate(AcpAlgorithm algorithm, AcpKey** out_key);
AcpErrorCode acp_key_from_bytes(const uint8_t* bytes, size_t len, AcpKey** out_key);
AcpErrorCode acp_key_derive(const uint8_t* password, size_t password_len,
                             const uint8_t* salt, size_t salt_len,
                             AcpKey** out_key);
void acp_key_free(AcpKey* key);

// Session management
AcpErrorCode acp_session_new(const AcpKey* key, AcpAlgorithm algorithm, AcpSession** out_session);
AcpErrorCode acp_session_encrypt(const AcpSession* session,
                                  const uint8_t* plaintext, size_t plaintext_len,
                                  uint8_t** out_ciphertext, size_t* out_len);
AcpErrorCode acp_session_decrypt(const AcpSession* session,
                                  const uint8_t* ciphertext, size_t ciphertext_len,
                                  uint8_t** out_plaintext, size_t* out_len);
void acp_session_free(AcpSession* session);

// Memory management
void acp_free_buffer(uint8_t* buffer);

// Error handling
const char* acp_error_message(AcpErrorCode code);
```

### C# API

```csharp
// acp-csharp/dotnet/ACP.cs
namespace Astrolune.Cipher;

public enum Algorithm
{
    Aes256Gcm,
    ChaCha20Poly1305
}

public class Key : IDisposable
{
    public static Key Generate(Algorithm algorithm);
    public static Key FromBytes(byte[] bytes);
    public static Key Derive(byte[] password, byte[] salt);
    public void Dispose();
}

public class Session : IDisposable
{
    public Session(Key key, Algorithm algorithm);
    public byte[] Encrypt(byte[] plaintext);
    public byte[] Decrypt(byte[] ciphertext);
    public void Dispose();
}

public class AcpException : Exception
{
    public AcpErrorCode ErrorCode { get; }
}
```

### C++ API

```cpp
// acp-cpp/include/acp.hpp
namespace acp {

enum class Algorithm {
    Aes256Gcm,
    ChaCha20Poly1305
};

class Key {
public:
    static Key generate(Algorithm algorithm);
    static Key from_bytes(std::span<const uint8_t> bytes);
    static Key derive(std::span<const uint8_t> password, 
                      std::span<const uint8_t> salt);
    
    ~Key();
    Key(Key&&) noexcept;
    Key& operator=(Key&&) noexcept;
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class Session {
public:
    Session(const Key& key, Algorithm algorithm);
    
    std::vector<uint8_t> encrypt(std::span<const uint8_t> plaintext);
    std::vector<uint8_t> decrypt(std::span<const uint8_t> ciphertext);
    
    ~Session();
    Session(Session&&) noexcept;
    Session& operator=(Session&&) noexcept;
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class Exception : public std::runtime_error {
public:
    ErrorCode error_code() const noexcept;
};

} // namespace acp
```

## 4. FFI Boundary Design

### Principles
1. **Opaque pointers**: All Rust types exposed as opaque pointers
2. **Error codes**: C-style error codes, no exceptions across FFI
3. **Memory ownership**: Clear ownership rules (caller frees with `acp_free_*`)
4. **No panics**: All Rust code catches panics at FFI boundary
5. **Thread safety**: All FFI functions are thread-safe

### Error Handling Pattern

```rust
// acp-ffi/src/lib.rs
#[no_mangle]
pub extern "C" fn acp_session_encrypt(
    session: *const AcpSession,
    plaintext: *const u8,
    plaintext_len: usize,
    out_ciphertext: *mut *mut u8,
    out_len: *mut usize,
) -> AcpErrorCode {
    // Null pointer checks
    if session.is_null() || plaintext.is_null() || out_ciphertext.is_null() || out_len.is_null() {
        return AcpErrorCode::NullPointer;
    }
    
    // Catch panics
    let result = std::panic::catch_unwind(|| {
        let session = unsafe { &*session };
        let plaintext_slice = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
        
        session.inner.encrypt(plaintext_slice)
    });
    
    match result {
        Ok(Ok(ciphertext)) => {
            let len = ciphertext.len();
            let ptr = Box::into_raw(ciphertext.into_boxed_slice()) as *mut u8;
            unsafe {
                *out_ciphertext = ptr;
                *out_len = len;
            }
            AcpErrorCode::Ok
        }
        Ok(Err(_)) => AcpErrorCode::EncryptionFailed,
        Err(_) => AcpErrorCode::InternalError,
    }
}
```

## 5. Test Strategy

### Unit Tests
- **Location**: `crates/*/tests/`
- **Coverage**: Each module in `acp-core`
- **Focus**: Algorithm correctness, error handling, edge cases

### Integration Tests
- **Location**: `tests/integration/`
- **Coverage**: 
  - Rust ↔ C interop
  - C ↔ C# interop
  - C ↔ C++ interop
  - Cross-language encryption/decryption
- **Test vectors**: NIST test vectors for AEAD algorithms

### Fuzz Tests
- **Tool**: `cargo-fuzz` (libFuzzer)
- **Targets**:
  - `fuzz_cipher`: Random inputs to encrypt/decrypt
  - `fuzz_key`: Random key generation/derivation
  - `fuzz_ffi`: Random FFI calls with invalid inputs

### Property-Based Tests
- **Tool**: `proptest`
- **Properties**:
  - `decrypt(encrypt(m)) == m`
  - Key derivation determinism
  - Error handling consistency

### Security Tests
- **Memory safety**: Valgrind, AddressSanitizer
- **Timing attacks**: Constant-time verification
- **Side channels**: Cache-timing analysis

## 6. CI/CD Plan

### GitHub Actions Workflows

#### `ci.yml` - Continuous Integration
```yaml
on: [push, pull_request]

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        rust: [stable, nightly]
    steps:
      - Checkout
      - Install Rust toolchain
      - cargo test --all-features
      - cargo clippy -- -D warnings
      - cargo fmt --check
      
  test-bindings:
    steps:
      - Build acp-ffi
      - Test C examples
      - Test C# bindings (.NET 6, 8)
      - Test C++ bindings
      
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - cargo fuzz run --all-targets -- -max_total_time=300
      
  coverage:
    steps:
      - cargo tarpaulin --all-features --out Xml
      - Upload to Codecov
```

#### `security.yml` - Security Audits
```yaml
on:
  schedule:
    - cron: '0 0 * * *'  # Daily
    
jobs:
  audit:
    steps:
      - cargo audit
      - cargo deny check
      
  sanitizers:
    strategy:
      matrix:
        sanitizer: [address, memory, thread]
    steps:
      - RUSTFLAGS="-Z sanitizer=${{ matrix.sanitizer }}"
      - cargo test
```

#### `release.yml` - Release Automation
```yaml
on:
  push:
    tags:
      - 'v*'
      
jobs:
  build-native:
    strategy:
      matrix:
        target: [x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu, 
                 x86_64-apple-darwin, aarch64-apple-darwin]
    steps:
      - cargo build --release --target ${{ matrix.target }}
      - Upload artifacts
      
  publish-crates:
    steps:
      - cargo publish -p acp-core
      - cargo publish -p acp-ffi
      
  publish-nuget:
    steps:
      - dotnet pack acp-csharp/dotnet/ACP.csproj
      - dotnet nuget push
```

## 7. Packaging & Release Strategy

### Versioning
- **Scheme**: Semantic Versioning 2.0.0
- **Sync**: All crates share same version
- **Breaking changes**: Major version bump

### Rust Crates (crates.io)
- `acp-core` - Core library
- `acp-ffi` - C bindings
- `acp-csharp` - C# support crate
- `acp-cpp` - C++ support crate

### C/C++ Distribution
- **Headers**: `acp.h` in releases
- **Libraries**: 
  - Linux: `libacp.so`
  - Windows: `acp.dll`
  - macOS: `libacp.dylib`
- **Package managers**: vcpkg, Conan

### C# NuGet Package
- **Package**: `Astrolune.Cipher`
- **Contents**: 
  - Managed DLL
  - Native libraries (runtimes/win-x64, linux-x64, osx-x64)
- **Targets**: net6.0, net8.0

### Documentation
- **Rust**: docs.rs automatic
- **C**: Doxygen from headers
- **C#**: XML docs → DocFX
- **C++**: Doxygen

### Release Checklist
1. Update CHANGELOG.md
2. Bump version in all Cargo.toml
3. Run full test suite
4. Security audit
5. Tag release
6. CI builds all artifacts
7. Publish to crates.io
8. Publish to NuGet
9. Create GitHub release with binaries
10. Update documentation

## 8. AVM Integration

### Submodule Setup
```bash
git submodule add https://github.com/Astrolune/AVM AVM
```

### Feature Flag
```toml
# acp-core/Cargo.toml
[features]
avm = ["avm-sys"]

[dependencies]
avm-sys = { path = "../AVM", optional = true }
```

### Usage Pattern
```rust
#[cfg(feature = "avm")]
pub mod avm_integration {
    use avm_sys::*;
    
    pub fn create_avm_session(key: &Key) -> Result<Session, AcpError> {
        // AVM-specific session creation
    }
}
```

## 9. Security Considerations

### Memory Safety
- Use `zeroize` for sensitive data
- No unsafe code in public API
- FFI boundary validates all pointers

### Cryptographic Guarantees
- Only NIST-approved algorithms
- Constant-time operations
- No custom crypto implementations

### Supply Chain Security
- Dependency pinning
- `cargo-deny` for license/security checks
- Reproducible builds

### Audit Trail
- All releases signed
- SBOM (Software Bill of Materials)
- Security advisories via GitHub Security

---

**Status**: Architecture design complete  
**Next Steps**: Implementation of `acp-core` crate
