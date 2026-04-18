# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-18

### Added
- Initial release of ACP (Astrolune Cipher Protocol)
- Core Rust library (`acp-core`) with:
  - AES-256-GCM encryption
  - ChaCha20-Poly1305 encryption
  - Key generation and derivation (Argon2, HKDF)
  - Session management
  - In-memory key manager
- C FFI bindings (`acp-ffi`)
- C# bindings (`acp-csharp`)
- C++ bindings (`acp-cpp`)
- Comprehensive examples for all languages
- Integration tests and fuzz tests
- CI/CD pipeline with GitHub Actions
- Security audit workflow
- Documentation and architecture guide

### Security
- Memory-safe implementation in Rust
- Automatic key zeroing with `zeroize`
- Constant-time cryptographic operations
- No custom cryptography - only proven primitives

[Unreleased]: https://github.com/Astrolune/ACP/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Astrolune/ACP/releases/tag/v0.1.0
