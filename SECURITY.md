# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: security@astrolune.dev

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Measures

ACP implements multiple layers of security:

### Cryptographic Security

- **No Custom Crypto**: Only NIST-approved, peer-reviewed algorithms
- **Proven Primitives**: AES-256-GCM, ChaCha20-Poly1305 from RustCrypto
- **Constant-Time Operations**: Protection against timing attacks
- **Authenticated Encryption**: AEAD modes prevent tampering

### Memory Safety

- **Rust Language**: Memory-safe by design, no buffer overflows
- **Automatic Zeroing**: Keys automatically zeroed on drop via `zeroize`
- **No Unsafe Code**: Core library is `#![forbid(unsafe_code)]`
- **FFI Safety**: All FFI boundaries validate pointers and catch panics

### Development Practices

- **Dependency Auditing**: Daily `cargo-audit` runs
- **Fuzz Testing**: Continuous fuzzing with libFuzzer
- **Sanitizers**: Address, memory, and leak sanitizers in CI
- **Code Review**: All changes require review
- **Minimal Dependencies**: Small dependency tree, all audited

### Supply Chain Security

- **Dependency Pinning**: Exact versions in `Cargo.lock`
- **License Checking**: `cargo-deny` for license compliance
- **SBOM Generation**: Software Bill of Materials for releases
- **Signed Releases**: All releases are cryptographically signed

## Known Limitations

- **Side-Channel Attacks**: While we use constant-time operations, physical side-channel attacks (power analysis, EM) are out of scope
- **Quantum Resistance**: Current algorithms are not quantum-resistant
- **Key Management**: Users are responsible for secure key storage
- **Random Number Generation**: Relies on OS-provided randomness

## Security Updates

Security updates will be released as soon as possible after a vulnerability is confirmed. Users should:

1. Subscribe to GitHub Security Advisories for this repository
2. Keep dependencies up to date
3. Monitor the [CHANGELOG](CHANGELOG.md) for security fixes
4. Use the latest stable version

## Disclosure Policy

- **Coordinated Disclosure**: We follow a 90-day disclosure timeline
- **Credit**: Security researchers will be credited (unless they prefer anonymity)
- **CVE Assignment**: We will request CVEs for confirmed vulnerabilities
- **Public Advisory**: Security advisories will be published on GitHub

## Security Checklist for Users

- [ ] Use the latest stable version
- [ ] Enable all security features in production
- [ ] Store keys securely (hardware security modules, key vaults)
- [ ] Use strong key derivation parameters
- [ ] Implement proper access controls
- [ ] Monitor for security advisories
- [ ] Audit your usage of the library
- [ ] Test your integration thoroughly

## Contact

For security concerns: security@astrolune.dev  
For general questions: support@astrolune.dev

PGP Key: [Coming Soon]
