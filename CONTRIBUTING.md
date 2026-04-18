# Contributing to ACP

Thank you for your interest in contributing to ACP (Astrolune Cipher Protocol)!

## Code of Conduct

Be respectful, professional, and constructive in all interactions.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/Astrolune/ACP/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Rust version, etc.)
   - Code samples if applicable

### Suggesting Features

1. Check existing issues and discussions
2. Create a new issue with:
   - Clear use case
   - Proposed API design
   - Alternatives considered
   - Impact on existing code

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes following our coding standards
4. Add tests for new functionality
5. Ensure all tests pass: `cargo test --all-features`
6. Run clippy: `cargo clippy --all-targets --all-features -- -D warnings`
7. Format code: `cargo fmt --all`
8. Commit with clear messages
9. Push and create a pull request

## Development Setup

```bash
# Clone with submodules
git clone --recursive https://github.com/Astrolune/ACP.git
cd ACP

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build --all-features

# Run tests
cargo test --all-features

# Run examples
cargo run --example basic_encryption
```

## Coding Standards

### Rust Code

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for formatting
- Pass `cargo clippy` with no warnings
- Write documentation for public APIs
- Add tests for new functionality
- Keep functions small and focused
- Prefer explicit error handling over panics

### Comments

- Write comments only when the WHY is non-obvious
- Don't comment WHAT the code does (use clear naming instead)
- Document public APIs with `///` doc comments
- Include examples in doc comments

### Testing

- Unit tests in the same file as the code
- Integration tests in `tests/` directory
- Property-based tests for complex logic
- Fuzz tests for parsing/validation code

### Security

- No custom cryptography
- Use only proven primitives
- Validate all inputs at boundaries
- Use `zeroize` for sensitive data
- Avoid timing side-channels
- Document security assumptions

## Commit Messages

Format: `<type>: <description>`

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Build/tooling changes

Examples:
```
feat: add ChaCha20-Poly1305 support
fix: prevent panic on invalid key size
docs: update API examples in README
test: add fuzz target for key derivation
```

## Review Process

1. Automated checks must pass (CI, tests, clippy, fmt)
2. At least one maintainer review required
3. Security-sensitive changes require additional review
4. Breaking changes need discussion and approval

## Release Process

Maintainers handle releases:

1. Update version in `Cargo.toml` files
2. Update `CHANGELOG.md`
3. Create git tag: `v0.x.y`
4. Push tag to trigger release workflow
5. Publish to crates.io and NuGet

## Questions?

- Open a [Discussion](https://github.com/Astrolune/ACP/discussions)
- Join our community chat (coming soon)
- Email: support@astrolune.dev

## License

By contributing, you agree that your contributions will be licensed under both MIT and Apache-2.0 licenses.
