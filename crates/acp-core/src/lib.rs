//! ACP (Astrolune Cipher Protocol) - Core Library
//!
//! A secure, transport-agnostic cryptographic library providing:
//! - Encryption/decryption with proven AEAD algorithms
//! - Key management and derivation
//! - Session abstractions
//! - Clean FFI boundaries for multi-language support

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod cipher;
pub mod error;
pub mod key;
pub mod primitives;
pub mod session;

#[cfg(feature = "avm")]
pub mod avm_integration;

pub use cipher::{Cipher, CipherFactory};
pub use error::{AcpError, CipherError, KeyError, SessionError};
pub use key::{Algorithm, Key, KeyManager};
pub use session::{Session, SessionMetadata};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
