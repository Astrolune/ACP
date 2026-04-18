//! Opaque types for C FFI

use acp_core::{Algorithm, Key, Session};

/// Opaque key handle
#[repr(C)]
pub struct AcpKey {
    pub(crate) inner: Key,
}

/// Opaque session handle
#[repr(C)]
pub struct AcpSession {
    pub(crate) inner: Session,
}

/// Algorithm identifier
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpAlgorithm {
    /// AES-256-GCM
    Aes256Gcm = 0,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305 = 1,
}

impl From<AcpAlgorithm> for Algorithm {
    fn from(algo: AcpAlgorithm) -> Self {
        match algo {
            AcpAlgorithm::Aes256Gcm => Algorithm::Aes256Gcm,
            AcpAlgorithm::ChaCha20Poly1305 => Algorithm::ChaCha20Poly1305,
        }
    }
}

impl From<Algorithm> for AcpAlgorithm {
    fn from(algo: Algorithm) -> Self {
        match algo {
            Algorithm::Aes256Gcm => AcpAlgorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305 => AcpAlgorithm::ChaCha20Poly1305,
        }
    }
}
