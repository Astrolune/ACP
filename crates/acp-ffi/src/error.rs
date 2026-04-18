//! Error codes for C FFI

use std::ffi::CStr;

/// Error codes returned by ACP functions
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpErrorCode {
    /// Operation succeeded
    Ok = 0,
    /// Encryption failed
    EncryptionFailed = 1,
    /// Decryption failed
    DecryptionFailed = 2,
    /// Invalid key
    InvalidKey = 3,
    /// Null pointer passed
    NullPointer = 4,
    /// Key generation failed
    KeyGenerationFailed = 5,
    /// Key derivation failed
    KeyDerivationFailed = 6,
    /// Session creation failed
    SessionCreationFailed = 7,
    /// Internal error
    InternalError = 99,
}

impl AcpErrorCode {
    /// Get error message as C string
    pub fn message(self) -> &'static CStr {
        unsafe {
            match self {
                AcpErrorCode::Ok => CStr::from_bytes_with_nul_unchecked(b"Success\0"),
                AcpErrorCode::EncryptionFailed => CStr::from_bytes_with_nul_unchecked(b"Encryption failed\0"),
                AcpErrorCode::DecryptionFailed => CStr::from_bytes_with_nul_unchecked(b"Decryption failed\0"),
                AcpErrorCode::InvalidKey => CStr::from_bytes_with_nul_unchecked(b"Invalid key\0"),
                AcpErrorCode::NullPointer => CStr::from_bytes_with_nul_unchecked(b"Null pointer\0"),
                AcpErrorCode::KeyGenerationFailed => CStr::from_bytes_with_nul_unchecked(b"Key generation failed\0"),
                AcpErrorCode::KeyDerivationFailed => CStr::from_bytes_with_nul_unchecked(b"Key derivation failed\0"),
                AcpErrorCode::SessionCreationFailed => CStr::from_bytes_with_nul_unchecked(b"Session creation failed\0"),
                AcpErrorCode::InternalError => CStr::from_bytes_with_nul_unchecked(b"Internal error\0"),
            }
        }
    }
}
