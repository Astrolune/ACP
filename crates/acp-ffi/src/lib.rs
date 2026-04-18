//! C FFI bindings for ACP

#![allow(non_camel_case_types)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use acp_core::{Key, Session};

mod error;
mod types;

pub use error::AcpErrorCode;
pub use types::*;

/// Generate a new key for the specified algorithm
///
/// # Safety
/// - `out_key` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn acp_key_generate(
    algorithm: AcpAlgorithm,
    out_key: *mut *mut AcpKey,
) -> AcpErrorCode {
    if out_key.is_null() {
        return AcpErrorCode::NullPointer;
    }

    let result = catch_unwind(|| {
        let algo = algorithm.into();
        Key::generate(algo)
    });

    match result {
        Ok(Ok(key)) => {
            let boxed = Box::new(AcpKey { inner: key });
            *out_key = Box::into_raw(boxed);
            AcpErrorCode::Ok
        }
        Ok(Err(_)) => AcpErrorCode::KeyGenerationFailed,
        Err(_) => AcpErrorCode::InternalError,
    }
}

/// Create a key from raw bytes
///
/// # Safety
/// - `bytes` must be valid for `len` bytes
/// - `out_key` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn acp_key_from_bytes(
    bytes: *const u8,
    len: usize,
    algorithm: AcpAlgorithm,
    out_key: *mut *mut AcpKey,
) -> AcpErrorCode {
    if bytes.is_null() || out_key.is_null() {
        return AcpErrorCode::NullPointer;
    }

    let result = catch_unwind(|| {
        let bytes_slice = slice::from_raw_parts(bytes, len);
        let algo = algorithm.into();
        Key::from_bytes(bytes_slice.to_vec(), algo)
    });

    match result {
        Ok(Ok(key)) => {
            let boxed = Box::new(AcpKey { inner: key });
            *out_key = Box::into_raw(boxed);
            AcpErrorCode::Ok
        }
        Ok(Err(_)) => AcpErrorCode::InvalidKey,
        Err(_) => AcpErrorCode::InternalError,
    }
}

/// Derive a key from a password using Argon2
///
/// # Safety
/// - `password` must be valid for `password_len` bytes
/// - `salt` must be valid for `salt_len` bytes
/// - `out_key` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn acp_key_derive(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    algorithm: AcpAlgorithm,
    out_key: *mut *mut AcpKey,
) -> AcpErrorCode {
    if password.is_null() || salt.is_null() || out_key.is_null() {
        return AcpErrorCode::NullPointer;
    }

    let result = catch_unwind(|| {
        let password_slice = slice::from_raw_parts(password, password_len);
        let salt_slice = slice::from_raw_parts(salt, salt_len);
        let algo = algorithm.into();
        Key::derive(password_slice, salt_slice, algo)
    });

    match result {
        Ok(Ok(key)) => {
            let boxed = Box::new(AcpKey { inner: key });
            *out_key = Box::into_raw(boxed);
            AcpErrorCode::Ok
        }
        Ok(Err(_)) => AcpErrorCode::KeyDerivationFailed,
        Err(_) => AcpErrorCode::InternalError,
    }
}

/// Free a key
///
/// # Safety
/// - `key` must be a valid pointer returned from `acp_key_*` functions
/// - `key` must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn acp_key_free(key: *mut AcpKey) {
    if !key.is_null() {
        let _ = Box::from_raw(key);
    }
}

/// Create a new session
///
/// # Safety
/// - `key` must be a valid pointer
/// - `session_id` must be a valid null-terminated string
/// - `out_session` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn acp_session_new(
    key: *const AcpKey,
    session_id: *const libc::c_char,
    out_session: *mut *mut AcpSession,
) -> AcpErrorCode {
    if key.is_null() || session_id.is_null() || out_session.is_null() {
        return AcpErrorCode::NullPointer;
    }

    let result = catch_unwind(|| {
        let key_ref = &(*key).inner;
        let id = std::ffi::CStr::from_ptr(session_id)
            .to_str()
            .unwrap()
            .to_string();
        Session::new(key_ref, id)
    });

    match result {
        Ok(Ok(session)) => {
            let boxed = Box::new(AcpSession { inner: session });
            *out_session = Box::into_raw(boxed);
            AcpErrorCode::Ok
        }
        Ok(Err(_)) => AcpErrorCode::SessionCreationFailed,
        Err(_) => AcpErrorCode::InternalError,
    }
}

/// Encrypt plaintext
///
/// # Safety
/// - `session` must be a valid pointer
/// - `plaintext` must be valid for `plaintext_len` bytes
/// - `out_ciphertext` and `out_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn acp_session_encrypt(
    session: *const AcpSession,
    plaintext: *const u8,
    plaintext_len: usize,
    out_ciphertext: *mut *mut u8,
    out_len: *mut usize,
) -> AcpErrorCode {
    if session.is_null() || plaintext.is_null() || out_ciphertext.is_null() || out_len.is_null() {
        return AcpErrorCode::NullPointer;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let session_ref = &(*session).inner;
        let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len);
        session_ref.encrypt(plaintext_slice)
    }));

    match result {
        Ok(Ok(ciphertext)) => {
            let len = ciphertext.len();
            let ptr = Box::into_raw(ciphertext.into_boxed_slice()) as *mut u8;
            *out_ciphertext = ptr;
            *out_len = len;
            AcpErrorCode::Ok
        }
        Ok(Err(_)) => AcpErrorCode::EncryptionFailed,
        Err(_) => AcpErrorCode::InternalError,
    }
}

/// Decrypt ciphertext
///
/// # Safety
/// - `session` must be a valid pointer
/// - `ciphertext` must be valid for `ciphertext_len` bytes
/// - `out_plaintext` and `out_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn acp_session_decrypt(
    session: *const AcpSession,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out_plaintext: *mut *mut u8,
    out_len: *mut usize,
) -> AcpErrorCode {
    if session.is_null() || ciphertext.is_null() || out_plaintext.is_null() || out_len.is_null() {
        return AcpErrorCode::NullPointer;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let session_ref = &(*session).inner;
        let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len);
        session_ref.decrypt(ciphertext_slice)
    }));

    match result {
        Ok(Ok(plaintext)) => {
            let len = plaintext.len();
            let ptr = Box::into_raw(plaintext.into_boxed_slice()) as *mut u8;
            *out_plaintext = ptr;
            *out_len = len;
            AcpErrorCode::Ok
        }
        Ok(Err(_)) => AcpErrorCode::DecryptionFailed,
        Err(_) => AcpErrorCode::InternalError,
    }
}

/// Free a session
///
/// # Safety
/// - `session` must be a valid pointer returned from `acp_session_new`
/// - `session` must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn acp_session_free(session: *mut AcpSession) {
    if !session.is_null() {
        let _ = Box::from_raw(session);
    }
}

/// Free a buffer allocated by ACP
///
/// # Safety
/// - `buffer` must be a valid pointer returned from ACP functions
/// - `buffer` must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn acp_free_buffer(buffer: *mut u8) {
    if !buffer.is_null() {
        let _ = Box::from_raw(buffer);
    }
}

/// Get error message for an error code
///
/// # Safety
/// - Returns a static string, no need to free
#[no_mangle]
pub extern "C" fn acp_error_message(code: AcpErrorCode) -> *const libc::c_char {
    code.message().as_ptr() as *const libc::c_char
}

/// Get library version
///
/// # Safety
/// - Returns a static string, no need to free
#[no_mangle]
pub extern "C" fn acp_version() -> *const libc::c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const libc::c_char
}
