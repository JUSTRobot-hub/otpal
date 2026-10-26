//! Password hashing (Argon2id) and Windows account binding (DPAPI).
//!
//! Argon2id is memory-hard, so guessing a master password on graphics cards
//! costs an attacker far more than with PBKDF2. DPAPI wraps the whole vault file
//! with a key held by Windows for this user account, so a copy of `vault.json`
//! taken to another machine cannot be opened even with the right password.

use argon2::{Algorithm, Argon2, Params, Version};

/// Mixed into DPAPI so another program asking Windows to unprotect a blob it
/// found would also need to know this. It is not a secret, only a speed bump.
const DPAPI_ENTROPY: &[u8] = b"com.otpal.app/vault/v2";

pub fn derive(password: &str, salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<[u8; 32], String> {
    if salt.len() < 16 {
        return Err("salt too short".into());
    }
    if !(8 * 1024..=512 * 1024).contains(&m_kib) || !(1..=20).contains(&t) || !(1..=16).contains(&p) {
        return Err("unsupported key derivation settings".into());
    }
    let params = Params::new(m_kib, t, p, Some(32)).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

#[cfg(windows)]
mod dpapi {
    use super::DPAPI_ENTROPY;
    use std::{ptr, slice};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
    }

    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        // SAFETY: Windows allocated `out.pbData` with `cbData` bytes; we copy then free it.
        unsafe {
            let bytes = slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            LocalFree(out.pbData as _);
            bytes
        }
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        let input = blob(data);
        let entropy = blob(DPAPI_ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
        // SAFETY: all pointers refer to live locals; `out` is filled by Windows.
        let ok = unsafe {
            CryptProtectData(&input, ptr::null(), &entropy, ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        };
        if ok == 0 {
            return Err("Windows could not protect the vault".into());
        }
        Ok(take(out))
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        let input = blob(data);
        let entropy = blob(DPAPI_ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
        // SAFETY: as above.
        let ok = unsafe {
            CryptUnprotectData(&input, ptr::null_mut(), &entropy, ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        };
        if ok == 0 {
            return Err("This vault is bound to a different Windows account or computer".into());
        }
        Ok(take(out))
    }
}

#[cfg(not(windows))]
mod dpapi {
    pub fn protect(_: &[u8]) -> Result<Vec<u8>, String> {
        Err("Windows account binding is only available on Windows".into())
    }
    pub fn unprotect(_: &[u8]) -> Result<Vec<u8>, String> {
        Err("Windows account binding is only available on Windows".into())
    }
}

pub use dpapi::{protect, unprotect};

#[tauri::command]
pub fn dpapi_available() -> bool {
    cfg!(windows)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"0123456789abcdef";

    #[test]
    fn argon2_is_deterministic_and_input_sensitive() {
        let a = derive("correct horse", SALT, 8 * 1024, 1, 1).unwrap();
        assert_eq!(a, derive("correct horse", SALT, 8 * 1024, 1, 1).unwrap());
        assert_ne!(a, derive("correct horsf", SALT, 8 * 1024, 1, 1).unwrap());
        assert_ne!(a, derive("correct horse", b"fedcba9876543210", 8 * 1024, 1, 1).unwrap());
        assert_ne!(a, derive("correct horse", SALT, 8 * 1024, 2, 1).unwrap());
    }

    #[test]
    fn argon2_rejects_unsafe_or_absurd_settings() {
        assert!(derive("x", b"short", 8 * 1024, 1, 1).is_err());
        assert!(derive("x", SALT, 1024, 1, 1).is_err());
        assert!(derive("x", SALT, 8 * 1024 * 1024, 1, 1).is_err());
        assert!(derive("x", SALT, 8 * 1024, 0, 1).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trips_and_hides_the_data() {
        let secret = b"JBSWY3DPEHPK3PXP vault contents";
        let blob = protect(secret).unwrap();
        assert!(!blob.windows(secret.len()).any(|w| w == secret));
        assert_eq!(unprotect(&blob).unwrap(), secret);

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(unprotect(&tampered).is_err());
        assert!(unprotect(b"not a dpapi blob").is_err());
    }
}
