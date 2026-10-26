//! Windows Hello (fingerprint, face or PIN) as an alternative to typing the master password.
//!
//! Hello creates a key pair held by Windows (TPM-backed where available). Signing a fixed
//! challenge with it needs a Hello check each time, and an RSA PKCS#1 signature is the same
//! every time, so a hash of it works as an encryption key the JS side uses to protect the
//! master password. Nothing here ever sees the password.

use base64::{engine::general_purpose::STANDARD, Engine};
use std::fs;
use tauri::AppHandle;

const FILE: &str = "hello.json";

fn file_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(crate::vault_path(app)?.with_file_name(FILE))
}

#[cfg(windows)]
mod imp {
    use windows::core::{Array, HSTRING};
    use windows::Security::Credentials::{
        KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;

    const KEY_NAME: &str = "otpal-vault";
    const CHALLENGE: &[u8] = b"otpal vault unlock challenge v1";

    fn err(e: windows::core::Error) -> String {
        e.message()
    }

    pub fn available() -> bool {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.get())
            .unwrap_or(false)
    }

    fn sign(credential: &KeyCredential) -> Result<Vec<u8>, String> {
        let challenge = CryptographicBuffer::CreateFromByteArray(CHALLENGE).map_err(err)?;
        let result = credential
            .RequestSignAsync(&challenge)
            .and_then(|op| op.get())
            .map_err(err)?;
        match result.Status().map_err(err)? {
            KeyCredentialStatus::Success => {}
            KeyCredentialStatus::UserCanceled => return Err("Windows Hello was cancelled.".into()),
            _ => return Err("Windows Hello could not verify you.".into()),
        }
        let sig = result.Result().map_err(err)?;
        let mut out = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&sig, &mut out).map_err(err)?;
        Ok(out.to_vec())
    }

    /// Creates (or replaces) the Hello key and returns a signature of the challenge.
    pub fn enroll() -> Result<Vec<u8>, String> {
        let result = KeyCredentialManager::RequestCreateAsync(
            &HSTRING::from(KEY_NAME),
            KeyCredentialCreationOption::ReplaceExisting,
        )
        .and_then(|op| op.get())
        .map_err(err)?;
        match result.Status().map_err(err)? {
            KeyCredentialStatus::Success => {}
            KeyCredentialStatus::UserCanceled => return Err("Windows Hello was cancelled.".into()),
            _ => return Err("Windows Hello is not set up on this PC.".into()),
        }
        sign(&result.Credential().map_err(err)?)
    }

    pub fn unlock() -> Result<Vec<u8>, String> {
        let result = KeyCredentialManager::OpenAsync(&HSTRING::from(KEY_NAME))
            .and_then(|op| op.get())
            .map_err(err)?;
        match result.Status().map_err(err)? {
            KeyCredentialStatus::Success => {}
            KeyCredentialStatus::NotFound => return Err("Windows Hello is not set up for Otpal.".into()),
            KeyCredentialStatus::UserCanceled => return Err("Windows Hello was cancelled.".into()),
            _ => return Err("Windows Hello could not verify you.".into()),
        }
        sign(&result.Credential().map_err(err)?)
    }

    pub fn forget() {
        let _ = KeyCredentialManager::DeleteAsync(&HSTRING::from(KEY_NAME)).and_then(|op| op.get());
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn available() -> bool { false }
    pub fn enroll() -> Result<Vec<u8>, String> { Err("Windows Hello needs Windows.".into()) }
    pub fn unlock() -> Result<Vec<u8>, String> { Err("Windows Hello needs Windows.".into()) }
    pub fn forget() {}
}

// Blocking WinRT calls run on a plain thread so they never stall the UI.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn hello_available() -> Result<bool, String> {
    blocking(imp::available).await
}

/// Base64 signature that the front end hashes into the wrapping key.
#[tauri::command]
pub async fn hello_enroll() -> Result<String, String> {
    Ok(STANDARD.encode(blocking(imp::enroll).await??))
}

#[tauri::command]
pub async fn hello_unlock() -> Result<String, String> {
    Ok(STANDARD.encode(blocking(imp::unlock).await??))
}

#[tauri::command]
pub async fn hello_forget(app: AppHandle) -> Result<(), String> {
    blocking(imp::forget).await?;
    let path = file_path(&app)?;
    if path.exists() {
        fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub fn read_hello(app: AppHandle) -> Result<Option<String>, String> {
    let path = file_path(&app)?;
    if !path.exists() {
        return Ok(None);
    }
    fs::read_to_string(path).map(Some).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn write_hello(app: AppHandle, data: String) -> Result<(), String> {
    let path = file_path(&app)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, data).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| e.to_string())
}
