//! The unlocked vault lives here, in the Rust process, and nowhere else.
//!
//! The web view never receives a secret key or the encryption key. It gets the list of accounts
//! (issuer and name only) and, when the user clicks one, a single six-digit code. Importing is
//! the one moment a secret passes through the web view (it just decoded the QR code); it is
//! handed over here and dropped there.
//!
//! File format, unchanged from earlier versions so existing vaults keep opening:
//!   v1  PBKDF2-SHA256, AES-256-GCM        v2  Argon2id, AES-256-GCM
//!   optional outer wrap {v:2, wrap:"dpapi", blob} binding the file to the Windows account.

use crate::protect;
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::{
    sync::{atomic::{AtomicU64, Ordering}, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::{Zeroize, Zeroizing};

const ARGON2: Kdf = Kdf::Argon2id { m: 64 * 1024, t: 3, p: 1 };
const WRONG_PASSWORD: &str = "Wrong password";

#[derive(Clone, Debug, PartialEq)]
enum Kdf {
    Pbkdf2 { iterations: u32 },
    Argon2id { m: u32, t: u32, p: u32 },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub name: String,
    pub secret: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    #[serde(default = "default_digits")]
    pub digits: u32,
    #[serde(default = "default_period")]
    pub period: u64,
}

fn default_algorithm() -> String { "SHA1".into() }
fn default_digits() -> u32 { 6 }
fn default_period() -> u64 { 30 }

impl Drop for Account {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

struct Unlocked {
    key: Zeroizing<[u8; 32]>,
    salt: Vec<u8>,
    kdf: Kdf,
    bound: bool,
    accounts: Vec<Account>,
}

pub struct Vault {
    inner: Mutex<Option<Unlocked>>,
    last_activity: Mutex<Instant>,
    idle_secs: AtomicU64,
}

impl Default for Vault {
    fn default() -> Self {
        Self { inner: Mutex::new(None), last_activity: Mutex::new(Instant::now()), idle_secs: AtomicU64::new(120) }
    }
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Drops the unlocked vault (which wipes the key and secrets) and tells the window.
pub fn lock(app: &AppHandle) {
    let was_open = guard(&app.state::<Vault>().inner).take().is_some();
    if was_open {
        let _ = app.emit("vault-locked", ());
    }
}

/// Locks after the user has been idle for the configured time.
pub fn start_idle_watcher(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));
        let vault = app.state::<Vault>();
        let limit = Duration::from_secs(vault.idle_secs.load(Ordering::Relaxed));
        if guard(&vault.last_activity).elapsed() >= limit {
            lock(&app);
        }
    });
}

// ---------------------------------------------------------------- crypto

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("the system random generator is unavailable");
    out
}

fn derive_key(password: &str, salt: &[u8], kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>, String> {
    match kdf {
        Kdf::Argon2id { m, t, p } => protect::derive(password, salt, *m, *t, *p).map(Zeroizing::new),
        Kdf::Pbkdf2 { iterations } => {
            if !(1_000..=5_000_000).contains(iterations) || salt.len() < 16 {
                return Err("unsupported key derivation settings".into());
            }
            let mut out = Zeroizing::new([0u8; 32]);
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, *iterations, &mut *out);
            Ok(out)
        }
    }
}

fn default_kdf() -> Kdf {
    ARGON2
}

fn same_key(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Plain vault text (the inner, encrypted JSON). `kdf_header` records how the key was made.
fn encrypt_inner(u: &Unlocked) -> Result<String, String> {
    let iv: [u8; 12] = random();
    let plain = Zeroizing::new(serde_json::to_vec(&u.accounts).map_err(|e| e.to_string())?);
    let cipher = Aes256Gcm::new_from_slice(&u.key[..]).map_err(|e| e.to_string())?;
    let ct = cipher.encrypt(Nonce::from_slice(&iv), plain.as_slice()).map_err(|_| "encryption failed".to_string())?;
    let header = match &u.kdf {
        Kdf::Argon2id { m, t, p } => serde_json::json!({ "v": 2, "kdf": { "name": "argon2id", "m": m, "t": t, "p": p } }),
        Kdf::Pbkdf2 { iterations } => serde_json::json!({ "v": 1, "kdf": "PBKDF2-SHA256", "iterations": iterations }),
    };
    let mut file = header.as_object().cloned().unwrap_or_default();
    file.insert("salt".into(), B64.encode(&u.salt).into());
    file.insert("iv".into(), B64.encode(iv).into());
    file.insert("ct".into(), B64.encode(ct).into());
    serde_json::to_string(&file).map_err(|e| e.to_string())
}

/// File contents to write: the inner text, wrapped for this Windows account when bound.
fn seal(u: &Unlocked) -> Result<String, String> {
    let inner = Zeroizing::new(encrypt_inner(u)?);
    if !u.bound {
        return Ok(inner.to_string());
    }
    let blob = protect::protect(inner.as_bytes())?;
    Ok(serde_json::json!({ "v": 2, "wrap": "dpapi", "blob": B64.encode(blob) }).to_string())
}

/// Returns the inner vault text and whether the file was bound to the Windows account.
fn unseal(file: &str) -> Result<(String, bool), String> {
    let outer: serde_json::Value = serde_json::from_str(file).map_err(|_| "The vault file is damaged".to_string())?;
    if outer.get("wrap").and_then(|w| w.as_str()) != Some("dpapi") {
        return Ok((file.to_string(), false));
    }
    let blob = B64.decode(outer["blob"].as_str().unwrap_or_default()).map_err(|_| "The vault file is damaged".to_string())?;
    let inner = protect::unprotect(&blob)?;
    Ok((String::from_utf8(inner).map_err(|_| "The vault file is damaged".to_string())?, true))
}

struct Parsed {
    kdf: Kdf,
    salt: Vec<u8>,
    iv: Vec<u8>,
    ct: Vec<u8>,
}

fn parse_inner(text: &str) -> Result<Parsed, String> {
    let f: serde_json::Value = serde_json::from_str(text).map_err(|_| "The vault file is damaged".to_string())?;
    let kdf = match (f["v"].as_u64(), &f["kdf"]) {
        (Some(1), k) if k.as_str() == Some("PBKDF2-SHA256") => {
            Kdf::Pbkdf2 { iterations: f["iterations"].as_u64().unwrap_or(0).min(u32::MAX as u64) as u32 }
        }
        (Some(2), k) if k["name"].as_str() == Some("argon2id") => Kdf::Argon2id {
            m: k["m"].as_u64().unwrap_or(0).min(u32::MAX as u64) as u32,
            t: k["t"].as_u64().unwrap_or(0).min(u32::MAX as u64) as u32,
            p: k["p"].as_u64().unwrap_or(0).min(u32::MAX as u64) as u32,
        },
        _ => return Err("Unsupported vault version".into()),
    };
    let field = |name: &str| B64.decode(f[name].as_str().unwrap_or_default()).map_err(|_| "The vault file is damaged".to_string());
    Ok(Parsed { kdf, salt: field("salt")?, iv: field("iv")?, ct: field("ct")? })
}

fn decrypt_accounts(key: &[u8; 32], p: &Parsed) -> Result<Vec<Account>, String> {
    if p.iv.len() != 12 {
        return Err("The vault file is damaged".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let plain = Zeroizing::new(cipher.decrypt(Nonce::from_slice(&p.iv), p.ct.as_slice()).map_err(|_| WRONG_PASSWORD.to_string())?);
    serde_json::from_slice(&plain).map_err(|_| WRONG_PASSWORD.to_string())
}

fn open_file(file: &str, password: &str) -> Result<Unlocked, String> {
    let (inner, bound) = unseal(file)?;
    let parsed = parse_inner(&inner)?;
    let key = derive_key(password, &parsed.salt, &parsed.kdf)?;
    let accounts = decrypt_accounts(&key, &parsed)?;
    Ok(Unlocked { key, salt: parsed.salt, kdf: parsed.kdf, bound, accounts })
}

// ---------------------------------------------------------------- TOTP

fn base32_decode(text: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut out = Zeroizing::new(Vec::new());
    let (mut bits, mut acc) = (0u32, 0u32);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=' && *c != '-') {
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return Err("Not a valid secret".into()),
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if out.is_empty() {
        return Err("Not a valid secret".into());
    }
    Ok(out)
}

fn mac_of<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <M as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 6238 one-time code for `account` at `unix_secs`.
fn totp(a: &Account, unix_secs: u64) -> Result<String, String> {
    if a.period == 0 || !(6..=9).contains(&a.digits) {
        return Err("Unsupported account settings".into());
    }
    let key = base32_decode(&a.secret)?;
    let msg = (unix_secs / a.period).to_be_bytes();
    let mac = match a.algorithm.as_str() {
        "SHA1" => mac_of::<Hmac<Sha1>>(&key, &msg),
        "SHA256" => mac_of::<Hmac<Sha256>>(&key, &msg),
        "SHA512" => mac_of::<Hmac<Sha512>>(&key, &msg),
        other => return Err(format!("Unsupported algorithm: {other}")),
    };
    let o = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([mac[o] & 0x7f, mac[o + 1], mac[o + 2], mac[o + 3]]);
    Ok(format!("{:0width$}", bin % 10u32.pow(a.digits), width = a.digits as usize))
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ---------------------------------------------------------------- commands

#[derive(Serialize)]
pub struct Info {
    kdf: &'static str,
    bound: bool,
}

fn info(u: &Unlocked) -> Info {
    Info { kdf: if matches!(u.kdf, Kdf::Argon2id { .. }) { "argon2id" } else { "pbkdf2" }, bound: u.bound }
}

#[derive(Serialize)]
pub struct AccountView {
    id: String,
    issuer: String,
    name: String,
    digits: u32,
    period: u64,
}

#[derive(Serialize)]
pub struct Code {
    code: String,
}

#[derive(Serialize)]
pub struct AddResult {
    added: usize,
    dupes: usize,
    rejected: usize,
}

fn read_file(app: &AppHandle) -> Result<Option<String>, String> {
    let path = crate::vault_path(app)?;
    if !path.exists() {
        return Ok(None);
    }
    std::fs::read_to_string(path).map(Some).map_err(|e| e.to_string())
}

fn write_file(app: &AppHandle, text: &str) -> Result<(), String> {
    let path = crate::vault_path(app)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
}

fn persist(app: &AppHandle, u: &Unlocked) -> Result<(), String> {
    write_file(app, &seal(u)?)
}

fn touch_now(vault: &Vault) {
    *guard(&vault.last_activity) = Instant::now();
}

fn open_state(vault: &Vault) -> Result<MutexGuard<'_, Option<Unlocked>>, String> {
    let g = guard(&vault.inner);
    if g.is_none() {
        return Err("The vault is locked".into());
    }
    Ok(g)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn vault_exists(app: AppHandle) -> Result<bool, String> {
    Ok(read_file(&app)?.is_some())
}

#[tauri::command]
pub async fn create_vault(app: AppHandle, vault: State<'_, Vault>, password: String, bind: bool) -> Result<Info, String> {
    if read_file(&app)?.is_some() {
        return Err("A vault already exists".into());
    }
    if bind && !cfg!(windows) {
        return Err("Windows account binding is only available on Windows".into());
    }
    let password = Zeroizing::new(password);
    let kdf = default_kdf();
    let salt = random::<16>().to_vec();
    let (s2, k2) = (salt.clone(), kdf.clone());
    let key = blocking(move || derive_key(&password, &s2, &k2)).await??;
    let unlocked = Unlocked { key, salt, kdf, bound: bind, accounts: Vec::new() };
    persist(&app, &unlocked)?;
    let result = info(&unlocked);
    *guard(&vault.inner) = Some(unlocked);
    touch_now(&vault);
    Ok(result)
}

#[tauri::command]
pub async fn unlock(app: AppHandle, vault: State<'_, Vault>, password: String) -> Result<Info, String> {
    let file = read_file(&app)?.ok_or("There is no vault yet")?;
    let password = Zeroizing::new(password);
    let unlocked = blocking(move || open_file(&file, &password)).await??;
    let result = info(&unlocked);
    *guard(&vault.inner) = Some(unlocked);
    touch_now(&vault);
    Ok(result)
}

#[tauri::command]
pub fn session_info(vault: State<'_, Vault>) -> Option<Info> {
    guard(&vault.inner).as_ref().map(info)
}

#[tauri::command]
pub fn lock_vault(app: AppHandle) {
    lock(&app);
}

#[tauri::command]
pub fn list_accounts(vault: State<'_, Vault>) -> Result<Vec<AccountView>, String> {
    let g = open_state(&vault)?;
    Ok(g.as_ref().map(|u| u.accounts.iter().map(|a| AccountView {
        id: a.id.clone(), issuer: a.issuer.clone(), name: a.name.clone(), digits: a.digits, period: a.period,
    }).collect()).unwrap_or_default())
}

/// The only way a code leaves this process: one account, one code, on request.
#[tauri::command]
pub fn get_code(vault: State<'_, Vault>, id: String) -> Result<Code, String> {
    let g = open_state(&vault)?;
    let a = g.as_ref().and_then(|u| u.accounts.iter().find(|a| a.id == id)).ok_or("No such account")?;
    touch_now(&vault);
    Ok(Code { code: totp(a, now_secs())? })
}

#[tauri::command]
pub fn add_accounts(app: AppHandle, vault: State<'_, Vault>, accounts: Vec<Account>) -> Result<AddResult, String> {
    let mut g = open_state(&vault)?;
    let u = g.as_mut().ok_or("The vault is locked")?;
    let key = |a: &Account| format!("{}|{}|{}", a.secret, a.issuer, a.name);
    let mut seen: std::collections::HashSet<String> = u.accounts.iter().map(key).collect();
    let (mut added, mut dupes, mut rejected) = (0, 0, 0);
    for mut a in accounts {
        if totp(&a, 0).is_err() {
            rejected += 1;
            continue;
        }
        if !seen.insert(key(&a)) {
            dupes += 1;
            continue;
        }
        a.id = hex(&random::<16>());
        u.accounts.push(a);
        added += 1;
    }
    if added > 0 {
        persist(&app, u)?;
    }
    touch_now(&vault);
    Ok(AddResult { added, dupes, rejected })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tauri::command]
pub fn remove_account(app: AppHandle, vault: State<'_, Vault>, id: String) -> Result<(), String> {
    let mut g = open_state(&vault)?;
    let u = g.as_mut().ok_or("The vault is locked")?;
    u.accounts.retain(|a| a.id != id);
    persist(&app, u)?;
    touch_now(&vault);
    Ok(())
}

/// Checks a password against the open vault without changing anything.
#[tauri::command]
pub async fn verify_password(vault: State<'_, Vault>, password: String) -> Result<(), String> {
    let (salt, kdf, key) = {
        let g = open_state(&vault)?;
        let u = g.as_ref().ok_or("The vault is locked")?;
        (u.salt.clone(), u.kdf.clone(), u.key.clone())
    };
    let password = Zeroizing::new(password);
    let ok = blocking(move || derive_key(&password, &salt, &kdf).map(|k| same_key(&k, &key))).await??;
    if ok { Ok(()) } else { Err(WRONG_PASSWORD.into()) }
}

/// Re-encrypts the vault with Argon2id. Only runs when the user asks for it.
#[tauri::command]
pub async fn upgrade_vault(app: AppHandle, vault: State<'_, Vault>, password: String, want_bind: bool) -> Result<Info, String> {
    verify_password(vault.clone(), password.clone()).await?;
    if want_bind && !cfg!(windows) {
        return Err("Windows account binding is only available on Windows".into());
    }
    let accounts = {
        let g = open_state(&vault)?;
        g.as_ref().ok_or("The vault is locked")?.accounts.clone()
    };
    let old_file = read_file(&app)?.ok_or("There is no vault yet")?;
    let password = Zeroizing::new(password);
    let kdf = default_kdf();
    let salt = random::<16>().to_vec();
    let (s2, k2) = (salt.clone(), kdf.clone());
    let key = blocking(move || derive_key(&password, &s2, &k2)).await??;
    let next = Unlocked { key, salt, kdf, bound: want_bind, accounts };

    // Prove the new file opens with the new key and holds the same accounts before replacing anything.
    let file = seal(&next)?;
    let check = {
        let (inner, _) = unseal(&file)?;
        decrypt_accounts(&next.key, &parse_inner(&inner)?)
            .map_err(|_| "Safety check failed. Your vault was left unchanged.".to_string())?
    };
    if serde_json::to_string(&check).ok() != serde_json::to_string(&next.accounts).ok() {
        return Err("Safety check failed. Your vault was left unchanged.".into());
    }
    write_file(&app, &file)?;
    if read_file(&app)?.as_deref() != Some(file.as_str()) {
        write_file(&app, &old_file)?;
        return Err("Could not write the new vault. Your vault was left unchanged.".into());
    }
    let result = info(&next);
    *guard(&vault.inner) = Some(next);
    Ok(result)
}

/// The window reports activity (throttled) so idle time is measured here, not in the web view.
#[tauri::command]
pub fn touch(vault: State<'_, Vault>) {
    touch_now(&vault);
}

#[tauri::command]
pub fn set_idle_minutes(vault: State<'_, Vault>, minutes: u64) {
    vault.idle_secs.store(minutes.clamp(1, 60) * 60, Ordering::Relaxed);
    touch_now(&vault);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(secret: &[u8], algorithm: &str, digits: u32) -> Account {
        let b32 = {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0u32);
            for &b in secret {
                acc = (acc << 8) | b as u32;
                bits += 8;
                while bits >= 5 {
                    bits -= 5;
                    out.push(A[((acc >> bits) & 31) as usize] as char);
                }
            }
            if bits > 0 {
                out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
            }
            out
        };
        Account { id: "x".into(), issuer: "I".into(), name: "n".into(), secret: b32, algorithm: algorithm.into(), digits, period: 30 }
    }

    #[test]
    fn totp_matches_rfc_6238_vectors() {
        let sha1 = acct(b"12345678901234567890", "SHA1", 8);
        assert_eq!(totp(&sha1, 59).unwrap(), "94287082");
        assert_eq!(totp(&sha1, 1111111109).unwrap(), "07081804");
        assert_eq!(totp(&sha1, 20000000000).unwrap(), "65353130");
        assert_eq!(totp(&acct(b"12345678901234567890123456789012", "SHA256", 8), 59).unwrap(), "46119246");
        let s512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        assert_eq!(totp(&acct(s512, "SHA512", 8), 59).unwrap(), "90693936");
    }

    #[test]
    fn base32_rejects_garbage() {
        assert!(base32_decode("not*valid").is_err());
        assert!(base32_decode("").is_err());
        assert_eq!(&base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap()[..], b"12345678901234567890");
    }

    fn unlocked(kdf: Kdf, password: &str) -> Unlocked {
        let salt = vec![7u8; 16];
        let key = derive_key(password, &salt, &kdf).unwrap();
        Unlocked { key, salt, kdf, bound: false, accounts: vec![acct(b"12345678901234567890", "SHA1", 6)] }
    }

    #[test]
    fn argon2_vault_round_trips_and_rejects_wrong_password_and_tampering() {
        let u = unlocked(Kdf::Argon2id { m: 8 * 1024, t: 1, p: 1 }, "correct horse");
        let file = seal(&u).unwrap();
        assert!(!file.contains("GEZDGNBV"));
        assert_eq!(open_file(&file, "correct horse").unwrap().accounts.len(), 1);
        assert_eq!(open_file(&file, "wrong").err().as_deref(), Some(WRONG_PASSWORD));
        let mut v: serde_json::Value = serde_json::from_str(&file).unwrap();
        let ct = v["ct"].as_str().unwrap().to_string();
        v["ct"] = (if ct.starts_with('A') { format!("B{}", &ct[1..]) } else { format!("A{}", &ct[1..]) }).into();
        assert_eq!(open_file(&v.to_string(), "correct horse").err().as_deref(), Some(WRONG_PASSWORD));
    }

    /// A v1 file produced by the previous (JavaScript) implementation must still open.
    #[test]
    fn opens_a_vault_written_by_the_old_javascript_code() {
        let file = include_str!("../tests/legacy-v1.json");
        let u = open_file(file, "legacy fixture pass").unwrap();
        assert_eq!(u.accounts.len(), 1);
        assert_eq!(u.accounts[0].issuer, "Example");
        assert_eq!(u.accounts[0].digits, 6);
        assert!(matches!(u.kdf, Kdf::Pbkdf2 { iterations: 1000 }));
        assert_eq!(open_file(file, "nope").err().as_deref(), Some(WRONG_PASSWORD));
    }

    #[test]
    fn rejects_unknown_versions_and_absurd_settings() {
        assert!(open_file(r#"{"v":3,"salt":"AA==","iv":"AA==","ct":"AA=="}"#, "x").is_err());
        assert!(open_file("not json", "x").is_err());
        assert!(derive_key("x", &[0u8; 16], &Kdf::Pbkdf2 { iterations: 1 }).is_err());
    }
}
