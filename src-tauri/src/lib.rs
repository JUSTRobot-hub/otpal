#[cfg(windows)]
mod hardening;
mod hello;
mod protect;
mod receiver;
mod vault;

use std::{fs, path::PathBuf};
use tauri::{AppHandle, Manager};

/// Opens the author's GitHub page in the default browser. The address is fixed here, so the
/// window cannot use this to open anything else.
#[tauri::command]
fn open_author_page() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (verb, url) = (wide("open"), wide("https://github.com/JUSTRobot-hub"));
        // SAFETY: both strings are NUL-terminated and outlive the call.
        unsafe {
            ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), url.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg("https://github.com/JUSTRobot-hub").spawn();
    }
}

pub(crate) fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    // OTPAL_DATA_DIR lets tests and dev runs use a throwaway folder.
    let dir = match std::env::var_os("OTPAL_DATA_DIR") {
        Some(custom) => PathBuf::from(custom),
        None => app.path().app_data_dir().map_err(|e| e.to_string())?,
    };
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("vault.json"))
}

/// Turns off browser features a password app does not need: the right-click menu, dev tools,
/// view-source, reload, print, save, zoom, autofill and the status bar. Release builds only, so
/// dev runs keep their tools. This hides internals from casual poking; it is not a security
/// boundary. The vault is protected by its encryption, not by the lack of a menu.
#[cfg(all(windows, not(debug_assertions)))]
fn lock_down_webview(app: &tauri::App) {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2Settings3, ICoreWebView2Settings4, ICoreWebView2Settings5,
    };
    use windows_core::Interface;

    let Some(window) = app.get_webview_window("main") else { return };
    let _ = window.with_webview(|webview| unsafe {
        let Ok(core) = webview.controller().CoreWebView2() else { return };
        let Ok(settings) = core.Settings() else { return };
        let _ = settings.SetAreDefaultContextMenusEnabled(false);
        let _ = settings.SetAreDevToolsEnabled(false);
        let _ = settings.SetIsStatusBarEnabled(false);
        let _ = settings.SetIsZoomControlEnabled(false);
        if let Ok(s) = settings.cast::<ICoreWebView2Settings3>() {
            // Turns off F5, Ctrl+R, Ctrl+P, Ctrl+S, Ctrl+U, F12 and the other browser shortcuts.
            let _ = s.SetAreBrowserAcceleratorKeysEnabled(false);
        }
        if let Ok(s) = settings.cast::<ICoreWebView2Settings4>() {
            let _ = s.SetIsPasswordAutosaveEnabled(false);
            let _ = s.SetIsGeneralAutofillEnabled(false);
        }
        if let Ok(s) = settings.cast::<ICoreWebView2Settings5>() {
            let _ = s.SetIsPinchZoomEnabled(false);
        }
    });
}

/// WebView2 reads WEBVIEW2_* environment variables, including one that opens a remote debugging
/// port and one that swaps in a different browser runtime. A shipped build ignores them so
/// another program cannot start Otpal with a debugger attached. The `e2e` feature keeps them
/// for the end-to-end tests.
#[cfg(all(windows, not(debug_assertions), not(feature = "e2e")))]
fn ignore_webview_overrides() {
    let names: Vec<_> = std::env::vars_os()
        .map(|(k, _)| k)
        .filter(|k| k.to_string_lossy().to_ascii_uppercase().starts_with("WEBVIEW2_"))
        .collect();
    for name in names {
        std::env::remove_var(name);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(all(windows, not(debug_assertions), not(feature = "e2e")))]
    ignore_webview_overrides();
    tauri::Builder::default()
        .setup(|app| {
            vault::start_idle_watcher(app.handle().clone());
            #[cfg(windows)]
            hardening::apply(app);
            #[cfg(all(windows, not(debug_assertions)))]
            lock_down_webview(app);
            Ok(())
        })
        .manage(receiver::Receiver::default())
        .manage(vault::Vault::default())
        .invoke_handler(tauri::generate_handler![
            protect::dpapi_available,
            open_author_page,
            vault::vault_exists,
            vault::create_vault,
            vault::unlock,
            vault::session_info,
            vault::lock_vault,
            vault::list_accounts,
            vault::get_code,
            vault::add_accounts,
            vault::remove_account,
            vault::verify_password,
            vault::upgrade_vault,
            vault::touch,
            vault::set_idle_minutes,
            hello::hello_available,
            hello::hello_enroll,
            hello::hello_unlock,
            hello::hello_forget,
            hello::read_hello,
            hello::write_hello,
            receiver::start_receiver,
            receiver::stop_receiver
        ])
        .run(tauri::generate_context!())
        .expect("error while running the application");
}
