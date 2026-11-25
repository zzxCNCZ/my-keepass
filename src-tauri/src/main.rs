mod clipboard;
mod password_gen;
mod platform;
mod prefs;
mod updates;
mod vault;

use clipboard::ClipboardGuard;
use password_gen::{GeneratedPassword, PasswordOptions, PasswordStrength};
use prefs::{AppPrefs, PrefsStore};
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tauri::{AppHandle, Manager, State};
use vault::{
    DatabaseSettingsPayload, EntryPayload, GroupPayload, TotpCodeView, VaultManager, VaultSnapshot,
};

type SharedPrefs = Arc<Mutex<PrefsStore>>;

async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(operation)
        .await
        .map_err(|error| error.to_string())?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlatformInfo {
    version: &'static str,
    os: &'static str,
    arch: &'static str,
}

#[tauri::command]
fn platform_info() -> PlatformInfo {
    PlatformInfo {
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
    }
}

#[tauri::command]
async fn load_prefs(store: State<'_, SharedPrefs>) -> Result<AppPrefs, String> {
    let store = store.inner().clone();
    blocking(move || store.lock().map_err(|e| e.to_string())?.load()).await
}

#[tauri::command]
async fn save_prefs(store: State<'_, SharedPrefs>, prefs: AppPrefs) -> Result<AppPrefs, String> {
    let store = store.inner().clone();
    blocking(move || store.lock().map_err(|e| e.to_string())?.save(prefs)).await
}

#[tauri::command]
async fn remove_recent_database(
    store: State<'_, SharedPrefs>,
    path: String,
) -> Result<AppPrefs, String> {
    let store = store.inner().clone();
    blocking(move || store.lock().map_err(|e| e.to_string())?.remove_recent(&path)).await
}

#[tauri::command]
async fn list_vaults(manager: State<'_, Arc<VaultManager>>) -> Result<Vec<VaultSnapshot>, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.list_tabs()).await
}

#[tauri::command]
async fn create_database(
    manager: State<'_, Arc<VaultManager>>,
    prefs: State<'_, SharedPrefs>,
    path: PathBuf,
    password: Option<String>,
    keyfile: Option<PathBuf>,
    name: String,
    description: String,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    let prefs = prefs.inner().clone();
    blocking(move || {
        let snap = manager.create_database(path.clone(), password, keyfile.clone(), name, description)?;
        if let Ok(store) = prefs.lock() {
            let _ = store.record_recent(&path, keyfile.as_deref());
        }
        Ok(snap)
    })
    .await
}

#[tauri::command]
async fn open_database(
    manager: State<'_, Arc<VaultManager>>,
    prefs: State<'_, SharedPrefs>,
    path: PathBuf,
    password: Option<String>,
    keyfile: Option<PathBuf>,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    let prefs = prefs.inner().clone();
    blocking(move || {
        let snap = manager.open_database(path.clone(), password, keyfile.clone())?;
        if let Ok(store) = prefs.lock() {
            let _ = store.record_recent(&PathBuf::from(&snap.path), keyfile.as_deref());
        }
        Ok(snap)
    })
    .await
}

#[tauri::command]
async fn stage_locked_database(
    manager: State<'_, Arc<VaultManager>>,
    path: PathBuf,
    keyfile: Option<PathBuf>,
) -> Result<Option<VaultSnapshot>, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.stage_locked_database(path, keyfile)).await
}

#[tauri::command]
async fn unlock_database(
    manager: State<'_, Arc<VaultManager>>,
    prefs: State<'_, SharedPrefs>,
    tab_id: String,
    password: Option<String>,
    keyfile: Option<PathBuf>,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    let prefs = prefs.inner().clone();
    blocking(move || {
        let snap = manager.unlock_database(&tab_id, password, keyfile.clone())?;
        if let Ok(store) = prefs.lock() {
            let _ = store.record_recent(&PathBuf::from(&snap.path), keyfile.as_deref());
        }
        Ok(snap)
    })
    .await
}

#[tauri::command]
async fn lock_database(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.lock_database(&tab_id)).await
}

#[tauri::command]
async fn lock_all_databases(
    manager: State<'_, Arc<VaultManager>>,
) -> Result<Vec<VaultSnapshot>, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.lock_all()).await
}

#[tauri::command]
async fn close_database(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
) -> Result<(), String> {
    let manager = manager.inner().clone();
    blocking(move || manager.close_database(&tab_id)).await
}

#[tauri::command]
async fn save_database(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    force: bool,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.save_database(&tab_id, force)).await
}

#[tauri::command]
async fn save_database_as(
    manager: State<'_, Arc<VaultManager>>,
    prefs: State<'_, SharedPrefs>,
    tab_id: String,
    new_path: PathBuf,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    let prefs = prefs.inner().clone();
    blocking(move || {
        let snap = manager.save_database_as(&tab_id, new_path.clone())?;
        if let Ok(store) = prefs.lock() {
            let _ = store.record_recent(&new_path, snap.keyfile_path.as_deref().map(std::path::Path::new));
        }
        Ok(snap)
    })
    .await
}

#[tauri::command]
async fn change_master_key(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    new_password: Option<String>,
    new_keyfile: Option<PathBuf>,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.change_master_key(&tab_id, new_password, new_keyfile)).await
}

#[tauri::command]
async fn generate_keyfile(dest_path: PathBuf) -> Result<(), String> {
    blocking(move || vault::generate_keyfile(&dest_path)).await
}

#[tauri::command]
async fn update_database_settings(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    settings: DatabaseSettingsPayload,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.update_database_settings(&tab_id, settings)).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatedItem {
    snapshot: VaultSnapshot,
    id: String,
}

#[tauri::command]
async fn create_group(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    parent_id: String,
    payload: GroupPayload,
) -> Result<CreatedItem, String> {
    let manager = manager.inner().clone();
    blocking(move || {
        let (snapshot, id) = manager.create_group(&tab_id, parent_id, payload)?;
        Ok(CreatedItem { snapshot, id })
    })
    .await
}

#[tauri::command]
async fn update_group(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    group_id: String,
    payload: GroupPayload,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.update_group(&tab_id, group_id, payload)).await
}

#[tauri::command]
async fn move_group(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    group_id: String,
    new_parent_id: String,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.move_group(&tab_id, group_id, new_parent_id)).await
}

#[tauri::command]
async fn delete_group(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    group_id: String,
    permanent: bool,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.delete_group(&tab_id, group_id, permanent)).await
}

#[tauri::command]
async fn empty_recycle_bin(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.empty_recycle_bin(&tab_id)).await
}

#[tauri::command]
async fn create_entry(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    group_id: String,
    payload: EntryPayload,
) -> Result<CreatedItem, String> {
    let manager = manager.inner().clone();
    blocking(move || {
        let (snapshot, id) = manager.create_entry(&tab_id, group_id, payload)?;
        Ok(CreatedItem { snapshot, id })
    })
    .await
}

#[tauri::command]
async fn update_entry(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    entry_id: String,
    payload: EntryPayload,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.update_entry(&tab_id, entry_id, payload)).await
}

#[tauri::command]
async fn clone_entry(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    entry_id: String,
) -> Result<CreatedItem, String> {
    let manager = manager.inner().clone();
    blocking(move || {
        let (snapshot, id) = manager.clone_entry(&tab_id, entry_id)?;
        Ok(CreatedItem { snapshot, id })
    })
    .await
}

#[tauri::command]
async fn move_entry(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    entry_id: String,
    target_group_id: String,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.move_entry(&tab_id, entry_id, target_group_id)).await
}

#[tauri::command]
async fn delete_entry(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    entry_id: String,
    permanent: bool,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.delete_entry(&tab_id, entry_id, permanent)).await
}

#[tauri::command]
async fn restore_entry_history(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    entry_id: String,
    history_index: usize,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.restore_entry_history(&tab_id, entry_id, history_index)).await
}

#[tauri::command]
async fn delete_entry_history(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    entry_id: String,
    history_index: usize,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.delete_entry_history(&tab_id, entry_id, history_index)).await
}

#[tauri::command]
async fn add_entry_attachment(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    entry_id: String,
    file_path: PathBuf,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.add_entry_attachment(&tab_id, entry_id, file_path)).await
}

#[tauri::command]
async fn export_entry_attachment(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    entry_id: String,
    name: String,
    dest_path: PathBuf,
) -> Result<(), String> {
    let manager = manager.inner().clone();
    blocking(move || manager.export_entry_attachment(&tab_id, entry_id, name, dest_path)).await
}

#[tauri::command]
async fn remove_entry_attachment(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    entry_id: String,
    name: String,
) -> Result<VaultSnapshot, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.remove_entry_attachment(&tab_id, entry_id, name)).await
}

#[tauri::command]
async fn get_entry_totp(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    entry_id: String,
) -> Result<TotpCodeView, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.get_entry_totp(&tab_id, entry_id)).await
}

#[tauri::command]
async fn export_csv(
    manager: State<'_, Arc<VaultManager>>,
    tab_id: String,
    dest_path: PathBuf,
) -> Result<usize, String> {
    let manager = manager.inner().clone();
    blocking(move || manager.export_csv(&tab_id, dest_path)).await
}

#[tauri::command]
fn generate_password(options: PasswordOptions) -> Result<GeneratedPassword, String> {
    password_gen::generate(&options)
}

#[tauri::command]
fn estimate_password_strength(password: String) -> PasswordStrength {
    password_gen::estimate_strength(&password)
}

#[tauri::command]
fn copy_secret(
    app: AppHandle,
    window: tauri::WebviewWindow,
    clipboard: State<'_, Arc<ClipboardGuard>>,
    text: String,
    clear_after_secs: Option<u32>,
) -> Result<(), String> {
    clipboard.copy(&app, &window, text, clear_after_secs)
}

#[tauri::command]
fn clear_clipboard_now(
    app: AppHandle,
    clipboard: State<'_, Arc<ClipboardGuard>>,
) -> Result<(), String> {
    clipboard.clear_now(&app)
}

#[tauri::command]
async fn open_entry_url(url: String) -> Result<(), String> {
    let normalized = platform::validate_http_url(&url)?;
    platform::open_browser(&normalized).await
}

fn main() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(updates::InstallLock::default())
        .manage(Arc::new(VaultManager::default()))
        .manage(Arc::new(ClipboardGuard::default()));

    #[cfg(target_os = "macos")]
    let builder = builder.on_window_event(|window, event| {
        if window.label() == "main"
            && let tauri::WindowEvent::CloseRequested { api, .. } = event
            && window.hide().is_ok()
        {
            api.prevent_close();
        }
    });

    builder
        .setup(|app| {
            app.manage(Arc::new(Mutex::new(PrefsStore::new(
                app.path().app_config_dir()?,
            ))));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            platform_info,
            load_prefs,
            save_prefs,
            remove_recent_database,
            list_vaults,
            create_database,
            open_database,
            stage_locked_database,
            unlock_database,
            lock_database,
            lock_all_databases,
            close_database,
            save_database,
            save_database_as,
            change_master_key,
            generate_keyfile,
            update_database_settings,
            create_group,
            update_group,
            move_group,
            delete_group,
            empty_recycle_bin,
            create_entry,
            update_entry,
            clone_entry,
            move_entry,
            delete_entry,
            restore_entry_history,
            delete_entry_history,
            add_entry_attachment,
            export_entry_attachment,
            remove_entry_attachment,
            get_entry_totp,
            export_csv,
            generate_password,
            estimate_password_strength,
            copy_secret,
            clear_clipboard_now,
            open_entry_url,
            updates::check_updates,
            updates::install_update,
            updates::open_release_page
        ])
        .build(tauri::generate_context!())
        .expect("failed to initialize My KeePass")
        .run(|app, event| {
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = &event
                && let Some(window) = app.get_webview_window("main")
            {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
            if matches!(
                event,
                tauri::RunEvent::Exit
                    | tauri::RunEvent::WindowEvent {
                        event: tauri::WindowEvent::Destroyed,
                        ..
                    }
            ) {
                app.state::<Arc<ClipboardGuard>>().clear_on_exit(app);
                app.state::<Arc<VaultManager>>().shutdown();
            }
        });
}
