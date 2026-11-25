use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
#[cfg(windows)]
use tauri::Manager;
use tauri::{AppHandle, Emitter};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct ClipboardGuard {
    generation: AtomicU64,
    last_secret: Mutex<Option<Zeroizing<String>>>,
}

impl ClipboardGuard {
    pub fn copy(
        self: &Arc<Self>,
        app: &AppHandle,
        window: &tauri::WebviewWindow,
        text: String,
        clear_after_secs: Option<u32>,
    ) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            let _ = window;
            crate::platform::write_clipboard(&text)?;
        }
        #[cfg(windows)]
        {
            crate::platform::write_clipboard(&text, window)?;
        }

        let seq = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(secs) = clear_after_secs.filter(|&s| s > 0) {
            if let Ok(mut guard) = self.last_secret.lock() {
                *guard = Some(Zeroizing::new(text));
            }
            let this = Arc::clone(self);
            let handle = app.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(u64::from(secs))).await;
                if this.generation.load(Ordering::SeqCst) != seq {
                    return;
                }
                let expected = this
                    .last_secret
                    .lock()
                    .ok()
                    .and_then(|mut guard| guard.take());
                let Some(expected) = expected else {
                    return;
                };
                if this.clear_if_matches(&handle, &expected) {
                    let _ = handle.emit("clipboard-cleared", ());
                }
            });
        } else if let Ok(mut guard) = self.last_secret.lock() {
            *guard = None;
        }
        Ok(())
    }

    pub fn clear_now(&self, app: &AppHandle) -> Result<(), String> {
        self.generation.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut guard) = self.last_secret.lock() {
            *guard = None;
        }
        #[cfg(target_os = "macos")]
        {
            let _ = app;
            crate::platform::clear_clipboard()?;
        }
        #[cfg(windows)]
        {
            if let Some(window) = app.get_webview_window("main") {
                crate::platform::clear_clipboard(&window)?;
            }
        }
        let _ = app.emit("clipboard-cleared", ());
        Ok(())
    }

    pub fn clear_on_exit(&self, app: &AppHandle) {
        let expected = self
            .last_secret
            .lock()
            .ok()
            .and_then(|mut guard| guard.take());
        if let Some(expected) = expected {
            let _ = self.clear_if_matches(app, &expected);
        }
    }

    fn clear_if_matches(&self, app: &AppHandle, expected: &str) -> bool {
        #[cfg(target_os = "macos")]
        {
            let _ = app;
            if crate::platform::read_clipboard().as_deref() == Some(expected) {
                return crate::platform::clear_clipboard().is_ok();
            }
            false
        }
        #[cfg(windows)]
        {
            let Some(window) = app.get_webview_window("main") else {
                return false;
            };
            if crate::platform::read_clipboard(&window).as_deref() == Some(expected) {
                return crate::platform::clear_clipboard(&window).is_ok();
            }
            false
        }
    }
}
