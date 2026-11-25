pub async fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut command = tokio::process::Command::new("/usr/bin/open");
    #[cfg(windows)]
    let mut command = tokio::process::Command::new(system_directory()?.join("rundll32.exe"));
    #[cfg(windows)]
    command.arg("url.dll,FileProtocolHandler");
    let status = command
        .arg(url)
        .status()
        .await
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("无法打开浏览器页面。".into())
    }
}

pub fn validate_http_url(url: &str) -> Result<String, String> {
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed.len() > 4096 || trimmed.chars().any(char::is_control) {
        return Err("URL 无效。".into());
    }
    let normalized = if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        trimmed.to_string()
    } else if !trimmed.contains("://") && trimmed.contains('.') {
        format!("https://{trimmed}")
    } else {
        return Err("仅支持打开 http:// 或 https:// 链接。".into());
    };
    Ok(normalized)
}

#[cfg(windows)]
pub fn system_directory() -> Result<std::path::PathBuf, String> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = [0; 260];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err("Unable to find the Windows system directory.".into());
    }
    Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..length],
    )))
}

#[cfg(target_os = "macos")]
pub fn write_clipboard(text: &str) -> Result<(), String> {
    use objc2_app_kit::NSPasteboard;
    write_pasteboard(&NSPasteboard::generalPasteboard(), text)
}

#[cfg(target_os = "macos")]
pub fn write_pasteboard(
    pasteboard: &objc2_app_kit::NSPasteboard,
    text: &str,
) -> Result<(), String> {
    use objc2_app_kit::NSPasteboardTypeString;
    let text = objc2_foundation::NSString::from_str(text);
    pasteboard.clearContents();
    if pasteboard.setString_forType(&text, unsafe { NSPasteboardTypeString }) {
        Ok(())
    } else {
        Err("无法写入系统剪贴板。".into())
    }
}

#[cfg(target_os = "macos")]
pub fn read_clipboard() -> Option<String> {
    use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
    let pasteboard = NSPasteboard::generalPasteboard();
    pasteboard
        .stringForType(unsafe { NSPasteboardTypeString })
        .map(|s| s.to_string())
}

#[cfg(target_os = "macos")]
pub fn clear_clipboard() -> Result<(), String> {
    use objc2_app_kit::NSPasteboard;
    let pasteboard = NSPasteboard::generalPasteboard();
    pasteboard.clearContents();
    Ok(())
}

#[cfg(windows)]
pub fn write_clipboard(text: &str, window: &tauri::WebviewWindow) -> Result<(), String> {
    use windows_sys::Win32::{
        Foundation::GlobalFree,
        System::{
            DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData},
            Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock},
        },
    };
    let hwnd = window.hwnd().map_err(|error| error.to_string())?;
    let units = text.encode_utf16().chain([0]).collect::<Vec<_>>();
    let error = || "Unable to write to the Windows clipboard.".to_string();
    unsafe {
        if OpenClipboard(hwnd.0) == 0 {
            return Err(error());
        }
        let result = (|| {
            let allocation = GlobalAlloc(GMEM_MOVEABLE, units.len() * size_of::<u16>());
            if allocation.is_null() {
                return Err(error());
            }
            let target = GlobalLock(allocation).cast::<u16>();
            if target.is_null() {
                GlobalFree(allocation);
                return Err(error());
            }
            std::ptr::copy_nonoverlapping(units.as_ptr(), target, units.len());
            GlobalUnlock(allocation);
            const CF_UNICODETEXT: u32 = 13;
            if EmptyClipboard() == 0 || SetClipboardData(CF_UNICODETEXT, allocation).is_null() {
                GlobalFree(allocation);
                return Err(error());
            }
            Ok(())
        })();
        CloseClipboard();
        result
    }
}

#[cfg(windows)]
pub fn read_clipboard(window: &tauri::WebviewWindow) -> Option<String> {
    use windows_sys::Win32::System::{
        DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard},
        Memory::{GlobalLock, GlobalUnlock},
    };
    let hwnd = window.hwnd().ok()?;
    unsafe {
        if OpenClipboard(hwnd.0) == 0 {
            return None;
        }
        const CF_UNICODETEXT: u32 = 13;
        let handle = GetClipboardData(CF_UNICODETEXT);
        let result = if handle.is_null() {
            None
        } else {
            let ptr = GlobalLock(handle).cast::<u16>();
            if ptr.is_null() {
                None
            } else {
                let mut len = 0usize;
                while *ptr.add(len) != 0 && len < 1_048_576 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(ptr, len);
                let text = String::from_utf16_lossy(slice);
                GlobalUnlock(handle);
                Some(text)
            }
        };
        CloseClipboard();
        result
    }
}

#[cfg(windows)]
pub fn clear_clipboard(window: &tauri::WebviewWindow) -> Result<(), String> {
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard,
    };
    let hwnd = window.hwnd().map_err(|error| error.to_string())?;
    unsafe {
        if OpenClipboard(hwnd.0) == 0 {
            return Err("Unable to open the Windows clipboard.".into());
        }
        let ok = EmptyClipboard() != 0;
        CloseClipboard();
        if ok {
            Ok(())
        } else {
            Err("Unable to clear the Windows clipboard.".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_normalizes_http_urls() {
        assert_eq!(
            validate_http_url("https://example.com/login").unwrap(),
            "https://example.com/login"
        );
        assert_eq!(
            validate_http_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            validate_http_url("github.com/user").unwrap(),
            "https://github.com/user"
        );
        assert!(validate_http_url("file:///etc/passwd").is_err());
        assert!(validate_http_url("javascript:alert(1)").is_err());
        assert!(validate_http_url("").is_err());
    }
}
