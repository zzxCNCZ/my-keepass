use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const PREFS_FILE: &str = "prefs.json";
const MAX_PREFS_BYTES: u64 = 512 * 1024;
const MAX_RECENT: usize = 12;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecentDatabase {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyfile: Option<String>,
    pub last_opened: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppPrefs {
    pub language: String,
    pub remember_recent: bool,
    pub remember_keyfiles: bool,
    pub open_last_database_on_startup: bool,
    pub auto_save_on_change: bool,
    pub auto_save_on_close: bool,
    pub clear_clipboard_enabled: bool,
    pub clear_clipboard_seconds: u32,
    pub auto_lock_enabled: bool,
    pub auto_lock_seconds: u32,
    pub hide_passwords: bool,
    pub show_detail_pane: bool,
    pub recent_databases: Vec<RecentDatabase>,
}

impl Default for AppPrefs {
    fn default() -> Self {
        Self {
            language: "zh-CN".into(),
            remember_recent: true,
            remember_keyfiles: true,
            open_last_database_on_startup: true,
            auto_save_on_change: false,
            auto_save_on_close: false,
            clear_clipboard_enabled: true,
            clear_clipboard_seconds: 15,
            auto_lock_enabled: true,
            auto_lock_seconds: 300,
            hide_passwords: true,
            show_detail_pane: true,
            recent_databases: Vec::new(),
        }
    }
}

impl AppPrefs {
    pub fn sanitize(&mut self) {
        if !matches!(self.language.as_str(), "zh-CN" | "en" | "system") {
            self.language = "zh-CN".into();
        }
        self.clear_clipboard_seconds = self.clear_clipboard_seconds.clamp(3, 300);
        self.auto_lock_seconds = self.auto_lock_seconds.clamp(30, 86_400);
        if !self.remember_recent {
            self.recent_databases.clear();
        } else {
            if !self.remember_keyfiles {
                for item in &mut self.recent_databases {
                    item.keyfile = None;
                }
            }
            self.recent_databases.truncate(MAX_RECENT);
        }
    }
}

pub struct PrefsStore {
    device_dir: PathBuf,
}

impl PrefsStore {
    pub fn new(device_dir: PathBuf) -> Self {
        Self { device_dir }
    }

    fn prefs_path(&self) -> PathBuf {
        self.device_dir.join(PREFS_FILE)
    }

    pub fn load(&self) -> Result<AppPrefs, String> {
        let path = self.prefs_path();
        match read_json::<AppPrefs>(&path) {
            Ok(mut prefs) => {
                prefs.sanitize();
                Ok(prefs)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(AppPrefs::default()),
            Err(error) => Err(format!("读取应用设置失败：{error}")),
        }
    }

    pub fn save(&self, mut prefs: AppPrefs) -> Result<AppPrefs, String> {
        prefs.sanitize();
        fs::create_dir_all(&self.device_dir).map_err(|error| error.to_string())?;
        write_json(&self.prefs_path(), &prefs).map_err(|error| format!("保存应用设置失败：{error}"))?;
        Ok(prefs)
    }

    pub fn record_recent(&self, path: &Path, keyfile: Option<&Path>) -> Result<AppPrefs, String> {
        let mut prefs = self.load()?;
        if !prefs.remember_recent {
            return Ok(prefs);
        }
        let path_str = path.to_string_lossy().to_string();
        let keyfile_str = if prefs.remember_keyfiles {
            keyfile.map(|kf| kf.to_string_lossy().to_string())
        } else {
            None
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        prefs.recent_databases.retain(|item| item.path != path_str);
        prefs.recent_databases.insert(
            0,
            RecentDatabase {
                path: path_str,
                keyfile: keyfile_str,
                last_opened: now,
            },
        );
        prefs.recent_databases.truncate(MAX_RECENT);
        self.save(prefs)
    }

    pub fn remove_recent(&self, path: &str) -> Result<AppPrefs, String> {
        let mut prefs = self.load()?;
        prefs.recent_databases.retain(|item| item.path != path);
        self.save(prefs)
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, io::Error> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::other("不是普通文件"));
    }
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_PREFS_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PREFS_BYTES {
        return Err(io::Error::other("配置文件过大"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), io::Error> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::other("缺少父目录"))?;
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_loads_and_sanitizes_preferences_and_recent_list() {
        let dir = tempfile::tempdir().unwrap();
        let store = PrefsStore::new(dir.path().to_path_buf());
        let mut prefs = store.load().unwrap();
        assert_eq!(prefs.language, "zh-CN");
        assert_eq!(prefs.clear_clipboard_seconds, 15);
        prefs.clear_clipboard_seconds = 1;
        prefs.auto_lock_seconds = 5;
        prefs.remember_keyfiles = true;
        let saved = store.save(prefs).unwrap();
        assert_eq!(saved.clear_clipboard_seconds, 3);
        assert_eq!(saved.auto_lock_seconds, 30);

        let updated = store
            .record_recent(Path::new("/tmp/a.kdbx"), Some(Path::new("/tmp/a.key")))
            .unwrap();
        assert_eq!(updated.recent_databases.len(), 1);
        assert_eq!(
            updated.recent_databases[0].keyfile.as_deref(),
            Some("/tmp/a.key")
        );

        let removed = store.remove_recent("/tmp/a.kdbx").unwrap();
        assert!(removed.recent_databases.is_empty());
    }
}
