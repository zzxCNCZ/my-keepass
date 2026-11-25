use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{NaiveDateTime, TimeZone, Utc};
use keepass::{
    Database, DatabaseKey,
    config::{CompressionConfig, DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig},
    db::{EntryId, EntryRef, GroupId, GroupRef, History, Icon, Times, Value, fields},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    hash::{DefaultHasher, Hash, Hasher},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};
use uuid::Uuid;

const MAX_ATTACHMENT_BYTES: u64 = 20 * 1024 * 1024;
const MAX_KEYFILE_BYTES: u64 = 10 * 1024 * 1024;
const RECYCLE_BIN_ICON: usize = 43;
const DEFAULT_GROUP_ICON: usize = 48;

pub struct VaultManager {
    tabs: Mutex<HashMap<String, VaultTab>>,
}

impl Default for VaultManager {
    fn default() -> Self {
        Self {
            tabs: Mutex::new(HashMap::new()),
        }
    }
}

struct VaultTab {
    id: String,
    path: PathBuf,
    keyfile_path: Option<PathBuf>,
    state: VaultState,
}

enum VaultState {
    Unlocked {
        db: Database,
        key: DatabaseKey,
        dirty: bool,
        file_etag: Option<String>,
    },
    Locked {
        name: String,
        format_version: String,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSnapshot {
    pub id: String,
    pub path: String,
    pub file_name: String,
    pub keyfile_path: Option<String>,
    pub locked: bool,
    pub dirty: bool,
    pub format_version: String,
    pub upgraded_on_save: bool,
    pub meta: VaultMetaView,
    pub root_group_id: Option<String>,
    pub recycle_bin_id: Option<String>,
    pub groups: Vec<GroupView>,
    pub entries: Vec<EntryView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMetaView {
    pub name: String,
    pub description: String,
    pub default_username: String,
    pub recycle_bin_enabled: bool,
    pub history_max_items: isize,
    pub history_max_size: isize,
    pub outer_cipher: String,
    pub compression: String,
    pub kdf_type: String,
    pub kdf_rounds: u64,
    pub kdf_memory_mib: u64,
    pub kdf_parallelism: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupView {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub notes: String,
    pub icon_id: usize,
    pub is_expanded: bool,
    pub is_root: bool,
    pub is_recycle_bin: bool,
    pub child_group_ids: Vec<String>,
    pub entry_ids: Vec<String>,
    pub total_entries: usize,
    pub enable_searching: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldPayload {
    pub key: String,
    pub value: String,
    pub protected: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    pub name: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryItemView {
    pub index: usize,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub modified_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    pub id: String,
    pub group_id: String,
    pub group_path: String,
    pub in_recycle_bin: bool,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub otp: Option<String>,
    pub tags: Vec<String>,
    pub icon_id: usize,
    pub custom_fields: Vec<CustomFieldPayload>,
    pub attachments: Vec<AttachmentView>,
    pub history: Vec<HistoryItemView>,
    pub expires: bool,
    pub expiry_time: Option<String>,
    pub is_expired: bool,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub accessed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryPayload {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    #[serde(default)]
    pub otp: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub icon_id: Option<usize>,
    #[serde(default)]
    pub expires: bool,
    #[serde(default)]
    pub expiry_time: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomFieldPayload>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupPayload {
    pub name: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub icon_id: Option<usize>,
    #[serde(default)]
    pub enable_searching: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseSettingsPayload {
    pub name: String,
    pub description: String,
    pub default_username: String,
    pub recycle_bin_enabled: bool,
    pub history_max_items: isize,
    pub history_max_size: isize,
    pub outer_cipher: String,
    pub compression: String,
    pub kdf_type: String,
    pub kdf_rounds: u64,
    pub kdf_memory_mib: u64,
    pub kdf_parallelism: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCodeView {
    pub code: String,
    pub valid_for_secs: u64,
    pub period_secs: u64,
}

fn build_key(password: Option<&str>, keyfile: Option<&Path>) -> Result<DatabaseKey, String> {
    let mut key = DatabaseKey::new();
    let has_password = password.is_some_and(|p| !p.is_empty());
    if let Some(pw) = password.filter(|p| !p.is_empty()) {
        key = key.with_password(pw);
    }
    if let Some(kf_path) = keyfile {
        let meta = fs::metadata(kf_path).map_err(|e| format!("无法读取密钥文件：{e}"))?;
        if !meta.is_file() {
            return Err("密钥路径不是普通文件。".into());
        }
        if meta.len() > MAX_KEYFILE_BYTES {
            return Err("密钥文件过大（超过 10 MiB）。".into());
        }
        let mut file = fs::File::open(kf_path).map_err(|e| format!("无法打开密钥文件：{e}"))?;
        key = key
            .with_keyfile(&mut file)
            .map_err(|e| format!("读取密钥文件失败：{e}"))?;
    }
    if !has_password && keyfile.is_none() {
        return Err("请输入主密码或选择密钥文件。".into());
    }
    Ok(key)
}

fn compute_etag(path: &Path, bytes: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    bytes.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn file_etag(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("读取数据库文件失败：{e}"))?;
    Ok(compute_etag(path, &bytes))
}

fn format_naive_dt(dt: Option<NaiveDateTime>) -> Option<String> {
    dt.map(|d| Utc.from_utc_datetime(&d).to_rfc3339())
}

fn parse_expiry_dt(value: Option<&str>) -> Option<NaiveDateTime> {
    let text = value?.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(text) {
        return Some(dt.with_timezone(&Utc).naive_utc());
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M") {
        return Some(dt);
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt);
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        return date.and_hms_opt(23, 59, 59);
    }
    None
}

fn icon_to_usize(icon: Option<&Icon>, fallback: usize) -> usize {
    match icon {
        Some(Icon::BuiltIn(id)) => *id,
        _ => fallback,
    }
}

fn parse_group_id(id: &str) -> Result<GroupId, String> {
    Uuid::parse_str(id)
        .map(GroupId::from_uuid)
        .map_err(|_| "分组 ID 无效。".to_string())
}

fn parse_entry_id(id: &str) -> Result<EntryId, String> {
    Uuid::parse_str(id)
        .map(EntryId::from_uuid)
        .map_err(|_| "条目 ID 无效。".to_string())
}

fn collect_recycle_bin_groups(db: &Database) -> HashSet<GroupId> {
    let mut set = HashSet::new();
    let Some(bin) = db.recycle_bin() else {
        return set;
    };
    let mut stack = vec![bin.id()];
    while let Some(gid) = stack.pop() {
        if set.insert(gid)
            && let Some(group) = db.group(gid)
        {
            for child in group.groups() {
                stack.push(child.id());
            }
        }
    }
    set
}

fn build_group_paths(db: &Database) -> HashMap<GroupId, String> {
    let mut paths = HashMap::new();
    fn walk(group: GroupRef<'_>, prefix: &str, out: &mut HashMap<GroupId, String>) {
        let current = if prefix.is_empty() {
            group.name.clone()
        } else {
            format!("{prefix} / {}", group.name)
        };
        out.insert(group.id(), current.clone());
        for child in group.groups() {
            walk(child, &current, out);
        }
    }
    let root = db.root();
    paths.insert(root.id(), root.name.clone());
    for child in root.groups() {
        walk(child, "", &mut paths);
    }
    paths
}

fn count_entries_recursive(group: GroupRef<'_>) -> usize {
    let mut total = group.entries().count();
    for child in group.groups() {
        total += count_entries_recursive(child);
    }
    total
}

fn serialize_entry(
    entry: EntryRef<'_>,
    group_paths: &HashMap<GroupId, String>,
    recycle_bin_groups: &HashSet<GroupId>,
) -> EntryView {
    let now = Times::now();
    let expires = entry.times.expires.unwrap_or(false);
    let is_expired = expires && entry.times.expiry < now;
    let parent_id = entry.parent().id();
    let group_path = group_paths.get(&parent_id).cloned().unwrap_or_default();
    let mut custom_fields: Vec<CustomFieldPayload> = entry
        .fields
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                fields::TITLE
                    | fields::USERNAME
                    | fields::PASSWORD
                    | fields::URL
                    | fields::NOTES
                    | fields::OTP
            )
        })
        .map(|(k, v)| CustomFieldPayload {
            key: k.clone(),
            value: v.as_str().to_string(),
            protected: v.is_protected(),
        })
        .collect();
    custom_fields.sort_by(|a, b| a.key.to_lowercase().cmp(&b.key.to_lowercase()));

    let mut attachments: Vec<AttachmentView> = entry
        .attachments_named()
        .map(|(name, att)| AttachmentView {
            name: name.to_string(),
            size: att.data.get().len(),
        })
        .collect();
    attachments.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    let history: Vec<HistoryItemView> = entry
        .history
        .as_ref()
        .map(|h| {
            h.get_entries()
                .iter()
                .enumerate()
                .map(|(index, item)| HistoryItemView {
                    index,
                    title: item.get_title().unwrap_or_default().to_string(),
                    username: item.get_username().unwrap_or_default().to_string(),
                    password: item.get_password().unwrap_or_default().to_string(),
                    url: item.get_url().unwrap_or_default().to_string(),
                    notes: item.get(fields::NOTES).unwrap_or_default().to_string(),
                    modified_at: format_naive_dt(item.times.last_modification),
                })
                .collect()
        })
        .unwrap_or_default();

    EntryView {
        id: entry.id().to_string(),
        group_id: parent_id.to_string(),
        group_path,
        in_recycle_bin: recycle_bin_groups.contains(&parent_id),
        title: entry.get_title().unwrap_or_default().to_string(),
        username: entry.get_username().unwrap_or_default().to_string(),
        password: entry.get_password().unwrap_or_default().to_string(),
        url: entry.get_url().unwrap_or_default().to_string(),
        notes: entry.get(fields::NOTES).unwrap_or_default().to_string(),
        otp: entry.get_raw_otp_value().map(ToOwned::to_owned),
        tags: entry.tags.clone(),
        icon_id: icon_to_usize(entry.icon(), 0),
        custom_fields,
        attachments,
        history,
        expires,
        expiry_time: if expires {
            format_naive_dt(Some(entry.times.expiry))
        } else {
            None
        },
        is_expired,
        created_at: format_naive_dt(entry.times.creation),
        modified_at: format_naive_dt(entry.times.last_modification),
        accessed_at: format_naive_dt(entry.times.last_access),
    }
}

fn serialize_meta(db: &Database, fallback_name: &str) -> VaultMetaView {
    let (kdf_type, kdf_rounds, kdf_memory_mib, kdf_parallelism) = match &db.config.kdf_config {
        KdfConfig::Aes { rounds } => ("aes".to_string(), *rounds, 0, 1),
        KdfConfig::Argon2 {
            iterations,
            memory,
            parallelism,
            ..
        } => (
            "argon2d".to_string(),
            *iterations,
            (*memory / (1024 * 1024)).max(1),
            *parallelism,
        ),
        KdfConfig::Argon2id {
            iterations,
            memory,
            parallelism,
            ..
        } => (
            "argon2id".to_string(),
            *iterations,
            (*memory / (1024 * 1024)).max(1),
            *parallelism,
        ),
        _ => ("argon2id".to_string(), 4, 16, 4),
    };
    let outer_cipher = match db.config.outer_cipher_config {
        OuterCipherConfig::AES256 => "aes256",
        OuterCipherConfig::ChaCha20 => "chacha20",
        OuterCipherConfig::Twofish => "twofish",
        _ => "aes256",
    }
    .to_string();
    let compression = match db.config.compression_config {
        CompressionConfig::GZip => "gzip",
        CompressionConfig::None => "none",
        _ => "gzip",
    }
    .to_string();

    VaultMetaView {
        name: db
            .meta
            .database_name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| fallback_name.to_string()),
        description: db.meta.database_description.clone().unwrap_or_default(),
        default_username: db.meta.default_username.clone().unwrap_or_default(),
        recycle_bin_enabled: db.meta.recyclebin_enabled.unwrap_or(true),
        history_max_items: db.meta.history_max_items.unwrap_or(10),
        history_max_size: db.meta.history_max_size.unwrap_or(6 * 1024 * 1024),
        outer_cipher,
        compression,
        kdf_type,
        kdf_rounds,
        kdf_memory_mib,
        kdf_parallelism,
    }
}

fn snapshot_tab(tab: &VaultTab) -> VaultSnapshot {
    let file_name = tab
        .path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "vault.kdbx".into());
    let path_str = tab.path.to_string_lossy().to_string();
    let keyfile_str = tab
        .keyfile_path
        .as_ref()
        .map(|p| p.to_string_lossy().to_string());

    match &tab.state {
        VaultState::Locked {
            name,
            format_version,
        } => VaultSnapshot {
            id: tab.id.clone(),
            path: path_str,
            file_name,
            keyfile_path: keyfile_str,
            locked: true,
            dirty: false,
            format_version: format_version.clone(),
            upgraded_on_save: false,
            meta: VaultMetaView {
                name: name.clone(),
                description: String::new(),
                default_username: String::new(),
                recycle_bin_enabled: true,
                history_max_items: 10,
                history_max_size: 6 * 1024 * 1024,
                outer_cipher: "aes256".into(),
                compression: "gzip".into(),
                kdf_type: "argon2id".into(),
                kdf_rounds: 4,
                kdf_memory_mib: 16,
                kdf_parallelism: 4,
            },
            root_group_id: None,
            recycle_bin_id: None,
            groups: Vec::new(),
            entries: Vec::new(),
        },
        VaultState::Unlocked { db, dirty, .. } => {
            let root = db.root();
            let root_id = root.id();
            let recycle_bin_id = db.recycle_bin().map(|g| g.id());
            let recycle_bin_groups = collect_recycle_bin_groups(db);
            let group_paths = build_group_paths(db);

            let mut groups = Vec::new();
            let mut entries = Vec::new();

            fn walk_group(
                group: GroupRef<'_>,
                root_id: GroupId,
                recycle_bin_id: Option<GroupId>,
                group_paths: &HashMap<GroupId, String>,
                recycle_bin_groups: &HashSet<GroupId>,
                groups_out: &mut Vec<GroupView>,
                entries_out: &mut Vec<EntryView>,
            ) {
                let is_root = group.id() == root_id;
                let is_recycle_bin = recycle_bin_id == Some(group.id());
                let fallback_icon = if is_recycle_bin {
                    RECYCLE_BIN_ICON
                } else {
                    DEFAULT_GROUP_ICON
                };
                let child_group_ids: Vec<String> =
                    group.groups().map(|g| g.id().to_string()).collect();
                let entry_ids: Vec<String> = group.entries().map(|e| e.id().to_string()).collect();
                let total_entries = count_entries_recursive(group.clone());

                groups_out.push(GroupView {
                    id: group.id().to_string(),
                    parent_id: group.parent().map(|p| p.id().to_string()),
                    name: if group.name.trim().is_empty() && is_root {
                        "Root".to_string()
                    } else {
                        group.name.clone()
                    },
                    notes: group.notes.clone().unwrap_or_default(),
                    icon_id: icon_to_usize(group.icon(), fallback_icon),
                    is_expanded: group.is_expanded,
                    is_root,
                    is_recycle_bin,
                    child_group_ids,
                    entry_ids,
                    total_entries,
                    enable_searching: group.enable_searching,
                });

                for entry in group.entries() {
                    entries_out.push(serialize_entry(entry, group_paths, recycle_bin_groups));
                }
                for child in group.groups() {
                    walk_group(
                        child,
                        root_id,
                        recycle_bin_id,
                        group_paths,
                        recycle_bin_groups,
                        groups_out,
                        entries_out,
                    );
                }
            }

            walk_group(
                root,
                root_id,
                recycle_bin_id,
                &group_paths,
                &recycle_bin_groups,
                &mut groups,
                &mut entries,
            );

            let fallback_name = tab
                .path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "Vault".into());
            let upgraded_on_save = !matches!(db.config.version, DatabaseVersion::KDB4(_));

            VaultSnapshot {
                id: tab.id.clone(),
                path: path_str,
                file_name,
                keyfile_path: keyfile_str,
                locked: false,
                dirty: *dirty,
                format_version: db.config.version.to_string(),
                upgraded_on_save,
                meta: serialize_meta(db, &fallback_name),
                root_group_id: Some(root_id.to_string()),
                recycle_bin_id: recycle_bin_id.map(|id| id.to_string()),
                groups,
                entries,
            }
        }
    }
}

fn ensure_kdbx4_for_save(db: &mut Database) {
    if !matches!(db.config.version, DatabaseVersion::KDB4(_)) {
        db.config.version = DatabaseVersion::KDB4(1);
        if matches!(db.config.inner_cipher_config, InnerCipherConfig::Plain) {
            db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        }
    }
}

fn write_database_atomic(db: &mut Database, key: &DatabaseKey, path: &Path) -> Result<String, String> {
    ensure_kdbx4_for_save(db);
    let mut buffer = Vec::new();
    db.save(&mut buffer, key.clone())
        .map_err(|error| format!("加密保存数据库失败：{error}"))?;
    let parent = path
        .parent()
        .ok_or_else(|| "数据库路径缺少父目录。".to_string())?;
    fs::create_dir_all(parent).map_err(|e| format!("创建目录失败：{e}"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("创建临时保存文件失败：{e}"))?;
    temp.write_all(&buffer)
        .map_err(|e| format!("写入临时文件失败：{e}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|e| format!("同步磁盘失败：{e}"))?;
    temp.persist(path)
        .map_err(|e| format!("替换目标数据库文件失败：{}", e.error))?;
    Ok(compute_etag(path, &buffer))
}

fn ensure_recycle_bin(db: &mut Database) -> GroupId {
    if let Some(bin) = db.recycle_bin() {
        return bin.id();
    }
    let bin_id = {
        let mut root = db.root_mut();
        let mut group = root.add_group();
        group.name = "Recycle Bin".into();
        group.set_icon_builtin(RECYCLE_BIN_ICON);
        group.enable_searching = Some(false);
        group.enable_autotype = Some(false);
        group.id()
    };
    db.meta.recyclebin_enabled = Some(true);
    db.meta.recyclebin_uuid = Some(bin_id.uuid());
    db.meta.recyclebin_changed = Some(Times::now());
    bin_id
}

fn apply_entry_payload(
    entry: &mut keepass::db::EntryMut<'_>,
    payload: &EntryPayload,
) {
    entry.set_unprotected(fields::TITLE, payload.title.trim());
    entry.set_unprotected(fields::USERNAME, &payload.username);
    entry.set_protected(fields::PASSWORD, &payload.password);
    entry.set_unprotected(fields::URL, payload.url.trim());
    entry.set_unprotected(fields::NOTES, &payload.notes);

    if let Some(otp) = payload.otp.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        entry.set_protected(fields::OTP, otp);
    } else {
        entry.fields.remove(fields::OTP);
    }

    // Remove old custom fields, then insert current ones
    let standard = [
        fields::TITLE,
        fields::USERNAME,
        fields::PASSWORD,
        fields::URL,
        fields::NOTES,
        fields::OTP,
    ];
    let old_custom: Vec<String> = entry
        .fields
        .keys()
        .filter(|k| !standard.contains(&k.as_str()))
        .cloned()
        .collect();
    for key in old_custom {
        entry.fields.remove(&key);
    }
    for field in &payload.custom_fields {
        let key = field.key.trim();
        if key.is_empty() || standard.contains(&key) {
            continue;
        }
        if field.protected {
            entry.set_protected(key, &field.value);
        } else {
            entry.set_unprotected(key, &field.value);
        }
    }

    entry.tags = payload
        .tags
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if let Some(icon_id) = payload.icon_id {
        entry.set_icon_builtin(icon_id);
    }

    entry.times.expires = Some(payload.expires);
    if payload.expires
        && let Some(expiry) = parse_expiry_dt(payload.expiry_time.as_deref())
    {
        entry.times.expiry = expiry;
    }
    entry.times.last_modification = Some(Times::now());
}

fn rebuild_history(entries: Vec<keepass::db::Entry>) -> History {
    let mut history = History::default();
    for item in entries.into_iter().rev() {
        history.add_entry(item);
    }
    history
}

fn truncate_entry_history(db: &mut Database, entry_id: EntryId) {
    let max_items = db.meta.history_max_items.unwrap_or(10);
    if max_items < 0 {
        return;
    }
    let max = max_items as usize;
    let trimmed = if let Some(mut entry) = db.entry_mut(entry_id) {
        if let Some(history) = entry.history.as_ref()
            && history.get_entries().len() > max
        {
            let kept = history.get_entries()[..max].to_vec();
            entry.history = Some(rebuild_history(kept));
            true
        } else {
            false
        }
    } else {
        false
    };
    if trimmed {
        db.remove_unused_attachments();
    }
}

fn escape_csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

impl VaultManager {
    pub fn list_tabs(&self) -> Result<Vec<VaultSnapshot>, String> {
        let tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        Ok(tabs.values().map(snapshot_tab).collect())
    }

    pub fn create_database(
        &self,
        path: PathBuf,
        password: Option<String>,
        keyfile: Option<PathBuf>,
        name: String,
        description: String,
    ) -> Result<VaultSnapshot, String> {
        let key = build_key(password.as_deref(), keyfile.as_deref())?;
        let mut db = Database::new();
        db.config.version = DatabaseVersion::KDB4(1);
        db.config.outer_cipher_config = OuterCipherConfig::AES256;
        db.config.compression_config = CompressionConfig::GZip;
        db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        db.config.kdf_config = KdfConfig::Argon2id {
            iterations: 4,
            memory: 16 * 1024 * 1024,
            parallelism: 4,
            version: argon2::Version::Version13,
        };
        let db_name = if name.trim().is_empty() {
            path.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "My Vault".into())
        } else {
            name.trim().to_string()
        };
        db.meta.generator = Some(concat!("My KeePass ", env!("CARGO_PKG_VERSION")).into());
        db.meta.database_name = Some(db_name.clone());
        db.meta.database_name_changed = Some(Times::now());
        if !description.trim().is_empty() {
            db.meta.database_description = Some(description.trim().to_string());
            db.meta.database_description_changed = Some(Times::now());
        }
        db.meta.recyclebin_enabled = Some(true);
        db.meta.history_max_items = Some(10);
        db.meta.history_max_size = Some(6 * 1024 * 1024);
        db.meta.master_key_changed = Some(Times::now());
        {
            let mut root = db.root_mut();
            root.name = db_name;
            root.set_icon_builtin(DEFAULT_GROUP_ICON);
            for (group_name, icon_id) in [
                ("General", 48usize),
                ("Internet", 1),
                ("Email", 19),
                ("Banking", 66),
                ("Server & SSH", 3),
            ] {
                let mut child = root.add_group();
                child.name = group_name.into();
                child.set_icon_builtin(icon_id);
            }
        }
        ensure_recycle_bin(&mut db);

        let etag = write_database_atomic(&mut db, &key, &path)?;
        let id = Uuid::new_v4().to_string();
        let tab = VaultTab {
            id: id.clone(),
            path,
            keyfile_path: keyfile,
            state: VaultState::Unlocked {
                db,
                key,
                dirty: false,
                file_etag: Some(etag),
            },
        };
        let snapshot = snapshot_tab(&tab);
        self.tabs
            .lock()
            .map_err(|e| e.to_string())?
            .insert(id, tab);
        Ok(snapshot)
    }

    pub fn open_database(
        &self,
        path: PathBuf,
        password: Option<String>,
        keyfile: Option<PathBuf>,
    ) -> Result<VaultSnapshot, String> {
        let canonical = path.canonicalize().unwrap_or(path);
        let bytes = fs::read(&canonical).map_err(|e| format!("读取数据库文件失败：{e}"))?;
        let etag = compute_etag(&canonical, &bytes);
        let key = build_key(password.as_deref(), keyfile.as_deref())?;
        let db = Database::parse(&bytes, key.clone()).map_err(|error| {
            let msg = error.to_string();
            if msg.to_lowercase().contains("key") || msg.to_lowercase().contains("hmac") {
                "解密失败：主密码或密钥文件不正确。".to_string()
            } else {
                format!("打开数据库失败：{msg}")
            }
        })?;

        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        if let Some(existing) = tabs.values_mut().find(|t| t.path == canonical) {
            existing.keyfile_path = keyfile;
            existing.state = VaultState::Unlocked {
                db,
                key,
                dirty: false,
                file_etag: Some(etag),
            };
            return Ok(snapshot_tab(existing));
        }
        let id = Uuid::new_v4().to_string();
        let tab = VaultTab {
            id: id.clone(),
            path: canonical,
            keyfile_path: keyfile,
            state: VaultState::Unlocked {
                db,
                key,
                dirty: false,
                file_etag: Some(etag),
            },
        };
        let snapshot = snapshot_tab(&tab);
        tabs.insert(id, tab);
        Ok(snapshot)
    }

    pub fn stage_locked_database(
        &self,
        path: PathBuf,
        keyfile: Option<PathBuf>,
    ) -> Result<Option<VaultSnapshot>, String> {
        if !path.is_file() {
            return Ok(None);
        }
        let canonical = path.canonicalize().unwrap_or(path);
        let valid_keyfile = keyfile.filter(|kf| kf.is_file());
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        if let Some(existing) = tabs.values().find(|t| t.path == canonical) {
            return Ok(Some(snapshot_tab(existing)));
        }
        let name = canonical
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "Vault".into());
        let id = Uuid::new_v4().to_string();
        let tab = VaultTab {
            id: id.clone(),
            path: canonical,
            keyfile_path: valid_keyfile,
            state: VaultState::Locked {
                name,
                format_version: "KDBX".into(),
            },
        };
        let snapshot = snapshot_tab(&tab);
        tabs.insert(id, tab);
        Ok(Some(snapshot))
    }

    pub fn unlock_database(
        &self,
        tab_id: &str,
        password: Option<String>,
        keyfile: Option<PathBuf>,
    ) -> Result<VaultSnapshot, String> {
        let path = {
            let tabs = self.tabs.lock().map_err(|e| e.to_string())?;
            let tab = tabs
                .get(tab_id)
                .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
            tab.path.clone()
        };
        let bytes = fs::read(&path).map_err(|e| format!("读取数据库文件失败：{e}"))?;
        let etag = compute_etag(&path, &bytes);
        let key = build_key(password.as_deref(), keyfile.as_deref())?;
        let db = Database::parse(&bytes, key.clone()).map_err(|error| {
            let msg = error.to_string();
            if msg.to_lowercase().contains("key") || msg.to_lowercase().contains("hmac") {
                "解锁失败：主密码或密钥文件不正确。".to_string()
            } else {
                format!("解锁数据库失败：{msg}")
            }
        })?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        tab.keyfile_path = keyfile;
        tab.state = VaultState::Unlocked {
            db,
            key,
            dirty: false,
            file_etag: Some(etag),
        };
        Ok(snapshot_tab(tab))
    }

    pub fn lock_database(&self, tab_id: &str) -> Result<VaultSnapshot, String> {
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let (name, format_version) = match &tab.state {
            VaultState::Unlocked { db, .. } => {
                let fallback = tab
                    .path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "Vault".into());
                let name = db
                    .meta
                    .database_name
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or(fallback);
                (name, db.config.version.to_string())
            }
            VaultState::Locked {
                name,
                format_version,
            } => (name.clone(), format_version.clone()),
        };
        // Replacing VaultState::Unlocked drops `db` and `key` (ZeroizeOnDrop).
        tab.state = VaultState::Locked {
            name,
            format_version,
        };
        Ok(snapshot_tab(tab))
    }

    pub fn lock_all(&self) -> Result<Vec<VaultSnapshot>, String> {
        let ids: Vec<String> = self
            .tabs
            .lock()
            .map_err(|e| e.to_string())?
            .keys()
            .cloned()
            .collect();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(self.lock_database(&id)?);
        }
        Ok(out)
    }

    pub fn close_database(&self, tab_id: &str) -> Result<(), String> {
        self.tabs
            .lock()
            .map_err(|e| e.to_string())?
            .remove(tab_id);
        Ok(())
    }

    pub fn shutdown(&self) {
        if let Ok(mut tabs) = self.tabs.lock() {
            tabs.clear();
        }
    }

    pub fn save_database(&self, tab_id: &str, force: bool) -> Result<VaultSnapshot, String> {
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let path = tab.path.clone();
        match &mut tab.state {
            VaultState::Unlocked {
                db,
                key,
                dirty,
                file_etag,
            } => {
                if !force
                    && let Some(expected) = file_etag.as_deref()
                    && path.exists()
                {
                    let current = file_etag_check(&path)?;
                    if current != expected {
                        return Err(
                            "CONFLICT:磁盘上的数据库文件已被外部程序修改。请确认是否强制覆盖，或另存为新文件。"
                                .into(),
                        );
                    }
                }
                let new_etag = write_database_atomic(db, key, &path)?;
                *file_etag = Some(new_etag);
                *dirty = false;
            }
            VaultState::Locked { .. } => return Err("数据库已锁定，无法保存。".into()),
        }
        Ok(snapshot_tab(tab))
    }

    pub fn save_database_as(&self, tab_id: &str, new_path: PathBuf) -> Result<VaultSnapshot, String> {
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        match &mut tab.state {
            VaultState::Unlocked {
                db,
                key,
                dirty,
                file_etag,
            } => {
                let new_etag = write_database_atomic(db, key, &new_path)?;
                *file_etag = Some(new_etag);
                *dirty = false;
            }
            VaultState::Locked { .. } => return Err("数据库已锁定，无法另存为。".into()),
        }
        tab.path = new_path;
        Ok(snapshot_tab(tab))
    }

    pub fn change_master_key(
        &self,
        tab_id: &str,
        new_password: Option<String>,
        new_keyfile: Option<PathBuf>,
    ) -> Result<VaultSnapshot, String> {
        let new_key = build_key(new_password.as_deref(), new_keyfile.as_deref())?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let path = tab.path.clone();
        match &mut tab.state {
            VaultState::Unlocked {
                db,
                key,
                dirty,
                file_etag,
            } => {
                db.meta.master_key_changed = Some(Times::now());
                let new_etag = write_database_atomic(db, &new_key, &path)?;
                *key = new_key;
                *file_etag = Some(new_etag);
                *dirty = false;
            }
            VaultState::Locked { .. } => return Err("数据库已锁定，请先解锁后再修改主密钥。".into()),
        }
        tab.keyfile_path = new_keyfile;
        Ok(snapshot_tab(tab))
    }

    pub fn update_database_settings(
        &self,
        tab_id: &str,
        settings: DatabaseSettingsPayload,
    ) -> Result<VaultSnapshot, String> {
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        let now = Times::now();
        let trimmed_name = settings.name.trim().to_string();
        if !trimmed_name.is_empty() {
            db.meta.database_name = Some(trimmed_name.clone());
            db.meta.database_name_changed = Some(now);
            db.root_mut().name = trimmed_name;
        }
        db.meta.database_description = Some(settings.description.trim().to_string());
        db.meta.database_description_changed = Some(now);
        db.meta.default_username = Some(settings.default_username.trim().to_string());
        db.meta.default_username_changed = Some(now);
        db.meta.recyclebin_enabled = Some(settings.recycle_bin_enabled);
        db.meta.recyclebin_changed = Some(now);
        db.meta.history_max_items = Some(settings.history_max_items.clamp(0, 1000));
        db.meta.history_max_size = Some(settings.history_max_size.clamp(65_536, 100 * 1024 * 1024));
        db.meta.settings_changed = Some(now);

        db.config.outer_cipher_config = match settings.outer_cipher.as_str() {
            "chacha20" => OuterCipherConfig::ChaCha20,
            "twofish" => OuterCipherConfig::Twofish,
            _ => OuterCipherConfig::AES256,
        };
        db.config.compression_config = match settings.compression.as_str() {
            "none" => CompressionConfig::None,
            _ => CompressionConfig::GZip,
        };
        db.config.kdf_config = match settings.kdf_type.as_str() {
            "aes" => KdfConfig::Aes {
                rounds: settings.kdf_rounds.clamp(1_000, 100_000_000),
            },
            "argon2d" => KdfConfig::Argon2 {
                iterations: settings.kdf_rounds.clamp(1, 200),
                memory: settings.kdf_memory_mib.clamp(1, 512) * 1024 * 1024,
                parallelism: settings.kdf_parallelism.clamp(1, 16),
                version: argon2::Version::Version13,
            },
            _ => KdfConfig::Argon2id {
                iterations: settings.kdf_rounds.clamp(1, 200),
                memory: settings.kdf_memory_mib.clamp(1, 512) * 1024 * 1024,
                parallelism: settings.kdf_parallelism.clamp(1, 16),
                version: argon2::Version::Version13,
            },
        };
        *dirty = true;
        Ok(snapshot_tab(tab))
    }

    pub fn create_group(
        &self,
        tab_id: &str,
        parent_id: String,
        payload: GroupPayload,
    ) -> Result<(VaultSnapshot, String), String> {
        let name = payload.name.trim().to_string();
        if name.is_empty() {
            return Err("分组名称不能为空。".into());
        }
        let parent_gid = parse_group_id(&parent_id)?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        let mut parent = db
            .group_mut(parent_gid)
            .ok_or_else(|| "父分组不存在。".to_string())?;
        let mut group = parent.add_group();
        group.name = name;
        group.notes = if payload.notes.trim().is_empty() {
            None
        } else {
            Some(payload.notes)
        };
        group.enable_searching = payload.enable_searching;
        group.set_icon_builtin(payload.icon_id.unwrap_or(DEFAULT_GROUP_ICON));
        let new_id = group.id().to_string();
        *dirty = true;
        Ok((snapshot_tab(tab), new_id))
    }

    pub fn update_group(
        &self,
        tab_id: &str,
        group_id: String,
        payload: GroupPayload,
    ) -> Result<VaultSnapshot, String> {
        let name = payload.name.trim().to_string();
        if name.is_empty() {
            return Err("分组名称不能为空。".into());
        }
        let gid = parse_group_id(&group_id)?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        let mut group = db
            .group_mut(gid)
            .ok_or_else(|| "分组不存在。".to_string())?;
        group.name = name;
        group.notes = if payload.notes.trim().is_empty() {
            None
        } else {
            Some(payload.notes)
        };
        group.enable_searching = payload.enable_searching;
        if let Some(icon_id) = payload.icon_id {
            group.set_icon_builtin(icon_id);
        }
        group.times.last_modification = Some(Times::now());
        *dirty = true;
        Ok(snapshot_tab(tab))
    }

    pub fn move_group(
        &self,
        tab_id: &str,
        group_id: String,
        new_parent_id: String,
    ) -> Result<VaultSnapshot, String> {
        let gid = parse_group_id(&group_id)?;
        let target_gid = parse_group_id(&new_parent_id)?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        let mut group = db
            .group_mut(gid)
            .ok_or_else(|| "分组不存在。".to_string())?;
        group
            .track_changes()
            .move_to(target_gid)
            .map_err(|e| format!("移动分组失败：{e}"))?;
        *dirty = true;
        Ok(snapshot_tab(tab))
    }

    pub fn delete_group(
        &self,
        tab_id: &str,
        group_id: String,
        permanent: bool,
    ) -> Result<VaultSnapshot, String> {
        let gid = parse_group_id(&group_id)?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        if db.root().id() == gid {
            return Err("不能删除根分组。".into());
        }
        let recycle_enabled = db.meta.recyclebin_enabled.unwrap_or(true);
        let in_bin = collect_recycle_bin_groups(db).contains(&gid);
        if !permanent && recycle_enabled && !in_bin {
            let bin_id = ensure_recycle_bin(db);
            if let Some(mut group) = db.group_mut(gid) {
                group
                    .track_changes()
                    .move_to(bin_id)
                    .map_err(|e| format!("移入回收站失败：{e}"))?;
            }
        } else if let Some(mut group) = db.group_mut(gid) {
            group
                .track_changes()
                .remove()
                .map_err(|e| format!("删除分组失败：{e}"))?;
        }
        *dirty = true;
        Ok(snapshot_tab(tab))
    }

    pub fn empty_recycle_bin(&self, tab_id: &str) -> Result<VaultSnapshot, String> {
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        if let Some(bin) = db.recycle_bin() {
            let child_groups: Vec<GroupId> = bin.group_ids().collect();
            let child_entries: Vec<EntryId> = bin.entry_ids().collect();
            for eid in child_entries {
                if let Some(mut entry) = db.entry_mut(eid) {
                    entry.track_changes().remove();
                }
            }
            for gid in child_groups {
                if let Some(mut group) = db.group_mut(gid) {
                    let _ = group.track_changes().remove();
                }
            }
            db.remove_unused_attachments();
            *dirty = true;
        }
        Ok(snapshot_tab(tab))
    }

    pub fn create_entry(
        &self,
        tab_id: &str,
        group_id: String,
        payload: EntryPayload,
    ) -> Result<(VaultSnapshot, String), String> {
        let gid = parse_group_id(&group_id)?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        let mut group = db
            .group_mut(gid)
            .ok_or_else(|| "目标分组不存在。".to_string())?;
        let mut entry = group.add_entry();
        apply_entry_payload(&mut entry, &payload);
        let new_id = entry.id().to_string();
        *dirty = true;
        Ok((snapshot_tab(tab), new_id))
    }

    pub fn update_entry(
        &self,
        tab_id: &str,
        entry_id: String,
        payload: EntryPayload,
    ) -> Result<VaultSnapshot, String> {
        let eid = parse_entry_id(&entry_id)?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        {
            let mut entry = db
                .entry_mut(eid)
                .ok_or_else(|| "条目不存在。".to_string())?;
            let mut tracked = entry.track_changes();
            let mut mutable = tracked.as_mut();
            apply_entry_payload(&mut mutable, &payload);
        }
        truncate_entry_history(db, eid);
        *dirty = true;
        Ok(snapshot_tab(tab))
    }

    pub fn clone_entry(&self, tab_id: &str, entry_id: String) -> Result<(VaultSnapshot, String), String> {
        let eid = parse_entry_id(&entry_id)?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        let (parent_id, fields_clone, tags_clone, icon_clone, expires, expiry, attachments_clone) = {
            let source = db
                .entry(eid)
                .ok_or_else(|| "条目不存在。".to_string())?;
            let atts: Vec<(String, Value<Vec<u8>>)> = source
                .attachments_named()
                .map(|(n, a)| (n.to_string(), a.data.clone()))
                .collect();
            (
                source.parent().id(),
                source.fields.clone(),
                source.tags.clone(),
                source.icon().cloned(),
                source.times.expires,
                source.times.expiry,
                atts,
            )
        };
        let new_id = {
            let mut group = db
                .group_mut(parent_id)
                .ok_or_else(|| "父分组不存在。".to_string())?;
            let mut cloned = group.add_entry();
            cloned.fields = fields_clone;
            let title = cloned.get_title().unwrap_or_default().to_string();
            cloned.set_unprotected(fields::TITLE, format!("{title} - Copy"));
            cloned.tags = tags_clone;
            if let Some(Icon::BuiltIn(icon_id)) = icon_clone {
                cloned.set_icon_builtin(icon_id);
            }
            cloned.times.expires = expires;
            cloned.times.expiry = expiry;
            for (name, data) in attachments_clone {
                cloned.add_attachment(name, data);
            }
            cloned.id().to_string()
        };
        *dirty = true;
        Ok((snapshot_tab(tab), new_id))
    }

    pub fn move_entry(
        &self,
        tab_id: &str,
        entry_id: String,
        target_group_id: String,
    ) -> Result<VaultSnapshot, String> {
        let eid = parse_entry_id(&entry_id)?;
        let gid = parse_group_id(&target_group_id)?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        let mut entry = db
            .entry_mut(eid)
            .ok_or_else(|| "条目不存在。".to_string())?;
        entry
            .track_changes()
            .move_to(gid)
            .map_err(|e| format!("移动条目失败：{e}"))?;
        *dirty = true;
        Ok(snapshot_tab(tab))
    }

    pub fn delete_entry(
        &self,
        tab_id: &str,
        entry_id: String,
        permanent: bool,
    ) -> Result<VaultSnapshot, String> {
        let eid = parse_entry_id(&entry_id)?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        let recycle_enabled = db.meta.recyclebin_enabled.unwrap_or(true);
        let in_bin = db
            .entry(eid)
            .is_some_and(|e| collect_recycle_bin_groups(db).contains(&e.parent().id()));
        if !permanent && recycle_enabled && !in_bin {
            let bin_id = ensure_recycle_bin(db);
            if let Some(mut entry) = db.entry_mut(eid) {
                entry
                    .track_changes()
                    .move_to(bin_id)
                    .map_err(|e| format!("移入回收站失败：{e}"))?;
            }
        } else if let Some(mut entry) = db.entry_mut(eid) {
            entry.track_changes().remove();
        }
        *dirty = true;
        Ok(snapshot_tab(tab))
    }

    pub fn restore_entry_history(
        &self,
        tab_id: &str,
        entry_id: String,
        history_index: usize,
    ) -> Result<VaultSnapshot, String> {
        let eid = parse_entry_id(&entry_id)?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        {
            let mut entry = db
                .entry_mut(eid)
                .ok_or_else(|| "条目不存在。".to_string())?;
            let historical = entry
                .history
                .as_ref()
                .and_then(|h| h.get_entries().get(history_index))
                .cloned()
                .ok_or_else(|| "历史记录不存在。".to_string())?;
            let mut tracked = entry.track_changes();
            let mut mutable = tracked.as_mut();
            mutable.fields = historical.fields;
            mutable.tags = historical.tags;
            mutable.times.expires = historical.times.expires;
            mutable.times.expiry = historical.times.expiry;
            mutable.times.last_modification = Some(Times::now());
        }
        truncate_entry_history(db, eid);
        *dirty = true;
        Ok(snapshot_tab(tab))
    }

    pub fn delete_entry_history(
        &self,
        tab_id: &str,
        entry_id: String,
        history_index: usize,
    ) -> Result<VaultSnapshot, String> {
        let eid = parse_entry_id(&entry_id)?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        let removed = if let Some(mut entry) = db.entry_mut(eid) {
            if let Some(history) = entry.history.as_ref()
                && history_index < history.get_entries().len()
            {
                let mut entries = history.get_entries().clone();
                entries.remove(history_index);
                entry.history = Some(rebuild_history(entries));
                true
            } else {
                false
            }
        } else {
            false
        };
        if removed {
            db.remove_unused_attachments();
            *dirty = true;
        }
        Ok(snapshot_tab(tab))
    }

    pub fn add_entry_attachment(
        &self,
        tab_id: &str,
        entry_id: String,
        file_path: PathBuf,
    ) -> Result<VaultSnapshot, String> {
        let eid = parse_entry_id(&entry_id)?;
        let meta = fs::metadata(&file_path).map_err(|e| format!("读取附件失败：{e}"))?;
        if !meta.is_file() {
            return Err("请选择普通文件作为附件。".into());
        }
        if meta.len() > MAX_ATTACHMENT_BYTES {
            return Err("附件大小不能超过 20 MiB。".into());
        }
        let name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .filter(|n| !n.is_empty())
            .ok_or_else(|| "附件文件名无效。".to_string())?;
        let data = fs::read(&file_path).map_err(|e| format!("读取附件内容失败：{e}"))?;

        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        let mut entry = db
            .entry_mut(eid)
            .ok_or_else(|| "条目不存在。".to_string())?;
        entry.add_attachment(name, Value::protected(data));
        entry.times.last_modification = Some(Times::now());
        *dirty = true;
        Ok(snapshot_tab(tab))
    }

    pub fn export_entry_attachment(
        &self,
        tab_id: &str,
        entry_id: String,
        name: String,
        dest_path: PathBuf,
    ) -> Result<(), String> {
        let eid = parse_entry_id(&entry_id)?;
        let tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, .. } = &tab.state else {
            return Err("数据库已锁定。".into());
        };
        let entry = db
            .entry(eid)
            .ok_or_else(|| "条目不存在。".to_string())?;
        let att = entry
            .attachment_by_name(&name)
            .ok_or_else(|| "附件不存在。".to_string())?;
        fs::write(&dest_path, att.data.get()).map_err(|e| format!("导出附件失败：{e}"))
    }

    pub fn remove_entry_attachment(
        &self,
        tab_id: &str,
        entry_id: String,
        name: String,
    ) -> Result<VaultSnapshot, String> {
        let eid = parse_entry_id(&entry_id)?;
        let mut tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get_mut(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, dirty, .. } = &mut tab.state else {
            return Err("数据库已锁定。".into());
        };
        let mut entry = db
            .entry_mut(eid)
            .ok_or_else(|| "条目不存在。".to_string())?;
        entry.remove_attachment_by_name(&name);
        entry.times.last_modification = Some(Times::now());
        *dirty = true;
        Ok(snapshot_tab(tab))
    }

    pub fn get_entry_totp(&self, tab_id: &str, entry_id: String) -> Result<TotpCodeView, String> {
        let eid = parse_entry_id(&entry_id)?;
        let tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, .. } = &tab.state else {
            return Err("数据库已锁定。".into());
        };
        let entry = db
            .entry(eid)
            .ok_or_else(|| "条目不存在。".to_string())?;
        let totp = entry
            .get_otp()
            .map_err(|e| format!("无效的 TOTP 配置：{e}"))?;
        let code = totp
            .value_now()
            .map_err(|e| format!("生成动态验证码失败：{e}"))?;
        Ok(TotpCodeView {
            code: code.code,
            valid_for_secs: code.valid_for.as_secs(),
            period_secs: code.period.as_secs(),
        })
    }

    pub fn export_csv(&self, tab_id: &str, dest_path: PathBuf) -> Result<usize, String> {
        let tabs = self.tabs.lock().map_err(|e| e.to_string())?;
        let tab = tabs
            .get(tab_id)
            .ok_or_else(|| "未找到对应的数据库标签。".to_string())?;
        let VaultState::Unlocked { db, .. } = &tab.state else {
            return Err("数据库已锁定。".into());
        };
        let recycle_bin_groups = collect_recycle_bin_groups(db);
        let group_paths = build_group_paths(db);

        let mut lines = vec!["\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"Tags\"".to_string()];
        let mut count = 0usize;

        fn walk(
            group: GroupRef<'_>,
            recycle_bin_groups: &HashSet<GroupId>,
            group_paths: &HashMap<GroupId, String>,
            lines: &mut Vec<String>,
            count: &mut usize,
        ) {
            if recycle_bin_groups.contains(&group.id()) {
                return;
            }
            let group_path = group_paths.get(&group.id()).cloned().unwrap_or_default();
            for entry in group.entries() {
                let row = [
                    escape_csv_cell(&group_path),
                    escape_csv_cell(entry.get_title().unwrap_or_default()),
                    escape_csv_cell(entry.get_username().unwrap_or_default()),
                    escape_csv_cell(entry.get_password().unwrap_or_default()),
                    escape_csv_cell(entry.get_url().unwrap_or_default()),
                    escape_csv_cell(entry.get(fields::NOTES).unwrap_or_default()),
                    escape_csv_cell(&entry.tags.join("; ")),
                ]
                .join(",");
                lines.push(row);
                *count += 1;
            }
            for child in group.groups() {
                walk(child, recycle_bin_groups, group_paths, lines, count);
            }
        }

        walk(db.root(), &recycle_bin_groups, &group_paths, &mut lines, &mut count);
        let content = lines.join("\n") + "\n";
        let parent = dest_path
            .parent()
            .ok_or_else(|| "导出路径缺少父目录。".to_string())?;
        let mut temp =
            tempfile::NamedTempFile::new_in(parent).map_err(|e| format!("创建临时导出文件失败：{e}"))?;
        temp.write_all(content.as_bytes())
            .map_err(|e| format!("写入 CSV 失败：{e}"))?;
        temp.as_file()
            .sync_all()
            .map_err(|e| format!("同步磁盘失败：{e}"))?;
        temp.persist(&dest_path)
            .map_err(|e| format!("保存 CSV 失败：{}", e.error))?;
        Ok(count)
    }
}

fn file_etag_check(path: &Path) -> Result<String, String> {
    file_etag(path)
}

pub fn generate_keyfile(dest_path: &Path) -> Result<(), String> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|e| format!("生成随机密钥失败：{e}"))?;
    let encoded = BASE64.encode(raw);
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n  <Meta>\n    <Version>1.00</Version>\n  </Meta>\n  <Key>\n    <Data>{encoded}</Data>\n  </Key>\n</KeyFile>\n"
    );
    let parent = dest_path
        .parent()
        .ok_or_else(|| "密钥文件路径缺少父目录。".to_string())?;
    fs::create_dir_all(parent).map_err(|e| format!("创建目录失败：{e}"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("创建密钥文件失败：{e}"))?;
    temp.write_all(xml.as_bytes())
        .map_err(|e| format!("写入密钥文件失败：{e}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|e| format!("同步密钥文件失败：{e}"))?;
    temp.persist(dest_path)
        .map_err(|e| format!("保存密钥文件失败：{}", e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_kdbx4_lifecycle_crud_history_recycle_bin_keyfile_and_csv() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("vault.kdbx");
        let kf_path = dir.path().join("vault.key");
        let csv_path = dir.path().join("export.csv");
        let att_src = dir.path().join("secret.txt");
        let att_dst = dir.path().join("secret_out.txt");
        fs::write(&att_src, b"top-secret-attachment").unwrap();
        generate_keyfile(&kf_path).unwrap();

        let mgr = VaultManager::default();
        let created = mgr
            .create_database(
                db_path.clone(),
                Some("master-pass-123".into()),
                Some(kf_path.clone()),
                "Personal Vault".into(),
                "Test vault".into(),
            )
            .unwrap();
        assert!(!created.locked);
        assert!(!created.dirty);
        assert!(created.format_version.starts_with("KDBX4"));
        let root_id = created.root_group_id.clone().unwrap();

        // Create subgroup
        let (snap, grp_id) = mgr
            .create_group(
                &created.id,
                root_id.clone(),
                GroupPayload {
                    name: "Cloud".into(),
                    notes: "Cloud accounts".into(),
                    icon_id: Some(1),
                    enable_searching: None,
                },
            )
            .unwrap();
        assert!(snap.dirty);

        // Create entry with custom field & TOTP
        let (snap, entry_id) = mgr
            .create_entry(
                &created.id,
                grp_id.clone(),
                EntryPayload {
                    title: "GitHub".into(),
                    username: "alice".into(),
                    password: "old-password".into(),
                    url: "https://github.com".into(),
                    notes: "Main account".into(),
                    otp: Some("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&period=30&digits=6".into()),
                    tags: vec!["dev".into(), "work".into()],
                    icon_id: Some(1),
                    expires: false,
                    expiry_time: None,
                    custom_fields: vec![CustomFieldPayload {
                        key: "RecoveryCode".into(),
                        value: "ABCD-1234".into(),
                        protected: true,
                    }],
                },
            )
            .unwrap();
        assert_eq!(snap.entries.len(), 1);

        // Verify TOTP generation
        let totp = mgr.get_entry_totp(&created.id, entry_id.clone()).unwrap();
        assert_eq!(totp.code.len(), 6);
        assert_eq!(totp.period_secs, 30);

        // Update entry -> creates history item
        let snap = mgr
            .update_entry(
                &created.id,
                entry_id.clone(),
                EntryPayload {
                    title: "GitHub".into(),
                    username: "alice".into(),
                    password: "new-password".into(),
                    url: "https://github.com".into(),
                    notes: "Updated".into(),
                    otp: None,
                    tags: vec!["dev".into()],
                    icon_id: Some(1),
                    expires: false,
                    expiry_time: None,
                    custom_fields: vec![],
                },
            )
            .unwrap();
        let updated_entry = snap.entries.iter().find(|e| e.id == entry_id).unwrap();
        assert_eq!(updated_entry.password, "new-password");
        assert_eq!(updated_entry.history.len(), 1);
        assert_eq!(updated_entry.history[0].password, "old-password");

        // Restore history item
        let snap = mgr
            .restore_entry_history(&created.id, entry_id.clone(), 0)
            .unwrap();
        let restored = snap.entries.iter().find(|e| e.id == entry_id).unwrap();
        assert_eq!(restored.password, "old-password");

        // Add & export attachment
        let snap = mgr
            .add_entry_attachment(&created.id, entry_id.clone(), att_src)
            .unwrap();
        assert_eq!(snap.entries[0].attachments.len(), 1);
        mgr.export_entry_attachment(&created.id, entry_id.clone(), "secret.txt".into(), att_dst.clone())
            .unwrap();
        assert_eq!(fs::read(&att_dst).unwrap(), b"top-secret-attachment");

        // Clone entry
        let (snap, clone_id) = mgr.clone_entry(&created.id, entry_id.clone()).unwrap();
        assert_eq!(snap.entries.len(), 2);

        // Save, lock, reject wrong password, unlock with right password + keyfile
        let saved = mgr.save_database(&created.id, false).unwrap();
        assert!(!saved.dirty);
        let locked = mgr.lock_database(&created.id).unwrap();
        assert!(locked.locked);
        assert!(locked.entries.is_empty());

        assert!(
            mgr.unlock_database(&created.id, Some("wrong".into()), Some(kf_path.clone()))
                .is_err()
        );
        let unlocked = mgr
            .unlock_database(&created.id, Some("master-pass-123".into()), Some(kf_path.clone()))
            .unwrap();
        assert!(!unlocked.locked);
        assert_eq!(unlocked.entries.len(), 2);

        // Export CSV
        let exported_count = mgr.export_csv(&created.id, csv_path.clone()).unwrap();
        assert_eq!(exported_count, 2);
        let csv_text = fs::read_to_string(&csv_path).unwrap();
        assert!(csv_text.contains("GitHub"));
        assert!(csv_text.contains("old-password"));

        // Soft delete moves to Recycle Bin, then empty Recycle Bin removes permanently
        let snap = mgr.delete_entry(&created.id, clone_id, false).unwrap();
        assert_eq!(snap.entries.iter().filter(|e| e.in_recycle_bin).count(), 1);
        let snap = mgr.empty_recycle_bin(&created.id).unwrap();
        assert_eq!(snap.entries.len(), 1);

        // Change master key (password only) and reopen
        mgr.change_master_key(&created.id, Some("brand-new-secret".into()), None)
            .unwrap();
        mgr.lock_database(&created.id).unwrap();
        assert!(
            mgr.unlock_database(&created.id, Some("master-pass-123".into()), Some(kf_path))
                .is_err()
        );
        let reopened = mgr
            .unlock_database(&created.id, Some("brand-new-secret".into()), None)
            .unwrap();
        assert_eq!(reopened.entries.len(), 1);

        // Stage locked database on startup for fast password-only unlock
        mgr.close_database(&created.id).unwrap();
        let missing = mgr
            .stage_locked_database(dir.path().join("does-not-exist.kdbx"), None)
            .unwrap();
        assert!(missing.is_none());
        let staged = mgr
            .stage_locked_database(db_path.clone(), None)
            .unwrap()
            .unwrap();
        assert!(staged.locked);
        let unlocked_again = mgr
            .unlock_database(&staged.id, Some("brand-new-secret".into()), None)
            .unwrap();
        assert!(!unlocked_again.locked);
        assert_eq!(unlocked_again.entries.len(), 1);
    }

    #[test]
    fn opens_existing_keepassx_kdbx3_fixture_if_available() {
        let fixture = Path::new("/Volumes/data/Users/zexinzhuang/Project/test/keepassx/tests/data/ProtectedStrings.kdbx");
        if !fixture.is_file() {
            return;
        }
        let mgr = VaultManager::default();
        let snap = mgr
            .open_database(fixture.to_path_buf(), Some("masterpw".into()), None)
            .unwrap();
        assert!(!snap.locked);
        assert!(snap.format_version.starts_with("KDBX3"));
        assert!(snap.upgraded_on_save);
        let sample = snap.entries.iter().find(|e| e.title == "Sample Entry").unwrap();
        assert_eq!(sample.username, "Protected User Name");
        assert_eq!(sample.password, "ProtectedPassword");
        let protected = sample
            .custom_fields
            .iter()
            .find(|f| f.key == "TestProtected")
            .unwrap();
        assert_eq!(protected.value, "ABC");
        assert!(protected.protected);

        // Verify save-as upgrades cleanly to KDBX4 and re-opens identically
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("upgraded.kdbx");
        let saved = mgr.save_database_as(&snap.id, out_path.clone()).unwrap();
        assert!(saved.format_version.starts_with("KDBX4"));
        assert!(!saved.dirty);
        mgr.close_database(&snap.id).unwrap();
        let reopened = mgr
            .open_database(out_path, Some("masterpw".into()), None)
            .unwrap();
        let reopened_sample = reopened
            .entries
            .iter()
            .find(|e| e.title == "Sample Entry")
            .unwrap();
        assert_eq!(reopened_sample.password, "ProtectedPassword");
    }
}
