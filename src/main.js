import './style.css';
import { Channel, invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';
import {
  createModalController,
  renderStrengthHtml,
  showChangeMasterKeyDialog,
  showCreateDatabaseDialog,
  showDatabaseSettingsDialog,
  showEntryEditorDialog,
  showGroupEditorDialog,
  showOpenDatabaseDialog,
  showPasswordGeneratorDialog,
  showPreferencesDialog,
} from './dialogs.js';
import { changeLanguage, t } from './i18n.js';
import { iconGlyph } from './icons.js';
import { installSplitters } from './layout.js';
import {
  buildGroupTree,
  escapeHtml,
  filterAndSortEntries,
  formatBytes,
  formatDateTime,
} from './model.js';

const LAYOUT_KEY = 'my-keepass.layout.v1';

const state = {
  version: '1.0.0',
  prefs: {
    language: 'zh-CN',
    rememberRecent: true,
    rememberKeyfiles: true,
    openLastDatabaseOnStartup: true,
    autoSaveOnChange: false,
    autoSaveOnClose: false,
    clearClipboardEnabled: true,
    clearClipboardSeconds: 15,
    autoLockEnabled: true,
    autoLockSeconds: 300,
    hidePasswords: true,
    showDetailPane: true,
    recentDatabases: [],
  },
  tabs: [],
  activeTabId: null,
  tabUi: new Map(), // tabId -> { selectedGroupId, selectedEntryId, collapsedGroups: Set, query, sortBy, sortDir, revealedEntryId, revealedCustomKeys: Set }
  clipboardDeadline: 0,
  lastActivity: Date.now(),
  totpCache: null,
};

const modal = createModalController();
const popupMenu = document.getElementById('popup-menu');
const toastEl = document.getElementById('toast');
let toastTimer = null;

function showToast(message) {
  toastEl.textContent = t(message);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toastEl.textContent = ''; }, 2800);
}

function getTabUi(tabId) {
  if (!state.tabUi.has(tabId)) {
    state.tabUi.set(tabId, {
      selectedGroupId: null,
      selectedEntryId: null,
      detailOpen: false,
      collapsedGroups: new Set(),
      query: '',
      sortBy: 'title',
      sortDir: 'asc',
      revealedEntryId: null,
      revealedCustomKeys: new Set(),
    });
  }
  return state.tabUi.get(tabId);
}

function activeVault() {
  return state.tabs.find(tab => tab.id === state.activeTabId) || null;
}

function activeUnlockedVault() {
  const vault = activeVault();
  return vault && !vault.locked ? vault : null;
}

function selectedEntry(vault = activeUnlockedVault()) {
  if (!vault) return null;
  const ui = getTabUi(vault.id);
  return vault.entries.find(e => e.id === ui.selectedEntryId) || null;
}

function selectedGroup(vault = activeUnlockedVault()) {
  if (!vault) return null;
  const ui = getTabUi(vault.id);
  return vault.groups.find(g => g.id === ui.selectedGroupId)
    || vault.groups.find(g => g.id === vault.rootGroupId)
    || null;
}

function upsertVault(snapshot, { activate = true, selectGroupId = null, selectEntryId = null } = {}) {
  const idx = state.tabs.findIndex(tab => tab.id === snapshot.id);
  if (idx >= 0) state.tabs[idx] = snapshot;
  else state.tabs.push(snapshot);
  if (activate) state.activeTabId = snapshot.id;

  const ui = getTabUi(snapshot.id);
  if (!snapshot.locked) {
    if (selectGroupId) {
      ui.selectedGroupId = selectGroupId;
    } else if (!ui.selectedGroupId || !snapshot.groups.some(g => g.id === ui.selectedGroupId)) {
      // Pick first non-recycle-bin child of root, or root itself
      const root = snapshot.groups.find(g => g.id === snapshot.rootGroupId);
      const firstNormal = root?.childGroupIds
        ?.map(id => snapshot.groups.find(g => g.id === id))
        ?.find(g => g && !g.isRecycleBin);
      ui.selectedGroupId = firstNormal?.id || snapshot.rootGroupId;
    }
    if (selectEntryId) {
      ui.selectedEntryId = selectEntryId;
    } else if (ui.selectedEntryId && !snapshot.entries.some(e => e.id === ui.selectedEntryId)) {
      ui.selectedEntryId = null;
      ui.detailOpen = false;
    }
  } else {
    ui.detailOpen = false;
    ui.revealedEntryId = null;
    ui.revealedCustomKeys.clear();
  }
  render();
}

async function maybeAutoSave(vaultId) {
  if (!state.prefs.autoSaveOnChange) return;
  try {
    const saved = await invoke('save_database', { tabId: vaultId, force: false });
    upsertVault(saved, { activate: false });
  } catch (error) {
    showToast(`自动保存失败：${error}`);
  }
}

async function copySecret(text, label = '已复制密码') {
  const clearAfterSecs = state.prefs.clearClipboardEnabled ? state.prefs.clearClipboardSeconds : null;
  await invoke('copy_secret', { text, clearAfterSecs });
  if (clearAfterSecs) {
    state.clipboardDeadline = Date.now() + clearAfterSecs * 1000;
  } else {
    state.clipboardDeadline = 0;
  }
  updateClipboardBanner();
  showToast(label);
}

async function clearClipboardNow() {
  await invoke('clear_clipboard_now');
  state.clipboardDeadline = 0;
  updateClipboardBanner();
  showToast('剪贴板已清空');
}

function updateClipboardBanner() {
  const banner = document.getElementById('clipboard-banner');
  const text = document.getElementById('clipboard-countdown');
  const remaining = Math.ceil((state.clipboardDeadline - Date.now()) / 1000);
  if (state.clipboardDeadline > 0 && remaining > 0) {
    banner.hidden = false;
    text.textContent = `📋 ${remaining}s 后清空剪贴板`;
  } else {
    state.clipboardDeadline = 0;
    banner.hidden = true;
  }
}

function lastDatabaseDir() {
  const refPath = activeVault()?.path || state.prefs.recentDatabases?.[0]?.path || '';
  if (!refPath) return undefined;
  const idx = Math.max(refPath.lastIndexOf('/'), refPath.lastIndexOf('\\'));
  return idx > 0 ? refPath.slice(0, idx) : undefined;
}

async function pickDatabaseFile() {
  const defaultPath = lastDatabaseDir();
  return openDialog({
    multiple: false,
    title: t('打开数据库'),
    defaultPath,
    filters: [{ name: 'KeePass Database', extensions: ['kdbx', 'kdb'] }],
  });
}

async function pickKeyfile() {
  const defaultPath = lastDatabaseDir();
  return openDialog({
    multiple: false,
    title: '选择密钥文件',
    defaultPath,
    filters: [{ name: 'Key Files', extensions: ['key', 'keyx', 'xml'] }, { name: 'All Files', extensions: ['*'] }],
  });
}

async function createKeyfile() {
  const destPath = await saveDialog({
    title: '生成新密钥文件',
    defaultPath: 'my-keepass.key',
    filters: [{ name: 'KeePass Key File', extensions: ['key', 'keyx'] }],
  });
  if (!destPath) return null;
  await invoke('generate_keyfile', { destPath });
  showToast('已生成密钥文件');
  return destPath;
}

async function openDatabaseFlow(presetPath = null, presetKeyfile = '') {
  const path = presetPath || await pickDatabaseFile();
  if (!path) return;
  showOpenDatabaseDialog(modal, {
    path,
    initialKeyfile: presetKeyfile || '',
    pickKeyfile,
    async onOpen({ path: dbPath, password, keyfile }) {
      const snapshot = await invoke('open_database', { path: dbPath, password, keyfile });
      state.prefs = await invoke('load_prefs');
      upsertVault(snapshot);
      showToast(`已打开 ${snapshot.fileName}`);
    },
  });
}

async function createDatabaseFlow() {
  const path = await saveDialog({
    title: t('新建数据库'),
    defaultPath: 'MyVault.kdbx',
    filters: [{ name: 'KeePass Database (KDBX 4)', extensions: ['kdbx'] }],
  });
  if (!path) return;
  showCreateDatabaseDialog(modal, {
    path,
    pickKeyfile,
    createKeyfile,
    async onCreate({ path: dbPath, name, description, password, keyfile }) {
      const snapshot = await invoke('create_database', { path: dbPath, password, keyfile, name, description });
      state.prefs = await invoke('load_prefs');
      upsertVault(snapshot);
      showToast(`已创建数据库 ${snapshot.fileName}`);
    },
  });
}

async function saveActiveDatabase(force = false) {
  const vault = activeUnlockedVault();
  if (!vault) return;
  try {
    const saved = await invoke('save_database', { tabId: vault.id, force });
    upsertVault(saved);
    showToast('数据库已保存');
  } catch (error) {
    const msg = String(error);
    if (msg.startsWith('CONFLICT:')) {
      if (confirm(`${msg.slice(9)}\n\n是否强制覆盖磁盘文件？`)) {
        await saveActiveDatabase(true);
      }
      return;
    }
    showToast(msg);
  }
}

async function saveDatabaseAsFlow() {
  const vault = activeUnlockedVault();
  if (!vault) return;
  const newPath = await saveDialog({
    title: t('另存为…'),
    defaultPath: vault.fileName.replace(/\.kdb$/i, '.kdbx'),
    filters: [{ name: 'KeePass Database (KDBX 4)', extensions: ['kdbx'] }],
  });
  if (!newPath) return;
  const saved = await invoke('save_database_as', { tabId: vault.id, newPath });
  state.prefs = await invoke('load_prefs');
  upsertVault(saved);
  showToast(`已另存为 ${saved.fileName}`);
}

async function closeTab(tabId) {
  const vault = state.tabs.find(tab => tab.id === tabId);
  if (!vault) return;
  if (!vault.locked && vault.dirty) {
    if (state.prefs.autoSaveOnClose) {
      await invoke('save_database', { tabId, force: false });
    } else if (!confirm(`数据库 "${vault.fileName}" 有未保存的更改，确定放弃更改并关闭吗？`)) {
      return;
    }
  }
  await invoke('close_database', { tabId });
  state.tabs = state.tabs.filter(tab => tab.id !== tabId);
  state.tabUi.delete(tabId);
  if (state.activeTabId === tabId) {
    state.activeTabId = state.tabs[0]?.id || null;
  }
  render();
}

async function lockActiveDatabase() {
  const vault = activeUnlockedVault();
  if (!vault) return;
  if (vault.dirty && state.prefs.autoSaveOnClose) {
    try { await invoke('save_database', { tabId: vault.id, force: false }); } catch {}
  } else if (vault.dirty) {
    if (!confirm(`数据库 "${vault.fileName}" 有未保存更改，锁定将丢弃未保存修改。确定锁定吗？`)) return;
  }
  const locked = await invoke('lock_database', { tabId: vault.id });
  upsertVault(locked);
  showToast('数据库已锁定。');
}

async function lockAllDatabases(silent = false) {
  if (!state.tabs.some(tab => !tab.locked)) return;
  if (!silent && state.tabs.some(tab => !tab.locked && tab.dirty)) {
    if (!confirm('存在未保存的数据库更改，确定立即锁定全部数据库吗？')) return;
  }
  const snapshots = await invoke('lock_all_databases');
  for (const snap of snapshots) upsertVault(snap, { activate: false });
  render();
  if (!silent) showToast('全部数据库已锁定。');
}

async function exportCsvFlow() {
  const vault = activeUnlockedVault();
  if (!vault) return;
  const destPath = await saveDialog({
    title: t('导出为 CSV…'),
    defaultPath: `${vault.meta.name || 'vault'}.csv`,
    filters: [{ name: 'CSV', extensions: ['csv'] }],
  });
  if (!destPath) return;
  const count = await invoke('export_csv', { tabId: vault.id, destPath });
  showToast(`已导出 ${count} 条记录到 CSV`);
}

function openNewEntryDialog() {
  const vault = activeUnlockedVault();
  if (!vault) return;
  const group = selectedGroup(vault);
  showEntryEditorDialog(modal, {
    vault,
    groupId: group?.id || vault.rootGroupId,
    defaultUsername: vault.meta.defaultUsername || '',
    generatePassword: opts => invoke('generate_password', { options: opts }),
    async onSave(payload, groupId) {
      const res = await invoke('create_entry', { tabId: vault.id, groupId, payload });
      upsertVault(res.snapshot, { selectGroupId: groupId, selectEntryId: res.id });
      await maybeAutoSave(vault.id);
      showToast('已创建条目');
    },
  });
}

function openEditEntryDialog(entry = selectedEntry()) {
  const vault = activeUnlockedVault();
  if (!vault || !entry) return;
  showEntryEditorDialog(modal, {
    vault,
    entry,
    groupId: entry.groupId,
    generatePassword: opts => invoke('generate_password', { options: opts }),
    async onSave(payload, targetGroupId) {
      let snap = await invoke('update_entry', { tabId: vault.id, entryId: entry.id, payload });
      if (targetGroupId && targetGroupId !== entry.groupId) {
        snap = await invoke('move_entry', { tabId: vault.id, entryId: entry.id, targetGroupId });
      }
      upsertVault(snap, { selectEntryId: entry.id });
      await maybeAutoSave(vault.id);
      showToast('已更新条目');
    },
    async onRestoreHistory(entryId, historyIndex) {
      const snap = await invoke('restore_entry_history', { tabId: vault.id, entryId, historyIndex });
      upsertVault(snap, { selectEntryId: entryId });
      await maybeAutoSave(vault.id);
      showToast('已恢复历史版本');
    },
    async onDeleteHistory(entryId, historyIndex) {
      const snap = await invoke('delete_entry_history', { tabId: vault.id, entryId, historyIndex });
      upsertVault(snap, { selectEntryId: entryId });
      await maybeAutoSave(vault.id);
      return snap.entries.find(e => e.id === entryId);
    },
    async onAddAttachment(entryId) {
      const filePath = await openDialog({ multiple: false, title: '选择附件文件' });
      if (!filePath) return null;
      const snap = await invoke('add_entry_attachment', { tabId: vault.id, entryId, filePath });
      upsertVault(snap, { selectEntryId: entryId });
      await maybeAutoSave(vault.id);
      showToast('已添加附件');
      return snap.entries.find(e => e.id === entryId);
    },
    async onExportAttachment(entryId, name) {
      const destPath = await saveDialog({ title: '导出附件', defaultPath: name });
      if (!destPath) return;
      await invoke('export_entry_attachment', { tabId: vault.id, entryId, name, destPath });
      showToast(`已导出附件：${name}`);
    },
    async onRemoveAttachment(entryId, name) {
      const snap = await invoke('remove_entry_attachment', { tabId: vault.id, entryId, name });
      upsertVault(snap, { selectEntryId: entryId });
      await maybeAutoSave(vault.id);
      return snap.entries.find(e => e.id === entryId);
    },
  });
}

async function cloneSelectedEntry(entry = selectedEntry()) {
  const vault = activeUnlockedVault();
  if (!vault || !entry) return;
  const res = await invoke('clone_entry', { tabId: vault.id, entryId: entry.id });
  upsertVault(res.snapshot, { selectEntryId: res.id });
  await maybeAutoSave(vault.id);
  showToast('已克隆条目');
}

async function deleteSelectedEntry(entry = selectedEntry(), permanent = false) {
  const vault = activeUnlockedVault();
  if (!vault || !entry) return;
  const reallyPermanent = permanent || entry.inRecycleBin || !vault.meta.recycleBinEnabled;
  const msg = reallyPermanent
    ? `确定要永久删除条目 "${entry.title || '(无标题)'}" 吗？此操作无法撤销。`
    : `确定将条目 "${entry.title || '(无标题)'}" 移入回收站吗？`;
  if (!confirm(msg)) return;
  const snap = await invoke('delete_entry', { tabId: vault.id, entryId: entry.id, permanent: reallyPermanent });
  upsertVault(snap);
  await maybeAutoSave(vault.id);
  showToast(reallyPermanent ? '已永久删除条目' : '已移入回收站');
}

function openNewGroupDialog(parentId = null) {
  const vault = activeUnlockedVault();
  if (!vault) return;
  const parent = parentId || selectedGroup(vault)?.id || vault.rootGroupId;
  showGroupEditorDialog(modal, {
    vault,
    parentId: parent,
    async onSave(payload) {
      const targetParent = payload.parentId || parent;
      const res = await invoke('create_group', {
        tabId: vault.id,
        parentId: targetParent,
        payload: {
          name: payload.name,
          notes: payload.notes,
          iconId: payload.iconId,
          enableSearching: payload.enableSearching,
        },
      });
      upsertVault(res.snapshot, { selectGroupId: res.id });
      await maybeAutoSave(vault.id);
      showToast(`已创建分组：${payload.name}`);
    },
  });
}

function openEditGroupDialog(group = selectedGroup()) {
  const vault = activeUnlockedVault();
  if (!vault || !group) return;
  showGroupEditorDialog(modal, {
    vault,
    group,
    async onSave(payload) {
      let snap = await invoke('update_group', {
        tabId: vault.id,
        groupId: group.id,
        payload: {
          name: payload.name,
          notes: payload.notes,
          iconId: payload.iconId,
          enableSearching: payload.enableSearching,
        },
      });
      if (!group.isRoot && payload.parentId && payload.parentId !== group.parentId) {
        snap = await invoke('move_group', {
          tabId: vault.id,
          groupId: group.id,
          newParentId: payload.parentId,
        });
      }
      upsertVault(snap, { selectGroupId: group.id });
      await maybeAutoSave(vault.id);
      showToast('已更新分组');
    },
  });
}

async function deleteGroupFlow(group = selectedGroup(), permanent = false) {
  const vault = activeUnlockedVault();
  if (!vault || !group || group.isRoot) return;
  const msg = permanent || group.isRecycleBin || !vault.meta.recycleBinEnabled
    ? `确定要永久删除分组 "${group.name}" 及其中的所有条目吗？`
    : `确定将分组 "${group.name}" 移入回收站吗？`;
  if (!confirm(msg)) return;
  const snap = await invoke('delete_group', { tabId: vault.id, groupId: group.id, permanent });
  upsertVault(snap, { selectGroupId: vault.rootGroupId });
  await maybeAutoSave(vault.id);
  showToast('已删除分组');
}

async function emptyRecycleBinFlow() {
  const vault = activeUnlockedVault();
  if (!vault) return;
  if (!confirm('确定要永久清空回收站中的所有分组与条目吗？此操作无法撤销。')) return;
  const snap = await invoke('empty_recycle_bin', { tabId: vault.id });
  upsertVault(snap);
  await maybeAutoSave(vault.id);
  showToast('已清空回收站');
}

function openPreferences(initialTab = 'general') {
  showPreferencesDialog(modal, {
    prefs: state.prefs,
    version: state.version,
    initialTab,
    async onSave(nextPrefs) {
      state.prefs = await invoke('save_prefs', { prefs: nextPrefs });
      changeLanguage(state.prefs.language);
      render();
      showToast('已保存偏好设置');
    },
    checkUpdates: () => invoke('check_updates'),
    installUpdate: (version, onProgress) => {
      const progress = new Channel();
      progress.onmessage = onProgress;
      return invoke('install_update', { version, progress });
    },
    openRelease: url => invoke('open_release_page', { url }),
  });
}

function openPasswordGen() {
  showPasswordGeneratorDialog(modal, {
    generatePassword: options => invoke('generate_password', { options }),
    copySecret,
  });
}

function openDatabaseSettings() {
  const vault = activeUnlockedVault();
  if (!vault) return;
  showDatabaseSettingsDialog(modal, {
    vault,
    async onSave(settings) {
      const snap = await invoke('update_database_settings', { tabId: vault.id, settings });
      upsertVault(snap);
      await maybeAutoSave(vault.id);
      showToast('已更新数据库设置');
    },
  });
}

function openChangeMasterKey() {
  const vault = activeUnlockedVault();
  if (!vault) return;
  showChangeMasterKeyDialog(modal, {
    vault,
    pickKeyfile,
    createKeyfile,
    async onSave({ password, keyfile }) {
      const snap = await invoke('change_master_key', {
        tabId: vault.id,
        newPassword: password,
        newKeyfile: keyfile,
      });
      upsertVault(snap);
      showToast('已更新主密钥并重新加密保存');
    },
  });
}

/* Popup menu system */
function closePopupMenu() {
  popupMenu.hidden = true;
  popupMenu.innerHTML = '';
  document.querySelectorAll('.menu-open').forEach(el => el.classList.remove('menu-open'));
}

function showPopupMenu(items, x, y, anchorEl = null) {
  closePopupMenu();
  if (anchorEl) anchorEl.classList.add('menu-open');
  popupMenu.innerHTML = '';
  for (const item of items) {
    if (item === 'separator') {
      popupMenu.appendChild(document.createElement('hr'));
      continue;
    }
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.disabled = Boolean(item.disabled);
    const labelSpan = document.createElement('span');
    labelSpan.textContent = t(item.label);
    btn.appendChild(labelSpan);
    if (item.shortcut) {
      const sc = document.createElement('span');
      sc.className = 'menu-shortcut';
      sc.textContent = item.shortcut;
      btn.appendChild(sc);
    }
    btn.addEventListener('click', () => {
      closePopupMenu();
      item.action?.();
    });
    popupMenu.appendChild(btn);
  }
  popupMenu.hidden = false;
  const rect = popupMenu.getBoundingClientRect();
  const left = Math.min(x, window.innerWidth - rect.width - 8);
  const top = Math.min(y, window.innerHeight - rect.height - 8);
  popupMenu.style.left = `${Math.max(4, left)}px`;
  popupMenu.style.top = `${Math.max(4, top)}px`;
}

function renderMenubar() {
  const menubar = document.getElementById('menubar');
  const vault = activeUnlockedVault();
  const entry = selectedEntry(vault);
  const group = selectedGroup(vault);

  const menus = [
    {
      label: '数据库',
      items: () => [
        { label: '新建数据库', shortcut: '⌘⇧N', action: createDatabaseFlow },
        { label: '打开数据库', shortcut: '⌘O', action: () => openDatabaseFlow() },
        'separator',
        { label: '保存', shortcut: '⌘S', disabled: !vault, action: () => saveActiveDatabase(false) },
        { label: '另存为…', disabled: !vault, action: saveDatabaseAsFlow },
        { label: '关闭数据库', disabled: !activeVault(), action: () => activeVault() && closeTab(activeVault().id) },
        'separator',
        { label: '锁定当前数据库', shortcut: '⌘L', disabled: !vault, action: lockActiveDatabase },
        { label: '锁定全部数据库', disabled: !state.tabs.some(tb => !tb.locked), action: () => lockAllDatabases(false) },
        'separator',
        { label: '修改主密钥…', disabled: !vault, action: openChangeMasterKey },
        { label: '数据库设置…', disabled: !vault, action: openDatabaseSettings },
        { label: '导出为 CSV…', disabled: !vault, action: exportCsvFlow },
      ],
    },
    {
      label: '条目',
      items: () => [
        { label: '新建条目', shortcut: '⌘N', disabled: !vault, action: openNewEntryDialog },
        { label: '编辑条目', shortcut: 'Enter', disabled: !entry, action: () => openEditEntryDialog(entry) },
        { label: '克隆条目', disabled: !entry, action: () => cloneSelectedEntry(entry) },
        { label: '删除条目', disabled: !entry, action: () => deleteSelectedEntry(entry, false) },
        'separator',
        { label: '复制用户名', shortcut: '⌘B', disabled: !entry?.username, action: () => copySecret(entry.username, '已复制用户名') },
        { label: '复制密码', shortcut: '⌘⇧C', disabled: !entry?.password, action: () => copySecret(entry.password, '已复制密码') },
        { label: '复制 URL', disabled: !entry?.url, action: () => copySecret(entry.url, '已复制 URL') },
        { label: '复制备注', disabled: !entry?.notes, action: () => copySecret(entry.notes, '已复制备注') },
        { label: '打开 URL', disabled: !entry?.url, action: () => invoke('open_entry_url', { url: entry.url }).catch(showToast) },
      ],
    },
    {
      label: '分组',
      items: () => [
        { label: '新建子分组', disabled: !vault, action: () => openNewGroupDialog() },
        { label: '编辑分组', disabled: !group, action: () => openEditGroupDialog(group) },
        { label: '删除分组', disabled: !group || group.isRoot, action: () => deleteGroupFlow(group, false) },
        'separator',
        { label: '清空回收站', disabled: !vault?.recycleBinId, action: emptyRecycleBinFlow },
      ],
    },
    {
      label: '视图',
      items: () => [
        {
          label: `${vault && getTabUi(vault.id).detailOpen ? '✓ ' : ''}显示/隐藏详情栏`,
          disabled: !vault,
          action: () => {
            if (!vault) return;
            const ui = getTabUi(vault.id);
            ui.detailOpen = !ui.detailOpen;
            render();
          },
        },
        {
          label: `${!state.prefs.hidePasswords ? '✓ ' : ''}列表中显示明文密码`,
          action: async () => {
            state.prefs = await invoke('save_prefs', {
              prefs: { ...state.prefs, hidePasswords: !state.prefs.hidePasswords },
            });
            render();
          },
        },
      ],
    },
    {
      label: '工具',
      items: () => [
        { label: '密码生成器', action: openPasswordGen },
        { label: '检查更新', action: () => openPreferences('updates') },
      ],
    },
  ];

  menubar.innerHTML = '';
  for (const menu of menus) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = t(menu.label);
    btn.addEventListener('click', event => {
      event.stopPropagation();
      if (btn.classList.contains('menu-open')) {
        closePopupMenu();
        return;
      }
      const rect = btn.getBoundingClientRect();
      showPopupMenu(menu.items(), rect.left, rect.bottom + 2, btn);
    });
    menubar.appendChild(btn);
  }
  const prefsBtn = document.createElement('button');
  prefsBtn.type = 'button';
  prefsBtn.className = 'menu-preferences';
  prefsBtn.textContent = `⚙ ${t('偏好设置')}`;
  prefsBtn.addEventListener('click', () => openPreferences('general'));
  menubar.appendChild(prefsBtn);
}

function renderTabs() {
  const tabsEl = document.getElementById('tabs');
  tabsEl.innerHTML = '';
  for (const vault of state.tabs) {
    const tabEl = document.createElement('div');
    tabEl.className = `tab${vault.id === state.activeTabId ? ' active' : ''}`;
    tabEl.setAttribute('role', 'tab');
    tabEl.setAttribute('aria-selected', String(vault.id === state.activeTabId));

    const labelBtn = document.createElement('button');
    labelBtn.type = 'button';
    labelBtn.className = 'tab-label';
    labelBtn.title = vault.path;
    const prefix = vault.locked ? '🔒 ' : '🔓 ';
    labelBtn.innerHTML = `${prefix}${escapeHtml(vault.meta.name || vault.fileName)}${vault.dirty ? '<span class="tab-dirty">*</span>' : ''}`;
    labelBtn.addEventListener('click', () => {
      state.activeTabId = vault.id;
      render();
    });

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'tab-close';
    closeBtn.textContent = '×';
    closeBtn.title = t('关闭标签');
    closeBtn.addEventListener('click', event => {
      event.stopPropagation();
      closeTab(vault.id);
    });

    tabEl.append(labelBtn, closeBtn);
    tabsEl.appendChild(tabEl);
  }
}

function renderToolbar() {
  const vault = activeUnlockedVault();
  const entry = selectedEntry(vault);
  const searchInput = document.getElementById('search-input');
  const searchClear = document.getElementById('search-clear');

  document.getElementById('btn-save').disabled = !vault;
  document.getElementById('btn-new-entry').disabled = !vault;
  document.getElementById('btn-edit-entry').disabled = !entry;
  document.getElementById('btn-clone-entry').disabled = !entry;
  document.getElementById('btn-delete-entry').disabled = !entry;
  document.getElementById('btn-copy-user').disabled = !entry?.username;
  document.getElementById('btn-copy-pass').disabled = !entry?.password;
  document.getElementById('btn-open-url').disabled = !entry?.url;
  document.getElementById('btn-lock').disabled = !vault;

  searchInput.disabled = !vault;
  const query = vault ? getTabUi(vault.id).query : '';
  if (searchInput.value !== query) searchInput.value = query;
  searchClear.hidden = !query;
}

function renderWelcome() {
  const recentSection = document.getElementById('recent-section');
  const recentList = document.getElementById('recent-list');
  const items = state.prefs.recentDatabases || [];
  recentSection.hidden = items.length === 0;
  recentList.innerHTML = '';

  for (const item of items) {
    const fileName = item.path.split(/[\\/]/).pop() || item.path;
    const row = document.createElement('div');
    row.className = 'recent-item';
    const openBtn = document.createElement('button');
    openBtn.type = 'button';
    openBtn.className = 'recent-main';
    openBtn.innerHTML = `<span class="recent-name">🔐 ${escapeHtml(fileName)}</span><span class="recent-path">${escapeHtml(item.path)}</span>`;
    openBtn.addEventListener('click', () => openDatabaseFlow(item.path, item.keyfile || ''));

    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.className = 'secondary';
    delBtn.textContent = '×';
    delBtn.title = '从最近列表移除';
    delBtn.addEventListener('click', async () => {
      state.prefs = await invoke('remove_recent_database', { path: item.path });
      renderWelcome();
    });

    row.append(openBtn, delBtn);
    recentList.appendChild(row);
  }
}

function renderLockedView(vault) {
  const lockedEl = document.getElementById('locked-view');
  const prevTabId = lockedEl.dataset.tabId;
  document.getElementById('unlock-title').textContent = `${vault.meta.name || vault.fileName} (${t('数据库已锁定')})`;
  document.getElementById('unlock-path').textContent = vault.path;
  const pwInput = document.getElementById('unlock-password');
  if (prevTabId !== vault.id) {
    lockedEl.dataset.tabId = vault.id;
    document.getElementById('unlock-keyfile').value = vault.keyfilePath || '';
    pwInput.value = '';
    pwInput.type = 'password';
    document.getElementById('unlock-error').hidden = true;
  }
  const focusPw = () => {
    if (!lockedEl.hidden && !modal.dialog.open) pwInput.focus();
  };
  focusPw();
  requestAnimationFrame(focusPw);
  setTimeout(focusPw, 40);
}

function renderGroupTree(vault) {
  const treeEl = document.getElementById('group-tree');
  const footer = document.getElementById('groups-footer');
  const ui = getTabUi(vault.id);
  const root = buildGroupTree(vault.groups, vault.rootGroupId);
  treeEl.innerHTML = '';

  const renderNode = node => {
    if (!node) return;
    const hasChildren = node.children.length > 0;
    const collapsed = ui.collapsedGroups.has(node.id);
    const row = document.createElement('div');
    row.className = `tree-row${ui.selectedGroupId === node.id && !ui.query ? ' selected' : ''}`;
    row.style.paddingLeft = `${6 + node.depth * 14}px`;
    row.setAttribute('role', 'treeitem');

    const toggleBtn = document.createElement('button');
    toggleBtn.type = 'button';
    toggleBtn.className = 'tree-toggle';
    toggleBtn.textContent = hasChildren ? (collapsed ? '▸' : '▾') : '';
    toggleBtn.disabled = !hasChildren;
    toggleBtn.addEventListener('click', event => {
      event.stopPropagation();
      if (collapsed) ui.collapsedGroups.delete(node.id);
      else ui.collapsedGroups.add(node.id);
      renderGroupTree(vault);
    });

    const labelBtn = document.createElement('button');
    labelBtn.type = 'button';
    labelBtn.className = 'tree-label';
    const glyph = iconGlyph(node.iconId, node.isRecycleBin ? '🗑️' : '📁');
    labelBtn.innerHTML = `<span>${glyph}</span><span class="tree-name">${escapeHtml(node.name)}</span><span class="tree-count">${node.totalEntries}</span>`;
    labelBtn.addEventListener('click', () => {
      ui.query = '';
      ui.selectedGroupId = node.id;
      ui.selectedEntryId = null;
      ui.detailOpen = false;
      render();
    });

    const moreBtn = document.createElement('button');
    moreBtn.type = 'button';
    moreBtn.className = 'tree-more';
    moreBtn.textContent = '⋯';
    moreBtn.addEventListener('click', event => {
      event.stopPropagation();
      const rect = moreBtn.getBoundingClientRect();
      showGroupContextMenu(vault, node, rect.left, rect.bottom + 2);
    });

    row.addEventListener('contextmenu', event => {
      event.preventDefault();
      showGroupContextMenu(vault, node, event.clientX, event.clientY);
    });

    row.append(toggleBtn, labelBtn, moreBtn);
    treeEl.appendChild(row);

    if (hasChildren && !collapsed) {
      for (const child of node.children) renderNode(child);
    }
  };

  renderNode(root);
  footer.textContent = `${vault.groups.length} 个分组`;
}

function showGroupContextMenu(vault, group, x, y) {
  const items = [
    { label: '新建条目', action: () => { getTabUi(vault.id).selectedGroupId = group.id; openNewEntryDialog(); } },
    { label: '新建子分组', action: () => openNewGroupDialog(group.id) },
    { label: '编辑分组', action: () => openEditGroupDialog(group) },
  ];
  if (group.isRecycleBin) {
    items.push('separator', { label: '清空回收站', action: emptyRecycleBinFlow });
  } else if (!group.isRoot) {
    items.push('separator', { label: '删除分组', action: () => deleteGroupFlow(group, false) });
  }
  showPopupMenu(items, x, y);
}

function renderEntries(vault) {
  const ui = getTabUi(vault.id);
  const listEl = document.getElementById('entry-list');
  const footer = document.getElementById('entries-footer');
  const searchBanner = document.getElementById('search-banner');
  const searchSummary = document.getElementById('search-summary');

  const entries = filterAndSortEntries(vault.entries, {
    groupId: ui.selectedGroupId,
    query: ui.query,
    sortBy: ui.sortBy,
    sortDir: ui.sortDir,
    groups: vault.groups,
  });

  if (ui.query.trim()) {
    searchBanner.hidden = false;
    searchSummary.textContent = `搜索 "${ui.query.trim()}" 找到 ${entries.length} 条记录`;
  } else {
    searchBanner.hidden = true;
  }

  // Update sort indicators
  document.querySelectorAll('#entry-head [data-sort]').forEach(btn => {
    const ind = btn.querySelector('.sort-ind');
    if (btn.dataset.sort === ui.sortBy) {
      ind.textContent = ui.sortDir === 'asc' ? '▲' : '▼';
    } else {
      ind.textContent = '';
    }
  });

  listEl.innerHTML = '';
  if (!entries.length) {
    listEl.innerHTML = `<p class="empty">${ui.query.trim() ? '未找到匹配的密码条目。' : '当前分组暂无条目，点击上方「＋ 条目」新建。'}</p>`;
    footer.textContent = '0 条记录';
    return;
  }

  for (const entry of entries) {
    const row = document.createElement('div');
    row.className = `entry-row${ui.selectedEntryId === entry.id ? ' selected' : ''}${entry.isExpired ? ' expired' : ''}`;
    row.dataset.entryId = entry.id;
    row.setAttribute('role', 'option');
    row.setAttribute('aria-selected', String(ui.selectedEntryId === entry.id));

    const pwDisplay = entry.password
      ? (state.prefs.hidePasswords ? '••••••••' : entry.password)
      : '—';
    const subPath = ui.query.trim() ? `<span class="entry-subpath">${escapeHtml(entry.groupPath)}</span>` : '';

    row.innerHTML = `
      <div class="entry-cell entry-title-cell">
        <span>${iconGlyph(entry.iconId, '🔑')}</span>
        <div style="min-width:0;overflow:hidden;text-overflow:ellipsis">
          <span class="entry-title-text">${escapeHtml(entry.title || '(无标题)')}</span>
          ${subPath}
        </div>
      </div>
      <div class="entry-cell">${escapeHtml(entry.username || '—')}</div>
      <div class="entry-cell entry-pw">${escapeHtml(pwDisplay)}</div>
      <div class="entry-cell">${escapeHtml(entry.url || '—')}</div>
      <div class="entry-cell entry-date">${escapeHtml(formatDateTime(entry.modifiedAt))}</div>
      <div class="entry-quick">
        <button type="button" data-quick-user title="复制用户名">👤</button>
        <button type="button" data-quick-pass title="复制密码">🔑</button>
      </div>
    `;

    row.addEventListener('click', () => {
      const changed = ui.selectedEntryId !== entry.id;
      if (changed) {
        ui.selectedEntryId = entry.id;
        ui.revealedEntryId = null;
        ui.revealedCustomKeys.clear();
        state.totpCache = null;
      }
      ui.detailOpen = true;
      // Update selection in-place without rebuilding DOM rows so dblclick always fires reliably.
      for (const el of listEl.querySelectorAll('.entry-row')) {
        const isSel = el.dataset.entryId === entry.id;
        el.classList.toggle('selected', isSel);
        el.setAttribute('aria-selected', String(isSel));
      }
      document.getElementById('vault-view').classList.remove('no-detail');
      renderToolbar();
      renderDetail(vault);
      if (changed) refreshTotp();
    });
    row.addEventListener('dblclick', () => {
      ui.selectedEntryId = entry.id;
      openEditEntryDialog(entry);
    });
    row.addEventListener('contextmenu', event => {
      event.preventDefault();
      ui.selectedEntryId = entry.id;
      render();
      showPopupMenu([
        { label: '编辑条目', action: () => openEditEntryDialog(entry) },
        { label: '克隆条目', action: () => cloneSelectedEntry(entry) },
        'separator',
        { label: '复制用户名', disabled: !entry.username, action: () => copySecret(entry.username, '已复制用户名') },
        { label: '复制密码', disabled: !entry.password, action: () => copySecret(entry.password, '已复制密码') },
        { label: '复制 URL', disabled: !entry.url, action: () => copySecret(entry.url, '已复制 URL') },
        { label: '打开 URL', disabled: !entry.url, action: () => invoke('open_entry_url', { url: entry.url }).catch(showToast) },
        'separator',
        { label: entry.inRecycleBin ? '永久删除条目' : '删除条目', action: () => deleteSelectedEntry(entry, entry.inRecycleBin) },
      ], event.clientX, event.clientY);
    });

    row.querySelector('[data-quick-user]').addEventListener('click', event => {
      event.stopPropagation();
      if (entry.username) copySecret(entry.username, '已复制用户名');
    });
    row.querySelector('[data-quick-pass]').addEventListener('click', event => {
      event.stopPropagation();
      if (entry.password) copySecret(entry.password, '已复制密码');
    });

    listEl.appendChild(row);
  }
  footer.textContent = `${entries.length} 条记录`;
}

function renderDetail(vault) {
  const detailEl = document.getElementById('detail-body');
  const ui = getTabUi(vault.id);
  const entry = selectedEntry(vault);
  if (!entry) {
    detailEl.innerHTML = '<div class="detail-empty">选择一条密码记录以查看详情、复制凭证或查看动态验证码。</div>';
    return;
  }

  const revealed = ui.revealedEntryId === entry.id;
  const pwShown = revealed ? entry.password : (entry.password ? '••••••••••••' : '—');
  const totpHtml = entry.otp
    ? `
      <div class="detail-field">
        <div class="detail-label"><span>TOTP 动态验证码</span><span class="totp-timer" id="detail-totp-timer">${state.totpCache ? `${state.totpCache.validForSecs}s` : '…'}</span></div>
        <div class="totp-box">
          <span class="totp-code" id="detail-totp-code">${escapeHtml(state.totpCache?.code || '------')}</span>
          <button type="button" class="secondary" id="detail-copy-totp">复制</button>
        </div>
      </div>`
    : '';

  const customHtml = entry.customFields.length
    ? `
      <div class="detail-field">
        <div class="detail-label"><span>自定义属性 (${entry.customFields.length})</span></div>
        ${entry.customFields.map(field => {
          const isRev = !field.protected || ui.revealedCustomKeys.has(field.key);
          return `
            <div class="detail-value-row" style="margin-bottom:4px">
              <span style="color:var(--muted);font-size:11px;min-width:72px">${escapeHtml(field.key)}</span>
              <span class="detail-value">${escapeHtml(isRev ? field.value : '••••••••')}</span>
              ${field.protected ? `<button type="button" data-cf-toggle="${escapeHtml(field.key)}" title="显示/隐藏">👁</button>` : ''}
              <button type="button" data-cf-copy="${escapeHtml(field.key)}" title="复制">📋</button>
            </div>`;
        }).join('')}
      </div>`
    : '';

  const attHtml = entry.attachments.length
    ? `
      <div class="detail-field">
        <div class="detail-label"><span>附件 (${entry.attachments.length})</span></div>
        ${entry.attachments.map(att => `
          <div class="att-row" style="margin-bottom:4px">
            <span class="att-name">📎 ${escapeHtml(att.name)} <small>(${formatBytes(att.size)})</small></span>
            <button type="button" class="secondary" data-detail-att-export="${escapeHtml(att.name)}">导出…</button>
          </div>
        `).join('')}
      </div>`
    : '';

  detailEl.innerHTML = `
    <div class="detail-head">
      <div class="detail-title">
        <span style="font-size:22px">${iconGlyph(entry.iconId, '🔑')}</span>
        <div style="min-width:0">
          <h2>${escapeHtml(entry.title || '(无标题)')}</h2>
          <div class="detail-group">${escapeHtml(entry.groupPath)}${entry.isExpired ? ' · <span class="expired-badge">已过期</span>' : ''}</div>
        </div>
      </div>
      <div class="detail-actions">
        <button type="button" class="secondary" id="detail-copy-title" ${entry.title ? '' : 'disabled'} title="复制标题">📋</button>
        <button type="button" class="secondary" id="detail-edit">✎ 编辑</button>
      </div>
    </div>

    <div class="detail-field">
      <div class="detail-label"><span>用户名</span></div>
      <div class="detail-value-row">
        <span class="detail-value">${escapeHtml(entry.username || '—')}</span>
        <button type="button" id="detail-copy-user" ${entry.username ? '' : 'disabled'} title="复制用户名">📋</button>
      </div>
    </div>

    <div class="detail-field">
      <div class="detail-label"><span>密码</span></div>
      <div class="detail-value-row">
        <span class="detail-value">${escapeHtml(pwShown)}</span>
        <button type="button" id="detail-toggle-pw" ${entry.password ? '' : 'disabled'} title="显示/隐藏密码">👁</button>
        <button type="button" id="detail-copy-pw" ${entry.password ? '' : 'disabled'} title="复制密码">📋</button>
      </div>
      ${entry.password ? `<div style="margin-top:6px">${renderStrengthHtml(entry.password)}</div>` : ''}
    </div>

    ${totpHtml}

    <div class="detail-field">
      <div class="detail-label"><span>URL</span></div>
      <div class="detail-value-row">
        <span class="detail-value">${escapeHtml(entry.url || '—')}</span>
        <button type="button" id="detail-copy-url" ${entry.url ? '' : 'disabled'} title="复制 URL">📋</button>
        <button type="button" id="detail-open-url" ${entry.url ? '' : 'disabled'} title="在浏览器中打开">↗</button>
      </div>
    </div>

    ${entry.tags.length ? `
      <div class="detail-field">
        <div class="detail-label"><span>标签</span></div>
        <div class="tag-list">${entry.tags.map(tag => `<span class="tag-pill">${escapeHtml(tag)}</span>`).join('')}</div>
      </div>` : ''}

    <div class="detail-field">
      <div class="detail-label"><span>备注</span>${entry.notes ? '<button type="button" id="detail-copy-notes" style="min-height:18px;font-size:11px">复制</button>' : ''}</div>
      <div class="detail-notes" ${entry.notes ? '' : 'style="color:var(--muted)"'}>${entry.notes ? escapeHtml(entry.notes) : escapeHtml(t('暂无备注'))}</div>
    </div>

    ${customHtml}
    ${attHtml}

    <div class="detail-meta">
      <div>创建时间：${escapeHtml(formatDateTime(entry.createdAt))}</div>
      <div>修改时间：${escapeHtml(formatDateTime(entry.modifiedAt))}</div>
      ${entry.expires ? `<div>过期时间：${escapeHtml(formatDateTime(entry.expiryTime))}</div>` : ''}
      <div>历史版本：${entry.history.length} 条</div>
    </div>
    <div class="detail-hint">${escapeHtml(t('双击条目可进入编辑模式'))}</div>
  `;

  detailEl.querySelector('#detail-copy-title')?.addEventListener('click', () => copySecret(entry.title, '已复制标题'));
  detailEl.querySelector('#detail-edit').addEventListener('click', () => openEditEntryDialog(entry));
  detailEl.querySelector('#detail-copy-user')?.addEventListener('click', () => copySecret(entry.username, '已复制用户名'));
  detailEl.querySelector('#detail-copy-pw')?.addEventListener('click', () => copySecret(entry.password, '已复制密码'));
  detailEl.querySelector('#detail-toggle-pw')?.addEventListener('click', () => {
    ui.revealedEntryId = revealed ? null : entry.id;
    renderDetail(vault);
  });
  detailEl.querySelector('#detail-copy-url')?.addEventListener('click', () => copySecret(entry.url, '已复制 URL'));
  detailEl.querySelector('#detail-open-url')?.addEventListener('click', () =>
    invoke('open_entry_url', { url: entry.url }).catch(showToast));
  detailEl.querySelector('#detail-copy-notes')?.addEventListener('click', () => copySecret(entry.notes, '已复制备注'));
  detailEl.querySelector('#detail-copy-totp')?.addEventListener('click', () => {
    if (state.totpCache?.code) copySecret(state.totpCache.code, '已复制动态验证码');
  });

  detailEl.querySelectorAll('[data-cf-toggle]').forEach(btn => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.cfToggle;
      if (ui.revealedCustomKeys.has(key)) ui.revealedCustomKeys.delete(key);
      else ui.revealedCustomKeys.add(key);
      renderDetail(vault);
    });
  });
  detailEl.querySelectorAll('[data-cf-copy]').forEach(btn => {
    btn.addEventListener('click', () => {
      const found = entry.customFields.find(f => f.key === btn.dataset.cfCopy);
      if (found) copySecret(found.value, '已复制属性');
    });
  });
  detailEl.querySelectorAll('[data-detail-att-export]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const name = btn.dataset.detailAttExport;
      const destPath = await saveDialog({ title: '导出附件', defaultPath: name });
      if (!destPath) return;
      await invoke('export_entry_attachment', { tabId: vault.id, entryId: entry.id, name, destPath });
      showToast(`已导出附件：${name}`);
    });
  });
}

async function refreshTotp() {
  const vault = activeUnlockedVault();
  const entry = selectedEntry(vault);
  if (!vault || !entry?.otp) {
    state.totpCache = null;
    return;
  }
  try {
    state.totpCache = await invoke('get_entry_totp', { tabId: vault.id, entryId: entry.id });
    const codeEl = document.getElementById('detail-totp-code');
    const timerEl = document.getElementById('detail-totp-timer');
    if (codeEl) codeEl.textContent = state.totpCache.code;
    if (timerEl) timerEl.textContent = `${state.totpCache.validForSecs}s / ${state.totpCache.periodSecs}s`;
  } catch {
    state.totpCache = null;
  }
}

function renderStatusbar() {
  const vault = activeVault();
  const fileEl = document.getElementById('status-file');
  const formatEl = document.getElementById('status-format');
  const dirtyEl = document.getElementById('status-dirty');
  const countsEl = document.getElementById('status-counts');
  const versionEl = document.getElementById('status-version');

  versionEl.textContent = `v${state.version}`;
  if (!vault) {
    fileEl.textContent = t('未打开数据库');
    formatEl.hidden = true;
    dirtyEl.hidden = true;
    countsEl.textContent = '';
    return;
  }
  fileEl.textContent = vault.path;
  fileEl.title = vault.path;
  formatEl.hidden = false;
  formatEl.textContent = vault.locked ? 'LOCKED' : vault.formatVersion;
  dirtyEl.hidden = vault.locked || !vault.dirty;
  countsEl.textContent = vault.locked ? '' : `${vault.entries.length} 条密码 · ${vault.groups.length} 个分组`;
}

function render() {
  const vault = activeVault();
  const welcomeView = document.getElementById('welcome-view');
  const lockedView = document.getElementById('locked-view');
  const vaultView = document.getElementById('vault-view');

  renderMenubar();
  renderTabs();
  renderToolbar();
  renderStatusbar();

  if (!vault) {
    welcomeView.hidden = false;
    lockedView.hidden = true;
    lockedView.dataset.tabId = '';
    vaultView.hidden = true;
    renderWelcome();
  } else if (vault.locked) {
    welcomeView.hidden = true;
    lockedView.hidden = false;
    vaultView.hidden = true;
    renderLockedView(vault);
  } else {
    welcomeView.hidden = true;
    lockedView.hidden = true;
    lockedView.dataset.tabId = '';
    vaultView.hidden = false;
    const ui = getTabUi(vault.id);
    const showDetail = Boolean(ui.detailOpen && selectedEntry(vault));
    vaultView.classList.toggle('no-detail', !showDetail);
    renderGroupTree(vault);
    renderEntries(vault);
    if (showDetail) renderDetail(vault);
  }
}

function wireEvents() {
  document.addEventListener('click', event => {
    if (!popupMenu.hidden && !popupMenu.contains(event.target)) closePopupMenu();
    const actionEl = event.target.closest('[data-action]');
    if (!actionEl) return;
    const action = actionEl.dataset.action;
    if (action === 'open-db') openDatabaseFlow();
    else if (action === 'new-db') createDatabaseFlow();
    else if (action === 'save-db') saveActiveDatabase(false);
    else if (action === 'new-entry') openNewEntryDialog();
    else if (action === 'edit-entry') openEditEntryDialog();
    else if (action === 'clone-entry') cloneSelectedEntry();
    else if (action === 'delete-entry') deleteSelectedEntry();
    else if (action === 'copy-username') {
      const e = selectedEntry();
      if (e?.username) copySecret(e.username, '已复制用户名');
    } else if (action === 'copy-password') {
      const e = selectedEntry();
      if (e?.password) copySecret(e.password, '已复制密码');
    } else if (action === 'open-url') {
      const e = selectedEntry();
      if (e?.url) invoke('open_entry_url', { url: e.url }).catch(showToast);
    } else if (action === 'password-gen') openPasswordGen();
    else if (action === 'lock-db') lockActiveDatabase();
    else if (action === 'new-group') openNewGroupDialog();
    else if (action === 'db-settings') openDatabaseSettings();
    else if (action === 'preferences') openPreferences('general');
    else if (action === 'clear-clipboard') clearClipboardNow();
    else if (action === 'close-active-tab') activeVault() && closeTab(activeVault().id);
    else if (action === 'toggle-detail') {
      const vault = activeUnlockedVault();
      if (vault) {
        const ui = getTabUi(vault.id);
        ui.detailOpen = !ui.detailOpen;
        render();
      }
    }
  });

  // Search box
  const searchInput = document.getElementById('search-input');
  const searchClear = document.getElementById('search-clear');
  searchInput.addEventListener('input', () => {
    const vault = activeUnlockedVault();
    if (!vault) return;
    const ui = getTabUi(vault.id);
    ui.query = searchInput.value;
    searchClear.hidden = !ui.query;
    renderEntries(vault);
  });
  const exitSearch = () => {
    const vault = activeUnlockedVault();
    if (!vault) return;
    getTabUi(vault.id).query = '';
    searchInput.value = '';
    searchClear.hidden = true;
    render();
  };
  searchClear.addEventListener('click', exitSearch);
  document.getElementById('exit-search').addEventListener('click', exitSearch);

  // Table column sort
  document.getElementById('entry-head').addEventListener('click', event => {
    const btn = event.target.closest('[data-sort]');
    const vault = activeUnlockedVault();
    if (!btn || !vault) return;
    const ui = getTabUi(vault.id);
    const field = btn.dataset.sort;
    if (ui.sortBy === field) ui.sortDir = ui.sortDir === 'asc' ? 'desc' : 'asc';
    else {
      ui.sortBy = field;
      ui.sortDir = 'asc';
    }
    renderEntries(vault);
  });

  // Locked overlay unlock form
  document.getElementById('unlock-toggle-vis').addEventListener('click', () => {
    const input = document.getElementById('unlock-password');
    input.type = input.type === 'password' ? 'text' : 'password';
  });
  document.getElementById('unlock-pick-keyfile').addEventListener('click', async () => {
    const kf = await pickKeyfile();
    if (kf) document.getElementById('unlock-keyfile').value = kf;
  });
  document.getElementById('unlock-clear-keyfile').addEventListener('click', () => {
    document.getElementById('unlock-keyfile').value = '';
  });
  document.getElementById('unlock-form').addEventListener('submit', async event => {
    event.preventDefault();
    const vault = activeVault();
    if (!vault || !vault.locked) return;
    const errEl = document.getElementById('unlock-error');
    const submitBtn = document.getElementById('unlock-submit');
    const pwInput = document.getElementById('unlock-password');
    errEl.hidden = true;
    submitBtn.disabled = true;
    try {
      const password = pwInput.value || null;
      const keyfile = document.getElementById('unlock-keyfile').value.trim() || null;
      const snap = await invoke('unlock_database', { tabId: vault.id, password, keyfile });
      state.prefs = await invoke('load_prefs');
      document.getElementById('locked-view').dataset.tabId = '';
      upsertVault(snap);
      showToast(`已解锁 ${snap.fileName}`);
    } catch (error) {
      errEl.textContent = String(error);
      errEl.hidden = false;
      pwInput.focus();
      pwInput.select();
    } finally {
      submitBtn.disabled = false;
    }
  });

  // Global keyboard shortcuts
  document.addEventListener('keydown', event => {
    state.lastActivity = Date.now();
    if (modal.dialog.open) return;
    const mod = event.metaKey || event.ctrlKey;
    const key = event.key.toLowerCase();
    if (mod && key === 'o') {
      event.preventDefault();
      openDatabaseFlow();
    } else if (mod && event.shiftKey && key === 'n') {
      event.preventDefault();
      createDatabaseFlow();
    } else if (mod && key === 'n' && activeUnlockedVault()) {
      event.preventDefault();
      openNewEntryDialog();
    } else if (mod && key === 's' && activeUnlockedVault()) {
      event.preventDefault();
      saveActiveDatabase(false);
    } else if (mod && key === 'f' && activeUnlockedVault()) {
      event.preventDefault();
      searchInput.focus();
      searchInput.select();
    } else if (mod && key === 'l' && activeUnlockedVault()) {
      event.preventDefault();
      lockActiveDatabase();
    } else if (mod && key === ',') {
      event.preventDefault();
      openPreferences('general');
    } else if (mod && key === 'b' && selectedEntry()?.username) {
      event.preventDefault();
      copySecret(selectedEntry().username, '已复制用户名');
    } else if (mod && event.shiftKey && key === 'c' && selectedEntry()?.password) {
      event.preventDefault();
      copySecret(selectedEntry().password, '已复制密码');
    } else if (key === 'escape') {
      if (!popupMenu.hidden) {
        closePopupMenu();
      } else {
        const vault = activeUnlockedVault();
        if (vault && getTabUi(vault.id).detailOpen) {
          getTabUi(vault.id).detailOpen = false;
          document.getElementById('vault-view').classList.add('no-detail');
        }
      }
    }
  });

  // Activity tracking for idle auto-lock
  for (const evt of ['pointerdown', 'pointermove', 'wheel']) {
    document.addEventListener(evt, () => { state.lastActivity = Date.now(); }, { passive: true });
  }
}

async function init() {
  wireEvents();
  try {
    const info = await invoke('platform_info');
    state.version = info.version;
    state.prefs = await invoke('load_prefs');
    changeLanguage(state.prefs.language);
    const openTabs = await invoke('list_vaults');
    for (const tab of openTabs) upsertVault(tab, { activate: false });
    if (state.tabs.length) {
      state.activeTabId = state.tabs[0].id;
    } else if (state.prefs.openLastDatabaseOnStartup !== false && state.prefs.recentDatabases?.length) {
      for (const recent of state.prefs.recentDatabases) {
        const staged = await invoke('stage_locked_database', {
          path: recent.path,
          keyfile: recent.keyfile || null,
        });
        if (staged) {
          upsertVault(staged, { activate: true });
          break;
        }
      }
    }
  } catch (error) {
    showToast(`初始化失败：${error}`);
  }

  let savedLayout = {};
  try { savedLayout = JSON.parse(localStorage.getItem(LAYOUT_KEY) || '{}'); } catch {}
  installSplitters(savedLayout, layout => {
    try { localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout)); } catch {}
  });

  await listen('clipboard-cleared', () => {
    state.clipboardDeadline = 0;
    updateClipboardBanner();
    showToast('剪贴板已自动清空');
  });

  // 1-second tick for clipboard countdown, live TOTP refresh, and idle auto-lock
  setInterval(() => {
    if (state.clipboardDeadline > 0) updateClipboardBanner();
    if (selectedEntry()?.otp) refreshTotp();
    if (
      state.prefs.autoLockEnabled
      && state.tabs.some(tab => !tab.locked)
      && (Date.now() - state.lastActivity) >= state.prefs.autoLockSeconds * 1000
    ) {
      lockAllDatabases(true);
      showToast('空闲超时，已自动锁定全部数据库。');
    }
  }, 1000);

  render();
}

init();
