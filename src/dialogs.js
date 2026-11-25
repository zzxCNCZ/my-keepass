import { PICKER_ICON_IDS, iconGlyph } from './icons.js';
import { t, localize } from './i18n.js';
import {
  collectDescendantGroupIds,
  escapeHtml,
  estimatePasswordStrength,
  flattenGroupOptions,
  formatBytes,
  formatDateTime,
  parseTagsInput,
  toLocalDateTimeInput,
} from './model.js';

const STRENGTH_LABELS = ['非常弱', '较弱', '一般', '较强', '非常强'];

export function renderStrengthHtml(password) {
  const { entropyBits, strength } = estimatePasswordStrength(password || '');
  const label = t(STRENGTH_LABELS[strength] || '非常弱');
  const percent = password ? Math.max(8, Math.min(100, Math.round((entropyBits / 110) * 100))) : 0;
  return `
    <div class="strength-meter" data-level="${strength}">
      <div class="strength-bar"><span style="width:${percent}%"></span></div>
      <small>${escapeHtml(label)} · ${entropyBits.toFixed(0)} bits</small>
    </div>
  `;
}

export function createModalController() {
  const dialog = document.getElementById('modal');
  const form = document.getElementById('modal-form');
  const titleEl = document.getElementById('modal-title');
  const fieldsEl = document.getElementById('modal-fields');
  const footerEl = document.getElementById('modal-footer');
  const closeBtn = document.getElementById('modal-close');

  let activeCleanup = null;
  let activeSubmit = null;

  function closeModal() {
    if (activeCleanup) {
      activeCleanup();
      activeCleanup = null;
    }
    activeSubmit = null;
    dialog.className = 'modal';
    if (dialog.open) dialog.close();
  }

  closeBtn.addEventListener('click', closeModal);
  dialog.addEventListener('cancel', event => {
    event.preventDefault();
    closeModal();
  });

  async function runIntent(intent) {
    if (!activeSubmit || intent === 'cancel') {
      closeModal();
      return;
    }
    const buttons = [
      ...footerEl.querySelectorAll('button'),
      ...fieldsEl.querySelectorAll('button[data-modal-intent], button[type="submit"]'),
    ];
    buttons.forEach(btn => { btn.disabled = true; });
    try {
      const keepOpen = (await activeSubmit(intent, form, fieldsEl)) === false;
      if (!keepOpen) closeModal();
    } catch (error) {
      const errBox = fieldsEl.querySelector('.modal-error');
      if (errBox) {
        errBox.textContent = String(error);
        errBox.hidden = false;
      } else {
        alert(String(error));
      }
      const pwInput = fieldsEl.querySelector('input[type="password"], input[name="password"]');
      if (pwInput) {
        pwInput.focus();
        pwInput.select();
      }
    } finally {
      buttons.forEach(btn => { btn.disabled = false; });
    }
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    const primaryBtn = footerEl.querySelector('button[type="submit"]');
    const intent = event.submitter?.value || primaryBtn?.value || 'submit';
    await runIntent(intent);
  });

  function openModal({ title, bodyHtml, buttons, className = '', onSubmit, onMount }) {
    closeModal();
    if (className) dialog.classList.add(className);
    titleEl.textContent = t(title);
    fieldsEl.innerHTML = `${bodyHtml}<p class="form-error modal-error" role="alert" hidden></p>`;
    const hasPrimary = buttons.some(([, , primary]) => Boolean(primary));
    footerEl.innerHTML = buttons
      .map(([label, value = 'cancel', primary = false], idx) => {
        const isSubmit = primary || (!hasPrimary && value !== 'cancel' && idx === buttons.length - 1);
        return `<button type="${isSubmit ? 'submit' : 'button'}" value="${escapeHtml(value)}" data-footer-intent="${escapeHtml(value)}" class="${primary ? 'primary' : 'secondary'}">${escapeHtml(t(label))}</button>`;
      })
      .join('');
    footerEl.querySelectorAll('button[type="button"]').forEach(btn => {
      btn.addEventListener('click', () => runIntent(btn.dataset.footerIntent));
    });
    fieldsEl.querySelectorAll('button[data-modal-intent]').forEach(btn => {
      btn.addEventListener('click', () => runIntent(btn.dataset.modalIntent));
    });
    localize(fieldsEl);
    activeSubmit = onSubmit;
    dialog.showModal();
    if (onMount) {
      const cleanup = onMount(form, fieldsEl, closeModal);
      if (typeof cleanup === 'function') activeCleanup = cleanup;
    }
    const focusable = fieldsEl.querySelector('input[name="password"], input:not([type="hidden"]):not([readonly]), textarea, select');
    if (focusable) focusable.focus();
  }

  return { openModal, closeModal, dialog };
}

export function showOpenDatabaseDialog(modal, { path, initialKeyfile = '', pickKeyfile, onOpen }) {
  modal.openModal({
    title: '打开数据库',
    className: 'modal-md',
    bodyHtml: `
      <label>数据库文件<input type="text" name="path" value="${escapeHtml(path)}" readonly></label>
      <label>主密码
        <div class="input-with-btn">
          <input type="password" name="password" autocomplete="off" placeholder="输入主密码">
          <button type="button" class="secondary" data-toggle-pw="password">👁</button>
        </div>
      </label>
      <label>密钥文件（可选）
        <div class="input-with-btn">
          <input type="text" name="keyfile" value="${escapeHtml(initialKeyfile)}" readonly placeholder="未使用密钥文件">
          <button type="button" class="secondary" data-pick-keyfile>选择…</button>
          <button type="button" class="secondary" data-clear-keyfile title="清除">×</button>
        </div>
      </label>
      <p class="hint">支持 KeePass 2 (KDBX 4 / KDBX 3) 及 KeePass 1 (KDB) 格式。至少需要主密码或密钥文件之一。</p>
    `,
    buttons: [['取消', 'cancel'], ['🔓 解密并打开', 'open', true]],
    onMount(form, fields) {
      wirePasswordToggles(fields);
      fields.querySelector('[data-pick-keyfile]').addEventListener('click', async () => {
        const kf = await pickKeyfile();
        if (kf) form.elements.keyfile.value = kf;
      });
      fields.querySelector('[data-clear-keyfile]').addEventListener('click', () => {
        form.elements.keyfile.value = '';
      });
    },
    async onSubmit(intent, form) {
      if (intent !== 'open') return;
      const password = form.elements.password.value;
      const keyfile = form.elements.keyfile.value.trim() || null;
      if (!password && !keyfile) throw new Error('请输入主密码或选择密钥文件。');
      await onOpen({ path, password: password || null, keyfile });
    },
  });
}

export function showCreateDatabaseDialog(modal, { path, pickKeyfile, createKeyfile, onCreate }) {
  const defaultName = path.split(/[\\/]/).pop()?.replace(/\.kdbx$/i, '') || 'My Vault';
  modal.openModal({
    title: '新建加密数据库',
    className: 'modal-md',
    bodyHtml: `
      <label>保存位置<input type="text" name="path" value="${escapeHtml(path)}" readonly></label>
      <div class="form-row">
        <label>数据库名称<input type="text" name="name" value="${escapeHtml(defaultName)}" required maxlength="100"></label>
        <label>描述（可选）<input type="text" name="description" maxlength="200" placeholder="例如：个人密码库"></label>
      </div>
      <label>设置主密码
        <div class="input-with-btn">
          <input type="password" name="password" autocomplete="off" placeholder="建议使用 12 位以上强密码">
          <button type="button" class="secondary" data-toggle-pw="password">👁</button>
        </div>
      </label>
      <div id="create-strength">${renderStrengthHtml('')}</div>
      <label>确认主密码
        <div class="input-with-btn">
          <input type="password" name="confirm" autocomplete="off" placeholder="再次输入主密码">
          <button type="button" class="secondary" data-toggle-pw="confirm">👁</button>
        </div>
      </label>
      <label>密钥文件（可选，增强双因素本地保护）
        <div class="input-with-btn">
          <input type="text" name="keyfile" readonly placeholder="未使用密钥文件">
          <button type="button" class="secondary" data-pick-keyfile>选择…</button>
          <button type="button" class="secondary" data-gen-keyfile>生成…</button>
          <button type="button" class="secondary" data-clear-keyfile title="清除">×</button>
        </div>
      </label>
      <p class="hint">数据库将采用标准 KDBX 4 格式（AES-256 + Argon2id + ChaCha20 内部流加密），与 KeePassXC / KeePass 2 兼容。</p>
    `,
    buttons: [['取消', 'cancel'], ['创建数据库', 'create', true]],
    onMount(form, fields) {
      wirePasswordToggles(fields);
      const pwInput = form.elements.password;
      const strengthBox = fields.querySelector('#create-strength');
      pwInput.addEventListener('input', () => {
        strengthBox.innerHTML = renderStrengthHtml(pwInput.value);
      });
      fields.querySelector('[data-pick-keyfile]').addEventListener('click', async () => {
        const kf = await pickKeyfile();
        if (kf) form.elements.keyfile.value = kf;
      });
      fields.querySelector('[data-gen-keyfile]').addEventListener('click', async () => {
        const kf = await createKeyfile();
        if (kf) form.elements.keyfile.value = kf;
      });
      fields.querySelector('[data-clear-keyfile]').addEventListener('click', () => {
        form.elements.keyfile.value = '';
      });
    },
    async onSubmit(intent, form) {
      if (intent !== 'create') return;
      const password = form.elements.password.value;
      const confirm = form.elements.confirm.value;
      const keyfile = form.elements.keyfile.value.trim() || null;
      if (!password && !keyfile) throw new Error('请至少设置主密码或选择密钥文件。');
      if (password !== confirm) throw new Error('两次输入的主密码不一致。');
      await onCreate({
        path,
        name: form.elements.name.value.trim() || defaultName,
        description: form.elements.description.value.trim(),
        password: password || null,
        keyfile,
      });
    },
  });
}

export function showChangeMasterKeyDialog(modal, { vault, pickKeyfile, createKeyfile, onSave }) {
  modal.openModal({
    title: '修改主密钥',
    className: 'modal-md',
    bodyHtml: `
      <p class="hint">修改主密钥后会立即使用新密钥重新加密并保存当前数据库：<strong>${escapeHtml(vault.fileName)}</strong></p>
      <label>新主密码
        <div class="input-with-btn">
          <input type="password" name="password" autocomplete="off" placeholder="输入新的主密码">
          <button type="button" class="secondary" data-toggle-pw="password">👁</button>
        </div>
      </label>
      <div id="cmk-strength">${renderStrengthHtml('')}</div>
      <label>确认新主密码
        <div class="input-with-btn">
          <input type="password" name="confirm" autocomplete="off" placeholder="再次输入新的主密码">
          <button type="button" class="secondary" data-toggle-pw="confirm">👁</button>
        </div>
      </label>
      <label>新密钥文件（可选）
        <div class="input-with-btn">
          <input type="text" name="keyfile" value="${escapeHtml(vault.keyfilePath || '')}" readonly placeholder="未使用密钥文件">
          <button type="button" class="secondary" data-pick-keyfile>选择…</button>
          <button type="button" class="secondary" data-gen-keyfile>生成…</button>
          <button type="button" class="secondary" data-clear-keyfile title="清除">×</button>
        </div>
      </label>
    `,
    buttons: [['取消', 'cancel'], ['更新主密钥并保存', 'save', true]],
    onMount(form, fields) {
      wirePasswordToggles(fields);
      const pwInput = form.elements.password;
      const strengthBox = fields.querySelector('#cmk-strength');
      pwInput.addEventListener('input', () => {
        strengthBox.innerHTML = renderStrengthHtml(pwInput.value);
      });
      fields.querySelector('[data-pick-keyfile]').addEventListener('click', async () => {
        const kf = await pickKeyfile();
        if (kf) form.elements.keyfile.value = kf;
      });
      fields.querySelector('[data-gen-keyfile]').addEventListener('click', async () => {
        const kf = await createKeyfile();
        if (kf) form.elements.keyfile.value = kf;
      });
      fields.querySelector('[data-clear-keyfile]').addEventListener('click', () => {
        form.elements.keyfile.value = '';
      });
    },
    async onSubmit(intent, form) {
      if (intent !== 'save') return;
      const password = form.elements.password.value;
      const confirm = form.elements.confirm.value;
      const keyfile = form.elements.keyfile.value.trim() || null;
      if (!password && !keyfile) throw new Error('请至少提供新主密码或密钥文件。');
      if (password !== confirm) throw new Error('两次输入的新主密码不一致。');
      await onSave({ password: password || null, keyfile });
    },
  });
}

export function showPasswordGeneratorDialog(modal, { generatePassword, copySecret, onApply }) {
  const buttons = onApply
    ? [['关闭', 'cancel'], ['复制密码', 'copy'], ['应用到条目', 'apply', true]]
    : [['关闭', 'cancel'], ['复制密码', 'copy', true]];

  modal.openModal({
    title: '密码生成器',
    className: 'modal-md',
    bodyHtml: `
      <div class="pwgen-output">
        <input type="text" name="generated" class="mono-input" readonly aria-label="生成的密码">
        <button type="button" class="secondary" id="pwgen-regen" title="重新生成">⟳ 重新生成</button>
      </div>
      <div id="pwgen-strength">${renderStrengthHtml('')}</div>
      <label>长度：<strong id="pwgen-len-val">20</strong>
        <div class="range-row">
          <input type="range" name="lengthRange" min="6" max="64" value="20">
          <input type="number" name="length" min="4" max="256" value="20" style="width:76px">
        </div>
      </label>
      <div class="check-grid">
        <label class="check"><input type="checkbox" name="lower" checked> 小写字母 (a-z)</label>
        <label class="check"><input type="checkbox" name="upper" checked> 大写字母 (A-Z)</label>
        <label class="check"><input type="checkbox" name="numbers" checked> 数字 (0-9)</label>
        <label class="check"><input type="checkbox" name="special" checked> 特殊符号 (!@#$…)</label>
        <label class="check"><input type="checkbox" name="excludeLookAlike"> 排除易混淆字符 (l 1 I 0 O |)</label>
        <label class="check"><input type="checkbox" name="everyGroup" checked> 每种已选类型至少包含一位</label>
      </div>
      <label>自定义额外字符（可选）<input type="text" name="custom" placeholder="例如：_-+=!?" autocomplete="off" spellcheck="false"></label>
    `,
    buttons,
    onMount(form, fields) {
      const lenRange = form.elements.lengthRange;
      const lenInput = form.elements.length;
      const lenLabel = fields.querySelector('#pwgen-len-val');
      const output = form.elements.generated;
      const strengthBox = fields.querySelector('#pwgen-strength');
      const errBox = fields.querySelector('.modal-error');

      const refresh = async () => {
        errBox.hidden = true;
        try {
          const result = await generatePassword({
            length: Number(lenInput.value) || 20,
            lower: form.elements.lower.checked,
            upper: form.elements.upper.checked,
            numbers: form.elements.numbers.checked,
            special: form.elements.special.checked,
            custom: form.elements.custom.value,
            excludeLookAlike: form.elements.excludeLookAlike.checked,
            everyGroup: form.elements.everyGroup.checked,
          });
          output.value = result.password;
          strengthBox.innerHTML = renderStrengthHtml(result.password);
        } catch (error) {
          errBox.textContent = String(error);
          errBox.hidden = false;
        }
      };

      lenRange.addEventListener('input', () => {
        lenInput.value = lenRange.value;
        lenLabel.textContent = lenRange.value;
        refresh();
      });
      lenInput.addEventListener('input', () => {
        lenRange.value = Math.min(64, Math.max(6, Number(lenInput.value) || 20));
        lenLabel.textContent = lenInput.value;
        refresh();
      });
      for (const name of ['lower', 'upper', 'numbers', 'special', 'excludeLookAlike', 'everyGroup', 'custom']) {
        form.elements[name].addEventListener('input', refresh);
        form.elements[name].addEventListener('change', refresh);
      }
      fields.querySelector('#pwgen-regen').addEventListener('click', refresh);
      refresh();
    },
    async onSubmit(intent, form) {
      const value = form.elements.generated.value;
      if (!value) throw new Error('尚未生成有效密码。');
      if (intent === 'copy') {
        await copySecret(value, '已复制生成的密码');
        return false;
      }
      if (intent === 'apply' && onApply) {
        onApply(value);
      }
    },
  });
}

export function showGroupEditorDialog(modal, { vault, group = null, parentId = null, onSave }) {
  const isEdit = Boolean(group);
  const exclude = isEdit ? collectDescendantGroupIds(vault.groups, group.id) : new Set();
  const parentOptions = flattenGroupOptions(vault.groups, vault.rootGroupId, exclude);
  const selectedParent = isEdit ? group.parentId : (parentId || vault.rootGroupId);
  const selectedIcon = group?.iconId ?? 48;
  const searchVal = group?.enableSearching === true ? 'true' : group?.enableSearching === false ? 'false' : 'inherit';

  modal.openModal({
    title: isEdit ? '编辑分组' : '新建子分组',
    className: 'modal-md',
    bodyHtml: `
      <label>分组名称<input type="text" name="name" value="${escapeHtml(group?.name || '')}" required maxlength="100" placeholder="例如：服务器 / 邮箱 / 金融"></label>
      ${(!isEdit || !group.isRoot) ? `
      <label>所属父分组
        <select name="parentId">
          ${parentOptions.map(opt => `<option value="${escapeHtml(opt.id)}" ${opt.id === selectedParent ? 'selected' : ''}>${escapeHtml(opt.label)}</option>`).join('')}
        </select>
      </label>` : ''}
      <label>图标
        <div class="icon-picker">
          ${PICKER_ICON_IDS.map(id => `<button type="button" class="icon-opt${id === selectedIcon ? ' active' : ''}" data-icon="${id}" title="Icon #${id}">${iconGlyph(id)}</button>`).join('')}
        </div>
        <input type="hidden" name="iconId" value="${selectedIcon}">
      </label>
      <label>搜索策略
        <select name="enableSearching">
          <option value="inherit" ${searchVal === 'inherit' ? 'selected' : ''}>继承上级分组</option>
          <option value="true" ${searchVal === 'true' ? 'selected' : ''}>允许搜索</option>
          <option value="false" ${searchVal === 'false' ? 'selected' : ''}>排除在全局搜索外</option>
        </select>
      </label>
      <label>备注<textarea name="notes" rows="3" placeholder="分组说明（可选）">${escapeHtml(group?.notes || '')}</textarea></label>
    `,
    buttons: [['取消', 'cancel'], ['保存', 'save', true]],
    onMount(form, fields) {
      wireIconPicker(fields, form.elements.iconId);
    },
    async onSubmit(intent, form) {
      if (intent !== 'save') return;
      const name = form.elements.name.value.trim();
      if (!name) throw new Error('请输入分组名称。');
      const searchSetting = form.elements.enableSearching.value;
      await onSave({
        name,
        notes: form.elements.notes.value,
        iconId: Number(form.elements.iconId.value),
        enableSearching: searchSetting === 'inherit' ? null : searchSetting === 'true',
        parentId: form.elements.parentId?.value || null,
      });
    },
  });
}

export function showEntryEditorDialog(modal, {
  vault,
  entry = null,
  groupId,
  defaultUsername = '',
  generatePassword,
  onSave,
  onRestoreHistory,
  onDeleteHistory,
  onAddAttachment,
  onExportAttachment,
  onRemoveAttachment,
}) {
  const isEdit = Boolean(entry);
  const selectedIcon = entry?.iconId ?? 0;
  const targetGroupId = entry?.groupId || groupId || vault.rootGroupId;
  const groupOptions = flattenGroupOptions(vault.groups, vault.rootGroupId);
  const customFields = (entry?.customFields || []).map(item => ({ ...item }));

  modal.openModal({
    title: isEdit ? '编辑条目' : '新建条目',
    className: 'modal-lg',
    bodyHtml: `
      <nav class="modal-tabs" role="tablist">
        <button type="button" class="secondary" data-tab="general" aria-pressed="true">常规</button>
        <button type="button" class="secondary" data-tab="advanced" aria-pressed="false">高级属性与附件</button>
        ${isEdit ? `<button type="button" class="secondary" data-tab="history" aria-pressed="false">历史版本 (${entry.history.length})</button>` : ''}
      </nav>

      <section class="modal-page" data-page="general">
        <div class="form-row">
          <label>标题<input type="text" name="title" value="${escapeHtml(entry?.title || '')}" required placeholder="例如：GitHub / 公司邮箱"></label>
          <label>所属分组
            <select name="groupId">
              ${groupOptions.map(opt => `<option value="${escapeHtml(opt.id)}" ${opt.id === targetGroupId ? 'selected' : ''}>${escapeHtml(opt.label)}</option>`).join('')}
            </select>
          </label>
        </div>
        <div class="form-row">
          <label>用户名 / 账号<input type="text" name="username" value="${escapeHtml(entry ? entry.username : defaultUsername)}" autocomplete="off" spellcheck="false"></label>
          <label>URL<input type="text" name="url" value="${escapeHtml(entry?.url || '')}" placeholder="https://example.com" spellcheck="false"></label>
        </div>
        <label>密码
          <div class="input-with-btn">
            <input type="password" name="password" class="mono-input" value="${escapeHtml(entry?.password || '')}" autocomplete="off" spellcheck="false">
            <button type="button" class="secondary" data-toggle-pw="password" title="显示/隐藏">👁</button>
            <button type="button" class="secondary" id="entry-quick-gen" title="快速生成强密码">⚡ 生成</button>
          </div>
        </label>
        <div id="entry-pw-strength">${renderStrengthHtml(entry?.password || '')}</div>
        <label>确认密码
          <input type="password" name="confirmPassword" class="mono-input" value="${escapeHtml(entry?.password || '')}" autocomplete="off" spellcheck="false">
        </label>
        <div class="form-row">
          <label>标签（逗号分隔）<input type="text" name="tags" value="${escapeHtml((entry?.tags || []).join(', '))}" placeholder="work, dev, 2fa"></label>
          <label>过期时间
            <div class="expiry-row">
              <input type="checkbox" name="expires" ${entry?.expires ? 'checked' : ''} aria-label="启用过期时间">
              <input type="datetime-local" name="expiryTime" value="${escapeHtml(toLocalDateTimeInput(entry?.expiryTime))}" ${entry?.expires ? '' : 'disabled'}>
            </div>
          </label>
        </div>
        <label>图标
          <div class="icon-picker">
            ${PICKER_ICON_IDS.map(id => `<button type="button" class="icon-opt${id === selectedIcon ? ' active' : ''}" data-icon="${id}">${iconGlyph(id)}</button>`).join('')}
          </div>
          <input type="hidden" name="iconId" value="${selectedIcon}">
        </label>
        <label>备注<textarea name="notes" rows="4" placeholder="支持多行备注…">${escapeHtml(entry?.notes || '')}</textarea></label>
      </section>

      <section class="modal-page" data-page="advanced" hidden>
        <label>TOTP 动态验证码 URI（可选）
          <input type="text" name="otp" class="mono-input" value="${escapeHtml(entry?.otp || '')}" placeholder="otpauth://totp/Issuer:account?secret=BASE32SECRET&period=30&digits=6" spellcheck="false" autocomplete="off">
        </label>
        <div class="section-bar">
          <strong>自定义属性</strong>
          <button type="button" class="secondary" id="add-custom-field">＋ 添加属性</button>
        </div>
        <div id="custom-fields-list" class="custom-fields-list"></div>
        ${isEdit ? `
        <div class="section-bar" style="margin-top:12px">
          <strong>附件 (${entry.attachments.length})</strong>
          <button type="button" class="secondary" id="add-attachment-btn">＋ 添加文件附件…</button>
        </div>
        <div id="entry-attachments-list" class="attachments-list"></div>
        ` : '<p class="hint">创建条目后，可在编辑页面为其添加加密附件。</p>'}
      </section>

      ${isEdit ? `
      <section class="modal-page" data-page="history" hidden>
        <div id="entry-history-list" class="history-list"></div>
      </section>
      ` : ''}
    `,
    buttons: [['取消', 'cancel'], ['保存条目', 'save', true]],
    onMount(form, fields, closeModal) {
      wireModalTabs(fields);
      wirePasswordToggles(fields);
      wireIconPicker(fields, form.elements.iconId);

      const pwInput = form.elements.password;
      const confirmInput = form.elements.confirmPassword;
      const strengthBox = fields.querySelector('#entry-pw-strength');
      pwInput.addEventListener('input', () => {
        strengthBox.innerHTML = renderStrengthHtml(pwInput.value);
      });

      form.elements.expires.addEventListener('change', () => {
        form.elements.expiryTime.disabled = !form.elements.expires.checked;
        if (form.elements.expires.checked && !form.elements.expiryTime.value) {
          const nextYear = new Date(Date.now() + 365 * 86400 * 1000);
          form.elements.expiryTime.value = toLocalDateTimeInput(nextYear.toISOString());
        }
      });

      fields.querySelector('#entry-quick-gen').addEventListener('click', async () => {
        const res = await generatePassword({
          length: 20,
          lower: true,
          upper: true,
          numbers: true,
          special: true,
          custom: '',
          excludeLookAlike: false,
          everyGroup: true,
        });
        pwInput.value = res.password;
        confirmInput.value = res.password;
        strengthBox.innerHTML = renderStrengthHtml(res.password);
      });

      const cfList = fields.querySelector('#custom-fields-list');
      const renderCustomFields = () => {
        if (!customFields.length) {
          cfList.innerHTML = '<p class="empty">暂无自定义属性。</p>';
          return;
        }
        cfList.innerHTML = customFields
          .map((field, idx) => `
            <div class="cf-row" data-cf-idx="${idx}">
              <input type="text" data-cf-key value="${escapeHtml(field.key)}" placeholder="属性名" spellcheck="false">
              <input type="${field.protected ? 'password' : 'text'}" data-cf-val value="${escapeHtml(field.value)}" placeholder="属性值" spellcheck="false">
              <label class="check"><input type="checkbox" data-cf-prot ${field.protected ? 'checked' : ''}> 保护</label>
              <button type="button" class="secondary" data-cf-del title="删除">×</button>
            </div>
          `)
          .join('');
        cfList.querySelectorAll('.cf-row').forEach(row => {
          const idx = Number(row.dataset.cfIdx);
          row.querySelector('[data-cf-key]').addEventListener('input', e => { customFields[idx].key = e.target.value; });
          row.querySelector('[data-cf-val]').addEventListener('input', e => { customFields[idx].value = e.target.value; });
          row.querySelector('[data-cf-prot]').addEventListener('change', e => {
            customFields[idx].protected = e.target.checked;
            renderCustomFields();
          });
          row.querySelector('[data-cf-del]').addEventListener('click', () => {
            customFields.splice(idx, 1);
            renderCustomFields();
          });
        });
      };
      renderCustomFields();
      fields.querySelector('#add-custom-field').addEventListener('click', () => {
        customFields.push({ key: '', value: '', protected: false });
        renderCustomFields();
      });

      if (isEdit) {
        const attBox = fields.querySelector('#entry-attachments-list');
        const renderAttachments = list => {
          if (!list.length) {
            attBox.innerHTML = '<p class="empty">暂无附件。</p>';
            return;
          }
          attBox.innerHTML = list
            .map(att => `
              <div class="att-row">
                <span class="att-name">📎 ${escapeHtml(att.name)} <small>(${formatBytes(att.size)})</small></span>
                <span>
                  <button type="button" class="secondary" data-att-export="${escapeHtml(att.name)}">导出…</button>
                  <button type="button" class="secondary" data-att-del="${escapeHtml(att.name)}">删除</button>
                </span>
              </div>
            `)
            .join('');
          attBox.querySelectorAll('[data-att-export]').forEach(btn => {
            btn.addEventListener('click', () => onExportAttachment(entry.id, btn.dataset.attExport));
          });
          attBox.querySelectorAll('[data-att-del]').forEach(btn => {
            btn.addEventListener('click', async () => {
              const updated = await onRemoveAttachment(entry.id, btn.dataset.attDel);
              if (updated) renderAttachments(updated.attachments);
            });
          });
        };
        renderAttachments(entry.attachments);
        fields.querySelector('#add-attachment-btn').addEventListener('click', async () => {
          const updated = await onAddAttachment(entry.id);
          if (updated) renderAttachments(updated.attachments);
        });

        const histBox = fields.querySelector('#entry-history-list');
        const renderHistory = list => {
          if (!list.length) {
            histBox.innerHTML = '<p class="empty">暂无历史版本。每次编辑并保存条目时都会自动记录历史快照。</p>';
            return;
          }
          histBox.innerHTML = [...list]
            .reverse()
            .map(item => `
              <div class="history-row">
                <div>
                  <strong>${escapeHtml(item.title || '(无标题)')}</strong>
                  <small>${escapeHtml(formatDateTime(item.modifiedAt))} · ${escapeHtml(item.username || '—')}</small>
                </div>
                <div class="history-actions">
                  <button type="button" class="secondary" data-hist-restore="${item.index}">恢复此版本</button>
                  <button type="button" class="secondary" data-hist-del="${item.index}">删除</button>
                </div>
              </div>
            `)
            .join('');
          histBox.querySelectorAll('[data-hist-restore]').forEach(btn => {
            btn.addEventListener('click', async () => {
              await onRestoreHistory(entry.id, Number(btn.dataset.histRestore));
              closeModal();
            });
          });
          histBox.querySelectorAll('[data-hist-del]').forEach(btn => {
            btn.addEventListener('click', async () => {
              const updated = await onDeleteHistory(entry.id, Number(btn.dataset.histDel));
              if (updated) renderHistory(updated.history);
            });
          });
        };
        renderHistory(entry.history);
      }
    },
    async onSubmit(intent, form) {
      if (intent !== 'save') return;
      const password = form.elements.password.value;
      const confirm = form.elements.confirmPassword.value;
      if (password !== confirm) throw new Error('两次输入的密码不一致。');
      const payload = {
        title: form.elements.title.value.trim(),
        username: form.elements.username.value,
        password,
        url: form.elements.url.value.trim(),
        notes: form.elements.notes.value,
        otp: form.elements.otp.value.trim() || null,
        tags: parseTagsInput(form.elements.tags.value),
        iconId: Number(form.elements.iconId.value),
        expires: form.elements.expires.checked,
        expiryTime: form.elements.expires.checked ? form.elements.expiryTime.value : null,
        customFields: customFields.filter(f => f.key.trim().length > 0),
      };
      await onSave(payload, form.elements.groupId.value);
    },
  });
}

export function showDatabaseSettingsDialog(modal, { vault, onSave }) {
  const m = vault.meta;
  modal.openModal({
    title: '数据库设置',
    className: 'modal-lg',
    bodyHtml: `
      <nav class="modal-tabs">
        <button type="button" class="secondary" data-tab="general" aria-pressed="true">常规</button>
        <button type="button" class="secondary" data-tab="crypto" aria-pressed="false">加密与安全</button>
      </nav>
      <section class="modal-page" data-page="general">
        <label>数据库名称<input type="text" name="name" value="${escapeHtml(m.name)}" required></label>
        <label>数据库描述<textarea name="description" rows="2">${escapeHtml(m.description)}</textarea></label>
        <label>新建条目默认用户名<input type="text" name="defaultUsername" value="${escapeHtml(m.defaultUsername)}"></label>
        <label class="check"><input type="checkbox" name="recycleBinEnabled" ${m.recycleBinEnabled ? 'checked' : ''}> 启用回收站（删除条目和分组时先移入回收站）</label>
        <div class="form-row">
          <label>最大历史版本数<input type="number" name="historyMaxItems" min="0" max="1000" value="${m.historyMaxItems}"></label>
          <label>历史记录上限 (MiB)<input type="number" name="historyMaxSizeMib" min="1" max="100" value="${Math.max(1, Math.round(m.historyMaxSize / (1024 * 1024)))}"></label>
        </div>
      </section>
      <section class="modal-page" data-page="crypto" hidden>
        <div class="form-row">
          <label>外层加密算法
            <select name="outerCipher">
              <option value="aes256" ${m.outerCipher === 'aes256' ? 'selected' : ''}>AES-256 (CBC)</option>
              <option value="chacha20" ${m.outerCipher === 'chacha20' ? 'selected' : ''}>ChaCha20 (256-bit)</option>
              <option value="twofish" ${m.outerCipher === 'twofish' ? 'selected' : ''}>Twofish (256-bit)</option>
            </select>
          </label>
          <label>压缩方式
            <select name="compression">
              <option value="gzip" ${m.compression === 'gzip' ? 'selected' : ''}>GZip 压缩</option>
              <option value="none" ${m.compression === 'none' ? 'selected' : ''}>不压缩</option>
            </select>
          </label>
        </div>
        <label>密钥派生算法 (KDF)
          <select name="kdfType">
            <option value="argon2id" ${m.kdfType === 'argon2id' ? 'selected' : ''}>Argon2id (推荐 · KDBX 4)</option>
            <option value="argon2d" ${m.kdfType === 'argon2d' ? 'selected' : ''}>Argon2d (KDBX 4)</option>
            <option value="aes" ${m.kdfType === 'aes' ? 'selected' : ''}>AES-KDF (经典)</option>
          </select>
        </label>
        <div class="form-row">
          <label>迭代次数 / 轮数<input type="number" name="kdfRounds" min="1" max="100000000" value="${m.kdfRounds}"></label>
          <label>Argon2 内存 (MiB)<input type="number" name="kdfMemoryMib" min="1" max="512" value="${m.kdfMemoryMib || 16}"></label>
          <label>并行线程数<input type="number" name="kdfParallelism" min="1" max="16" value="${m.kdfParallelism || 4}"></label>
        </div>
        <p class="hint">修改加密参数后，请点击保存数据库（⌘S）使新配置生效。若当前为旧版 KDB/KDBX 3 文件，保存时将自动升级为 KDBX 4 格式。</p>
      </section>
    `,
    buttons: [['取消', 'cancel'], ['应用设置', 'save', true]],
    onMount(form, fields) {
      wireModalTabs(fields);
      const toggleKdfFields = () => {
        const isAes = form.elements.kdfType.value === 'aes';
        form.elements.kdfMemoryMib.disabled = isAes;
        form.elements.kdfParallelism.disabled = isAes;
      };
      form.elements.kdfType.addEventListener('change', () => {
        if (form.elements.kdfType.value === 'aes' && Number(form.elements.kdfRounds.value) < 1000) {
          form.elements.kdfRounds.value = 60000;
        } else if (form.elements.kdfType.value !== 'aes' && Number(form.elements.kdfRounds.value) > 200) {
          form.elements.kdfRounds.value = 4;
        }
        toggleKdfFields();
      });
      toggleKdfFields();
    },
    async onSubmit(intent, form) {
      if (intent !== 'save') return;
      await onSave({
        name: form.elements.name.value.trim(),
        description: form.elements.description.value,
        defaultUsername: form.elements.defaultUsername.value,
        recycleBinEnabled: form.elements.recycleBinEnabled.checked,
        historyMaxItems: Number(form.elements.historyMaxItems.value) || 10,
        historyMaxSize: (Number(form.elements.historyMaxSizeMib.value) || 6) * 1024 * 1024,
        outerCipher: form.elements.outerCipher.value,
        compression: form.elements.compression.value,
        kdfType: form.elements.kdfType.value,
        kdfRounds: Number(form.elements.kdfRounds.value) || 4,
        kdfMemoryMib: Number(form.elements.kdfMemoryMib.value) || 16,
        kdfParallelism: Number(form.elements.kdfParallelism.value) || 4,
      });
    },
  });
}

export function showPreferencesDialog(modal, {
  prefs,
  version,
  onSave,
  checkUpdates,
  installUpdate,
  openRelease,
  initialTab = 'general',
}) {
  let updateState = null;

  modal.openModal({
    title: '偏好设置',
    className: 'modal-lg',
    bodyHtml: `
      <nav class="modal-tabs" aria-label="偏好设置">
        <button type="button" class="secondary" data-tab="general" aria-pressed="true">通用</button>
        <button type="button" class="secondary" data-tab="security" aria-pressed="false">安全</button>
        <button type="button" class="secondary" data-tab="updates" aria-pressed="false">版本更新</button>
      </nav>

      <section class="modal-page" data-page="general">
        <label>界面语言
          <select name="language">
            <option value="zh-CN" ${prefs.language === 'zh-CN' ? 'selected' : ''}>简体中文</option>
            <option value="en" ${prefs.language === 'en' ? 'selected' : ''}>English</option>
            <option value="system" ${prefs.language === 'system' ? 'selected' : ''}>跟随系统</option>
          </select>
        </label>
        <label class="check"><input type="checkbox" name="rememberRecent" ${prefs.rememberRecent ? 'checked' : ''}> 记住最近打开的数据库</label>
        <label class="check"><input type="checkbox" name="openLastDatabaseOnStartup" ${prefs.openLastDatabaseOnStartup !== false ? 'checked' : ''}> 启动时自动定位到上次打开的数据库密码框</label>
        <label class="check"><input type="checkbox" name="rememberKeyfiles" ${prefs.rememberKeyfiles ? 'checked' : ''}> 记住密钥文件路径</label>
        <label class="check"><input type="checkbox" name="autoSaveOnChange" ${prefs.autoSaveOnChange ? 'checked' : ''}> 每次修改后自动保存</label>
        <label class="check"><input type="checkbox" name="autoSaveOnClose" ${prefs.autoSaveOnClose ? 'checked' : ''}> 关闭数据库前自动保存</label>
      </section>

      <section class="modal-page" data-page="security" hidden>
        <label class="check"><input type="checkbox" name="clearClipboardEnabled" ${prefs.clearClipboardEnabled ? 'checked' : ''}> 复制敏感信息后自动清空剪贴板</label>
        <label>清空倒计时（秒）<input type="number" name="clearClipboardSeconds" min="3" max="300" value="${prefs.clearClipboardSeconds}"></label>
        <div class="modal-rule"></div>
        <label class="check"><input type="checkbox" name="autoLockEnabled" ${prefs.autoLockEnabled ? 'checked' : ''}> 空闲超时后自动锁定数据库</label>
        <label>空闲锁定时间（秒）<input type="number" name="autoLockSeconds" min="30" max="86400" value="${prefs.autoLockSeconds}"></label>
        <div class="modal-rule"></div>
        <label class="check"><input type="checkbox" name="hidePasswords" ${prefs.hidePasswords ? 'checked' : ''}> 条目列表中默认隐藏密码</label>
      </section>

      <section class="modal-page" data-page="updates" hidden>
        <strong>GitHub Releases 在线升级</strong>
        <p class="hint">通过内置公钥校验签名与版本号，安全下载并安装新版客户端。</p>
        <div class="prefs-actions">
          <span id="current-version">My KeePass ${escapeHtml(version)}</span>
          <button type="button" data-modal-intent="check-update" class="secondary">检查更新</button>
          <button type="button" data-modal-intent="install-update" id="install-update-btn" class="primary" hidden>下载并安装</button>
          <button type="button" id="open-release-btn" class="secondary" hidden>查看 GitHub Release</button>
        </div>
        <progress id="update-progress" aria-label="更新下载进度" hidden></progress>
        <p id="update-result" class="hint" role="status"></p>
      </section>
    `,
    buttons: [['取消', 'cancel'], ['保存', 'save', true]],
    onMount(form, fields) {
      const switchTab = wireModalTabs(fields);
      if (initialTab !== 'general') switchTab(initialTab);
      const releaseBtn = fields.querySelector('#open-release-btn');
      releaseBtn.addEventListener('click', () => {
        if (updateState?.url) openRelease(updateState.url);
      });
    },
    async onSubmit(intent, form, fields) {
      const installBtn = fields.querySelector('#install-update-btn');
      const releaseBtn = fields.querySelector('#open-release-btn');
      const progressEl = fields.querySelector('#update-progress');
      const resultEl = fields.querySelector('#update-result');

      if (intent === 'check-update') {
        updateState = null;
        installBtn.hidden = true;
        releaseBtn.hidden = true;
        progressEl.hidden = true;
        resultEl.textContent = t('正在检查更新…');
        try {
          updateState = await checkUpdates();
          if (updateState.available) {
            installBtn.hidden = !updateState.installable;
            releaseBtn.hidden = updateState.installable;
            const msg = t(updateState.installable ? '安装后应用将重新启动。' : '此版本未提供可用的应用内更新包。');
            resultEl.textContent = `${t('发现新版本：')}${updateState.latest} · ${msg}`;
          } else {
            resultEl.textContent = t(updateState.latest ? '当前已是最新版本。' : 'GitHub 暂无正式版本。');
          }
        } catch (error) {
          resultEl.textContent = `${t('检查更新失败：')}${String(error)}`;
        }
        return false;
      }

      if (intent === 'install-update') {
        if (!updateState?.installable) return false;
        releaseBtn.hidden = true;
        progressEl.hidden = false;
        progressEl.removeAttribute('value');
        resultEl.textContent = t('正在准备更新…');
        try {
          await installUpdate(updateState.latest, event => {
            if (event.kind === 'installing') {
              progressEl.removeAttribute('value');
              resultEl.textContent = t('正在校验并安装更新…');
              return;
            }
            if (event.total > 0) {
              progressEl.max = event.total;
              progressEl.value = event.received;
            }
            const rec = formatBytes(event.received);
            const tot = event.total > 0 ? ` / ${formatBytes(event.total)}` : '';
            resultEl.textContent = `${t('正在下载更新：')}${rec}${tot}`;
          });
        } catch (error) {
          progressEl.hidden = true;
          releaseBtn.hidden = false;
          resultEl.textContent = `${t('更新安装失败：')}${String(error)}`;
        }
        return false;
      }

      if (intent === 'save') {
        await onSave({
          ...prefs,
          language: form.elements.language.value,
          rememberRecent: form.elements.rememberRecent.checked,
          openLastDatabaseOnStartup: form.elements.openLastDatabaseOnStartup.checked,
          rememberKeyfiles: form.elements.rememberKeyfiles.checked,
          autoSaveOnChange: form.elements.autoSaveOnChange.checked,
          autoSaveOnClose: form.elements.autoSaveOnClose.checked,
          clearClipboardEnabled: form.elements.clearClipboardEnabled.checked,
          clearClipboardSeconds: Number(form.elements.clearClipboardSeconds.value) || 15,
          autoLockEnabled: form.elements.autoLockEnabled.checked,
          autoLockSeconds: Number(form.elements.autoLockSeconds.value) || 300,
          hidePasswords: form.elements.hidePasswords.checked,
        });
      }
    },
  });
}

function wireModalTabs(fields) {
  const buttons = [...fields.querySelectorAll('[data-tab]')];
  const pages = [...fields.querySelectorAll('[data-page]')];
  const activate = name => {
    buttons.forEach(btn => btn.setAttribute('aria-pressed', String(btn.dataset.tab === name)));
    pages.forEach(page => { page.hidden = page.dataset.page !== name; });
  };
  buttons.forEach(btn => btn.addEventListener('click', () => activate(btn.dataset.tab)));
  return activate;
}

function wirePasswordToggles(fields) {
  fields.querySelectorAll('[data-toggle-pw]').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = fields.querySelector(`[name="${btn.dataset.togglePw}"]`);
      if (!target) return;
      target.type = target.type === 'password' ? 'text' : 'password';
      btn.setAttribute('aria-pressed', String(target.type === 'text'));
    });
  });
}

function wireIconPicker(fields, hiddenInput) {
  const buttons = [...fields.querySelectorAll('.icon-opt')];
  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      buttons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      hiddenInput.value = btn.dataset.icon;
    });
  });
}
