export function buildGroupTree(groups, rootGroupId) {
  const byId = new Map(groups.map(group => [group.id, group]));
  const build = (id, depth) => {
    const group = byId.get(id);
    if (!group) return null;
    const children = (group.childGroupIds || [])
      .map(childId => build(childId, depth + 1))
      .filter(Boolean);
    return { ...group, depth, children };
  };
  return rootGroupId ? build(rootGroupId, 0) : null;
}

export function flattenGroupOptions(groups, rootGroupId, excludeIds = new Set()) {
  const tree = buildGroupTree(groups, rootGroupId);
  const result = [];
  const walk = node => {
    if (!node || excludeIds.has(node.id)) return;
    result.push({
      id: node.id,
      label: `${'  '.repeat(node.depth)}${node.depth > 0 ? '└ ' : ''}${node.name}`,
      isRecycleBin: node.isRecycleBin,
    });
    for (const child of node.children) walk(child);
  };
  walk(tree);
  return result;
}

export function collectDescendantGroupIds(groups, groupId) {
  const byId = new Map(groups.map(group => [group.id, group]));
  const ids = new Set();
  const stack = [groupId];
  while (stack.length) {
    const current = stack.pop();
    if (!current || ids.has(current)) continue;
    ids.add(current);
    const group = byId.get(current);
    if (group) {
      for (const childId of group.childGroupIds || []) stack.push(childId);
    }
  }
  return ids;
}

export function matchesEntryQuery(entry, query) {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return true;
  const customText = (entry.customFields || [])
    .filter(field => !field.protected)
    .map(field => `${field.key} ${field.value}`)
    .join(' ');
  const haystack = [
    entry.title,
    entry.username,
    entry.url,
    entry.notes,
    entry.groupPath,
    ...(entry.tags || []),
    customText,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  return terms.every(term => haystack.includes(term));
}

export function filterAndSortEntries(entries, { groupId, query = '', sortBy = 'title', sortDir = 'asc', groups = [] } = {}) {
  const trimmed = query.trim();
  let list;
  if (trimmed) {
    const groupMap = new Map(groups.map(g => [g.id, g]));
    list = entries.filter(entry => {
      if (entry.inRecycleBin) return false;
      const g = groupMap.get(entry.groupId);
      if (g && g.enableSearching === false) return false;
      return matchesEntryQuery(entry, trimmed);
    });
  } else if (groupId) {
    list = entries.filter(entry => entry.groupId === groupId);
  } else {
    list = [...entries];
  }

  const direction = sortDir === 'desc' ? -1 : 1;
  return [...list].sort((a, b) => {
    const av = (a[sortBy] || '').toString().toLowerCase();
    const bv = (b[sortBy] || '').toString().toLowerCase();
    if (av < bv) return -1 * direction;
    if (av > bv) return 1 * direction;
    return a.id.localeCompare(b.id) * direction;
  });
}

export function estimatePasswordStrength(password = '') {
  if (!password) return { entropyBits: 0, strength: 0 };
  let hasLower = false;
  let hasUpper = false;
  let hasDigit = false;
  let hasSpecial = false;
  let hasUnicode = false;
  for (const ch of password) {
    const code = ch.codePointAt(0);
    if (code >= 97 && code <= 122) hasLower = true;
    else if (code >= 65 && code <= 90) hasUpper = true;
    else if (code >= 48 && code <= 57) hasDigit = true;
    else if (code >= 32 && code <= 126) hasSpecial = true;
    else hasUnicode = true;
  }
  let pool = 0;
  if (hasLower) pool += 26;
  if (hasUpper) pool += 26;
  if (hasDigit) pool += 10;
  if (hasSpecial) pool += 33;
  if (hasUnicode) pool += 64;
  const bits = pool > 1 ? [...password].length * Math.log2(pool) : 0;
  const strength = bits < 28 ? 0 : bits < 45 ? 1 : bits < 65 ? 2 : bits < 95 ? 3 : 4;
  return { entropyBits: Math.round(bits * 10) / 10, strength };
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KiB', 'MiB', 'GiB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`;
}

export function formatDateTime(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  const pad = n => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function toLocalDateTimeInput(iso) {
  if (!iso) return '';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  const pad = n => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function parseTagsInput(text = '') {
  return text
    .split(/[,;，；\n]+/)
    .map(tag => tag.trim())
    .filter(Boolean);
}

export function escapeHtml(value = '') {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
