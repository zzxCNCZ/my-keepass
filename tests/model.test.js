import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildGroupTree,
  collectDescendantGroupIds,
  escapeHtml,
  estimatePasswordStrength,
  filterAndSortEntries,
  flattenGroupOptions,
  formatBytes,
  matchesEntryQuery,
  parseTagsInput,
} from '../src/model.js';

const sampleGroups = [
  { id: 'root', parentId: null, name: 'Vault', childGroupIds: ['g1', 'g2', 'bin'], isRoot: true, isRecycleBin: false },
  { id: 'g1', parentId: 'root', name: 'Internet', childGroupIds: ['g1a'], isRoot: false, isRecycleBin: false },
  { id: 'g1a', parentId: 'g1', name: 'Dev', childGroupIds: [], isRoot: false, isRecycleBin: false },
  { id: 'g2', parentId: 'root', name: 'Hidden', childGroupIds: [], isRoot: false, isRecycleBin: false, enableSearching: false },
  { id: 'bin', parentId: 'root', name: 'Recycle Bin', childGroupIds: [], isRoot: false, isRecycleBin: true },
];

const sampleEntries = [
  {
    id: 'e1',
    groupId: 'g1a',
    groupPath: 'Internet / Dev',
    inRecycleBin: false,
    title: 'GitHub',
    username: 'alice',
    url: 'https://github.com',
    notes: 'Main repo',
    tags: ['dev', 'git'],
    customFields: [{ key: 'Org', value: 'Acme', protected: false }, { key: 'Secret', value: 'hidden-token', protected: true }],
    modifiedAt: '2026-10-01T10:00:00Z',
  },
  {
    id: 'e2',
    groupId: 'g2',
    groupPath: 'Hidden',
    inRecycleBin: false,
    title: 'Secret GitHub',
    username: 'bob',
    url: 'https://github.com',
    notes: '',
    tags: [],
    customFields: [],
    modifiedAt: '2026-10-02T10:00:00Z',
  },
  {
    id: 'e3',
    groupId: 'bin',
    groupPath: 'Recycle Bin',
    inRecycleBin: true,
    title: 'Deleted GitHub',
    username: 'old',
    url: '',
    notes: '',
    tags: [],
    customFields: [],
    modifiedAt: '2026-09-01T10:00:00Z',
  },
];

test('builds hierarchical group tree and collects descendants', () => {
  const tree = buildGroupTree(sampleGroups, 'root');
  assert.equal(tree.name, 'Vault');
  assert.equal(tree.children.length, 3);
  assert.equal(tree.children[0].children[0].name, 'Dev');

  const descendants = collectDescendantGroupIds(sampleGroups, 'g1');
  assert.deepEqual([...descendants].sort(), ['g1', 'g1a']);

  const options = flattenGroupOptions(sampleGroups, 'root', descendants);
  assert.equal(options.some(o => o.id === 'g1' || o.id === 'g1a'), false);
  assert.equal(options.some(o => o.id === 'root'), true);
});

test('filters entries by group or search query while excluding recycle bin, unsearchable groups, and protected custom fields', () => {
  assert.equal(matchesEntryQuery(sampleEntries[0], 'github acme'), true);
  assert.equal(matchesEntryQuery(sampleEntries[0], 'hidden-token'), false);

  const searchResults = filterAndSortEntries(sampleEntries, {
    groupId: 'g1',
    query: 'github',
    groups: sampleGroups,
  });
  assert.deepEqual(searchResults.map(e => e.id), ['e1']);

  const groupResults = filterAndSortEntries(sampleEntries, {
    groupId: 'g1a',
    query: '',
    groups: sampleGroups,
  });
  assert.deepEqual(groupResults.map(e => e.id), ['e1']);
});

test('estimates password strength, parses tags, formats bytes, and escapes HTML', () => {
  assert.equal(estimatePasswordStrength('').strength, 0);
  assert.equal(estimatePasswordStrength('1234').strength, 0);
  assert.equal(estimatePasswordStrength('Correct-Horse-99!Battery').strength, 4);

  assert.deepEqual(parseTagsInput('dev, work；2fa, '), ['dev', 'work', '2fa']);
  assert.equal(formatBytes(512), '512 B');
  assert.equal(formatBytes(2048), '2.00 KiB');
  assert.equal(escapeHtml('<script>"a&b"</script>'), '&lt;script&gt;&quot;a&amp;b&quot;&lt;/script&gt;');
});
