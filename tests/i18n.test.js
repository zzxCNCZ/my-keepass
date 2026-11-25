import assert from 'node:assert/strict';
import test from 'node:test';
import { changeLanguage, resolveLanguage, t } from '../src/i18n.js';

test('resolves language settings and translates UI strings', () => {
  assert.equal(resolveLanguage('zh-CN', 'en-US'), 'zh-CN');
  assert.equal(resolveLanguage('en', 'zh-CN'), 'en');
  assert.equal(resolveLanguage('system', 'zh-Hans-CN'), 'zh-CN');
  assert.equal(resolveLanguage('system', 'en-US'), 'en');

  changeLanguage('en');
  assert.equal(t('打开数据库'), 'Open Database');
  assert.equal(t('检查更新'), 'Check for Updates');

  changeLanguage('zh-CN');
  assert.equal(t('打开数据库'), '打开数据库');
});
