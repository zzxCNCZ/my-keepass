import { english } from './translations.js';

let language = 'zh-CN';
let chrome = [];
const attributes = ['aria-label', 'placeholder', 'title'];

export function resolveLanguage(setting, system = 'zh-CN') {
  if (setting === 'system') return system.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en';
  return setting === 'en' ? 'en' : 'zh-CN';
}

export function currentLanguage() {
  return language;
}

export function t(label) {
  if (language !== 'en' || typeof label !== 'string') return label;
  const trimmed = label.trim();
  const direct = english[trimmed];
  if (typeof direct === 'string') return label.replace(trimmed, direct);
  return label;
}

function bindings(root) {
  const result = [];
  for (const element of root.querySelectorAll('*')) {
    if (element.matches('script, style') || element.closest('script, style')) continue;
    for (const key of attributes) {
      const value = element.getAttribute(key);
      if (value && Object.hasOwn(english, value.trim())) {
        result.push(() => element.setAttribute(key, t(value)));
      }
    }
    for (const node of element.childNodes) {
      if (node.nodeType === 3 && Object.hasOwn(english, node.textContent.trim())) {
        const value = node.textContent;
        result.push(() => { node.textContent = t(value); });
      }
    }
  }
  return result;
}

export function localize(root) {
  for (const translate of bindings(root)) translate();
}

export function changeLanguage(setting) {
  language = resolveLanguage(setting, typeof navigator !== 'undefined' ? navigator.language : 'zh-CN');
  if (typeof document !== 'undefined') {
    document.documentElement.lang = language;
    if (!chrome.length && document.body) chrome = bindings(document.body);
    for (const translate of chrome) translate();
  }
}
