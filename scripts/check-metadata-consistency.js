#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = process.cwd();
const EXPECTED = {
  repoUrl: 'https://github.com/itdojp/practical-auth-book',
  repoGitUrl: 'https://github.com/itdojp/practical-auth-book.git',
  packageRepoUrl: 'git+https://github.com/itdojp/practical-auth-book.git',
  issuesUrl: 'https://github.com/itdojp/practical-auth-book/issues',
  homepage: 'https://itdojp.github.io/practical-auth-book/',
  pagesOrigin: 'https://itdojp.github.io',
  baseurl: '/practical-auth-book',
};

const errors = [];

function fail(file, message) {
  errors.push(`${file}: ${message}`);
}

function readText(file) {
  try {
    return fs.readFileSync(path.join(ROOT, file), 'utf8');
  } catch (error) {
    fail(file, `ファイルを読めません: ${error.message}`);
    return '';
  }
}

function readJson(file) {
  const text = readText(file);
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch (error) {
    fail(file, `JSONを解析できません: ${error.message}`);
    return null;
  }
}

function unquote(value) {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function parseTopLevelYaml(file) {
  const result = {};
  const text = readText(file);
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+#.*$/, '');
    if (!line.trim() || /^\s/.test(line) || line.trim().startsWith('#')) continue;
    const match = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (!match) continue;
    result[match[1]] = unquote(match[2]);
  }
  return result;
}

function parseFrontMatter(file) {
  const text = readText(file);
  if (!text.startsWith('---\n')) {
    fail(file, 'YAML front matter がありません');
    return {};
  }
  const end = text.indexOf('\n---', 4);
  if (end === -1) {
    fail(file, 'YAML front matter の終了マーカーがありません');
    return {};
  }
  const front = text.slice(4, end);
  const result = {};
  for (const rawLine of front.split(/\r?\n/)) {
    if (!rawLine.trim() || rawLine.trim().startsWith('#')) continue;
    const match = rawLine.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (match) result[match[1]] = unquote(match[2]);
  }
  return result;
}

function parseNavigation(file) {
  const text = readText(file);
  const sections = {};
  let currentSection = null;
  let currentItem = null;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+#.*$/, '');
    if (!line.trim()) continue;

    const sectionMatch = line.match(/^([A-Za-z0-9_-]+):\s*$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1];
      sections[currentSection] = sections[currentSection] || [];
      currentItem = null;
      continue;
    }

    const itemTitle = line.match(/^\s*-\s*title:\s*(.+)$/);
    if (itemTitle && currentSection) {
      currentItem = { title: unquote(itemTitle[1]) };
      sections[currentSection].push(currentItem);
      continue;
    }

    const itemPath = line.match(/^\s*path:\s*(.+)$/);
    if (itemPath && currentSection && currentItem) {
      currentItem.path = unquote(itemPath[1]);
    }
  }

  return sections;
}

function expectEqual(file, field, actual, expected) {
  if (actual !== expected) {
    fail(file, `${field} は ${JSON.stringify(expected)} にしてください（現在: ${JSON.stringify(actual)}）`);
  }
}

function ensureSafeRoute(file, route, context) {
  if (typeof route !== 'string') {
    fail(file, `${context} の path は文字列である必要があります`);
    return;
  }
  if (!route.startsWith('/')) fail(file, `${context} の path は / から始めてください: ${route}`);
  if (!route.endsWith('/')) fail(file, `${context} の path は / で終えてください: ${route}`);
  if (route.includes('..')) fail(file, `${context} の path に .. を含めないでください: ${route}`);
  if (route.includes('//')) fail(file, `${context} の path に // を含めないでください: ${route}`);
  if (/[?#%\\]/.test(route)) fail(file, `${context} の path にクエリ・フラグメント・エンコード・逆スラッシュを含めないでください: ${route}`);
}

function routeCandidates(route) {
  if (route === '/') return ['docs/index.md'];
  const rel = route.replace(/^\//, '').replace(/\/$/, '');
  return [`docs/${rel}/index.md`, `docs/${rel}.md`];
}

function routeExists(route) {
  return routeCandidates(route).some(candidate => fs.existsSync(path.join(ROOT, candidate)));
}

function checkRouteSource(route, sourceFile, context) {
  if (typeof route !== 'string') {
    return;
  }
  if (!routeExists(route)) {
    fail(sourceFile, `${context} の path に対応する docs ソースがありません: ${route}（候補: ${routeCandidates(route).join(', ')}）`);
  }
}

function collectStructureRoutes(bookConfig) {
  const routes = [];
  const structure = bookConfig && bookConfig.structure;
  if (!structure || typeof structure !== 'object') {
    fail('book-config.json', 'structure がありません');
    return routes;
  }

  for (const section of ['introduction', 'chapters', 'appendices']) {
    const items = structure[section];
    if (!Array.isArray(items) || items.length === 0) {
      fail('book-config.json', `structure.${section} は1件以上の配列にしてください`);
      continue;
    }
    for (const [index, item] of items.entries()) {
      const context = `structure.${section}[${index}]`;
      for (const required of ['id', 'title', 'path', 'description']) {
        if (!item || typeof item[required] !== 'string' || !item[required].trim()) {
          fail('book-config.json', `${context}.${required} を設定してください`);
        }
      }
      ensureSafeRoute('book-config.json', item && item.path, context);
      checkRouteSource(item && item.path, 'book-config.json', context);
      routes.push(item && item.path);
    }
  }
  return routes;
}

function arraySet(values) {
  return new Set(values.filter(Boolean));
}

function compareRouteSets(file, labelA, routesA, labelB, routesB) {
  const a = arraySet(routesA);
  const b = arraySet(routesB);
  for (const route of a) {
    if (!b.has(route)) fail(file, `${labelA} にある ${route} が ${labelB} にありません`);
  }
  for (const route of b) {
    if (!a.has(route)) fail(file, `${labelB} にある ${route} が ${labelA} にありません`);
  }
}

function checkUnique(file, values, label) {
  const seen = new Set();
  for (const value of values) {
    if (seen.has(value)) fail(file, `${label} が重複しています: ${value}`);
    seen.add(value);
  }
}

const bookConfig = readJson('book-config.json') || {};
for (const field of ['title', 'description', 'author', 'version', 'license']) {
  if (!bookConfig[field]) fail('book-config.json', `${field} を設定してください`);
}
expectEqual('book-config.json', 'homepage', bookConfig.homepage, EXPECTED.homepage);
expectEqual('book-config.json', 'repository.url', bookConfig.repository && bookConfig.repository.url, EXPECTED.repoGitUrl);
expectEqual('book-config.json', 'repository.branch', bookConfig.repository && bookConfig.repository.branch, 'main');

for (const file of ['package.json', 'package-simple.json']) {
  const pkg = readJson(file) || {};
  expectEqual(file, 'name', pkg.name, 'practical-auth-book');
  expectEqual(file, 'version', pkg.version, bookConfig.version);
  expectEqual(file, 'description', pkg.description, bookConfig.description);
  expectEqual(file, 'author', pkg.author, bookConfig.author);
  expectEqual(file, 'license', pkg.license, bookConfig.license);
  expectEqual(file, 'repository.url', pkg.repository && pkg.repository.url, EXPECTED.packageRepoUrl);
  expectEqual(file, 'bugs.url', pkg.bugs && pkg.bugs.url, EXPECTED.issuesUrl);
  expectEqual(file, 'homepage', pkg.homepage, EXPECTED.homepage);
  if (pkg.dependencies && Object.prototype.hasOwnProperty.call(pkg.dependencies, 'gray-matter')) {
    fail(file, '未使用かつ脆弱な transitive dependency を含む gray-matter は dependencies から除外してください');
  }
}

const lock = readJson('package-lock.json') || {};
expectEqual('package-lock.json', 'name', lock.name, 'practical-auth-book');
expectEqual('package-lock.json', 'version', lock.version, bookConfig.version);
const lockRoot = lock.packages && lock.packages[''];
if (!lockRoot) {
  fail('package-lock.json', 'packages[""] がありません');
} else {
  expectEqual('package-lock.json', 'packages[""].name', lockRoot.name, 'practical-auth-book');
  expectEqual('package-lock.json', 'packages[""].version', lockRoot.version, bookConfig.version);
  expectEqual('package-lock.json', 'packages[""].license', lockRoot.license, bookConfig.license);
  if (lockRoot.dependencies && Object.prototype.hasOwnProperty.call(lockRoot.dependencies, 'gray-matter')) {
    fail('package-lock.json', 'packages[""].dependencies に gray-matter を残さないでください');
  }
}

for (const file of ['_config.yml', 'docs/_config.yml']) {
  const config = parseTopLevelYaml(file);
  expectEqual(file, 'title', config.title, bookConfig.title);
  expectEqual(file, 'description', config.description, bookConfig.description);
  expectEqual(file, 'author', config.author, bookConfig.author);
  expectEqual(file, 'version', config.version, bookConfig.version);
  expectEqual(file, 'license', config.license, bookConfig.license);
  expectEqual(file, 'lang', config.lang, bookConfig.language || 'ja');
  expectEqual(file, 'url', config.url, EXPECTED.pagesOrigin);
  expectEqual(file, 'baseurl', config.baseurl, EXPECTED.baseurl);
  expectEqual(file, 'repository', config.repository, EXPECTED.repoUrl);
  expectEqual(file, 'homepage', config.homepage, EXPECTED.homepage);
}

const indexFront = parseFrontMatter('docs/index.md');
expectEqual('docs/index.md', 'title', indexFront.title, bookConfig.title);
expectEqual('docs/index.md', 'description', indexFront.description, bookConfig.description);
expectEqual('docs/index.md', 'author', indexFront.author, bookConfig.author);
expectEqual('docs/index.md', 'version', indexFront.version, bookConfig.version);
expectEqual('docs/index.md', 'permalink', indexFront.permalink, '/');

const structureRoutes = collectStructureRoutes(bookConfig);
checkUnique('book-config.json', structureRoutes, 'structure path');

const navigation = parseNavigation('docs/_data/navigation.yml');
const navRoutes = [];
for (const section of ['introduction', 'chapters', 'appendices']) {
  const items = navigation[section];
  if (!Array.isArray(items) || items.length === 0) {
    fail('docs/_data/navigation.yml', `${section} セクションがありません`);
    continue;
  }
  for (const [index, item] of items.entries()) {
    const context = `${section}[${index}]`;
    if (!item.title) fail('docs/_data/navigation.yml', `${context}.title を設定してください`);
    ensureSafeRoute('docs/_data/navigation.yml', item.path, context);
    checkRouteSource(item.path, 'docs/_data/navigation.yml', context);
    navRoutes.push(item.path);
  }
}
checkUnique('docs/_data/navigation.yml', navRoutes, 'navigation path');
compareRouteSets('docs/_data/navigation.yml', 'book-config.json structure', structureRoutes, 'docs/_data/navigation.yml', navRoutes);

const currentDocsRoutes = [];
for (const section of ['introduction', 'chapters', 'appendices']) {
  const dir = path.join(ROOT, 'docs', section);
  if (!fs.existsSync(dir)) continue;
  if (fs.existsSync(path.join(dir, 'index.md'))) {
    currentDocsRoutes.push(`/${section}/`);
  }
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory() && fs.existsSync(path.join(dir, entry.name, 'index.md'))) {
      currentDocsRoutes.push(`/${section}/${entry.name}/`);
    }
  }
}
compareRouteSets('book-config.json', 'book-config.json structure', structureRoutes, 'published docs route directories', currentDocsRoutes);

const requiredAssets = [
  'docs/assets/css/main.css',
  'docs/assets/css/syntax-highlighting.css',
  'docs/assets/js/theme.js',
  'docs/assets/js/sidebar.js',
  'docs/assets/js/search.js',
  'docs/assets/js/code-copy-lightweight.js',
  'docs/_layouts/book.html',
  'docs/_includes/page-navigation.html',
  'docs/_includes/sidebar-nav.html',
];
for (const asset of requiredAssets) {
  const full = path.join(ROOT, asset);
  if (!fs.existsSync(full) || fs.statSync(full).size === 0) {
    fail(asset, '公開サイトに必要なアセットまたはレイアウトがありません');
  }
}

const packageJsonText = readText('package.json');
if (!packageJsonText.includes('"check:metadata"')) {
  fail('package.json', 'check:metadata スクリプトを設定してください');
}

if (errors.length) {
  console.error('Metadata consistency check failed:');
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Metadata consistency check passed: ${structureRoutes.length} routes, ${requiredAssets.length} required assets.`);
