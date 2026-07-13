#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const FIGURE_INDEX_ROUTE = '/appendices/figure-index/';
const FIGURE_INDEX_ID = 'appendix-figure-index';
const FIGURE_INDEX_TITLE = '付録：図表索引';
const FIGURE_INDEX_SOURCE = 'src/appendices/figure-index/index.md';
const FIGURE_INDEX_DOCS = 'docs/appendices/figure-index/index.md';

const FIGURES = [
  {
    title: '書籍構造マインドマップ', section: 'はじめに', purpose: '本書全体の章立てと、基礎から応用へ進む構成を把握する。', focus: '4部構成と各章の位置付け。',
    source: 'src/introduction/index.md', docs: 'docs/introduction/index.md', anchor: 'figure-book-structure-mindmap', asset: 'assets/images/diagrams/introduction/book-structure-mindmap.svg',
  },
  {
    title: '学習ロードマップ', section: 'はじめに', purpose: '読者の前提知識に応じた学習順序を確認する。', focus: '基礎概念、標準、実装、応用へ進む段階。',
    source: 'src/introduction/index.md', docs: 'docs/introduction/index.md', anchor: 'figure-learning-roadmap', asset: 'assets/images/diagrams/introduction/learning-roadmap.svg',
  },
  {
    title: '認証認可が解決する根本的な問題', section: '第1章 1.1.2', purpose: '認証・認可が扱う問題領域を整理する。', focus: 'アイデンティティ、権限、責任追跡、利便性の関係。',
    source: 'src/chapters/chapter-01-overview.md', docs: 'docs/chapters/chapter-01-overview/index.md', anchor: 'figure-auth-fundamental-problems', asset: 'assets/images/diagrams/chapter01/auth-fundamental-problems.svg',
  },
  {
    title: '認証と認可のシーケンス図', section: '第1章 1.2.1', purpose: '認証と認可の処理順序を区別する。', focus: '本人確認後に権限判定を行う流れ。',
    source: 'src/chapters/chapter-01-overview.md', docs: 'docs/chapters/chapter-01-overview/index.md', anchor: 'figure-auth-authz-sequence', asset: 'assets/images/diagrams/chapter01/auth-authz-sequence.svg',
  },
  {
    title: '認証技術の歴史的進化', section: '第1章 1.3.1', purpose: '認証技術の発展と現在の設計判断の背景を把握する。', focus: 'パスワードから多要素認証、パスワードレスへの変化。',
    source: 'src/chapters/chapter-01-overview.md', docs: 'docs/chapters/chapter-01-overview/index.md', anchor: 'figure-authentication-evolution-timeline', asset: 'assets/images/diagrams/chapter01/authentication-evolution-timeline.svg',
  },
  {
    title: '認可モデルの進化', section: '第1章 1.3.2', purpose: '代表的な認可モデルの適用範囲を比較する。', focus: 'ACL、RBAC、ABAC、PBAC の特徴と使い分け。',
    source: 'src/chapters/chapter-01-overview.md', docs: 'docs/chapters/chapter-01-overview/index.md', anchor: 'figure-authorization-model-evolution', asset: 'assets/images/diagrams/chapter01/authorization-model-evolution.svg',
  },
  {
    title: '技術選択フレームワーク', section: '第1章 1.3.4', purpose: '認証・認可技術を要件に基づいて選択する観点を整理する。', focus: 'セキュリティ、UX、コスト、拡張性の評価軸。',
    source: 'src/chapters/chapter-01-overview.md', docs: 'docs/chapters/chapter-01-overview/index.md', anchor: 'figure-technology-selection-framework', asset: 'assets/images/diagrams/chapter01/technology-selection-framework.svg',
  },
];

function read(root, relative, errors) {
  try {
    return fs.readFileSync(path.join(root, relative), 'utf8');
  } catch (error) {
    errors.push(`${relative}: 読み込めません: ${error.message}`);
    return '';
  }
}

function exists(root, relative) {
  try {
    const stat = fs.statSync(path.join(root, relative));
    return stat.isFile() && stat.size > 0;
  } catch {
    return false;
  }
}

function figureMarkup(figure) {
  return `<figure id="${figure.anchor}">\n  <img src="{{ site.baseurl }}/${figure.asset}" alt="${figure.title}">\n</figure>`;
}

function parsedFigures(content) {
  return [...content.matchAll(/<figure\s+id="([^"]+)">\s*<img\s+src="([^"]+)"\s+alt="([^"]+)">\s*<\/figure>/g)]
    .map((match) => ({ anchor: match[1], src: match[2], title: match[3] }));
}

function stripFrontMatter(content) {
  return content.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n?/, '');
}

function normalizedMarkdownBody(content) {
  return stripFrontMatter(content)
    .replace(/^(?:\r?\n)+/, '')
    .replace(/\r\n/g, '\n');
}

function parseNavigation(content) {
  const unquote = (value) => value.trim().replace(/^(['"])(.*)\1$/, '$2');
  return [...content.matchAll(/^\s*-\s*title:\s*(.+?)\s*\r?\n\s+path:\s*(.+?)\s*$/gm)]
    .map((match) => ({ title: unquote(match[1]), path: unquote(match[2]) }));
}

function validate(root = process.cwd()) {
  const errors = [];
  let config = {};
  const configText = read(root, 'book-config.json', errors);
  try {
    config = JSON.parse(configText);
  } catch (error) {
    errors.push(`book-config.json: JSONを解析できません: ${error.message}`);
  }

  if (config.ux?.modules?.figureIndex !== true) {
    errors.push('book-config.json: ux.modules.figureIndex は true である必要があります');
  }
  const configuredAppendices = config.structure?.appendices || [];
  const configured = configuredAppendices.filter((item) => item?.id === FIGURE_INDEX_ID || item?.path === FIGURE_INDEX_ROUTE);
  if (configured.length !== 1 || configured[0]?.id !== FIGURE_INDEX_ID || configured[0]?.path !== FIGURE_INDEX_ROUTE || configured[0]?.title !== FIGURE_INDEX_TITLE) {
    errors.push(`book-config.json: ${FIGURE_INDEX_ID} の付録 route/title 定義が正しくありません`);
  }
  const configuredE13 = configuredAppendices.findIndex((item) => item?.id === 'appendix-e-13');
  const configuredFigureIndex = configuredAppendices.findIndex((item) => item?.id === FIGURE_INDEX_ID);
  if (configuredE13 < 0 || configuredFigureIndex !== configuredE13 + 1) {
    errors.push('book-config.json: 図表索引は付録E-13の直後に配置してください');
  }

  const navigation = parseNavigation(read(root, 'docs/_data/navigation.yml', errors));
  const navEntries = navigation.filter((item) => item.path === FIGURE_INDEX_ROUTE || item.title === FIGURE_INDEX_TITLE);
  if (navEntries.length !== 1 || navEntries[0].path !== FIGURE_INDEX_ROUTE || navEntries[0].title !== FIGURE_INDEX_TITLE) {
    errors.push('docs/_data/navigation.yml: 図表索引の navigation 定義が正しくありません');
  }
  const navE13 = navigation.findIndex((item) => (
    item.path === '/appendices/appendix-e-13/' || item.path === '/appendices/appendix-e-13.html'
  ));
  const navFigureIndex = navigation.findIndex((item) => item.path === FIGURE_INDEX_ROUTE);
  if (navE13 < 0 || navFigureIndex !== navE13 + 1) {
    errors.push('docs/_data/navigation.yml: 図表索引は付録E-13の直後に配置してください');
  }

  const topPage = read(root, 'docs/index.md', errors);
  if (!topPage.includes(`[${FIGURE_INDEX_TITLE}]({{ site.baseurl }}${FIGURE_INDEX_ROUTE})`)) {
    errors.push('docs/index.md: 図表索引への top page リンクがありません');
  }
  const topE = topPage.indexOf('[付録E（E-1〜E-13）');
  const topFigureIndex = topPage.indexOf(`[${FIGURE_INDEX_TITLE}]({{ site.baseurl }}${FIGURE_INDEX_ROUTE})`);
  if (topE < 0 || topFigureIndex < topE) {
    errors.push('docs/index.md: 図表索引は付録Eの後に配置してください');
  }
  const sidebar = read(root, 'docs/_includes/sidebar-nav.html', errors);
  if (!sidebar.includes('navigation.appendices')) errors.push('docs/_includes/sidebar-nav.html: appendices navigation を描画しません');
  for (const navigationInclude of ['templates/includes/page-navigation.html', 'docs/_includes/page-navigation.html']) {
    const pageNavigation = read(root, navigationInclude, errors);
    if (!pageNavigation.includes('concat: navigation.appendices') || !pageNavigation.includes('rel="prev"') || !pageNavigation.includes('rel="next"')) {
      errors.push(`${navigationInclude}: appendices の previous/next navigation を描画しません`);
    }
  }

  if (!exists(root, FIGURE_INDEX_SOURCE)) errors.push(`${FIGURE_INDEX_SOURCE}: source page がありません`);
  if (!exists(root, FIGURE_INDEX_DOCS)) errors.push(`${FIGURE_INDEX_DOCS}: published route page がありません`);
  const sourceIndex = read(root, FIGURE_INDEX_SOURCE, errors);
  const docsIndex = read(root, FIGURE_INDEX_DOCS, errors);
  if (normalizedMarkdownBody(docsIndex) !== normalizedMarkdownBody(sourceIndex)) errors.push('src/docs: 図表索引本文が同期していません');
  if (docsIndex.includes('.svg')) errors.push(`${FIGURE_INDEX_DOCS}: 図表索引は本文図への deep link だけを掲載し、diagram asset を直接列挙してはいけません`);

  const expectedByFile = new Map();
  for (const figure of FIGURES) {
    for (const file of [figure.source, figure.docs]) {
      if (!expectedByFile.has(file)) expectedByFile.set(file, []);
      expectedByFile.get(file).push(figure);
    }
    // The docs source path is flat while its reader route is directory-shaped.
    const route = figure.docs === 'docs/introduction/index.md'
      ? '/introduction/'
      : '/chapters/chapter-01-overview/';
    const indexEntry = `[${figure.title}]({{ site.baseurl }}${route}#${figure.anchor})`;
    for (const required of [indexEntry, `掲載章: ${figure.section}`, `目的: ${figure.purpose}`, `見るべき点: ${figure.focus}`]) {
      if (!sourceIndex.includes(required)) errors.push(`${FIGURE_INDEX_SOURCE}: ${figure.title} の索引情報が不足しています: ${required}`);
      if (!docsIndex.includes(required)) errors.push(`${FIGURE_INDEX_DOCS}: ${figure.title} の索引情報が不足しています: ${required}`);
    }
    if (!exists(root, `docs/${figure.asset}`)) errors.push(`docs/${figure.asset}: ${figure.title} の公開 SVG asset がありません`);
  }

  for (const [file, expected] of expectedByFile) {
    const content = read(root, file, errors);
    const actual = parsedFigures(content);
    const expectedActual = expected.map((figure) => ({
      anchor: figure.anchor,
      src: `{{ site.baseurl }}/${figure.asset}`,
      title: figure.title,
    }));
    if (JSON.stringify(actual) !== JSON.stringify(expectedActual)) {
      errors.push(`${file}: SVG figure inventory/anchor/asset は expected ${expected.length} 件と完全一致する必要があります`);
    }
    for (const figure of expected) {
      if (!content.includes(figureMarkup(figure))) errors.push(`${file}: ${figure.title} の stable anchor と public asset markup がありません`);
    }
  }

  return errors;
}

if (require.main === module) {
  const errors = validate(process.cwd());
  if (errors.length) {
    console.error('Figure index consistency check failed:');
    for (const error of errors) console.error(`- ${error}`);
    process.exit(1);
  }
  console.log(`Figure index consistency check passed: ${FIGURES.length} published SVG figures, one reader-facing index route.`);
}

module.exports = { FIGURES, validate };
