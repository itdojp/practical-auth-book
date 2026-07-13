#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { FIGURES, validate } = require('./check-figure-index');

const root = path.resolve('temp/check-figure-index-fixture');
const files = [
  'book-config.json',
  'docs/_data/navigation.yml',
  'docs/index.md',
  'docs/_includes/sidebar-nav.html',
  'docs/_includes/page-navigation.html',
  'templates/includes/page-navigation.html',
  'src/appendices/figure-index/index.md',
  'docs/appendices/figure-index/index.md',
  ...new Set(FIGURES.flatMap((figure) => [figure.source, figure.docs, `docs/${figure.asset}`])),
];

function copy(relative) {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(relative, target);
}

try {
  fs.rmSync(root, { recursive: true, force: true });
  files.forEach(copy);
  assert.deepEqual(validate(root), [], 'complete figure-index fixture must pass');

  const configPath = path.join(root, 'book-config.json');
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  config.ux.modules.figureIndex = false;
  fs.writeFileSync(configPath, JSON.stringify(config));
  assert.ok(validate(root).some((error) => error.includes('figureIndex は true')), 'disabled flag must fail closed');

  config.ux.modules.figureIndex = true;
  fs.writeFileSync(configPath, JSON.stringify(config));
  fs.rmSync(path.join(root, `docs/${FIGURES[0].asset}`));
  assert.ok(validate(root).some((error) => error.includes('公開 SVG asset がありません')), 'missing public SVG asset must fail closed');

  copy(`docs/${FIGURES[0].asset}`);
  const topPath = path.join(root, 'docs/index.md');
  const top = fs.readFileSync(topPath, 'utf8');
  const figureLine = `- [付録：図表索引]({{ site.baseurl }}/appendices/figure-index/)\n`;
  fs.writeFileSync(topPath, figureLine + top.replace(figureLine, ''));
  assert.ok(validate(root).some((error) => error.includes('図表索引は付録Eの後')), 'top-page order drift must fail closed');

  console.log('Figure index fixtures passed.');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
