#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const TARGETS = [
  'src/appendices/appendix-e-05.md',
  'docs/appendices/appendix-e-05.md',
  'docs/appendices/appendix-e-05/index.md',
];

const REQUIRED_EXPLANATIONS = [
  ['X-Frame-Options', /`X-Frame-Options`/],
  ['X-Content-Type-Options', /`X-Content-Type-Options`/],
  ['server response-header responsibility', /サーバーが各HTTPレスポンスに付けるレスポンスヘッダー/],
  ['initial document CSP response header', /初回のHTML document responseの `Content-Security-Policy` レスポンスヘッダー/],
  ['static meta early parse constraint', /静的な `<meta http-equiv="Content-Security-Policy" \.\.\.>`.*可能な限り早い位置.*初期parse時/],
  ['meta policy is not retroactive', /metaより前に読み込まれたresourceには遡及して適用されず/],
  ['post-parse meta mutation is ignored', /parse後にJavaScriptでmetaの `content` を変更しても適用されません/],
  ['frame-ancestors is ignored in meta', /`frame-ancestors` はmetaで配信したCSPでは無視される/],
  ['server-generated nonce per response', /nonceはサーバーがレスポンスごとに暗号学的に安全な乱数から一意に生成/],
  ['client nonce generation is invalid', /client JavaScriptがnonceを生成して、実行後にCSP metaを追加/],
];

const REQUEST_SECURITY_HEADERS = [
  ['X-Frame-Options', 'request-side X-Frame-Options'],
  ['X-Content-Type-Options', 'request-side X-Content-Type-Options'],
];

const CSP_META_MARKUP = /<meta\b(?=[^>]*\bhttp-equiv\s*=\s*(?:\\?['"])?Content-Security-Policy\b)[^>]*>/i;
const HTML_INJECTION_SINK = /\.insertAdjacentHTML\s*\(|\.(?:innerHTML|outerHTML)\s*(?:\+?=)/i;
const META_ELEMENT_CREATION = /document\.createElement\s*\(\s*(?:['"]meta['"]|`meta`)\s*\)/i;
const CSP_HTTP_EQUIV_ASSIGNMENT = /\.httpEquiv\s*=\s*(?:['"]Content-Security-Policy['"]|`Content-Security-Policy`)|\.setAttribute\s*\(\s*(?:['"]http-equiv['"]|`http-equiv`)\s*,\s*(?:['"]Content-Security-Policy['"]|`Content-Security-Policy`)/i;
const NODE_INJECTION_SINK = /\.(?:appendChild|append|prepend|insertBefore|insertAdjacentElement|replaceChild|replaceChildren)\s*\(/i;
const CLIENT_NONCE_GENERATION = /\b[\w.]*nonce\w*\s*=|\bgenerateNonce\s*\(|crypto\.(?:getRandomValues|randomUUID)\s*\(/i;

function read(root, relativePath) {
  try {
    return fs.readFileSync(path.join(root, relativePath), 'utf8');
  } catch (error) {
    return { error: `${relativePath}: ファイルを読めません: ${error.message}` };
  }
}

function removeFrontMatter(text) {
  return text.replace(/^---\r?\n[\s\S]*?\r?\n---(?:\r?\n)?/, '');
}

function canonicalBody(text) {
  return removeFrontMatter(text)
    .replace(/\r\n/g, '\n')
    .replace(/^(?:[ \t]*\n)+/, '')
    .replace(/^# .*\n/, '')
    .replace(/^(?:[ \t]*\n)+/, '')
    .trimEnd();
}

function codeBlocks(markdown) {
  return [...markdown.matchAll(/^```([^\r\n]*)\r?\n([\s\S]*?)^```\s*$/gm)].map((match) => ({
    language: match[1].trim().toLowerCase(),
    code: match[2],
  }));
}

function isJavaScript(block) {
  return ['js', 'javascript'].includes(block.language);
}

function requestHeaderPattern(headerName) {
  const literalName = `(?:['"]${headerName}['"]|\`${headerName}\`)`;
  return new RegExp([
    `${literalName}\\s*:`,
    `\\[\\s*${literalName}\\s*\\]\\s*:`,
    `\\.(?:set|append)\\s*\\(\\s*${literalName}`,
    `new\\s+Headers\\s*\\(\\s*\\[[\\s\\S]*?\\[\\s*${literalName}\\s*,`,
    `\\bheaders\\s*\\[\\s*${literalName}\\s*\\]\\s*=(?!=)`,
  ].join('|'), 'i');
}

function hasDynamicCspMetaInjection(code) {
  const injectsMarkup = CSP_META_MARKUP.test(code) && HTML_INJECTION_SINK.test(code);
  const injectsElement = META_ELEMENT_CREATION.test(code) &&
    CSP_HTTP_EQUIV_ASSIGNMENT.test(code) &&
    NODE_INJECTION_SINK.test(code);
  return injectsMarkup || injectsElement;
}

function validate(root) {
  const errors = [];
  const contents = new Map();

  for (const relativePath of TARGETS) {
    const value = read(root, relativePath);
    if (typeof value === 'object') {
      errors.push(value.error);
      continue;
    }
    contents.set(relativePath, value);
  }

  const source = contents.get(TARGETS[0]);
  const flatDocs = contents.get(TARGETS[1]);
  const routeDocs = contents.get(TARGETS[2]);
  if (!source || !flatDocs || !routeDocs) return errors;

  if (canonicalBody(source) !== canonicalBody(flatDocs)) {
    errors.push('src/appendices/appendix-e-05.md と docs/appendices/appendix-e-05.md の本文が同期していません');
  }
  if (flatDocs !== routeDocs) {
    errors.push('docs/appendices/appendix-e-05.md と docs/appendices/appendix-e-05/index.md が同期していません');
  }

  for (const [description, pattern] of REQUIRED_EXPLANATIONS) {
    if (!pattern.test(source)) errors.push(`Appendix E-05の${description}の説明がありません`);
  }

  for (const relativePath of TARGETS) {
    const blocks = codeBlocks(contents.get(relativePath));
    for (const [blockIndex, block] of blocks.entries()) {
      if (!isJavaScript(block)) continue;

      if (/\bclass\s+SecureTokenStorage\b/.test(block.code)) {
        for (const [headerName, description] of REQUEST_SECURITY_HEADERS) {
          if (requestHeaderPattern(headerName).test(block.code)) {
            errors.push(`${relativePath} のSecureTokenStorageコードブロック${blockIndex + 1}に禁止された${description}パターンがあります`);
          }
        }
      }

      if (hasDynamicCspMetaInjection(block.code)) {
        errors.push(`${relativePath} のJavaScriptコードブロック${blockIndex + 1}に禁止されたdynamic CSP meta injectionパターンがあります`);
        if (CLIENT_NONCE_GENERATION.test(block.code) && /nonce/i.test(block.code)) {
          errors.push(`${relativePath} のJavaScriptコードブロック${blockIndex + 1}に禁止されたclient-generated nonce with post-parse CSP injectionパターンがあります`);
        }
      }
    }
  }

  return errors;
}

if (require.main === module) {
  const errors = validate(process.cwd());
  if (errors.length > 0) {
    console.error(errors.join('\n'));
    process.exitCode = 1;
  } else {
    console.log('Appendix E-05 security checks passed.');
  }
}

module.exports = { TARGETS, canonicalBody, validate };
