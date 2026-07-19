#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { TARGETS, validate } = require('./check-appendix-e-05-security');

const root = path.resolve('temp/check-appendix-e-05-security');

function copyFixture() {
  fs.rmSync(root, { recursive: true, force: true });
  for (const relativePath of TARGETS) {
    const destination = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(relativePath, destination);
  }
}

function readFixture(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

function writeFixture(relativePath, content) {
  fs.writeFileSync(path.join(root, relativePath), content);
}

function appendSynchronizedJavaScript(code) {
  const fixture = `\n\n\`\`\`javascript\n${code.trim()}\n\`\`\`\n`;
  for (const relativePath of TARGETS) {
    writeFixture(relativePath, readFixture(relativePath) + fixture);
  }
}

try {
  copyFixture();
  assert.deepEqual(validate(root), [], '同期済みのAppendix E-05は検査を通過する');

  copyFixture();
  appendSynchronizedJavaScript(`
const { randomBytes } = require('node:crypto');

function generateNonce() {
  return randomBytes(16).toString('base64');
}

function sendDocument(response) {
  const nonce = generateNonce();
  response.setHeader('Content-Security-Policy', "script-src 'nonce-" + nonce + "'");
}
  `);
  assert.deepEqual(
    validate(root),
    [],
    'server-side CSP nonceのgenerateNonce名とnonce-source文字列を許可する'
  );

  copyFixture();
  appendSynchronizedJavaScript(`
class SecureTokenStorage {
  addDescriptionMeta() {
    const meta = document.createElement('meta');
    meta.name = 'description';
    meta.content = 'Authentication guide';
    document.head.append(meta);
  }
}
  `);
  assert.deepEqual(
    validate(root),
    [],
    'SecureTokenStorage内でもCSPと無関係なmeta要素生成を許可する'
  );

  copyFixture();
  appendSynchronizedJavaScript(`
class SecureTokenStorage {
  request() {
    return fetch('/api', { headers: { 'X-Frame-Options': 'DENY' } });
  }
}
  `);
  assert.ok(
    validate(root).some((error) => error.includes('request-side X-Frame-Options')),
    'SecureTokenStorageのobject形式request header再混入を拒否する'
  );

  copyFixture();
  appendSynchronizedJavaScript(`
class SecureTokenStorage {
  request() {
    const headers = new Headers();
    headers.set('X-Frame-Options', 'DENY');
    headers.append('X-Content-Type-Options', 'nosniff');
    return fetch('/api', { headers });
  }
}
  `);
  const setAppendErrors = validate(root);
  assert.ok(
    setAppendErrors.some((error) => error.includes('request-side X-Frame-Options')),
    'headers.set経由のX-Frame-Options再混入を拒否する'
  );
  assert.ok(
    setAppendErrors.some((error) => error.includes('request-side X-Content-Type-Options')),
    'headers.append経由のX-Content-Type-Options再混入を拒否する'
  );

  copyFixture();
  appendSynchronizedJavaScript([
    'class SecureTokenStorage {',
    '  request() {',
    '    const headers = new Headers();',
    '    headers.set(`X-Frame-Options`, `DENY`);',
    '    headers.append(`X-Content-Type-Options`, `nosniff`);',
    "    return fetch('/api', { headers });",
    '  }',
    '}',
  ].join('\n'));
  const fixedTemplateHeaderErrors = validate(root);
  assert.ok(
    fixedTemplateHeaderErrors.some((error) => error.includes('request-side X-Frame-Options')),
    '固定template literalのX-Frame-Options再混入を拒否する'
  );
  assert.ok(
    fixedTemplateHeaderErrors.some((error) => error.includes('request-side X-Content-Type-Options')),
    '固定template literalのX-Content-Type-Options再混入を拒否する'
  );

  copyFixture();
  appendSynchronizedJavaScript(`
class SecureTokenStorage {
  request() {
    const headers = {};
    headers['X-Frame-Options'] = 'DENY';
    headers["X-Content-Type-Options"] = 'nosniff';
    return fetch('/api', { headers });
  }
}
  `);
  const bracketAssignmentErrors = validate(root);
  assert.ok(
    bracketAssignmentErrors.some((error) => error.includes('request-side X-Frame-Options')),
    "headers['X-Frame-Options']代入の再混入を拒否する"
  );
  assert.ok(
    bracketAssignmentErrors.some((error) => error.includes('request-side X-Content-Type-Options')),
    'headers["X-Content-Type-Options"]代入の再混入を拒否する'
  );

  copyFixture();
  appendSynchronizedJavaScript(`
class SecureTokenStorage {
  request() {
    const headers = new Headers([
      ['X-Frame-Options', 'DENY'],
      ['X-Content-Type-Options', 'nosniff']
    ]);
    return fetch('/api', { headers });
  }
}
  `);
  const arrayErrors = validate(root);
  assert.ok(
    arrayErrors.some((error) => error.includes('request-side X-Frame-Options')),
    'new Headers配列形式のX-Frame-Options再混入を拒否する'
  );
  assert.ok(
    arrayErrors.some((error) => error.includes('request-side X-Content-Type-Options')),
    'new Headers配列形式のX-Content-Type-Options再混入を拒否する'
  );

  copyFixture();
  appendSynchronizedJavaScript(`
class SecureTokenStorage {
  installCsp() {
    const meta = document.createElement('meta');
    meta.setAttribute('http-equiv', 'Content-Security-Policy');
    document.head.appendChild(meta);
  }
}
  `);
  assert.ok(
    validate(root).some((error) => error.includes('dynamic CSP meta injection')),
    'createElementとDOM挿入を組み合わせた動的CSP metaの再混入を拒否する'
  );

  copyFixture();
  appendSynchronizedJavaScript([
    'class SecureTokenStorage {',
    '  installCsp() {',
    "    const meta = document.createElement('meta');",
    '    meta.httpEquiv = `Content-Security-Policy`;',
    '    document.head.appendChild(meta);',
    '  }',
    '}',
  ].join('\n'));
  assert.ok(
    validate(root).some((error) => error.includes('dynamic CSP meta injection')),
    '固定template literalのCSP値による動的meta再混入を拒否する'
  );

  copyFixture();
  appendSynchronizedJavaScript(`
class SecureTokenStorage {
  installCsp() {
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    document.head.insertAdjacentElement('afterbegin', meta);
  }
}
  `);
  assert.ok(
    validate(root).some((error) => error.includes('dynamic CSP meta injection')),
    'insertAdjacentElement経由の動的CSP meta再混入を拒否する'
  );

  for (const [sinkName, injection] of [
    [
      'insertAdjacentHTML',
      `document.head.insertAdjacentHTML('afterbegin', '<meta http-equiv="Content-Security-Policy" content="default-src self">');`,
    ],
    [
      'innerHTML',
      `document.head.innerHTML += '<meta http-equiv="Content-Security-Policy" content="default-src self">';`,
    ],
    [
      'outerHTML',
      `document.head.outerHTML = '<head><meta http-equiv="Content-Security-Policy" content="default-src self"></head>';`,
    ],
  ]) {
    copyFixture();
    appendSynchronizedJavaScript(`
class SecureTokenStorage {
  installCsp() {
    ${injection}
  }
}
    `);
    assert.ok(
      validate(root).some((error) => error.includes('dynamic CSP meta injection')),
      `${sinkName}経由の動的CSP meta再混入を拒否する`
    );
  }

  copyFixture();
  appendSynchronizedJavaScript(`
class SecureTokenStorage {
  installCsp() {
    const nonce = crypto.randomUUID();
    const meta = '<meta http-equiv="Content-Security-Policy" content="script-src nonce-' + nonce + '">';
    document.head.insertAdjacentHTML('afterbegin', meta);
  }
}
  `);
  const clientNonceErrors = validate(root);
  assert.ok(
    clientNonceErrors.some((error) => error.includes('dynamic CSP meta injection')),
    'client生成nonceを含むpost-parse CSP注入を動的metaとして拒否する'
  );
  assert.ok(
    clientNonceErrors.some((error) => error.includes('client-generated nonce with post-parse CSP injection')),
    'client生成nonceとpost-parse CSP注入の複合再混入を明示的に拒否する'
  );

  copyFixture();
  const flatPath = TARGETS[1];
  writeFixture(flatPath, `${readFixture(flatPath)}\n本文の同期ドリフト\n`);
  assert.ok(
    validate(root).some((error) => error.includes('本文が同期していません')),
    '正本とflat mirrorのドリフトを拒否する'
  );

  copyFixture();
  const noncePattern = /CSPの `nonce-source` を使う場合、nonceはサーバーがレスポンスごとに暗号学的に安全な乱数から一意に生成し、同じ値をレスポンスヘッダーと許可するinline scriptの `nonce` 属性へ埋め込みます。/;
  for (const relativePath of TARGETS) {
    writeFixture(relativePath, readFixture(relativePath).replace(noncePattern, ''));
  }
  assert.ok(
    validate(root).some((error) => error.includes('server-generated nonce per response')),
    'server responseごとのnonce責務の説明欠落を拒否する'
  );

  console.log('Appendix E-05 security fixtures passed.');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
