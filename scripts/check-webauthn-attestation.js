#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const CHAPTERS = [
  {
    name: 'chapter 10',
    sampleAnchor: 'generate_registration_options(',
    copies: [
      'src/chapters/chapter-10-implementation-patterns.md',
      'docs/chapters/chapter-10-implementation-patterns.md',
      'docs/chapters/chapter-10-implementation-patterns/index.md',
    ],
  },
  {
    name: 'chapter 13',
    sampleAnchor: 'navigator.credentials.create(',
    copies: [
      'src/chapters/chapter-13-future.md',
      'docs/chapters/chapter-13-future.md',
      'docs/chapters/chapter-13-future/index.md',
    ],
  },
];

const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'webauthn-attestation');
const GUIDANCE_HEADING = 'Attestation の選択: 一般向け Passkey と管理対象 enterprise';
const REQUIRED_PROSE = [
  'WebAuthn の `attestation` の既定値も `none`',
  '**プライバシー**:',
  'AAGUID など認証器の型式に関係する情報が含まれ得る',
  '**互換性**:',
  '**運用**:',
  '信頼アンカー、証明書失効、メタデータ更新、拒否時の利用者支援',
  'それだけで管理対象端末であることを証明しない',
  '一般向け登録へこの設定を流用しない',
  'attestation: "enterprise"',
];
const ENTERPRISE_MARKER = 'ENTERPRISE_ATTESTATION_EXCEPTION: managed asset inventory requires device evidence.';

function read(relativePath) {
  return fs.readFileSync(path.resolve(relativePath), 'utf8');
}

function codeBlocks(markdown) {
  return [...markdown.matchAll(/^```[^\n]*\n([\s\S]*?)^```\s*$/gm)].map((match) => match[1]);
}

function guidanceBlock(markdown) {
  const heading = new RegExp(`^(#{3,4}) ${GUIDANCE_HEADING}$`, 'm').exec(markdown);
  if (!heading) return null;
  const start = heading.index;
  const headingLevel = heading[1].length;
  const remainderStart = start + heading[0].length;
  const remainder = markdown.slice(remainderStart);
  const nextHeading = new RegExp(`^#{1,${headingLevel}}\\s+`, 'm').exec(remainder);
  const end = nextHeading ? remainderStart + nextHeading.index : undefined;
  return markdown.slice(start, end).trim();
}

function validateDocument(markdown, label, sampleAnchor) {
  const errors = [];
  const blocks = codeBlocks(markdown);
  const normalBlocks = blocks.filter((block) =>
    /attestation\s*[:=]\s*"none"/.test(block) && !block.includes(ENTERPRISE_MARKER)
  );
  const directBlocks = blocks.filter((block) => /attestation\s*[:=]\s*"direct"/.test(block));
  const directOccurrences = [...markdown.matchAll(/attestation\s*[:=]\s*"direct"/g)];

  if (normalBlocks.length !== 1) {
    errors.push(`${label}: exactly one general-registration attestation="none" code example is required; found ${normalBlocks.length}`);
  }
  const anchoredNormalBlocks = normalBlocks.filter((block) => block.includes(sampleAnchor));
  if (anchoredNormalBlocks.length !== 1) {
    errors.push(`${label}: the attestation="none" example must be in the intended registration block anchored by ${sampleAnchor}`);
  }
  if (directOccurrences.length !== 1 || directBlocks.length !== 1) {
    errors.push(`${label}: exactly one attestation="direct" occurrence in an enterprise exception code block is required`);
  } else if (!directBlocks[0].includes(ENTERPRISE_MARKER)) {
    errors.push(`${label}: direct attestation must be labeled with the enterprise exception marker`);
  }

  const guidance = guidanceBlock(markdown);
  if (!guidance) {
    errors.push(`${label}: attestation guidance section is missing`);
  } else {
    for (const snippet of REQUIRED_PROSE) {
      if (!guidance.includes(snippet)) errors.push(`${label}: required guidance is missing: ${snippet}`);
    }
    if (!guidance.includes(ENTERPRISE_MARKER)) {
      errors.push(`${label}: enterprise exception marker must appear in the guidance section`);
    }
  }

  return errors;
}

function runFixtureTests() {
  const sampleAnchor = 'navigator.credentials.create(';
  const valid = read(path.join(FIXTURE_DIR, 'valid.md'));
  assert.deepEqual(validateDocument(valid, 'valid fixture', sampleAnchor), [], 'the valid fixture must pass');
  const levelFour = valid.replace(`### ${GUIDANCE_HEADING}`, `#### ${GUIDANCE_HEADING}`);
  assert.deepEqual(validateDocument(levelFour, 'level-four heading fixture', sampleAnchor), [], 'a level-four guidance heading must pass');

  for (const fixture of [
    'basic-direct.md',
    'direct-without-enterprise-marker.md',
    'missing-operations-tradeoff.md',
    'displaced-none.md',
  ]) {
    const errors = validateDocument(read(path.join(FIXTURE_DIR, fixture)), fixture, sampleAnchor);
    assert.ok(errors.length > 0, `${fixture} must be rejected by the regression checker`);
  }
}

function validateCopies() {
  const errors = [];
  for (const chapter of CHAPTERS) {
    const guidance = new Map();
    for (const file of chapter.copies) {
      const content = read(file);
      errors.push(...validateDocument(content, file, chapter.sampleAnchor));
      guidance.set(file, guidanceBlock(content));
    }

    const [canonicalFile, canonicalGuidance] = guidance.entries().next().value;
    for (const [file, block] of guidance) {
      if (block !== canonicalGuidance) {
        errors.push(`${chapter.name}: attestation guidance copy drift between ${canonicalFile} and ${file}`);
      }
    }
  }
  return errors;
}

function main() {
  runFixtureTests();
  const errors = validateCopies();
  if (errors.length > 0) {
    for (const error of errors) console.error(`ERROR: ${error}`);
    process.exitCode = 1;
    return;
  }
  console.log('WebAuthn attestation guidance and source/docs copy synchronization checks passed.');
}

main();
