'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const EasySetup = require('../easy-setup');

const ROOT = path.resolve(__dirname, '..');
const read = (relativePath) => fs.readFileSync(path.join(ROOT, relativePath), 'utf8');
const json = (relativePath) => JSON.parse(read(relativePath));

const packageJson = json('package.json');
const packageSimple = json('package-simple.json');
const packageLock = json('package-lock.json');
assert.equal(packageJson.engines.node, '>=22.22.2');
assert.equal(packageSimple.engines.node, '>=22.22.2');
assert.equal(packageLock.packages[''].engines.node, '>=22.22.2');

const workflowDirectory = path.join(ROOT, '.github', 'workflows');
const workflowText = fs.readdirSync(workflowDirectory)
  .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
  .map((name) => fs.readFileSync(path.join(workflowDirectory, name), 'utf8'))
  .join('\n');
const nodeVersions = [...workflowText.matchAll(/node-version:\s*['"]?([^'"\s]+)['"]?/g)]
  .map((match) => match[1]);
assert.ok(nodeVersions.includes('22.22.2'));
assert.ok(nodeVersions.includes('24'));
assert.deepEqual([...new Set(nodeVersions)].sort(), ['22.22.2', '24']);

assert.match(read('README.md'), /通常の CI は Node\.js 22\.22\.2 以上/);
assert.match(read('README.md'), /公開リンク監査だけは[^\n]*Node\.js 24/);
assert.match(read('QUICK-START.md'), /Node\.js 22\.22\.2以上が必要/);
assert.equal(EasySetup.isNodeVersionSupported('v20.20.2'), false);
assert.equal(EasySetup.isNodeVersionSupported('v22.22.1'), false);
assert.equal(EasySetup.isNodeVersionSupported('v22.22.2'), true);
assert.equal(EasySetup.isNodeVersionSupported('v23.0.0'), true);
assert.equal(EasySetup.isNodeVersionSupported('invalid'), false);
assert.equal(
  EasySetup.isNodeVersionSupported(process.version),
  true,
  `current Node.js ${process.version} does not satisfy the >=22.22.2 quality baseline`,
);

console.log('Node runtime contract passed: standard QA 22.22.2, link audit 24.');
