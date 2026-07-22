'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const {
  classifyCommandOutput,
  classifyMaintenanceState,
  chooseIssueAction,
  renderIssueBody,
} = require('./maintenance-state');

const cleanCommand = { found: false, infrastructureFailure: false };
const base = {
  install: 'success',
  validation: 'success',
  build: 'success',
  contract: 'success',
  outdated: cleanCommand,
  audit: cleanCommand,
  links: cleanCommand,
};

const clean = classifyMaintenanceState(base);
assert.equal(clean.issueRequired, false);
assert.equal(clean.infrastructureFailure, false);

const finding = classifyMaintenanceState({ ...base, outdated: { found: true, infrastructureFailure: false } });
assert.equal(finding.issueRequired, true);
assert.deepEqual(finding.findings, ['outdated']);

const buildFailure = classifyMaintenanceState({ ...base, build: 'failure' });
assert.equal(buildFailure.infrastructureFailure, true);
assert.deepEqual(buildFailure.infrastructure, ['build']);

const installFailure = classifyMaintenanceState({
  ...base,
  install: 'failure',
  validation: 'skipped',
  build: 'skipped',
});
assert.deepEqual(installFailure.infrastructure, ['install']);

const unexpectedBuildSkip = classifyMaintenanceState({ ...base, build: 'skipped' });
assert.deepEqual(unexpectedBuildSkip.infrastructure, ['build']);

const commandFailure = classifyMaintenanceState({
  ...base,
  links: { found: false, infrastructureFailure: true },
});
assert.deepEqual(commandFailure.infrastructure, ['links-command']);

const duplicate = classifyMaintenanceState({ ...base, outdated: { found: true, infrastructureFailure: false } });
assert.equal(duplicate.fingerprint, finding.fingerprint);
assert.match(renderIssueBody(finding, 'https://example.test/run'), /maintenance-fingerprint/);
assert.equal(chooseIssueAction(finding, false), 'create');
assert.equal(chooseIssueAction(duplicate, true), 'update');
assert.equal(chooseIssueAction(clean, true), 'recover');
assert.equal(chooseIssueAction(clean, false), 'none');

assert.deepEqual(classifyCommandOutput('outdated', 1, '{"pkg":{"current":"1","latest":"2"}}'), {
  found: true,
  infrastructureFailure: false,
  reason: 'findings detected',
});
assert.deepEqual(classifyCommandOutput('outdated', 1, '{"error":{"code":"EAI_AGAIN"}}'), {
  found: false,
  infrastructureFailure: true,
  reason: 'npm outdated returned an error envelope',
});
assert.equal(classifyCommandOutput('audit', 0, '{"metadata":{"vulnerabilities":{"total":0}}}').found, false);
assert.equal(classifyCommandOutput('links', 1, '{"passed":false,"links":[{"state":"BROKEN"}]}').found, true);
assert.equal(classifyCommandOutput('links', 0, '{"passed":true,"links":[{"state":"SKIPPED"}]}').found, false);
const unavailableBuildOutput = classifyCommandOutput('links', 1, '');
assert.equal(unavailableBuildOutput.found, false);
assert.equal(unavailableBuildOutput.infrastructureFailure, true);

const missingCliArgument = spawnSync(
  process.execPath,
  [path.join(__dirname, 'classify-maintenance-command.js'), 'links', '1', 'payload.json', 'output', 'summary', 'result'],
  { encoding: 'utf8' },
);
assert.notEqual(missingCliArgument.status, 0);
assert.match(missingCliArgument.stderr, /usage: classify-maintenance-command/);

console.log('scheduled maintenance contract tests passed (clean/finding/infrastructure/duplicate/recovery)');
