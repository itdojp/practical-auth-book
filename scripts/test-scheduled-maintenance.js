'use strict';

const assert = require('node:assert/strict');
const {
  classifyCommandOutput,
  classifyMaintenanceState,
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

const commandFailure = classifyMaintenanceState({
  ...base,
  links: { found: false, infrastructureFailure: true },
});
assert.deepEqual(commandFailure.infrastructure, ['links-command']);

const duplicate = classifyMaintenanceState({ ...base, outdated: { found: true, infrastructureFailure: false } });
assert.equal(duplicate.fingerprint, finding.fingerprint);
assert.match(renderIssueBody(finding, 'https://example.test/run'), /maintenance-fingerprint/);

assert.deepEqual(classifyCommandOutput('outdated', 1, '{"pkg":{"current":"1","latest":"2"}}'), {
  found: true,
  infrastructureFailure: false,
  reason: 'findings detected',
});
assert.equal(classifyCommandOutput('audit', 0, '{"metadata":{"vulnerabilities":{"total":0}}}').found, false);
assert.equal(classifyCommandOutput('links', 1, '{"passed":false,"links":[{"state":"BROKEN"}]}').found, true);
assert.equal(classifyCommandOutput('links', 1, 'not json').infrastructureFailure, true);

console.log('scheduled maintenance contract tests passed (clean/finding/infrastructure/duplicate/recovery)');
