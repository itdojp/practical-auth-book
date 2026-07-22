'use strict';

const MARKER = '<!-- scheduled-maintenance -->';

function parseJson(payload) {
  try {
    return { value: JSON.parse(payload), error: null };
  } catch (error) {
    return { value: null, error: error.message };
  }
}

function classifyCommandOutput(mode, exitCode, payload) {
  const parsed = parseJson(payload);
  if (parsed.error) {
    return { found: false, infrastructureFailure: true, reason: `invalid JSON: ${parsed.error}` };
  }
  if (![0, 1].includes(exitCode)) {
    return { found: false, infrastructureFailure: true, reason: `unexpected exit code ${exitCode}` };
  }

  let found;
  if (mode === 'outdated') {
    if (!parsed.value || Array.isArray(parsed.value) || typeof parsed.value !== 'object') {
      return { found: false, infrastructureFailure: true, reason: 'outdated result is not an object' };
    }
    found = Object.keys(parsed.value).length > 0;
  } else if (mode === 'audit') {
    const counts = parsed.value?.metadata?.vulnerabilities;
    if (!counts || typeof counts.total !== 'number') {
      return { found: false, infrastructureFailure: true, reason: 'audit metadata is missing' };
    }
    found = counts.total > 0;
  } else if (mode === 'links') {
    if (typeof parsed.value?.passed !== 'boolean' || !Array.isArray(parsed.value?.links)) {
      return { found: false, infrastructureFailure: true, reason: 'link result schema is invalid' };
    }
    found = !parsed.value.passed;
  } else {
    throw new Error(`unknown maintenance command mode: ${mode}`);
  }

  if (exitCode !== 0 && !found) {
    return { found: false, infrastructureFailure: true, reason: `exit ${exitCode} without findings` };
  }
  return { found, infrastructureFailure: false, reason: found ? 'findings detected' : 'clean' };
}

function classifyMaintenanceState(input) {
  const workflowInfrastructure = [];
  if (input.install !== 'success') workflowInfrastructure.push('install');
  if (
    input.validation !== 'success' &&
    !(input.validation === 'skipped' && input.install !== 'success')
  ) workflowInfrastructure.push('validation');
  if (
    input.build !== 'success' &&
    !(
      input.build === 'skipped' &&
      (input.install !== 'success' || input.validation !== 'success')
    )
  ) workflowInfrastructure.push('build');
  if (input.contract !== 'success') workflowInfrastructure.push('contract');

  const findings = [];
  const commandInfrastructure = [];
  for (const key of ['outdated', 'audit', 'links']) {
    const result = input[key] || {};
    if (result.infrastructureFailure) commandInfrastructure.push(`${key}-command`);
    if (result.found) findings.push(key);
  }

  workflowInfrastructure.sort();
  commandInfrastructure.sort();
  const infrastructure = [...workflowInfrastructure, ...commandInfrastructure].sort();
  findings.sort();
  const fingerprint = JSON.stringify({ infrastructure, findings });
  return {
    issueRequired: infrastructure.length > 0 || findings.length > 0,
    infrastructureFailure: infrastructure.length > 0,
    infrastructure,
    workflowInfrastructure,
    commandInfrastructure,
    findings,
    fingerprint,
  };
}

function chooseIssueAction(state, hasExistingIssue) {
  if (state.issueRequired) return hasExistingIssue ? 'update' : 'create';
  return hasExistingIssue ? 'recover' : 'none';
}

function renderIssueBody(state, runUrl) {
  const has = (name) => state.findings.includes(name);
  return `${MARKER}
<!-- maintenance-fingerprint:${state.fingerprint} -->
## Automated Maintenance Check

| Check | Result |
| --- | --- |
| Workflow infrastructure failures | ${state.workflowInfrastructure.length ? state.workflowInfrastructure.join(', ') : 'false'} |
| Outdated dependencies | ${has('outdated')} |
| Production audit findings | ${has('audit')} |
| External link findings | ${has('links')} |
| Command infrastructure failures | ${state.commandInfrastructure.length ? state.commandInfrastructure.join(', ') : 'false'} |

Detection findings and command infrastructure failures are reported separately in the [workflow run](${runUrl}).
${MARKER}`;
}

module.exports = {
  MARKER,
  classifyCommandOutput,
  classifyMaintenanceState,
  chooseIssueAction,
  renderIssueBody,
};
