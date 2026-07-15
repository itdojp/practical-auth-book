'use strict';

function classify({ build, outdated, audit, links }) {
  const findings = [
    outdated && 'outdated',
    audit && 'audit',
    links && 'links',
  ].filter(Boolean);
  return {
    createOrUpdateIssue: findings.length > 0 || build === 'failure',
    infrastructureFailure: build === 'failure',
    findingTypes: findings,
  };
}

const cases = [
  [{ build: 'success', outdated: false, audit: false, links: false }, false, false],
  [{ build: 'success', outdated: true, audit: false, links: false }, true, false],
  [{ build: 'success', outdated: false, audit: true, links: false }, true, false],
  [{ build: 'success', outdated: false, audit: false, links: true }, true, false],
  [{ build: 'success', outdated: true, audit: true, links: true }, true, false],
  [{ build: 'failure', outdated: false, audit: false, links: false }, true, true],
];

for (const [input, issue, infrastructure] of cases) {
  const actual = classify(input);
  if (actual.createOrUpdateIssue !== issue || actual.infrastructureFailure !== infrastructure) {
    throw new Error(`classification mismatch: ${JSON.stringify(input)} => ${JSON.stringify(actual)}`);
  }
}

const fingerprints = new Set();
for (const [input] of cases) {
  const result = classify(input);
  if (result.createOrUpdateIssue) fingerprints.add(JSON.stringify(result));
}
if (fingerprints.size !== 5) throw new Error('finding fingerprints were not stable');

const recovered = classify({ build: 'success', outdated: false, audit: false, links: false });
if (recovered.createOrUpdateIssue) throw new Error('recovery incorrectly creates an issue');

console.log(`scheduled maintenance contract tests passed (${cases.length} cases, ${fingerprints.size} fingerprints)`);
