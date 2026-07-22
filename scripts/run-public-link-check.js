'use strict';

const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const sleepBuffer = new Int32Array(new SharedArrayBuffer(4));
const sleep = (milliseconds) => {
  Atomics.wait(sleepBuffer, 0, 0, milliseconds);
};

function combineDiagnostics(stderr, error) {
  const parts = [stderr?.trimEnd(), error?.message].filter(Boolean);
  return parts.length ? `${parts.join('\n')}\n` : '';
}

function runWithRetries(runAttempt, { maxAttempts = 3, wait = sleep } = {}) {
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new Error('maxAttempts must be a positive integer');
  }

  const attempts = [];
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const result = runAttempt(attempt);
    attempts.push({ attempt, ...result });
    if (result.exitCode === 0) break;
    if (attempt < maxAttempts) wait(attempt * 2000);
  }
  return { attempts, final: attempts.at(-1) };
}

function runLinkinator(rootUrl, version, attempt) {
  const args = [
    '--yes', `linkinator@${version}`, rootUrl,
    '--recurse',
    '--skip', 'localhost|127.0.0.1',
    '--timeout', '30000',
    '--concurrency', '10',
    '--retry-errors',
    '--retry-errors-count', '2',
    '--retry-errors-jitter', '250',
    '--status-code', '429:warn',
    '--format', 'json',
  ];
  const result = spawnSync('npx', args, {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  const stderr = combineDiagnostics(result.stderr, result.error);
  const exitCode = Number.isInteger(result.status) ? result.status : 2;
  fs.writeFileSync(`links-attempt-${attempt}.json`, result.stdout || '');
  fs.writeFileSync(`links-attempt-${attempt}.stderr`, stderr);
  return { exitCode, stdout: result.stdout || '', stderr };
}

function main() {
  const [rootUrl] = process.argv.slice(2);
  const version = process.env.LINKINATOR_VERSION;
  if (!rootUrl || !/^https:\/\//.test(rootUrl)) throw new Error('usage: run-public-link-check.js HTTPS_ROOT_URL');
  if (!version || !/^\d+\.\d+\.\d+$/.test(version)) throw new Error('LINKINATOR_VERSION must be an exact version');

  const result = runWithRetries((attempt) => runLinkinator(rootUrl, version, attempt));
  fs.writeFileSync('links.json', result.final.stdout);
  fs.writeFileSync('links.stderr', result.final.stderr);
  fs.writeFileSync(
    'links-attempts.json',
    `${JSON.stringify({ attempts: result.attempts.map(({ attempt, exitCode }) => ({ attempt, exitCode })) }, null, 2)}\n`,
  );

  const lines = result.attempts.map(({ attempt, exitCode }) => `- attempt ${attempt}: exit ${exitCode}`).join('\n');
  process.stdout.write(`${lines}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `\n### link scan attempts\n\n${lines}\n`);
  }
  process.exitCode = result.final.exitCode;
}

if (require.main === module) main();

module.exports = { combineDiagnostics, runWithRetries };
