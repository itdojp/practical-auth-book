'use strict';

const fs = require('node:fs');
const { classifyCommandOutput } = require('./maintenance-state');

const [mode, exitCodeText, payloadPath, stderrPath, outputPath, summaryPath, resultPath] = process.argv.slice(2);
if (
  process.argv.slice(2).length !== 7 ||
  !mode || !exitCodeText || !payloadPath || !stderrPath || !outputPath || !summaryPath || !resultPath
) {
  throw new Error('usage: classify-maintenance-command MODE EXIT JSON STDERR GITHUB_OUTPUT STEP_SUMMARY RESULT_JSON');
}

const exitCode = Number(exitCodeText);
if (!Number.isInteger(exitCode)) throw new Error(`invalid exit code: ${exitCodeText}`);
const payload = fs.existsSync(payloadPath) ? fs.readFileSync(payloadPath, 'utf8') : '';
const stderr = stderrPath && fs.existsSync(stderrPath) ? fs.readFileSync(stderrPath, 'utf8') : '';
const result = classifyCommandOutput(mode, exitCode, payload);

fs.appendFileSync(outputPath, `found=${result.found}\ninfrastructure_failure=${result.infrastructureFailure}\n`);
fs.appendFileSync(
  summaryPath,
  `\n### ${mode}\n\n- exit code: ${exitCode}\n- finding: ${result.found}\n- command infrastructure failure: ${result.infrastructureFailure}\n- classification: ${result.reason}\n`,
);
fs.writeFileSync(resultPath, `${JSON.stringify({ mode, exitCode, stderr, ...result }, null, 2)}\n`);
