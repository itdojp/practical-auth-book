#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const CHAPTER_COPIES = [
  'src/chapters/chapter-06-oauth2.md',
  'docs/chapters/chapter-06-oauth2.md',
  'docs/chapters/chapter-06-oauth2/index.md',
];

function consumeStateBeforeTokenExchange(session, returnedState, tokenExchange) {
  const expectedState = session.oauthState;
  delete session.oauthState;

  if (!returnedState || !expectedState) throw new Error('Missing OAuth state');
  if (returnedState !== expectedState) throw new Error('Invalid OAuth state');

  return tokenExchange();
}

function runBehaviorFixtures() {
  let exchanges = 0;
  const successfulSession = { oauthState: 'bound-state' };
  assert.equal(
    consumeStateBeforeTokenExchange(successfulSession, 'bound-state', () => {
      exchanges += 1;
      return 'token';
    }),
    'token',
    'a matching state must permit token exchange'
  );
  assert.equal(successfulSession.oauthState, undefined, 'matching state must be consumed');

  const missingSession = { oauthState: 'bound-state' };
  assert.throws(
    () => consumeStateBeforeTokenExchange(missingSession, undefined, () => { exchanges += 1; }),
    /Missing OAuth state/,
    'a callback without state must be rejected'
  );
  assert.equal(missingSession.oauthState, undefined, 'missing callback state must consume the bound state');

  const mismatchSession = { oauthState: 'bound-state' };
  assert.throws(
    () => consumeStateBeforeTokenExchange(mismatchSession, 'attacker-state', () => { exchanges += 1; }),
    /Invalid OAuth state/,
    'a mismatched state must be rejected'
  );
  assert.equal(mismatchSession.oauthState, undefined, 'mismatched state must consume the bound state');

  assert.throws(
    () => consumeStateBeforeTokenExchange(successfulSession, 'bound-state', () => { exchanges += 1; }),
    /Missing OAuth state/,
    'a previously accepted state must not be replayed'
  );
  assert.equal(exchanges, 1, 'negative state cases must not reach token exchange');
}

function read(relativePath) {
  return fs.readFileSync(path.resolve(relativePath), 'utf8');
}

function indentation(line) {
  return line.match(/^\s*/)[0].replace(/\t/g, '    ').length;
}

function extractPkceClasses(markdown) {
  const blocks = [...markdown.matchAll(/^```(?:python|py)\s*\n([\s\S]*?)^```\s*$/gm)].map((match) => match[1]);
  const classes = [];
  for (const block of blocks) {
    const lines = block.split(/\r?\n/);
    for (let start = 0; start < lines.length; start += 1) {
      if (!/^\s*class PKCEClient\s*:/.test(lines[start])) continue;
      const classIndent = indentation(lines[start]);
      let end = lines.length;
      for (let index = start + 1; index < lines.length; index += 1) {
        if (lines[index].trim() && indentation(lines[index]) <= classIndent) {
          end = index;
          break;
        }
      }
      classes.push({ code: lines.slice(start, end).join('\n'), classIndent });
      start = end - 1;
    }
  }
  return classes;
}

function extractMethods(pkceClass, name) {
  const lines = pkceClass.code.split(/\r?\n/);
  const methods = [];
  for (let start = 0; start < lines.length; start += 1) {
    if (!new RegExp(`^\\s*def ${name}\\s*\\(`).test(lines[start])) continue;
    const methodIndent = indentation(lines[start]);
    let end = lines.length;
    for (let index = start + 1; index < lines.length; index += 1) {
      if (!lines[index].trim()) continue;
      const currentIndent = indentation(lines[index]);
      if (currentIndent < methodIndent || (currentIndent === methodIndent && /^\s*def\s+/.test(lines[index]))) {
        end = index;
        break;
      }
    }
    methods.push(lines.slice(start, end));
    start = end - 1;
  }
  return methods;
}

function executableLines(methodLines) {
  return methodLines.flatMap((raw, index) => {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#') || /^(["']{3}).*\1$/.test(trimmed)) return [];
    return [{ raw, text: trimmed, indent: indentation(raw), index }];
  });
}

function lineIndex(lines, expression) {
  return lines.findIndex((line) => expression.test(line.text));
}

function requireImmediateRaise(lines, ifExpression, raiseExpression, errors, label) {
  const ifIndex = lineIndex(lines, ifExpression);
  if (ifIndex < 0) {
    errors.push(`${label}: guard is missing`);
    return -1;
  }
  const next = lines[ifIndex + 1];
  if (!next || next.indent <= lines[ifIndex].indent || !raiseExpression.test(next.text)) {
    errors.push(`${label}: guard must immediately raise on the rejected path`);
  }
  return ifIndex;
}

function validatePkceCode(markdown, label) {
  const errors = [];
  const pkceClasses = extractPkceClasses(markdown);
  if (pkceClasses.length === 0) return [`${label}: executable Python block containing PKCEClient is missing`];
  if (pkceClasses.length !== 1) {
    return [`${label}: exactly one PKCEClient example is allowed; found ${pkceClasses.length}`];
  }
  const pkceClass = pkceClasses[0];

  const createMethods = extractMethods(pkceClass, 'create_authorization_url_with_pkce');
  const exchangeMethods = extractMethods(pkceClass, 'exchange_code_with_pkce');
  if (createMethods.length !== 1) errors.push(`${label}: exactly one create_authorization_url_with_pkce method is required; found ${createMethods.length}`);
  if (exchangeMethods.length !== 1) errors.push(`${label}: exactly one exchange_code_with_pkce method is required; found ${exchangeMethods.length}`);
  if (createMethods.length !== 1 || exchangeMethods.length !== 1) return errors;
  const createMethod = createMethods[0];
  const exchangeMethod = exchangeMethods[0];

  const create = executableLines(createMethod);
  for (const [description, expression] of [
    ['state generation', /^state\s*=\s*secrets\.token_urlsafe\(32\)$/],
    ['state browser-session binding', /^session\[['"]oauth_state['"]\]\s*=\s*state$/],
    ['verifier browser-session binding', /^session\[['"]pkce_verifier['"]\]\s*=\s*code_verifier$/],
    ['authorization request state', /^['"]state['"]\s*:\s*state,?$/],
  ]) {
    if (lineIndex(create, expression) < 0) errors.push(`${label}: ${description} is missing from the executable create method`);
  }
  if (lineIndex(create, /^['"]state['"]\s*:\s*secrets\.token_urlsafe/) >= 0) {
    errors.push(`${label}: generated state must be browser-session-bound instead of being used inline`);
  }

  const exchange = executableLines(exchangeMethod);
  const signature = exchangeMethod.join('\n').slice(0, exchangeMethod.join('\n').indexOf(') ->') + 1);
  if (!/returned_state\s*:\s*Optional\[str\]/.test(signature)) {
    errors.push(`${label}: callback state input is missing from the exchange method signature`);
  }

  const expectedAt = lineIndex(exchange, /^expected_state\s*=\s*session\.pop\(['"]oauth_state['"],\s*None\)$/);
  const verifierAt = lineIndex(exchange, /^code_verifier\s*=\s*session\.pop\(['"]pkce_verifier['"],\s*None\)$/);
  const missingAt = requireImmediateRaise(
    exchange,
    /^if not returned_state or not expected_state:$/,
    /^raise SecurityError\(["']Missing OAuth state["']\)$/,
    errors,
    `${label}: missing-state rejection`
  );
  const mismatchAt = requireImmediateRaise(
    exchange,
    /^if not secrets\.compare_digest\(returned_state,\s*expected_state\):$/,
    /^raise SecurityError\(["']Invalid OAuth state["']\)$/,
    errors,
    `${label}: mismatched-state rejection`
  );
  const verifierGuardAt = requireImmediateRaise(
    exchange,
    /^if not code_verifier:$/,
    /^raise SecurityError\(["']PKCE verifier not found["']\)$/,
    errors,
    `${label}: missing-verifier rejection`
  );
  const tokenAt = lineIndex(exchange, /^response\s*=\s*requests\.post\(self\.token_endpoint,\s*data=token_data\)$/);

  const ordered = [expectedAt, verifierAt, missingAt, mismatchAt, verifierGuardAt, tokenAt];
  if (ordered.some((index) => index < 0) || !ordered.every((index, position) => position === 0 || ordered[position - 1] < index)) {
    errors.push(`${label}: state/verifier consumption and rejecting guards must execute in order before token exchange`);
  }

  return errors;
}

function runCheckerResistanceFixtures() {
  const valid = `\`\`\`python
class PKCEClient:
    def create_authorization_url_with_pkce(self):
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        session['pkce_verifier'] = code_verifier
        params = {
            'state': state,
        }

    def exchange_code_with_pkce(self, returned_state: Optional[str]) -> Dict:
        expected_state = session.pop('oauth_state', None)
        code_verifier = session.pop('pkce_verifier', None)
        if not returned_state or not expected_state:
            raise SecurityError("Missing OAuth state")
        if not secrets.compare_digest(returned_state, expected_state):
            raise SecurityError("Invalid OAuth state")
        if not code_verifier:
            raise SecurityError("PKCE verifier not found")
        response = requests.post(self.token_endpoint, data=token_data)
\`\`\``;
  assert.deepEqual(validatePkceCode(valid, 'valid fixture'), [], 'valid structural fixture must pass');

  const commentBypass = valid
    .replace('        expected_state = session.pop', '        response = requests.post(self.token_endpoint, data=token_data)\n        # expected_state = session.pop')
    .replace('        code_verifier = session.pop', '        # code_verifier = session.pop')
    .replace('        if not returned_state', '        # if not returned_state')
    .replace('            raise SecurityError("Missing', '        #     raise SecurityError("Missing')
    .replace('        if not secrets.compare_digest', '        # if not secrets.compare_digest')
    .replace('            raise SecurityError("Invalid', '        #     raise SecurityError("Invalid')
    .replace('        if not code_verifier', '        # if not code_verifier')
    .replace('            raise SecurityError("PKCE', '        #     raise SecurityError("PKCE')
    .replace(/\n        response = requests\.post\(self\.token_endpoint, data=token_data\)\n\`\`\`$/, '\n```');
  assert.ok(validatePkceCode(commentBypass, 'comment bypass fixture').length > 0, 'comment-only contracts must fail');

  const lateValidation = valid.replace(
    "        expected_state = session.pop('oauth_state', None)",
    "        response = requests.post(self.token_endpoint, data=token_data)\n        expected_state = session.pop('oauth_state', None)"
  ).replace(/\n        response = requests\.post\(self\.token_endpoint, data=token_data\)\n\`\`\`$/, '\n```');
  assert.ok(validatePkceCode(lateValidation, 'late validation fixture').length > 0, 'validation after exchange must fail');

  const nonRaising = valid.replace('            raise SecurityError("Invalid OAuth state")', '            pass');
  assert.ok(validatePkceCode(nonRaising, 'non-raising fixture').length > 0, 'non-raising mismatch guard must fail');

  const decoyFirstBlock = `${valid}\n\n${valid.replace('        if not returned_state or not expected_state:', '        if returned_state:')}`;
  assert.ok(validatePkceCode(decoyFirstBlock, 'decoy first-block fixture').length > 0, 'multiple PKCEClient examples must fail instead of trusting the first');

  const duplicateMethod = valid.replace(
    '        response = requests.post(self.token_endpoint, data=token_data)',
    `        response = requests.post(self.token_endpoint, data=token_data)

    def exchange_code_with_pkce(self, returned_state: Optional[str]) -> Dict:
        response = requests.post(self.token_endpoint, data=token_data)`
  );
  assert.ok(validatePkceCode(duplicateMethod, 'duplicate method fixture').length > 0, 'duplicate PKCE methods must fail instead of trusting the first');
}

function validateDocumentation() {
  const errors = [];
  const copies = new Map(CHAPTER_COPIES.map((file) => [file, read(file)]));
  const requiredProse = [
    'PKCE は認可コード横取りへの対策であり、`state` の CSRF および authorization response binding の代替ではない。',
    'ROPC）は非推奨であり、新規採用しない。ROPCは既存システムの移行時に限る歴史的な参照として扱う。',
    "'resource_owner_password': '非推奨。新規採用しない。既存システム移行時に限る歴史的参照'",
  ];

  for (const [file, content] of copies) {
    errors.push(...validatePkceCode(content, file));
    for (const snippet of requiredProse) {
      if (!content.includes(snippet)) errors.push(`${file}: required prose contract is missing: ${snippet}`);
    }
    if (content.includes("'resource_owner_password': 'レガシー対応'")) {
      errors.push(`${file}: ROPC must not be presented as a normal legacy option`);
    }
    for (const occurrence of content.matchAll(/resource_owner_password/g)) {
      const context = content.slice(occurrence.index, occurrence.index + 320);
      if (!context.includes('非推奨') || !context.includes('新規採用') || !context.includes('移行')) {
        errors.push(`${file}: every ROPC occurrence must state deprecated, no-new-adoption, and migration-only context`);
      }
    }
  }

  const source = copies.get(CHAPTER_COPIES[0]);
  for (const snippet of [
    "'status': '非推奨（新規採用不可）'",
    "'exception': '既存システムからの移行時に限る歴史的な参照'",
  ]) {
    if (!source.includes(snippet)) errors.push(`${CHAPTER_COPIES[0]}: ROPC migration-only contract is missing: ${snippet}`);
  }

  const flat = copies.get(CHAPTER_COPIES[1]);
  const route = copies.get(CHAPTER_COPIES[2]);
  if (flat !== route) errors.push('published chapter flat file and route mirror must be byte-identical');

  if (errors.length) {
    throw new Error(`OAuth PKCE/state documentation check failed:\n- ${errors.join('\n- ')}`);
  }
}

try {
  runBehaviorFixtures();
  runCheckerResistanceFixtures();
  validateDocumentation();
  console.log(`OAuth PKCE/state checker passed: ${CHAPTER_COPIES.length} active copies; behavior and checker-resistance fixtures passed.`);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
