#!/usr/bin/env node

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const LinkChecker = require('./check-links');

const root = path.resolve('temp/check-links-fixture');
const docs = path.join(root, 'docs');

function write(relativePath, content) {
  const target = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
}

function resetFixture(indexContent) {
  fs.rmSync(root, { recursive: true, force: true });
  write('book-config.json', JSON.stringify({
    structure: {
      introduction: [{ path: '/guide/' }],
      chapters: [],
      appendices: []
    }
  }));
  write('docs/_config.yml', 'baseurl: "/practical-auth-book"\n');
  write('docs/_data/navigation.yml', '- title: Guide\n  path: /guide/\n');
  write('docs/index.md', indexContent);
  write('docs/guide/index.md', '# Guide\n\n## Target {#target}\n');
  write('docs/assets/diagram.svg', '<svg xmlns="http://www.w3.org/2000/svg"></svg>\n');
  write('docs/legacy.md', '# Legacy\n');
}

async function run(indexContent, expected, label) {
  resetFixture(indexContent);
  const result = await new LinkChecker().checkLinks(docs);
  assert.equal(result, expected, label);
}

const valid = `# Home

[guide]({{ site.baseurl }}/guide/#target)
![diagram]({{ '/assets/diagram.svg' | relative_url }})
[dynamic]({{ page.dynamic_url }})

\`[inline code](missing-inline.md)\`

    [indented code](missing-indented.md)

<pre><a href="missing-pre.html">code</a></pre>

~~~text
[fenced code](missing-fenced.md)
~~~
`;

(async () => {
  try {
    await run(valid, true, 'valid routes, image and cross-file anchor must pass');
    await run(valid.replace('/assets/diagram.svg', '/assets/missing.svg'), false, 'missing image must fail');
    await run(valid.replace('#target', '#missing-anchor'), false, 'cross-file missing anchor must fail');
    await run(`${valid}\n[legacy](legacy.md)\n`, false, 'unpublished legacy document must fail');
    await run(`${valid}\n[root](/#missing-root)\n`, false, 'missing root anchor must fail');
    console.log('Link checker fixtures passed.');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
