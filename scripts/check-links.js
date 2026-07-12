#!/usr/bin/env node

/**
 * Link Checker for Book Publishing Template
 * 
 * Validates internal links in the built documentation to prevent 404 errors
 */

const fs = require('fs').promises;
const path = require('path');
const { glob } = require('glob');

const LIQUID_BASEURL = /\{\{\s*site\.baseurl\s*\}\}/g;
const LIQUID_SITE_URL = /\{\{\s*site\.url\s*\}\}/g;
const LIQUID_RELATIVE_URL = /\{\{\s*(['"])([^'"]+)\1\s*\|\s*relative_url\s*\}\}/g;
const LIQUID_LINK_TAG = /\{%\s*link\s+([^%]+?)\s*%\}/g;

// Color output for better UX
const colors = {
  green: (text) => `\x1b[32m${text}\x1b[0m`,
  red: (text) => `\x1b[31m${text}\x1b[0m`,
  yellow: (text) => `\x1b[33m${text}\x1b[0m`,
  blue: (text) => `\x1b[34m${text}\x1b[0m`
};

class LinkChecker {
  constructor() {
    this.brokenLinks = [];
    this.checkedLinks = new Set();
    this.existingFiles = new Map();
    this.anchorsByFile = new Map();
    this.publicFiles = new Set();
    this.publicTargets = new Set();
    this.skippedDynamicLinks = new Set();
    this.baseurl = '';
  }

  log(message, type = 'info') {
    const prefix = {
      info: '📝',
      success: '✅',
      warning: '⚠️',
      error: '❌'
    };
    console.log(`${prefix[type]} ${message}`);
  }

  async buildFileIndex(docsDir) {
    this.log('Building file index...');
    
    const files = await glob('**/*', {
      cwd: docsDir,
      absolute: false,
      nodir: true
    });
    
    for (const file of files) {
      const normalizedPath = file.replace(/\\/g, '/');
      this.existingFiles.set(normalizedPath, true);
      
      // Also store without extension for directory URLs
      if (normalizedPath.endsWith('/index.html')) {
        const dirPath = normalizedPath.replace('/index.html', '/');
        this.existingFiles.set(dirPath, true);
        this.existingFiles.set(dirPath.replace(/\/$/, ''), true);
      }
      
      // Store .html version for .md files
      if (normalizedPath.endsWith('.md')) {
        const htmlPath = normalizedPath.replace(/\.md$/, '.html');
        this.existingFiles.set(htmlPath, true);
      }
    }
    
    this.log(`Indexed ${files.length} files`);
  }

  async buildPublicFileSet(docsDir) {
    // _layouts/_includes are implementation details, and the flat .md files
    // beside generated route directories are legacy duplicates.  The
    // navigation/configuration is the source of truth for reader routes.
    const configPath = path.join(docsDir, '..', 'book-config.json');
    let config = {};
    try {
      config = JSON.parse(await fs.readFile(configPath, 'utf8'));
    } catch (error) {
      // A standalone docs fixture may omit book-config.json, but an existing
      // malformed or unreadable config must fail closed instead of silently
      // reducing the set of reader-facing routes to validate.
      if (error.code !== 'ENOENT') {
        throw new Error(`Unable to read or parse ${configPath}: ${error.message}`);
      }
    }
    try {
      const yaml = await fs.readFile(path.join(docsDir, '_config.yml'), 'utf8');
      const match = yaml.match(/^baseurl:\s*["']?([^"'\s]+)["']?/m);
      this.baseurl = match ? match[1].replace(/\/$/, '') : '';
    } catch (_) { this.baseurl = ''; }

    const routes = [];
    for (const section of ['introduction', 'chapters', 'appendices']) {
      for (const item of (config.structure?.[section] || [])) routes.push(item.path);
    }
    const navigation = await fs.readFile(path.join(docsDir, '_data', 'navigation.yml'), 'utf8').catch(() => '');
    for (const match of navigation.matchAll(/^\s*path:\s*["']?([^"'\s]+)["']?/gm)) routes.push(match[1]);
    const uniqueRoutes = [...new Set(['/'].concat(routes))];
    for (const route of uniqueRoutes) {
      const relative = route.replace(/^\//, '').replace(/\/$/, '');
      const candidates = route === '/'
        ? ['index.md', 'index.html']
        : [`${relative}/index.md`, `${relative}/index.html`, `${relative}.md`, `${relative}.html`];
      const candidate = candidates.find(file => this.existingFiles.has(file));
      if (candidate) {
        this.publicFiles.add(candidate);
        this.registerPublicTarget(route, candidate);
      }
    }
    // Layouts and includes are not reader routes, but their href/src values
    // are rendered into every public page. Scan them as link sources without
    // registering the template files themselves as public targets.
    for (const template of await glob('{_layouts,_includes}/**/*.{html,md}', {
      cwd: docsDir,
      nodir: true
    })) {
      this.publicFiles.add(template);
    }
    // Static assets may contain HTML entry points, but never Jekyll internals.
    for (const file of await glob('**/*.html', { cwd: docsDir, nodir: true })) {
      if (!file.startsWith('_') && !file.includes('/_')) {
        this.publicFiles.add(file);
        this.publicTargets.add(file);
      }
    }
    // Jekyll copies non-document assets below docs unless the path belongs to
    // an internal underscore directory.
    for (const file of this.existingFiles.keys()) {
      if (/\.(?:md|html?)$/i.test(file)) continue;
      if (file.split('/').some(part => part.startsWith('_') || part.startsWith('.'))) continue;
      this.publicTargets.add(file);
    }
  }

  registerPublicTarget(route, sourceFile) {
    const relativeRoute = route.replace(/^\//, '');
    for (const value of [route, relativeRoute, sourceFile]) {
      this.publicTargets.add(value.replace(/^\//, ''));
    }
    if (sourceFile.endsWith('.md')) this.publicTargets.add(sourceFile.replace(/\.md$/, '.html'));
    if (route === '/') {
      for (const value of ['', '/', 'index.md', 'index.html']) this.publicTargets.add(value);
    } else {
      const base = relativeRoute.replace(/\/$/, '');
      for (const value of [base, `${base}/`, `${base}/index.md`, `${base}/index.html`, `${base}.md`, `${base}.html`]) {
        this.publicTargets.add(value);
      }
    }
  }

  async buildAnchorIndex(docsDir) {
    for (const file of this.publicFiles) {
      if (!/\.(?:md|html?)$/i.test(file)) continue;
      const content = await fs.readFile(path.join(docsDir, file), 'utf8');
      await this.extractAnchors(file, content);
    }
  }

  async extractAnchors(filePath, content) {
    const anchors = new Set();
    
    // Extract heading IDs from markdown
    if (filePath.endsWith('.md')) {
      // Match headings with explicit IDs: ## Heading {#custom-id}
      const explicitIds = content.match(/^#+\s+.*?\{#([^}]+)\}/gm) || [];
      for (const match of explicitIds) {
        const id = match.match(/\{#([^}]+)\}/)[1];
        anchors.add(id);
      }
      
      // Match auto-generated IDs from headings
      const headings = content.match(/^#+\s+(.+?)\s*(?:\{#[^}]+\})?$/gm) || [];
      for (const heading of headings) {
        const text = heading.replace(/^#+\s+/, '').replace(/\s*\{#[^}]+\}$/, '');
        // Convert to slug (basic implementation)
        const id = text.toLowerCase()
          .replace(/[^\w\s\u3040-\u309f\u30a0-\u30ff\u4e00-\u9faf]/g, '')
          .replace(/\s+/g, '-');
        if (id) anchors.add(id);
      }
    }
    
    // Extract IDs from HTML
    const htmlIds = content.match(/\sid=["']([^"']+)["']/g) || [];
    for (const match of htmlIds) {
      const id = match.match(/id=["']([^"']+)["']/)[1];
      anchors.add(id);
    }
    
    this.anchorsByFile.set(filePath, anchors);
  }

  extractLinks(content, filePath) {
    const links = [];

    // Code examples are not reader links. Remove fenced, indented, inline and
    // HTML code regions before extracting reader-facing links.
    let withoutCode = content
      .replace(/(^|\n)([ \t]*)(`{3,}|~{3,})[^\n]*\n[\s\S]*?\n\2\3[ \t]*(?=\n|$)/g, '$1')
      .replace(/<(pre|code)\b[^>]*>[\s\S]*?<\/\1>/gi, '');
    // Indentation and backticks represent code only in Markdown. Applying
    // those removals to HTML templates would erase normally indented tags and
    // JavaScript template literals before their rendered asset links are read.
    if (filePath.endsWith('.md')) {
      withoutCode = withoutCode
        .replace(/(^|\n)(?: {4}|\t).*?(?=\n|$)/g, '$1')
        .replace(/`+[^`\n]*`+/g, '');
    }
    
    // Match markdown links: [text](url)
    const mdLinks = withoutCode.match(/(?<!!)\[([^\]]+)\]\(([^)]+)\)/g) || [];
    for (const match of mdLinks) {
      const url = match.match(/\]\(([^)]+)\)/)[1];
      links.push(url);
    }
    
    // Match HTML links: href="url"
    for (const match of withoutCode.matchAll(/href=(["'])(.*?)\1/gi)) links.push(match[2]);

    // Images are public assets and must remain covered by the link gate.
    const markdownImages = withoutCode.match(/!\[[^\]]*\]\(([^)]+)\)/g) || [];
    for (const match of markdownImages) links.push(match.match(/\]\(([^)]+)\)/)[1]);
    const htmlImages = withoutCode.match(/<img\b[^>]*>/gi) || [];
    for (const image of htmlImages) {
      const src = image.match(/\bsrc=(["'])(.*?)\1/i);
      if (src) links.push(src[2]);
    }
    
    return links;
  }

  isInternalLink(url) {
    url = url.trim();
    // Skip external URLs
    if (url.match(/^https?:\/\//)) return false;
    if (url.match(/^mailto:/)) return false;
    if (url.match(/^tel:/)) return false;
    if (url.match(/^#/)) return true; // Fragment only
    if (url.startsWith('//')) return false;
    
    return true;
  }

  resolveLink(link, fromFile, docsDir) {
    const original = link;
    link = this.normalizeLiquidUrl(link);
    if (link === null) return { skip: true, original };
    // Handle fragment-only links
    if (link.startsWith('#')) {
      return {
        file: fromFile,
        fragment: link.substring(1),
        original: link
      };
    }
    
    // Split link and fragment
    const [pathnameWithQuery, fragment] = link.split('#');
    const pathname = pathnameWithQuery.split('?', 1)[0];
    
    let resolvedPath;
    
    if (pathname.startsWith('/')) {
      // Absolute path
      resolvedPath = pathname.substring(1);
    } else {
      // Relative path
      const fromDir = path.dirname(fromFile);
      resolvedPath = path.join(fromDir, pathname).replace(/\\/g, '/');
    }
    
    // Normalize path
    resolvedPath = resolvedPath.replace(/\/+/g, '/');
    if (resolvedPath === '') resolvedPath = 'index.html';
    
    return {
      file: resolvedPath,
      fragment: fragment || null,
      original: link
    };
  }

  normalizeLiquidUrl(url) {
    const original = url.trim();
    let normalized = original
      // site.url denotes this site regardless of the Pages host used by a
      // fork or local configuration. Normalize it to the site root rather
      // than hard-coding the canonical production host.
      .replace(LIQUID_SITE_URL, '')
      .replace(LIQUID_BASEURL, this.baseurl)
      .replace(LIQUID_RELATIVE_URL, '$2')
      .replace(LIQUID_LINK_TAG, '$1');
    // A URL containing an unresolved variable cannot be checked safely. It is
    // intentionally skipped, rather than disabling checking for its file.
    if (/\{[%{].*[%}]\}/.test(normalized)) {
      this.skippedDynamicLinks.add(original);
      return null;
    }
    if (this.baseurl && normalized.startsWith(`${this.baseurl}/`)) {
      return normalized.slice(this.baseurl.length);
    }
    if (this.baseurl && normalized === this.baseurl) return '/';
    return normalized;
  }

  candidateFiles(file) {
    if (file === '' || file === '/' || file === 'index.html' || file === 'index.md') {
      return ['index.html', 'index.md', '', '/'];
    }
    const normalized = file.replace(/^\//, '');
    const base = normalized.replace(/\/$/, '');
    const candidates = [normalized];
    if (!/\.(?:md|html?)$/i.test(normalized)) {
      candidates.push(`${base}/`, `${base}/index.html`, `${base}/index.md`, `${base}.html`, `${base}.md`);
    }
    return [...new Set(candidates)];
  }

  checkLink(resolved, fromFile) {
    const { file, fragment, original } = resolved;
    
    // Check if file exists
    const candidates = this.candidateFiles(file);
    const matchingTarget = candidates.find(candidate =>
      this.existingFiles.has(candidate) && this.publicTargets.has(candidate)
    );
    const fileExists = Boolean(matchingTarget);
    
    if (!fileExists) {
      return {
        valid: false,
        file: fromFile,
        link: original,
        target: file,
        reason: candidates.some(candidate => this.existingFiles.has(candidate))
          ? 'Target is not published'
          : 'File not found'
      };
    }
    
    // Check fragment if present
    if (fragment) {
      const targetFile = matchingTarget || file;
      const anchorCandidates = [...new Set([
        targetFile,
        ...candidates,
        targetFile.replace('.html', '.md'),
        targetFile.replace(/\/index\.html$/, '/index.md'),
        targetFile.replace(/\.html$/, '/index.md')
      ])];
      const anchors = anchorCandidates.map(candidate => this.anchorsByFile.get(candidate)).find(Boolean);

      if (!anchors || !anchors.has(fragment)) {
        return {
          valid: false,
          reason: 'Anchor not found',
          file: fromFile,
          link: original,
          target: file,
          fragment: fragment
        };
      }
    }
    
    return { valid: true };
  }

  async checkFile(filePath, docsDir) {
    if (this.publicFiles.size && !this.publicFiles.has(filePath)) return;
    const fullPath = path.join(docsDir, filePath);
    const content = await fs.readFile(fullPath, 'utf-8');
    
    // Extract and check links
    const links = this.extractLinks(content, filePath);
    
    for (const link of links) {
      // Skip if already checked
      const checkKey = `${filePath}:${link}`;
      if (this.checkedLinks.has(checkKey)) continue;
      this.checkedLinks.add(checkKey);
      
      // Skip external links
      if (!this.isInternalLink(link)) continue;
      
      // Resolve and check link
      const resolved = this.resolveLink(link, filePath, docsDir);
      if (resolved.skip) continue;
      const result = this.checkLink(resolved, filePath);
      
      if (!result.valid) {
        this.brokenLinks.push(result);
      }
    }
  }

  async checkLinks(docsDir = 'docs') {
    const startTime = Date.now();
    
    try {
      // Check if docs directory exists
      await fs.access(docsDir);
    } catch (error) {
      this.log(`Directory not found: ${docsDir}`, 'error');
      return false;
    }
    
    // Build file index
    await this.buildFileIndex(docsDir);
    await this.buildPublicFileSet(docsDir);
    await this.buildAnchorIndex(docsDir);
    
    // Check all HTML and Markdown files
    const files = await glob('**/*.{html,md}', {
      cwd: docsDir,
      absolute: false
    });
    
    this.log(`Checking links in ${files.length} files...`);
    
    for (const file of files) {
      await this.checkFile(file, docsDir);
    }
    if (this.skippedDynamicLinks.size) {
      this.log(`Skipped ${this.skippedDynamicLinks.size} unresolved dynamic Liquid link(s): ${[...this.skippedDynamicLinks].join(', ')}`, 'warning');
    }
    
    // Report results
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    
    if (this.brokenLinks.length === 0) {
      this.log(`${colors.green('All links valid!')} (${this.checkedLinks.size} links checked in ${duration}s)`, 'success');
      return true;
    } else {
      this.log(`${colors.red(`Found ${this.brokenLinks.length} broken links`)} in ${duration}s`, 'error');
      
      // Group by file
      const byFile = {};
      for (const broken of this.brokenLinks) {
        if (!byFile[broken.file]) byFile[broken.file] = [];
        byFile[broken.file].push(broken);
      }
      
      // Display broken links
      console.log('\n' + colors.red('Broken Links:'));
      for (const [file, links] of Object.entries(byFile)) {
        console.log(`\n${colors.yellow(file)}:`);
        for (const link of links) {
          let message = `  ${link.link} → ${link.target}`;
          if (link.fragment) {
            message += `#${link.fragment}`;
          }
          message += ` (${link.reason})`;
          console.log(colors.red(message));
        }
      }
      
      return false;
    }
  }
}

// CLI interface
if (require.main === module) {
  const checker = new LinkChecker();
  const docsDir = process.argv[2] || 'docs';
  
  checker.checkLinks(docsDir).then(success => {
    process.exit(success ? 0 : 1);
  }).catch(error => {
    console.error(colors.red('Error:'), error.message);
    process.exit(1);
  });
}

module.exports = LinkChecker;
