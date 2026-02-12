# Link Checker Documentation

## Overview

The link checker validates all internal links in your built documentation to prevent 404 errors and broken references.

## Usage

### Basic Check
```bash
# Build and check links
npm run build:validate

# Check links only (after build)
npm run check-links

# Check specific directory
node scripts/check-links.js docs
```

## Features

### 1. File Validation
- Checks if linked files exist
- Handles both .html and .md extensions
- Resolves directory URLs to index.html

### 2. Anchor Validation
- Validates fragment identifiers (#section)
- Checks heading IDs in markdown files
- Validates HTML element IDs

### 3. Smart Path Resolution
- Handles relative paths (./file.html, ../other/file.html)
- Handles absolute paths (/chapters/chapter-01.html)
- Normalizes paths with trailing slashes

### 4. Link Types Supported
- Markdown links: `[text](url)`
- HTML links: `<a href="url">`
- Image sources: `![alt](url)` and `<img src="url">`
- Fragment-only links: `#section`

### 5. External Links
Automatically skips:
- HTTP/HTTPS URLs
- mailto: links
- tel: links
- Protocol-relative URLs (//)

## Output

### Success
```text
✅ All links valid! (152 links checked in 2.35s)
```

### Errors
```text
❌ Found 3 broken links in 1.82s

Broken Links:

chapters/chapter-01.html:
  ../introduction/overview.html → introduction/overview.html (File not found)
  #non-existent-section → chapters/chapter-01.html#non-existent-section (Anchor not found)

appendices/glossary.html:
  /chapters/chapter-99.html → chapters/chapter-99.html (File not found)
```

## Integration with Build Process

### Continuous Integration
Add to your GitHub Actions workflow:

```yaml
- name: Build and validate links
  run: |
    npm install
    npm run build:validate
```

### Pre-commit Hook
Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
npm run build:validate || {
  echo "Link validation failed. Please fix broken links before committing."
  exit 1
}
```

## Troubleshooting

### Common Issues

1. **False Positives for Directory URLs**
   - The checker handles `/chapters/` → `/chapters/index.html`
   - Ensure index.html exists in directories

2. **Markdown vs HTML Extension**
   - Links to `.md` files are automatically checked as `.html`
   - Use `.html` extensions in production links

3. **Case Sensitivity**
   - File systems may be case-sensitive
   - Ensure link case matches actual files

4. **Dynamic Content**
   - JavaScript-generated anchors are not detected
   - Add explicit IDs to headings when needed

### Debug Mode

For detailed output, modify the script:
```javascript
// Add to constructor
this.debug = true;

// Add debug logging
if (this.debug) {
  console.log(`Checking: ${link} from ${file}`);
}
```

## Performance

- Caches checked links to avoid duplicates
- Builds file index before checking
- Parallel file reading for speed
- Typical performance: ~100 files/second

## Limitations

1. Does not check external URLs
2. Does not validate JavaScript-generated content
3. Does not check redirects
4. Does not validate query parameters

## Future Enhancements

- [ ] External URL validation (optional)
- [ ] Redirect chain following
- [ ] Sitemap generation from valid links
- [ ] Integration with spell checker
- [ ] Visual link map generation
