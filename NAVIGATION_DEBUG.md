# Navigation Debug Guide

## Enabling Debug Mode

When navigation links (previous/next) are not working correctly, you can enable debug mode to diagnose the issue.

### Method 1: Environment Variable
```bash
JEKYLL_ENV=development npm run build
```

### Method 2: Site Configuration
Add to your `_config.yml`:
```yaml
debug_navigation: true
```

## Debug Output

When enabled, HTML comments will be added to the page source showing:
- Current page URL
- Total navigation items
- URL normalization process for each item
- Match status for current page
- Previous/Next item details

### Example Debug Output
```html
<!-- Navigation Debug Info -->
<!-- Current page URL: /chapters/chapter-02.html -->
<!-- Total navigation items: 17 -->
<!-- Debug item 1: path="/introduction/" clean="introduction/" normalized="introduction/" -->
<!-- Debug item 2: path="/chapters/chapter-01.html" clean="chapters/chapter-01.html" normalized="chapters/chapter-01.html" -->
<!-- Debug item 3: path="/chapters/chapter-02.html" clean="chapters/chapter-02.html" normalized="chapters/chapter-02.html" -->
<!-- ✓ MATCH FOUND at index 2 -->
<!-- Current page index: 2 -->
<!-- Previous item: 第1章：ITインフラの全体像とLinuxの位置づけ (index: 1) -->
<!-- Next item: 第3章：ファイルシステムという抽象化の威力 (index: 3) -->
<!-- End Debug Info -->
```

## Common Issues

### 1. Page Not Found in Navigation
If you see `Current page index: NOT_FOUND`, check:
- Does the page URL match exactly with a path in `navigation.yml`?
- Are file extensions consistent? (`.html` vs no extension)
- Is the page included in `navigation.yml`?

### 2. URL Mismatch
Compare the "Page URL normalized" with navigation paths:
- `/chapters/chapter-01` vs `/chapters/chapter-01.html`
- `/introduction/` vs `/introduction`

### 3. Missing Navigation Data
If `Total navigation items: 0`:
- Check that `_data/navigation.yml` exists
- Verify the YAML syntax is correct
- Ensure the build process completed successfully

## Troubleshooting Steps

1. Enable debug mode
2. View page source (Ctrl+U / Cmd+U)
3. Search for "Navigation Debug Info"
4. Check the debug output
5. Fix mismatches in `navigation.yml` or file names
6. Rebuild and test again

## Disabling Debug Mode

Remember to disable debug mode before deploying:
1. Remove `debug_navigation: true` from `_config.yml`
2. Use production build: `npm run build` (without JEKYLL_ENV=development)