# Pre-commit Hooks Guide

## Overview

Pre-commit hooks automatically validate your changes before committing, preventing common issues from entering the repository.

## Quick Setup

```bash
# Install pre-commit hooks
./scripts/setup-pre-commit.sh

# Or manually:
pip install pre-commit
pre-commit install
```

## Included Hooks

### 1. General File Checks
- **Trailing whitespace**: Removes trailing spaces
- **End of file fixer**: Ensures files end with newline
- **YAML/JSON validation**: Checks syntax
- **Merge conflict detection**: Prevents committing conflicts
- **Private key detection**: Prevents accidental key commits
- **Line ending normalization**: Enforces LF line endings

### 2. Markdown Linting
- Enforces consistent markdown style
- Auto-fixes common issues
- Excludes generated docs/ directory

### 3. Configuration Validation
- **validate-config**: Checks _config.yml structure
- **detect-placeholders**: Warns about placeholder values
- **validate-navigation**: Verifies navigation.yml format

### 4. Content Validation
- **check-jekyll-conflicts**: Detects Liquid syntax conflicts
- Runs on all markdown files
- Suggests fixes for Podman/container syntax

## Usage

### Automatic Validation
Hooks run automatically when you commit:
```bash
git add .
git commit -m "Your message"
# Hooks run here automatically
```

### Manual Validation
Run all hooks manually:
```bash
pre-commit run --all-files
```

Run specific hook:
```bash
pre-commit run validate-config
```

### Skipping Hooks
If needed, skip hooks for a commit:
```bash
git commit --no-verify -m "Emergency fix"
```

⚠️ **Use sparingly!** Hooks exist to prevent issues.

## Hook Details

### validate-config
**Files**: `_config.yml`, `book-config.json`
**Checks**:
- Required fields present
- Valid YAML/JSON syntax
- No syntax errors

**Fix**: Update configuration files with required fields

### detect-placeholders
**Files**: Configuration files
**Checks**:
- No placeholder values like "YOUR_BOOK_TITLE_HERE"
- All values customized

**Fix**: Run `npm run setup` or manually update values

### check-jekyll-conflicts
**Files**: `*.md`, `*.markdown`
**Checks**:
- Liquid syntax conflicts ({{}} patterns)
- Container/Prometheus syntax issues

**Fix**: Escape with backslashes or use code blocks

### validate-navigation
**Files**: `navigation.yml`
**Checks**:
- Valid YAML structure
- Required title/path fields
- No empty values

**Fix**: Ensure proper YAML formatting

## Troubleshooting

### Installation Issues

**Python/pip not found**:
```bash
# macOS
brew install python3

# Ubuntu/Debian
sudo apt-get install python3-pip

# Windows
# Download from python.org
```

**Permission denied**:
```bash
# Install for user only
pip install --user pre-commit
```

### Hook Failures

**YAML validation fails**:
- Check for proper indentation (spaces, not tabs)
- Validate with online YAML validator
- Look for missing colons or quotes

**Placeholder detection triggered**:
- Run `npm run setup` to configure
- Manually edit configuration files
- Search for all "YOUR_" strings

**Jekyll conflicts detected**:
- Review the reported conflicts
- Escape with backslashes: `\{\{example\}\}`
- Use code blocks for literal syntax

### Disabling Specific Hooks

Edit `.pre-commit-config.yaml` and comment out:
```yaml
# - id: hook-to-disable
```

Or exclude files:
```yaml
- id: markdownlint
  exclude: ^docs/|^templates/|^legacy/
```

## Customization

### Adding New Hooks

1. Edit `.pre-commit-config.yaml`
2. Add new hook configuration:
```yaml
- repo: https://github.com/example/hooks
  rev: v1.0.0
  hooks:
    - id: new-hook
      args: [--fix]
```

### Custom Local Hooks

Create script in `scripts/` and add:
```yaml
- repo: local
  hooks:
    - id: my-custom-check
      name: My custom validation
      entry: scripts/my-check.sh
      language: script
      files: '\.md$'
```

### Project-Specific Rules

1. Create `.markdownlintrc` for markdown rules
2. Adjust validation scripts in `scripts/`
3. Update hook configurations as needed

## CI Integration

Pre-commit can run in CI:

```yaml
# .github/workflows/pre-commit.yml
name: pre-commit

on: [push, pull_request]

jobs:
  pre-commit:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v6
    - uses: pre-commit/action@v3.0.1
```

## Best Practices

1. **Never skip hooks in main branch**
2. **Fix issues, don't disable hooks**
3. **Run `pre-commit autoupdate` periodically**
4. **Commit `.pre-commit-config.yaml` to repo**
5. **Document custom hooks clearly**

## Uninstalling

To remove pre-commit hooks:
```bash
pre-commit uninstall
pip uninstall pre-commit
```

This removes the Git hooks but keeps the configuration file.