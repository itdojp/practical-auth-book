#!/bin/bash

# Detect placeholder values in configuration files

set -e

echo "Checking for placeholder values..."

found_placeholders=0

# Common placeholders to check
placeholders=(
    "YOUR_BOOK_TITLE_HERE"
    "YOUR_BOOK_DESCRIPTION_HERE"
    "YOUR_AUTHOR_NAME"
    "YOUR_REPOSITORY_NAME_HERE"
    "YOUR_GITHUB_USERNAME"
    "your.email@example.com"
    "書籍タイトル"
    "your-book-repository-name"
)

# Check _config.yml
if [ -f "_config.yml" ]; then
    for placeholder in "${placeholders[@]}"; do
        if grep -q "$placeholder" _config.yml; then
            echo "WARNING: Found placeholder '$placeholder' in _config.yml"
            found_placeholders=1
        fi
    done
fi

# Check docs/_config.yml
if [ -f "docs/_config.yml" ]; then
    for placeholder in "${placeholders[@]}"; do
        if grep -q "$placeholder" docs/_config.yml; then
            echo "WARNING: Found placeholder '$placeholder' in docs/_config.yml"
            found_placeholders=1
        fi
    done
fi

# Check book-config.json
if [ -f "book-config.json" ]; then
    for placeholder in "${placeholders[@]}"; do
        if grep -q "$placeholder" book-config.json; then
            echo "WARNING: Found placeholder '$placeholder' in book-config.json"
            found_placeholders=1
        fi
    done
fi

if [ $found_placeholders -eq 1 ]; then
    echo ""
    echo "⚠️  Placeholder values detected!"
    echo "Please update these values before committing."
    echo "Run 'npm run setup' for interactive configuration."
    exit 1
else
    echo "✅ No placeholder values found"
fi