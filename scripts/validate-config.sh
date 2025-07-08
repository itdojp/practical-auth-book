#!/bin/bash

# Validate configuration files

set -e

echo "Validating configuration files..."

# Check if _config.yml exists
if [ -f "_config.yml" ]; then
    echo "Checking _config.yml..."
    
    # Check for required fields
    required_fields=("title" "description" "baseurl")
    for field in "${required_fields[@]}"; do
        if ! grep -q "^${field}:" _config.yml; then
            echo "ERROR: Missing required field '${field}' in _config.yml"
            exit 1
        fi
    done
    
    echo "✓ _config.yml validation passed"
fi

# Check if docs/_config.yml exists
if [ -f "docs/_config.yml" ]; then
    echo "Checking docs/_config.yml..."
    
    # Check for required fields
    required_fields=("title" "description" "baseurl")
    for field in "${required_fields[@]}"; do
        if ! grep -q "^${field}:" docs/_config.yml; then
            echo "ERROR: Missing required field '${field}' in docs/_config.yml"
            exit 1
        fi
    done
    
    echo "✓ docs/_config.yml validation passed"
fi

# Check book-config.json
if [ -f "book-config.json" ]; then
    echo "Checking book-config.json..."
    
    # Validate JSON syntax
    if ! python -m json.tool book-config.json > /dev/null 2>&1; then
        echo "ERROR: Invalid JSON syntax in book-config.json"
        exit 1
    fi
    
    # Check for required fields using jq if available
    if command -v jq &> /dev/null; then
        if [ -z "$(jq -r '.book.title // empty' book-config.json)" ]; then
            echo "ERROR: Missing book.title in book-config.json"
            exit 1
        fi
    fi
    
    echo "✓ book-config.json validation passed"
fi

echo "✅ All configuration files are valid"