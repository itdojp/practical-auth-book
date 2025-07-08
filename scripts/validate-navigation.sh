#!/bin/bash

# Validate navigation.yml structure

set -e

echo "Validating navigation structure..."

# Check for navigation files
navigation_files=(
    "docs/_data/navigation.yml"
    "_data/navigation.yml"
)

found_navigation=0

for nav_file in "${navigation_files[@]}"; do
    if [ -f "$nav_file" ]; then
        echo "Checking $nav_file..."
        found_navigation=1
        
        # Basic YAML syntax check
        if ! python -c "import yaml; yaml.safe_load(open('$nav_file'))" 2>/dev/null; then
            # Fallback to basic syntax check if PyYAML not available
            if grep -E '^[[:space:]]*-[[:space:]]*$' "$nav_file" > /dev/null; then
                echo "ERROR: Found empty list items in $nav_file"
                exit 1
            fi
        fi
        
        # Check for required structure
        if ! grep -q "title:" "$nav_file"; then
            echo "ERROR: No 'title' fields found in $nav_file"
            exit 1
        fi
        
        if ! grep -q "path:" "$nav_file"; then
            echo "ERROR: No 'path' fields found in $nav_file"
            exit 1
        fi
        
        # Check for common issues
        if grep -E 'path:[[:space:]]*""' "$nav_file" > /dev/null; then
            echo "ERROR: Empty path values found in $nav_file"
            exit 1
        fi
        
        if grep -E 'title:[[:space:]]*""' "$nav_file" > /dev/null; then
            echo "ERROR: Empty title values found in $nav_file"
            exit 1
        fi
        
        echo "✓ $nav_file validation passed"
    fi
done

if [ $found_navigation -eq 0 ]; then
    echo "WARNING: No navigation.yml file found"
    echo "Navigation will be generated during build"
fi

echo "✅ Navigation validation complete"