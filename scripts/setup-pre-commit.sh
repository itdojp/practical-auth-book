#!/bin/bash

# Setup pre-commit hooks

echo "🆘 Setting up pre-commit hooks..."

# Check if pre-commit is installed
if ! command -v pre-commit &> /dev/null; then
    echo "pre-commit is not installed. Installing..."
    
    # Try pip first
    if command -v pip &> /dev/null; then
        pip install pre-commit
    elif command -v pip3 &> /dev/null; then
        pip3 install pre-commit
    else
        echo "ERROR: pip is not available. Please install pre-commit manually:"
        echo "  https://pre-commit.com/#installation"
        exit 1
    fi
fi

# Install the git hooks
echo "Installing git hooks..."
pre-commit install

# Run against all files to check current state
echo ""
echo "Running initial validation..."
echo "(This may take a moment on first run)"
pre-commit run --all-files || true

echo ""
echo "✅ Pre-commit hooks installed successfully!"
echo ""
echo "Hooks will now run automatically before each commit."
echo "To run manually: pre-commit run --all-files"
echo "To skip hooks: git commit --no-verify"