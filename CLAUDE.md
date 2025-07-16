# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Japanese-language technical book project: "実践 認証認可システム設計 - 認証・認可システムの設計と実装を体系的に学ぶ実践的な技術書"

## Book Framework Migration

**IMPORTANT**: This book has been migrated to **book-formatter**.

- ✅ **Current**: Uses book-formatter system
- ❌ **Deprecated**: book-publishing-template2 (no longer supported)

## Key Commands and Workflows

### Development
```bash
npm start                    # Start Jekyll development server
npm run build               # Build the book for production
npm run preview             # Local preview of built book
npm run deploy              # Deploy to GitHub Pages
```

### Content Management
```bash
npm run lint                # Check markdown formatting
npm run check-links         # Validate internal links
npm test                    # Run all tests (lint + links)
npm run clean               # Clean build artifacts
```

## Contact Information

**Author**: ITDO Inc.（株式会社アイティードゥ）  
**Email**: knowledge@itdo.jp  
**GitHub**: [@itdojp](https://github.com/itdojp)
EOF < /dev/null
