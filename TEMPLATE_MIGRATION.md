# Template Migration Guide

## Navigation System Update (v3.0)

This guide helps you migrate existing books to use the unified navigation system introduced in Book Publishing Template v3.0.

### What Changed

1. **Navigation is now handled by the book layout** - Individual markdown files no longer need `{% include navigation.html %}`
2. **Support for flat file structure** - Chapters can be organized as either:
   - Directory structure: `chapters/chapter-01/index.md`
   - Flat file structure: `chapters/chapter-01-title.md`
3. **Automatic navigation generation** - The build script generates `_data/navigation.yml` automatically

### Migration Steps

#### 1. Update Your Build Script

Copy the latest `scripts/build-simple.js` from the template to your book project:

```bash
cp path/to/book-publishing-template2/scripts/build-simple.js scripts/
```

#### 2. Clean Existing Navigation Includes

Run the navigation cleaner script to remove duplicate navigation includes:

```bash
# Copy the cleaner script
cp path/to/book-publishing-template2/scripts/navigation-cleaner.js scripts/

# Run the cleaner
node scripts/navigation-cleaner.js

# Review changes
git diff

# Commit if satisfied
git add -A && git commit -m "Remove duplicate navigation includes"
```

#### 3. Rebuild Your Book

```bash
npm run build
```

The build script will:
- Generate proper `_data/navigation.yml` based on your chapter structure
- Copy the v3.0 templates and includes
- NOT add navigation includes to individual files

#### 4. Verify Navigation

After rebuilding:
1. Check that `docs/_data/navigation.yml` contains all your chapters
2. Preview locally with `npm run preview`
3. Verify that:
   - Sidebar navigation shows all chapters
   - Breadcrumbs work correctly
   - Previous/Next navigation appears at the bottom of pages

### Troubleshooting

#### Navigation not showing
- Check that `docs/_data/navigation.yml` was generated correctly
- Ensure your markdown files have proper front matter with `layout: book`

#### Duplicate navigation
- Run the navigation cleaner script again
- Check that individual markdown files don't have `{% include navigation.html %}`

#### Chapters missing from navigation
- Flat structure: Ensure files are named like `chapter-01-title.md`
- Directory structure: Ensure each chapter directory has an `index.md`
- Check that chapter files have a proper H1 heading for title extraction

### Benefits of the New System

1. **Cleaner markdown files** - No navigation clutter in content files
2. **Consistent navigation** - All navigation is centrally managed
3. **Better maintainability** - Update navigation in one place
4. **Support for both structures** - Works with your existing file organization

### Need Help?

If you encounter issues during migration, please:
1. Check the troubleshooting section above
2. Review the example books in the template
3. Open an issue on the template repository