#!/usr/bin/env node

/**
 * Navigation Cleaner Script
 * Removes legacy navigation includes from markdown files
 * to prevent duplicate navigation when using the book layout
 */

const fs = require('fs').promises;
const path = require('path');

class NavigationCleaner {
  constructor() {
    this.processedCount = 0;
    this.cleanedCount = 0;
  }

  async cleanDirectory(dirPath) {
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        if (entry.isDirectory()) {
          await this.cleanDirectory(fullPath);
        } else if (entry.isFile() && entry.name.endsWith('.md')) {
          await this.cleanMarkdownFile(fullPath);
        }
      }
    } catch (error) {
      console.error(`Error processing directory ${dirPath}:`, error.message);
    }
  }

  async cleanMarkdownFile(filePath) {
    try {
      let content = await fs.readFile(filePath, 'utf-8');
      const originalContent = content;
      
      // Remove navigation includes
      // Pattern 1: {% include navigation.html %}
      content = content.replace(/\{%\s*include\s+navigation\.html\s*%\}/g, '');
      
      // Pattern 2: Remove empty lines left by removal
      content = content.replace(/\n\n\n+/g, '\n\n');
      
      // Pattern 3: Clean up navigation at the beginning of file (after front matter)
      content = content.replace(/^(---[\s\S]*?---\n)\n*/, '$1\n');
      
      // Pattern 4: Clean up navigation at the end of file
      content = content.replace(/\n*$/, '\n');
      
      this.processedCount++;
      
      if (content !== originalContent) {
        await fs.writeFile(filePath, content, 'utf-8');
        this.cleanedCount++;
        console.log(`✅ Cleaned: ${path.relative(process.cwd(), filePath)}`);
      }
    } catch (error) {
      console.error(`Error processing file ${filePath}:`, error.message);
    }
  }

  async clean() {
    console.log('🧹 Starting navigation cleanup...\n');
    
    const publicDir = path.join(process.cwd(), 'docs');
    
    try {
      await fs.access(publicDir);
    } catch {
      console.error('❌ Error: docs/ directory not found');
      console.log('Please run this script from the project root directory');
      process.exit(1);
    }
    
    await this.cleanDirectory(publicDir);
    
    console.log('\n✨ Cleanup complete!');
    console.log(`📄 Files processed: ${this.processedCount}`);
    console.log(`🔧 Files cleaned: ${this.cleanedCount}`);
    
    if (this.cleanedCount > 0) {
      console.log('\n💡 Next steps:');
      console.log('1. Review the changes with: git diff');
      console.log('2. Commit the changes: git add -A && git commit -m "Remove duplicate navigation includes"');
      console.log('3. Test the site locally: npm run preview');
    }
  }
}

// Run if called directly
if (require.main === module) {
  const cleaner = new NavigationCleaner();
  cleaner.clean().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

module.exports = NavigationCleaner;