#!/usr/bin/env node

/**
 * 🚀 Simplified Build Script
 * 
 * 複雑な依存関係を排除し、基本的なビルド機能のみを提供
 * 使い勝手を重視した軽量版ビルドスクリプト
 */

const fs = require('fs').promises;
const path = require('path');

// Color output for better UX
const colors = {
  green: (text) => `\x1b[32m${text}\x1b[0m`,
  blue: (text) => `\x1b[34m${text}\x1b[0m`,
  yellow: (text) => `\x1b[33m${text}\x1b[0m`,
  red: (text) => `\x1b[31m${text}\x1b[0m`
};

class SimpleBuild {
  constructor() {
    this.config = null;
    this.processedFiles = 0;
  }

  log(message, type = 'info') {
    const prefix = {
      info: '📝',
      success: '✅',
      warning: '⚠️',
      error: '❌'
    };
    console.log(`${prefix[type]} ${message}`);
  }

  async validateConfig() {
    this.log('設定ファイルの検証を開始します...');
    
    const configPath = path.join(process.cwd(), 'docs', '_config.yml');
    
    try {
      const content = await fs.readFile(configPath, 'utf-8');
      
      const placeholders = [
        'YOUR_BOOK_TITLE_HERE',
        'YOUR_BOOK_DESCRIPTION_HERE',
        'YOUR_AUTHOR_NAME',
        'YOUR_REPOSITORY_NAME_HERE',
        'YOUR_GITHUB_USERNAME',
        'your.email@example.com',
        '書籍タイトル',
        'your-book-repository-name'
      ];
      
      const warnings = [];
      const errors = [];
      
      // Check for placeholder values
      placeholders.forEach(placeholder => {
        if (content.includes(placeholder)) {
          warnings.push(`⚠️  プレースホルダーが見つかりました: "${placeholder}"`);
        }
      });
      
      // Parse YAML-like structure for required fields
      const lines = content.split('\n');
      const configData = {};
      
      lines.forEach(line => {
        if (line.includes(':') && !line.trim().startsWith('#')) {
          const [key, ...valueParts] = line.split(':');
          const value = valueParts.join(':').trim().replace(/["']/g, '');
          if (key && value) {
            configData[key.trim()] = value;
          }
        }
      });
      
      // Check required fields
      const required = ['title', 'description', 'baseurl'];
      required.forEach(field => {
        if (!configData[field] || configData[field].length === 0) {
          errors.push(`❌ 必須フィールドが未設定です: ${field}`);
        }
      });
      
      // Report results
      if (errors.length > 0) {
        this.log('設定エラーが見つかりました:', 'error');
        errors.forEach(error => this.log(error, 'error'));
        throw new Error('設定の検証に失敗しました');
      }
      
      if (warnings.length > 0) {
        this.log('設定に関する警告:', 'warning');
        warnings.forEach(warning => this.log(warning, 'warning'));
        this.log('デプロイ前にこれらの値を更新することを検討してください', 'warning');
      } else {
        this.log('設定の検証が完了しました ✓', 'success');
      }
    } catch (error) {
      if (error.code === 'ENOENT') {
        this.log('_config.yml が見つかりません', 'warning');
        this.log('ビルド後に生成されます', 'info');
      } else if (error.message === '設定の検証に失敗しました') {
        throw error;
      } else {
        this.log(`設定の検証中にエラーが発生しました: ${error.message}`, 'error');
      }
    }
  }

  async loadConfig() {
    try {
      const configPath = path.join(process.cwd(), 'book-config.json');
      const configContent = await fs.readFile(configPath, 'utf-8');
      this.config = JSON.parse(configContent);
      this.log('設定ファイルを読み込みました');
    } catch (error) {
      // Fallback to default config
      this.config = {
        book: { title: 'My Book', author: { name: 'Author' } },
        contentSections: [
          { name: 'introduction', directory: 'introduction', enabled: true, order: 1 },
          { name: 'chapters', directory: 'chapters', enabled: true, order: 2 },
          { name: 'appendices', directory: 'appendices', enabled: true, order: 3 },
          { name: 'afterword', directory: 'afterword', enabled: true, order: 4 }
        ],
        excludePatterns: ['draft.md', '*.tmp'],
        contentExcludePatterns: ['<!-- PRIVATE:', '<!-- TODO:']
      };
      this.log('デフォルト設定を使用します', 'warning');
    }
  }

  async createPublicDirectory() {
    const publicDir = path.join(process.cwd(), 'docs');
    const indexPath = path.join(publicDir, 'index.md');
    let indexBackup = null;
    
    try {
      await fs.access(publicDir);
      
      // Backup index.md if it exists and has substantial content
      try {
        const indexContent = await fs.readFile(indexPath, 'utf-8');
        if (indexContent.length > 200) {
          indexBackup = indexContent;
          this.log('index.mdをバックアップしました');
        }
      } catch {
        // index.md doesn't exist, continue
      }
      
      // Clean existing directory
      await fs.rm(publicDir, { recursive: true, force: true });
    } catch {
      // Directory doesn't exist, which is fine
    }
    
    await fs.mkdir(publicDir, { recursive: true });
    
    // Restore index.md if we had a backup
    if (indexBackup) {
      await fs.writeFile(indexPath, indexBackup, 'utf-8');
      this.log('index.mdを復元しました');
    }
    
    this.log('公開ディレクトリを準備しました');
    return publicDir;
  }

  async processContentSections(srcDir, publicDir) {
    const sections = this.config.contentSections
      .filter(section => section.enabled)
      .sort((a, b) => (a.order || 0) - (b.order || 0));

    for (const section of sections) {
      await this.processSection(
        path.join(srcDir, section.directory),
        path.join(publicDir, section.directory),
        section
      );
    }
  }

  async processSection(srcPath, destPath, section) {
    try {
      await fs.access(srcPath);
      
      await fs.mkdir(destPath, { recursive: true });
      const entries = await fs.readdir(srcPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const srcFile = path.join(srcPath, entry.name);
        const destFile = path.join(destPath, entry.name);
        
        if (entry.isDirectory()) {
          // Recursively process subdirectories
          await this.processDirectory(srcFile, destFile);
        } else if (entry.isFile() && this.shouldIncludeFile(entry.name)) {
          if (entry.name.endsWith('.md')) {
            await this.processMarkdownFile(srcFile, destFile);
          } else {
            await this.copyFile(srcFile, destFile);
          }
          this.processedFiles++;
        }
      }
      
      this.log(`${section.directory} を処理しました`);
    } catch (error) {
      if (error.code === 'ENOENT') {
        this.log(`${section.directory} ディレクトリが見つかりません`, 'warning');
      } else {
        throw error;
      }
    }
  }

  async processDirectory(srcPath, destPath) {
    await fs.mkdir(destPath, { recursive: true });
    const entries = await fs.readdir(srcPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const srcFile = path.join(srcPath, entry.name);
      const destFile = path.join(destPath, entry.name);
      
      if (entry.isDirectory()) {
        await this.processDirectory(srcFile, destFile);
      } else if (entry.isFile() && this.shouldIncludeFile(entry.name)) {
        if (entry.name.endsWith('.md')) {
          await this.processMarkdownFile(srcFile, destFile);
        } else {
          await this.copyFile(srcFile, destFile);
        }
        this.processedFiles++;
      }
    }
  }

  shouldIncludeFile(filename) {
    const excludePatterns = this.config.excludePatterns || [];
    
    for (const pattern of excludePatterns) {
      if (pattern.includes('*')) {
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        if (regex.test(filename)) return false;
      } else if (filename === pattern) {
        return false;
      }
    }
    
    return true;
  }

  async processMarkdownFile(srcPath, destPath) {
    let content = await fs.readFile(srcPath, 'utf-8');
    
    // Remove private content
    const excludePatterns = this.config.contentExcludePatterns || [];
    for (const pattern of excludePatterns) {
      const regex = new RegExp(`${this.escapeRegex(pattern)}.*?-->`, 'gs');
      content = content.replace(regex, '');
    }
    
    // Add Jekyll Front Matter if not present
    if (!content.trimStart().startsWith('---')) {
      const titleMatch = content.match(/^#\s+(.+)$/m);
      const title = titleMatch ? titleMatch[1] : 'Page';
      
      const frontMatter = `---
layout: book
title: "${title}"
---

`;
      content = frontMatter + content;
    }
    
    await fs.writeFile(destPath, content, 'utf-8');
  }

  async copyFile(srcPath, destPath) {
    await fs.mkdir(path.dirname(destPath), { recursive: true });
    await fs.copyFile(srcPath, destPath);
  }

  escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  async copyAssets(srcDir, publicDir) {
    const assetsPath = path.join(srcDir, '..', 'assets');
    const publicAssetsPath = path.join(publicDir, 'assets');
    
    try {
      await fs.access(assetsPath);
      await this.copyDirectory(assetsPath, publicAssetsPath);
      this.log('アセットをコピーしました');
    } catch {
      this.log('アセットディレクトリが見つかりません', 'warning');
    }
  }

  async copyDirectory(srcDir, destDir) {
    await fs.mkdir(destDir, { recursive: true });
    const entries = await fs.readdir(srcDir, { withFileTypes: true });
    
    for (const entry of entries) {
      const srcPath = path.join(srcDir, entry.name);
      const destPath = path.join(destDir, entry.name);
      
      if (entry.isDirectory()) {
        await this.copyDirectory(srcPath, destPath);
      } else {
        await fs.copyFile(srcPath, destPath);
      }
    }
  }

  async generateIndex(publicDir) {
    const indexPath = path.join(publicDir, 'index.md');
    
    // Check if index.md already exists with substantial content
    try {
      const existingContent = await fs.readFile(indexPath, 'utf-8');
      if (existingContent.length > 200) {
        this.log('既存のindex.mdを保持します');
        return;
      }
    } catch {
      // File doesn't exist, generate new one
    }
    
    // Try to use custom index.md from project root first
    const customIndexPath = path.join(process.cwd(), 'index.md');
    try {
      await fs.access(customIndexPath);
      await fs.copyFile(customIndexPath, indexPath);
      this.log('カスタムindex.mdをコピーしました');
      return;
    } catch {
      // No custom index.md, generate from template
    }
    
    // Generate basic index.md with correct author information
    const book = this.config.book || {};
    const author = book.author || {};
    const authorName = author.name || 'Author';
    
    const indexContent = `# ${book.title || 'Book Title'}

${book.subtitle ? book.subtitle + '\n\n' : ''}## 概要

${book.description || 'Book description'}

## 目次

- [はじめに](introduction/)
- [第1章](chapters/chapter01/)

---

## 著者について

**${authorName}**

${author.email ? `- Email: [${author.email}](mailto:${author.email})\n` : ''}${author.github ? `- GitHub: [@${author.github}](https://github.com/${author.github})\n` : ''}
## ライセンス

${book.license || `© 2025 ${authorName}. All rights reserved.`}

---

Built with [Book Publishing Template v3.0](https://github.com/itdojp/book-publishing-template2)
`;

    await fs.writeFile(indexPath, indexContent);
    this.log('インデックスページを生成しました');
  }

  async copyJekyllConfig(publicDir) {
    const configPath = path.join(process.cwd(), '_config.yml');
    const destPath = path.join(publicDir, '_config.yml');
    
    try {
      await fs.access(configPath);
      await fs.copyFile(configPath, destPath);
      this.log('Jekyll設定をコピーしました');
    } catch {
      // Generate v3.0 Jekyll config with custom layout
      // Extract repository info from package.json or git if available
      let repoName = '';
      let userName = '';
      try {
        const packageJson = JSON.parse(await fs.readFile(path.join(process.cwd(), 'package.json'), 'utf-8'));
        if (packageJson.repository?.url) {
          const match = packageJson.repository.url.match(/github\.com[/:](.*?)\/(.+?)(?:\.git)?$/);
          if (match) {
            userName = match[1];
            repoName = match[2];
          }
        }
      } catch {
        // No package.json found
      }
      
      // Try git remote as another source
      if (!repoName) {
        try {
          const { execSync } = require('child_process');
          const gitRemote = execSync('git remote get-url origin', { encoding: 'utf8' }).trim();
          const match = gitRemote.match(/github\.com[/:](.*?)\/(.+?)(?:\.git)?$/);
          if (match) {
            userName = match[1];
            repoName = match[2];
          }
        } catch {
          // Git not available or no remote
        }
      }
      
      // Fallback to directory name if not found in package.json or git
      if (!repoName) {
        repoName = path.basename(process.cwd());
      }
      
      this.log(`Repository detection: user=${userName}, repo=${repoName}`);

      const baseurl = repoName ? `/${repoName}` : '';
      const url = userName ? `https://${userName}.github.io` : '';
      const githubRepo = (userName && repoName) ? `${userName}/${repoName}` : '';

      const defaultConfig = `title: "${this.config.book?.title || 'My Book'}"
description: "${this.config.book?.description || 'Book description'}"
author: "${this.config.book?.author?.name || 'Author'}"
baseurl: "${baseurl}"
url: "${url}"

# v3.0 Design System Configuration
markdown: kramdown
highlighter: rouge

# Use custom book layout as default
defaults:
  - scope:
      path: ""
      type: "pages"
    values:
      layout: "book"

# plugins:
#   - jekyll-feed

# Repository information for edit links
repository:
  github: "${githubRepo}"

exclude:
  - node_modules/
  - scripts/
  - templates/
  - src/
  - package*.json
  - README.md
  - "*.tmp"
  - Gemfile*
`;
      await fs.writeFile(destPath, defaultConfig);
      this.log('v3.0 Jekyll設定を生成しました');
    }
    
    // Copy Gemfile for GitHub Pages compatibility
    const gemfilePath = path.join(__dirname, '..', 'templates', 'Gemfile');
    const destGemfilePath = path.join(publicDir, 'Gemfile');
    try {
      await fs.copyFile(gemfilePath, destGemfilePath);
      this.log('Gemfileをコピーしました');
    } catch {
      this.log('Gemfileが見つかりません', 'warning');
    }
  }

  async copyWorkflowTemplates(publicDir) {
    // Create .github/workflows directory
    const workflowDir = path.join(process.cwd(), '.github', 'workflows');
    try {
      await fs.mkdir(workflowDir, { recursive: true });
      
      // Check if build.yml already exists
      const buildYmlPath = path.join(workflowDir, 'build.yml');
      try {
        await fs.access(buildYmlPath);
        this.log('既存のGitHub Actionsワークフローを保持します');
        return;
      } catch {
        // File doesn't exist, copy template
      }
      
      // Copy legacy workflow as default (more reliable)
      const legacyWorkflowPath = path.join(__dirname, '..', 'templates', 'github-workflows', 'build-legacy.yml');
      try {
        await fs.copyFile(legacyWorkflowPath, buildYmlPath);
        this.log('GitHub Actionsワークフロー（Legacy版）をコピーしました');
      } catch {
        this.log('ワークフローテンプレートが見つかりません', 'warning');
      }
    } catch (error) {
      this.log(`ワークフローのコピーに失敗: ${error.message}`, 'warning');
    }
  }

  async generateNavigationData(srcDir, publicDir) {
    const navigationData = {
      introduction: [],
      chapters: [],
      appendices: [],
      afterword: []
    };

    // Process introduction (only if enabled)
    const introductionSection = this.config.contentSections.find(s => s.name === 'introduction');
    if (introductionSection && introductionSection.enabled) {
      const introductionPath = path.join(srcDir, 'introduction');
      try {
        const indexPath = path.join(introductionPath, 'index.md');
        const content = await fs.readFile(indexPath, 'utf-8');
        const titleMatch = content.match(/^#\s+(.+)$/m);
        const title = titleMatch ? titleMatch[1] : 'はじめに';
        
        navigationData.introduction.push({
          title: title,
          path: '/introduction/'
        });
      } catch {
        this.log('はじめにのindex.mdが見つかりません', 'warning');
      }
    }

    // Process chapters - now supports both directory and flat file structure
    const chaptersPath = path.join(srcDir, 'chapters');
    try {
      const entries = await fs.readdir(chaptersPath, { withFileTypes: true });
      const chapterItems = [];
      
      // Process both directories and flat files
      for (const entry of entries) {
        if (entry.isDirectory()) {
          // Directory structure: chapters/chapter-01/index.md
          const indexPath = path.join(chaptersPath, entry.name, 'index.md');
          try {
            const content = await fs.readFile(indexPath, 'utf-8');
            const titleMatch = content.match(/^#\s+(.+)$/m);
            const title = titleMatch ? titleMatch[1] : `第${entry.name.match(/\d+/)?.[0]}章`;
            const chapterNum = parseInt(entry.name.match(/\d+/)?.[0] || '0');
            
            chapterItems.push({
              title: title,
              path: `/chapters/${entry.name}/`,
              order: chapterNum,
              type: 'directory'
            });
          } catch {
            // Skip if index.md doesn't exist
          }
        } else if (entry.isFile() && entry.name.endsWith('.md') && entry.name !== 'index.md') {
          // Flat file structure: chapters/01-basic-features.md
          const filePath = path.join(chaptersPath, entry.name);
          try {
            const content = await fs.readFile(filePath, 'utf-8');
            const titleMatch = content.match(/^#\s+(.+)$/m);
            const title = titleMatch ? titleMatch[1] : entry.name.replace('.md', '');
            const chapterNum = parseInt(entry.name.match(/\d+/)?.[0] || '0');
            
            chapterItems.push({
              title: title,
              path: `/chapters/${entry.name.replace('.md', '.html')}`,
              order: chapterNum,
              type: 'file'
            });
          } catch {
            // Skip if file can't be read
          }
        }
      }
      
      // Sort chapters by order number
      const sortedChapters = chapterItems.sort((a, b) => a.order - b.order);
      
      // Add to navigation data without the order property
      for (const chapter of sortedChapters) {
        navigationData.chapters.push({
          title: chapter.title,
          path: chapter.path
        });
      }
    } catch {
      this.log('章ディレクトリが見つかりません', 'warning');
    }

    // Process appendices (only if enabled) - supports both directory and flat file structure
    const appendicesSection = this.config.contentSections.find(s => s.name === 'appendices');
    if (appendicesSection && appendicesSection.enabled) {
      const appendicesPath = path.join(srcDir, 'appendices');
      try {
        const entries = await fs.readdir(appendicesPath, { withFileTypes: true });
        const appendixItems = [];
        
        // Process both directories and flat files
        for (const entry of entries) {
          if (entry.isDirectory()) {
            // Directory structure: appendices/appendix-a/index.md
            const indexPath = path.join(appendicesPath, entry.name, 'index.md');
            try {
              const content = await fs.readFile(indexPath, 'utf-8');
              const titleMatch = content.match(/^#\s+(.+)$/m);
              const title = titleMatch ? titleMatch[1] : `付録${entry.name.replace('appendix-', '').toUpperCase()}`;
              
              appendixItems.push({
                title: title,
                path: `/appendices/${entry.name}/`,
                order: entry.name
              });
            } catch {
              // Skip if index.md doesn't exist
            }
          } else if (entry.isFile() && entry.name.endsWith('.md') && entry.name !== 'index.md') {
            // Flat file structure: appendices/appendix-a-title.md
            const filePath = path.join(appendicesPath, entry.name);
            try {
              const content = await fs.readFile(filePath, 'utf-8');
              const titleMatch = content.match(/^#\s+(.+)$/m);
              const title = titleMatch ? titleMatch[1] : entry.name.replace('.md', '');
              
              appendixItems.push({
                title: title,
                path: `/appendices/${entry.name.replace('.md', '.html')}`,
                order: entry.name
              });
            } catch {
              // Skip if file can't be read
            }
          }
        }
        
        // Sort appendices alphabetically
        const sortedAppendices = appendixItems.sort((a, b) => a.order.localeCompare(b.order));
        
        // Add to navigation data without the order property
        for (const appendix of sortedAppendices) {
          navigationData.appendices.push({
            title: appendix.title,
            path: appendix.path
          });
        }
      } catch {
        this.log('付録ディレクトリが見つかりません', 'warning');
      }
    }

    // Process afterword (only if enabled)
    const afterwordSection = this.config.contentSections.find(s => s.name === 'afterword');
    if (afterwordSection && afterwordSection.enabled) {
      const afterwordPath = path.join(srcDir, 'afterword');
      try {
        const indexPath = path.join(afterwordPath, 'index.md');
        const content = await fs.readFile(indexPath, 'utf-8');
        const titleMatch = content.match(/^#\s+(.+)$/m);
        const title = titleMatch ? titleMatch[1] : 'あとがき';
        
        navigationData.afterword.push({
          title: title,
          path: '/afterword/'
        });
      } catch {
        this.log('あとがきのindex.mdが見つかりません', 'warning');
      }
    }

    // Write navigation data
    const dataDir = path.join(publicDir, '_data');
    await fs.mkdir(dataDir, { recursive: true });
    
    // Build navigation YAML with only sections that have content
    let navigationYaml = '# Navigation configuration\n';
    
    if (navigationData.introduction.length > 0) {
      navigationYaml += 'introduction:\n';
      navigationYaml += navigationData.introduction.map(intro => 
        `  - title: "${intro.title}"\n    path: "${intro.path}"`).join('\n') + '\n\n';
    }
    
    if (navigationData.chapters.length > 0) {
      navigationYaml += 'chapters:\n';
      navigationYaml += navigationData.chapters.map(ch => 
        `  - title: "${ch.title}"\n    path: "${ch.path}"`).join('\n') + '\n\n';
    }
    
    if (navigationData.appendices.length > 0) {
      navigationYaml += 'appendices:\n';
      navigationYaml += navigationData.appendices.map(ap => 
        `  - title: "${ap.title}"\n    path: "${ap.path}"`).join('\n') + '\n\n';
    }
    
    if (navigationData.afterword.length > 0) {
      navigationYaml += 'afterword:\n';
      navigationYaml += navigationData.afterword.map(after => 
        `  - title: "${after.title}"\n    path: "${after.path}"`).join('\n') + '\n';
    }
    
    await fs.writeFile(path.join(dataDir, 'navigation.yml'), navigationYaml);
    
    this.log('ナビゲーションデータを生成しました');
  }

  async copyV3DesignSystem(publicDir) {
    const templatesDir = path.join(__dirname, '..', 'templates');
    
    // Copy CSS files
    const assetsDir = path.join(publicDir, 'assets');
    const cssDir = path.join(assetsDir, 'css');
    const jsDir = path.join(assetsDir, 'js');
    
    await fs.mkdir(cssDir, { recursive: true });
    await fs.mkdir(jsDir, { recursive: true });
    
    // Copy CSS files
    const cssFiles = ['main.css', 'syntax-highlighting.css'];
    for (const cssFile of cssFiles) {
      try {
        const cssPath = path.join(templatesDir, 'styles', cssFile);
        await fs.copyFile(cssPath, path.join(cssDir, cssFile));
      } catch {
        this.log(`${cssFile}が見つかりません`, 'warning');
      }
    }
    this.log('CSSファイルをコピーしました');
    
    // Copy JavaScript files
    const jsFiles = ['theme.js', 'sidebar.js', 'code-copy.js'];
    for (const jsFile of jsFiles) {
      try {
        const jsPath = path.join(templatesDir, 'js', jsFile);
        await fs.copyFile(jsPath, path.join(jsDir, jsFile));
      } catch {
        this.log(`${jsFile}が見つかりません`, 'warning');
      }
    }
    this.log('JavaScriptファイルをコピーしました');
    
    // Copy layout files
    const layoutsDir = path.join(publicDir, '_layouts');
    await fs.mkdir(layoutsDir, { recursive: true });
    
    try {
      const bookLayoutPath = path.join(templatesDir, 'layouts', 'book.html');
      await fs.copyFile(bookLayoutPath, path.join(layoutsDir, 'book.html'));
      this.log('書籍レイアウトをコピーしました');
    } catch {
      this.log('書籍レイアウトが見つかりません', 'warning');
    }
    
    // Copy include files
    const includesDir = path.join(publicDir, '_includes');
    await fs.mkdir(includesDir, { recursive: true });
    
    const includeFiles = ['sidebar-nav.html', 'breadcrumb.html', 'page-navigation.html'];
    for (const includeFile of includeFiles) {
      try {
        const includePath = path.join(templatesDir, 'includes', includeFile);
        await fs.copyFile(includePath, path.join(includesDir, includeFile));
      } catch {
        this.log(`${includeFile}が見つかりません`, 'warning');
      }
    }
    this.log('Includeファイルをコピーしました');
    
    // Copy legacy navigation for backward compatibility
    try {
      const navigationTemplatePath = path.join(templatesDir, 'navigation', 'navigation.html');
      await fs.copyFile(navigationTemplatePath, path.join(includesDir, 'navigation.html'));
      this.log('レガシーナビゲーションをコピーしました');
    } catch {
      // Legacy navigation is optional
    }
  }

  async addNavigationToMarkdownFiles(publicDir) {
    // Check if auto navigation is enabled (defaults to false for v3.0)
    const enableAutoNavigation = this.config.build?.enableAutoNavigation ?? false;
    
    if (!enableAutoNavigation) {
      this.log('Navigation handled by layout - skipping individual file injection', 'info');
      this.log('To enable auto navigation, set "build.enableAutoNavigation": true in book-config.json', 'info');
      return;
    }
    
    this.log('Auto navigation enabled - adding navigation to individual files', 'warning');
    this.log('Note: This may cause duplication if using book layout', 'warning');
    
    const addNavigation = async (dirPath) => {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        if (entry.isDirectory()) {
          await addNavigation(fullPath);
        } else if (entry.isFile() && entry.name.endsWith('.md') && entry.name !== 'index.md') {
          // Skip the root index.md
          const relativePath = path.relative(publicDir, fullPath);
          if (relativePath === 'index.md') continue;
          
          let content = await fs.readFile(fullPath, 'utf-8');
          
          // Check if navigation is already included to prevent duplication
          if (!content.includes('{% include navigation.html %}')) {
            // Add navigation at the end
            content = content.trimEnd() + '\n\n{% include navigation.html %}\n';
            await fs.writeFile(fullPath, content, 'utf-8');
            this.log(`Added navigation to ${relativePath}`, 'info');
          }
        }
      }
    };

    // Process all content directories
    const contentDirs = ['chapters', 'appendices', 'introduction', 'afterword'];
    
    for (const dir of contentDirs) {
      const dirPath = path.join(publicDir, dir);
      try {
        await addNavigation(dirPath);
      } catch {
        // Directory doesn't exist - skip
      }
    }
    
    this.log('Navigation injection completed');
  }

  async build() {
    console.log(colors.blue('🔨 Simplified Build Process Starting...\n'));
    
    try {
      await this.loadConfig();
      
      const srcDir = path.join(process.cwd(), 'src');
      const publicDir = await this.createPublicDirectory();
      
      await this.processContentSections(srcDir, publicDir);
      await this.copyAssets(srcDir, publicDir);
      await this.generateIndex(publicDir);
      await this.copyJekyllConfig(publicDir);
      
      // Validate configuration after copying
      await this.validateConfig();
      
      // Deploy v3.0 Design System
      await this.copyV3DesignSystem(publicDir);
      await this.generateNavigationData(srcDir, publicDir);
      await this.addNavigationToMarkdownFiles(publicDir);
      
      // Copy GitHub Actions workflows
      await this.copyWorkflowTemplates(publicDir);
      
      console.log('\n' + colors.green('✅ ビルド完了!'));
      console.log(colors.blue(`📁 出力先: ${publicDir}`));
      console.log(colors.blue(`📄 処理ファイル数: ${this.processedFiles}`));
      console.log('\n' + colors.yellow('次のステップ:'));
      console.log('  npm run preview  # ローカルプレビュー');
      console.log('  GitHub Pages設定  # Settings > Pages > Source: Deploy from a branch > Branch: main > Folder: /docs');
      
    } catch (error) {
      console.error('\n' + colors.red('❌ ビルドエラー:'));
      console.error(colors.red(error.message));
      console.log('\n' + colors.yellow('トラブルシューティング:'));
      console.log('1. src/ ディレクトリが存在するか確認');
      console.log('2. book-config.json の設定を確認');
      console.log('3. ファイルの読み書き権限を確認');
      process.exit(1);
    }
  }
}

// Execute build
if (require.main === module) {
  const builder = new SimpleBuild();
  builder.build();
}

module.exports = SimpleBuild;