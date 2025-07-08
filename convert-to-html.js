const fs = require('fs');
const path = require('path');

// Base HTML template
const htmlTemplate = (title, content, basePath = '') => `<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title} - 実践 認証認可システム設計</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f8f9fa;
        }
        .book-layout {
            display: flex;
            min-height: 100vh;
        }
        .book-sidebar {
            width: 280px;
            background-color: #fff;
            border-right: 1px solid #e9ecef;
            padding: 20px;
            overflow-y: auto;
            position: fixed;
            height: 100vh;
        }
        .book-main {
            margin-left: 280px;
            flex: 1;
            padding: 40px;
            max-width: 900px;
        }
        .sidebar-title {
            font-size: 1.2em;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .nav-section {
            margin-bottom: 30px;
        }
        .nav-section-title {
            font-size: 0.9em;
            font-weight: 600;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 10px;
        }
        .nav-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .nav-link {
            display: block;
            padding: 8px 12px;
            color: #495057;
            text-decoration: none;
            border-radius: 4px;
            transition: all 0.2s;
        }
        .nav-link:hover {
            background-color: #e9ecef;
            color: #007bff;
        }
        .nav-link.active {
            background-color: #007bff;
            color: white;
        }
        .container {
            background-color: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
        }
        h3 {
            color: #2c3e50;
            margin-top: 25px;
        }
        pre {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
        }
        code {
            background-color: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e9ecef;
            color: #6c757d;
            text-align: center;
        }
        @media (max-width: 768px) {
            .book-sidebar {
                display: none;
            }
            .book-main {
                margin-left: 0;
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="book-layout">
        <!-- Sidebar Navigation -->
        <aside class="book-sidebar">
            <div class="sidebar-title">
                <a href="/practical-auth-book/" style="color: inherit; text-decoration: none;">実践 認証認可システム設計</a>
            </div>
            
            <nav class="sidebar-nav">
                <div class="nav-section">
                    <ul class="nav-list">
                        <li><a href="/practical-auth-book/introduction" class="nav-link">はじめに</a></li>
                    </ul>
                </div>

                <div class="nav-section">
                    <h3 class="nav-section-title">第I部: 基礎概念編</h3>
                    <ul class="nav-list">
                        <li><a href="/practical-auth-book/chapters/chapter-01-overview" class="nav-link">第1章: 認証認可の全体像</a></li>
                        <li><a href="/practical-auth-book/chapters/chapter-02-authentication" class="nav-link">第2章: 認証の基礎</a></li>
                        <li><a href="/practical-auth-book/chapters/chapter-03-authorization" class="nav-link">第3章: 認可の基礎</a></li>
                    </ul>
                </div>

                <div class="nav-section">
                    <h3 class="nav-section-title">第II部: プロトコルと標準編</h3>
                    <ul class="nav-list">
                        <li><a href="/practical-auth-book/chapters/chapter-04-session" class="nav-link">第4章: セッション管理</a></li>
                        <li><a href="/practical-auth-book/chapters/chapter-05-token-auth" class="nav-link">第5章: トークンベース認証</a></li>
                        <li><a href="/practical-auth-book/chapters/chapter-06-oauth2" class="nav-link">第6章: OAuth 2.0</a></li>
                        <li><a href="/practical-auth-book/chapters/chapter-07-oidc-saml" class="nav-link">第7章: OpenID ConnectとSAML</a></li>
                    </ul>
                </div>

                <div class="nav-section">
                    <h3 class="nav-section-title">第III部: 実装編</h3>
                    <ul class="nav-list">
                        <li><a href="/practical-auth-book/chapters/chapter-08-auth-system-design" class="nav-link">第8章: 認証システムの設計</a></li>
                        <li><a href="/practical-auth-book/chapters/chapter-09-microservices-auth" class="nav-link">第9章: マイクロサービスでの認証認可</a></li>
                        <li><a href="/practical-auth-book/chapters/chapter-10-implementation-patterns" class="nav-link">第10章: 実装パターンとベストプラクティス</a></li>
                    </ul>
                </div>

                <div class="nav-section">
                    <h3 class="nav-section-title">第IV部: 応用編</h3>
                    <ul class="nav-list">
                        <li><a href="/practical-auth-book/chapters/chapter-11-security-threats" class="nav-link">第11章: セキュリティ脅威と対策</a></li>
                        <li><a href="/practical-auth-book/chapters/chapter-12-performance" class="nav-link">第12章: パフォーマンス最適化</a></li>
                        <li><a href="/practical-auth-book/chapters/chapter-13-future" class="nav-link">第13章: 認証技術の未来</a></li>
                    </ul>
                </div>

                <div class="nav-section">
                    <h3 class="nav-section-title">付録</h3>
                    <ul class="nav-list">
                        <li><a href="/practical-auth-book/appendices/appendix-a-libraries" class="nav-link">付録A: 主要ライブラリ・ツール一覧</a></li>
                        <li><a href="/practical-auth-book/appendices/appendix-b-troubleshooting" class="nav-link">付録B: トラブルシューティングガイド</a></li>
                        <li><a href="/practical-auth-book/appendices/appendix-c-glossary" class="nav-link">付録C: 用語集</a></li>
                        <li><a href="/practical-auth-book/appendices/appendix-d-references" class="nav-link">付録D: 参考文献・リソース</a></li>
                    </ul>
                </div>
            </nav>
        </aside>

        <!-- Main Content -->
        <main class="book-main">
            <div class="container">
                ${content}
            </div>
        </main>
    </div>
</body>
</html>`;

// Simple Markdown to HTML converter
function markdownToHtml(markdown) {
    return markdown
        // Remove frontmatter
        .replace(/^---[\s\S]*?---/, '')
        // Headers
        .replace(/^### (.*$)/gm, '<h3>$1</h3>')
        .replace(/^## (.*$)/gm, '<h2>$1</h2>')
        .replace(/^# (.*$)/gm, '<h1>$1</h1>')
        // Bold and italic
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        // Code blocks
        .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
        // Inline code
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        // Links
        .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>')
        // Paragraphs
        .replace(/\n\n/g, '</p><p>')
        .replace(/^(.*)$/gm, function(match) {
            if (match.startsWith('<h') || match.startsWith('<pre') || match.startsWith('</p>') || match.startsWith('<p>') || match.trim() === '') {
                return match;
            }
            return '<p>' + match + '</p>';
        })
        // Clean up
        .replace(/<p><\/p>/g, '')
        .replace(/<p>(<h[1-6])/g, '$1')
        .replace(/(<\/h[1-6]>)<\/p>/g, '$1');
}

// Convert chapters
const chaptersDir = './chapters';
const chapters = [
    'chapter-01-overview',
    'chapter-02-authentication', 
    'chapter-03-authorization',
    'chapter-04-session',
    'chapter-05-token-auth',
    'chapter-06-oauth2',
    'chapter-07-oidc-saml',
    'chapter-08-auth-system-design',
    'chapter-09-microservices-auth',
    'chapter-10-implementation-patterns',
    'chapter-11-security-threats',
    'chapter-12-performance',
    'chapter-13-future'
];

chapters.forEach(chapter => {
    const mdPath = path.join(chaptersDir, `${chapter}.md`);
    const htmlPath = path.join(chaptersDir, `${chapter}.html`);
    
    if (fs.existsSync(mdPath)) {
        const markdown = fs.readFileSync(mdPath, 'utf8');
        const title = markdown.match(/^# (.*)$/m)?.[1] || chapter;
        const htmlContent = markdownToHtml(markdown);
        const fullHtml = htmlTemplate(title, htmlContent);
        
        fs.writeFileSync(htmlPath, fullHtml);
        console.log(`Created ${htmlPath}`);
    }
});

// Convert appendices
const appendicesDir = './appendices';
const appendices = [
    'appendix-a-libraries',
    'appendix-b-troubleshooting',
    'appendix-c-glossary', 
    'appendix-d-references',
    'appendix-e-01',
    'appendix-e-02',
    'appendix-e-03',
    'appendix-e-04',
    'appendix-e-05',
    'appendix-e-06',
    'appendix-e-07',
    'appendix-e-08',
    'appendix-e-09',
    'appendix-e-10',
    'appendix-e-11',
    'appendix-e-12',
    'appendix-e-13'
];

appendices.forEach(appendix => {
    const mdPath = path.join(appendicesDir, `${appendix}.md`);
    const htmlPath = path.join(appendicesDir, `${appendix}.html`);
    
    if (fs.existsSync(mdPath)) {
        const markdown = fs.readFileSync(mdPath, 'utf8');
        const title = markdown.match(/^# (.*)$/m)?.[1] || appendix;
        const htmlContent = markdownToHtml(markdown);
        const fullHtml = htmlTemplate(title, htmlContent);
        
        fs.writeFileSync(htmlPath, fullHtml);
        console.log(`Created ${htmlPath}`);
    }
});

// Convert introduction
const introPath = './introduction/index.md';
const introHtmlPath = './introduction.html';

if (fs.existsSync(introPath)) {
    const markdown = fs.readFileSync(introPath, 'utf8');
    const title = markdown.match(/^# (.*)$/m)?.[1] || 'はじめに';
    const htmlContent = markdownToHtml(markdown);
    const fullHtml = htmlTemplate(title, htmlContent);
    
    fs.writeFileSync(introHtmlPath, fullHtml);
    console.log(`Created ${introHtmlPath}`);
}

console.log('HTML conversion completed!');