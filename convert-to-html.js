const fs = require('fs');
const path = require('path');

// Navigation items with titles
const navigationItems = [
    { id: 'introduction', title: 'はじめに', url: '/practical-auth-book/introduction' },
    { id: 'chapter-01-overview', title: '第1章: 認証認可の全体像', url: '/practical-auth-book/chapters/chapter-01-overview' },
    { id: 'chapter-02-authentication', title: '第2章: 認証の基礎', url: '/practical-auth-book/chapters/chapter-02-authentication' },
    { id: 'chapter-03-authorization', title: '第3章: 認可の基礎', url: '/practical-auth-book/chapters/chapter-03-authorization' },
    { id: 'chapter-04-session', title: '第4章: セッション管理', url: '/practical-auth-book/chapters/chapter-04-session' },
    { id: 'chapter-05-token-auth', title: '第5章: トークンベース認証', url: '/practical-auth-book/chapters/chapter-05-token-auth' },
    { id: 'chapter-06-oauth2', title: '第6章: OAuth 2.0', url: '/practical-auth-book/chapters/chapter-06-oauth2' },
    { id: 'chapter-07-oidc-saml', title: '第7章: OpenID ConnectとSAML', url: '/practical-auth-book/chapters/chapter-07-oidc-saml' },
    { id: 'chapter-08-auth-system-design', title: '第8章: 認証システムの設計', url: '/practical-auth-book/chapters/chapter-08-auth-system-design' },
    { id: 'chapter-09-microservices-auth', title: '第9章: マイクロサービスでの認証認可', url: '/practical-auth-book/chapters/chapter-09-microservices-auth' },
    { id: 'chapter-10-implementation-patterns', title: '第10章: 実装パターンとベストプラクティス', url: '/practical-auth-book/chapters/chapter-10-implementation-patterns' },
    { id: 'chapter-11-security-threats', title: '第11章: セキュリティ脅威と対策', url: '/practical-auth-book/chapters/chapter-11-security-threats' },
    { id: 'chapter-12-performance', title: '第12章: パフォーマンス最適化', url: '/practical-auth-book/chapters/chapter-12-performance' },
    { id: 'chapter-13-future', title: '第13章: 認証技術の未来', url: '/practical-auth-book/chapters/chapter-13-future' },
    { id: 'appendix-a-libraries', title: '付録A: 主要ライブラリ・ツール一覧', url: '/practical-auth-book/appendices/appendix-a-libraries' },
    { id: 'appendix-b-troubleshooting', title: '付録B: トラブルシューティングガイド', url: '/practical-auth-book/appendices/appendix-b-troubleshooting' },
    { id: 'appendix-c-glossary', title: '付録C: 用語集', url: '/practical-auth-book/appendices/appendix-c-glossary' },
    { id: 'appendix-d-references', title: '付録D: 参考文献・リソース', url: '/practical-auth-book/appendices/appendix-d-references' },
    { id: 'appendix-e-01', title: '第1章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-01' },
    { id: 'appendix-e-02', title: '第2章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-02' },
    { id: 'appendix-e-03', title: '第3章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-03' },
    { id: 'appendix-e-04', title: '第4章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-04' },
    { id: 'appendix-e-05', title: '第5章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-05' },
    { id: 'appendix-e-06', title: '第6章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-06' },
    { id: 'appendix-e-07', title: '第7章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-07' },
    { id: 'appendix-e-08', title: '第8章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-08' },
    { id: 'appendix-e-09', title: '第9章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-09' },
    { id: 'appendix-e-10', title: '第10章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-10' },
    { id: 'appendix-e-11', title: '第11章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-11' },
    { id: 'appendix-e-12', title: '第12章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-12' },
    { id: 'appendix-e-13', title: '第13章 演習問題解答', url: '/practical-auth-book/appendices/appendix-e-13' }
];

// Generate page navigation HTML
function generatePageNavigation(currentPageId) {
    const currentIndex = navigationItems.findIndex(item => item.id === currentPageId);
    if (currentIndex === -1) return '';

    const prevItem = currentIndex > 0 ? navigationItems[currentIndex - 1] : null;
    const nextItem = currentIndex < navigationItems.length - 1 ? navigationItems[currentIndex + 1] : null;

    return `
        <nav class="page-nav" aria-label="Page navigation">
            <div class="page-nav-container">
                <!-- Previous Page -->
                <div class="page-nav-item page-nav-prev">
                    ${prevItem ? `
                    <a href="${prevItem.url}" class="page-nav-link" rel="prev">
                        <div class="page-nav-link-label">← 前のページ</div>
                        <div class="page-nav-link-title">${prevItem.title}</div>
                    </a>
                    ` : '<div></div>'}
                </div>
                
                <!-- Table of Contents -->
                <div class="page-nav-item page-nav-toc">
                    <a href="/practical-auth-book/" class="page-nav-toc-btn">目次に戻る</a>
                </div>

                <!-- Next Page -->
                <div class="page-nav-item page-nav-next">
                    ${nextItem ? `
                    <a href="${nextItem.url}" class="page-nav-link" rel="next">
                        <div class="page-nav-link-label">次のページ →</div>
                        <div class="page-nav-link-title">${nextItem.title}</div>
                    </a>
                    ` : '<div></div>'}
                </div>
            </div>
        </nav>
    `;
}

// Base HTML template
const htmlTemplate = (title, content, pageId = '', basePath = '') => `<!DOCTYPE html>
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
            overflow-x: hidden;
            width: 100%;
        }
        .book-layout {
            display: flex;
            min-height: 100vh;
            width: 100%;
            position: relative;
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
                padding: 15px;
                max-width: 100%;
                width: 100%;
                overflow-x: hidden;
            }
            .container {
                padding: 15px;
                margin: 0;
                box-shadow: none;
                border-radius: 0;
                width: 100%;
                max-width: 100%;
                overflow-x: hidden;
            }
            h1 {
                font-size: 1.8rem;
                line-height: 1.3;
            }
            h2 {
                font-size: 1.4rem;
                line-height: 1.3;
                margin-top: 2rem;
            }
            h3 {
                font-size: 1.2rem;
                line-height: 1.3;
                margin-top: 1.5rem;
            }
            /* コードブロックのモバイル最適化 */
            pre {
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
                padding: 12px;
                font-size: 0.85rem;
                line-height: 1.4;
                white-space: pre;
                word-wrap: normal;
                max-width: 100%;
                margin: 1rem 0;
            }
            code {
                font-size: 0.85rem;
                word-break: break-word;
                white-space: pre-wrap;
            }
            pre code {
                white-space: pre;
                word-break: normal;
            }
            /* テーブルのモバイル対応 */
            table {
                width: 100%;
                overflow-x: auto;
                display: block;
                white-space: nowrap;
            }
            table tbody {
                display: table;
                width: 100%;
            }
            /* リストの調整 */
            ul, ol {
                padding-left: 1.2rem;
            }
            li {
                margin-bottom: 0.3rem;
            }
            /* 画像の最適化 */
            img {
                max-width: 100%;
                height: auto;
                display: block;
                margin: 1rem auto;
            }
            /* 長いURLやテキストの折り返し */
            p {
                word-wrap: break-word;
                overflow-wrap: break-word;
                max-width: 100%;
            }
            /* ボックスモデルの調整 */
            * {
                box-sizing: border-box;
            }
            /* フォントサイズの調整 */
            body {
                font-size: 0.95rem;
                line-height: 1.6;
            }
        }
        /* 前・次ナビゲーション */
        .page-nav {
            margin-top: 50px;
            padding: 30px 0;
            border-top: 1px solid #e9ecef;
        }
        .page-nav-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }
        .page-nav-item {
            flex: 1;
            min-width: 200px;
        }
        .page-nav-prev {
            text-align: left;
        }
        .page-nav-next {
            text-align: right;
        }
        .page-nav-toc {
            text-align: center;
            flex: 0 0 auto;
        }
        .page-nav-link {
            display: inline-block;
            padding: 12px 20px;
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            color: #495057;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.2s ease;
        }
        .page-nav-link:hover {
            background-color: #007bff;
            color: white;
            border-color: #007bff;
            transform: translateY(-1px);
        }
        .page-nav-link-label {
            font-size: 0.85em;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 4px;
        }
        .page-nav-link-title {
            font-size: 0.95em;
            line-height: 1.3;
        }
        .page-nav-link:hover .page-nav-link-label {
            color: rgba(255, 255, 255, 0.8);
        }
        .page-nav-toc-btn {
            padding: 10px 16px;
            background-color: #6c757d;
            color: white;
            border: none;
            border-radius: 4px;
            text-decoration: none;
            font-size: 0.9em;
            font-weight: 500;
        }
        .page-nav-toc-btn:hover {
            background-color: #5a6268;
            color: white;
        }
        @media (max-width: 768px) {
            .page-nav-container {
                flex-direction: column;
                gap: 15px;
            }
            .page-nav-item {
                width: 100%;
                text-align: center;
            }
            .page-nav-prev, .page-nav-next {
                text-align: center;
            }
            .page-nav-link {
                width: 100%;
                max-width: 300px;
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
                ${generatePageNavigation(pageId)}
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
        const fullHtml = htmlTemplate(title, htmlContent, chapter);
        
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
        const fullHtml = htmlTemplate(title, htmlContent, appendix);
        
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
    const fullHtml = htmlTemplate(title, htmlContent, 'introduction');
    
    fs.writeFileSync(introHtmlPath, fullHtml);
    console.log(`Created ${introHtmlPath}`);
}

console.log('HTML conversion completed!');