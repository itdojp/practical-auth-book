# Claude Code トラブルシューティングガイド

このドキュメントは、Claude Codeが書籍テンプレートプロジェクトで遭遇した問題と解決策をまとめたものです。
同じ問題を繰り返さないよう、作業前に必ず参照してください。

## 目次
1. [GitHub Pages 関連](#github-pages-関連)
2. [Jekyll 関連](#jekyll-関連)
3. [Git 関連](#git-関連)
4. [ビルドシステム関連](#ビルドシステム関連)
5. [一般的な注意事項](#一般的な注意事項)

---

## GitHub Pages 関連

### 1. 404エラーの主な原因と対処法

#### 原因1: プライベートリポジトリの扱い
- **問題**: 「プライベートリポジトリではGitHub Pagesが使えない」と誤解する
- **事実**: 有料プラン（Pro/Team/Enterprise）ではプライベートリポジトリでもPages利用可能
- **対処**: ユーザーに確認してから判断する。勝手にパブリックに変更しない

#### 原因2: .nojekyllファイル
- **問題**: `.nojekyll`ファイルがあるとJekyllビルドが無効化される
- **事実**: GitHub PagesはデフォルトでJekyllを使用する
- **対処**: 
  - 通常のMarkdownサイト → `.nojekyll`を削除
  - 静的HTMLのみ → `.nojekyll`を保持

#### 原因3: ディレクトリ名の大文字小文字
- **問題**: Windowsでは`Docs`と`docs`が同じだが、GitHubでは異なる
- **対処**: 
  ```bash
  # 正しい手順
  git rm -r --cached Docs
  git add docs
  git commit -m "Fix directory case sensitivity"
  ```

#### 原因4: Jekyll設定の問題
- **問題**: `_config.yml`にテンプレート変数が残っている
- **例**: `{{BOOK_TITLE}}`、`{{AUTHOR_NAME}}`
- **対処**: ビルドスクリプトが正しく変数を置換しているか確認

### 2. GitHub Pages デプロイメント方式

#### "Deploy from a branch" vs "GitHub Actions"
- **違い**: 
  - Branch: GitHubが自動的にJekyllビルド
  - Actions: カスタムビルドプロセスを使用可能
- **選択基準**
  - 通常 → "Deploy from a branch"
  - Jekyll競合が多い → "GitHub Actions"
- **注意**: 勝手に変更せず、ユーザーの意向を確認

---

## Jekyll 関連

### 1. Liquid構文の競合

#### 問題パターン
```markdown
# 競合する例
{{.Container}}      # Dockerコンテナ形式
{{ .Values.name }}  # Kubernetes形式
{%range%}          # Prometheus形式
```

#### 解決策
1. エスケープ: `{{ }}` → `\{\{ \}\}`
2. 自動検出・修正スクリプトの使用
   ```bash
   npm run check-conflicts
   npm run fix-conflicts
   ```

### 2. Front Matterの必要性

#### 必須要素
```yaml
---
layout: book
title: "ページタイトル"
---
```

#### 注意点
- index.mdには必ずFront Matterが必要
- layoutを指定しないとデフォルトテーマが適用される

---

## Git 関連

### 1. ケースセンシティブな問題

#### Windows環境での注意
- ファイルシステムは大文字小文字を区別しない
- Gitは区別する
- 結果: `Docs`と`docs`の混在問題

#### 対処法
```bash
# 安全な名前変更手順
git rm -r --cached OldName
git add newname
git commit -m "Rename directory"
```

### 2. リモートリポジトリの確認

#### 作業前の確認事項
```bash
# リポジトリの存在確認
gh repo view owner/repo --json name,visibility

# Pages設定の確認
gh api repos/owner/repo/pages --jq '{status, html_url, source}'
```

---

## ビルドシステム関連

### 1. build-simple.js の動作

#### 主な処理
1. `src/` → `docs/` へのコピー
2. Jekyll Front Matterの自動追加
3. 設定ファイルの生成

#### 注意点
- テンプレート変数の置換が不完全な場合がある
- `_config.yml`が上書きされる可能性

### 2. Jekyll競合検出

#### 使用すべきコマンド
```bash
# チェックのみ
npm run check-conflicts

# 自動修正
npm run fix-conflicts

# 安全なビルド
npm run build:safe
```

---

## 一般的な注意事項

### 1. 作業開始前のチェックリスト

- [ ] リポジトリの可視性（public/private）を確認
- [ ] ユーザーのGitHubプランを確認（無料/有料）
- [ ] 既存のGitHub Pages設定を確認
- [ ] Jekyll使用の有無を確認

### 2. 問題解決の優先順位

1. **最小限の変更**: まず簡単な修正から試す
2. **ユーザー確認**: 大きな変更は必ず確認を取る
3. **ログ確認**: エラーメッセージを正確に読む
4. **段階的アプローチ**: 一度に複数の変更をしない

### 3. よくある誤解

- ❌ 「プライベートリポジトリではPages使用不可」
- ✅ 有料プランなら使用可能

- ❌ 「.nojekyllは常に必要」
- ✅ Jekyllを使う場合は削除が必要

- ❌ 「GitHub Actionsへの変更が必須」
- ✅ 通常は"Deploy from a branch"で十分

### 4. デバッグ手順

1. **シンプルなテスト**
   ```bash
   # test.htmlを作成してアクセス確認
   echo "<h1>Test</h1>" > docs/test.html
   git add docs/test.html && git commit -m "Test" && git push
   ```

2. **ビルド状況確認**
   ```bash
   gh api repos/owner/repo/pages/builds/latest --jq '{status, error}'
   ```

3. **キャッシュ考慮**
   - GitHub Pagesは最大10分のキャッシュ
   - 強制リロード: Ctrl+F5

---

## 更新履歴

- 2025-07-05: 初版作成
  - Podman書籍とSupabase書籍の移行経験から作成
  - Jekyll Liquid競合問題の解決策を文書化
  - GitHub Pages 404エラーの各種原因と対処法

---

**重要**: このドキュメントは継続的に更新してください。新しい問題と解決策を追加することで、効率的な作業が可能になります。
