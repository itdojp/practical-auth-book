# 📚 Book Publishing Template v3.0 セットアップガイド

## 📋 必須設定チェックリスト

書籍テンプレートを使用する前に、以下の設定を必ず更新してください：

### ✅ _config.yml の更新
- [ ] `title`: 「YOUR_BOOK_TITLE_HERE」を実際の書籍タイトルに変更
- [ ] `description`: 「YOUR_BOOK_DESCRIPTION_HERE」を書籍の説明に変更  
- [ ] `baseurl`: 「/YOUR_REPOSITORY_NAME_HERE」を実際のリポジトリ名に変更
- [ ] `author.name`: 「YOUR_AUTHOR_NAME」を著者名に変更
- [ ] `author.email`: 「your.email@example.com」を実際のメールアドレスに変更
- [ ] `author.github`: 「YOUR_GITHUB_USERNAME」をGitHubユーザー名に変更
- [ ] `url`: 「YOUR_GITHUB_USERNAME」を実際のユーザー名に変更
- [ ] `repository.github`: GitHubリポジトリの正しいURLに変更

### ✅ book-config.json の更新
- [ ] `book.title`: 書籍タイトルを設定
- [ ] `book.author.name`: 著者名を設定
- [ ] `book.author.email`: メールアドレスを設定
- [ ] `book.description`: 書籍の説明を設定

### ✅ GitHub Pages 設定
- [ ] リポジトリの Settings > Pages で「Deploy from a branch」を選択
- [ ] Branch を「main」、Folder を「/docs」に設定
- [ ] カスタムドメインを使用する場合は適切に設定

## 🔧 よくある問題と解決法

### 1. ナビゲーションリンクが404エラー
**症状**: 章のリンクをクリックすると404ページが表示される

**原因**: baseurl設定が間違っている、またはnavigation.ymlのパスが不正

**解決法**: 
- `_config.yml` の baseurl がリポジトリ名と一致しているか確認
- navigation.yml のパス形式が正しいか確認（.html拡張子の有無）
- 例: リポジトリ名が `my-book` の場合、baseurl は `/my-book`

### 2. 前次リンクが表示されない  
**症状**: ページ下部の「前へ」「次へ」ボタンが表示されない

**原因**: URL比較ロジックでマッチしていない

**解決法**: 
- ファイル名がnavigation.ymlのパスと一致しているか確認
- デバッグモードを有効にして詳細を確認: `JEKYLL_ENV=development npm run build`
- [Navigation Debug Guide](NAVIGATION_DEBUG.md)を参照

### 3. スマホでリンクが辿れない
**症状**: モバイルでナビゲーションメニューは開くがリンクをタップできない

**原因**: JavaScript ファイルの404エラー、またはCSS/JS読み込み問題

**解決法**:
- ブラウザの開発者ツールでコンソールエラーを確認
- search.js、main.js ファイルが存在するか確認
- baseurl設定が正しいか再確認

### 4. GitHub Pagesで「YOUR_BOOK_TITLE_HERE」が表示される
**症状**: サイトヘッダーに「YOUR_BOOK_TITLE_HERE」がそのまま表示

**原因**: `_config.yml` のデフォルト値が更新されていない  

**解決法**: 
1. `_config.yml` を開く
2. 全ての `YOUR_*_HERE` を実際の値に変更
3. `git add _config.yml && git commit -m "Update configuration"`
4. `git push` してGitHub Pagesの更新を待つ

### 5. 演習問題解答集のタイトルが間違っている
**症状**: 付録のタイトルに古い書籍名が表示される

**原因**: merged-exercise-answers.md のタイトルが更新されていない

**解決法**: 
1. `appendices/merged-exercise-answers.md` を開く
2. Front Matter の `title:` を適切な値に更新
3. ファイル内の H1 見出しも更新

## ✅ 動作確認チェックリスト

### デスクトップブラウザ
- [ ] トップページが正しいタイトルで表示される
- [ ] サイドバーナビゲーションで全ての章にアクセスできる
- [ ] 各章の前次リンクが正常に動作する
- [ ] 付録（演習問題解答集）にアクセスできる
- [ ] GitHub の "Edit this page" リンクが正しく動作する

### モバイルブラウザ  
- [ ] ハンバーガーメニューが表示される
- [ ] ナビゲーションメニューが開閉できる
- [ ] メニューから各章にアクセスできる
- [ ] 章ページで前次リンクが動作する
- [ ] メニュー外タップでナビゲーションが閉じる

### 全体確認
- [ ] 全ページで404エラーがない
- [ ] ブラウザコンソールにJavaScript エラーがない  
- [ ] 設定検証で警告が出ない: `npm run build`

## 🚀 クイックスタート

```bash
# 1. リポジトリをクローン
git clone https://github.com/your-username/your-book-repo.git
cd your-book-repo

# 2. 依存関係をインストール
npm install

# 3. 設定ファイルを更新
# _config.yml と book-config.json を編集

# 4. ビルド（設定検証付き）
npm run build

# 5. ローカルプレビュー
npm run preview

# 6. 問題があればデバッグモードで確認
JEKYLL_ENV=development npm run build
```

## 📚 追加リソース

- [Navigation Debug Guide](NAVIGATION_DEBUG.md) - ナビゲーション問題の詳細なトラブルシューティング
- [GitHub Pages Documentation](https://docs.github.com/en/pages)
- [Jekyll Documentation](https://jekyllrb.com/docs/)

## 💡 ヒント

1. **設定変更後は必ずビルドを実行**: 設定ファイルの変更はビルドプロセスで反映されます
2. **キャッシュのクリア**: 問題が続く場合は `rm -rf docs/_site` でキャッシュをクリア
3. **段階的な変更**: 一度に多くの変更をせず、段階的に変更して動作確認
4. **バックアップ**: 大きな変更前には `git commit` でバックアップ

---

問題が解決しない場合は、[Issues](https://github.com/itdojp/book-publishing-template2/issues)で報告してください。