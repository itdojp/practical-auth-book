# 実践 認証認可システム設計

認証・認可システムの基礎から実装、運用までを体系的に学ぶことを目的とした技術書です。単なる技術解説にとどまらず、「なぜその技術が必要なのか」「どのような問題を解決するのか」という観点から理解を整理します。

- 公開ページ（GitHub Pages）: [practical-auth-book](https://itdojp.github.io/practical-auth-book/)
- 目次（リポジトリ内）: `docs/index.md`
- 環境構築と `runnable minimum`: [`docs/appendices/appendix-0-environment-setup/`](docs/appendices/appendix-0-environment-setup/)
- シリーズ: [it-engineer-knowledge-architecture](https://github.com/itdojp/it-engineer-knowledge-architecture)

PR previewは、現在のGitHub Pages設定（`main:/docs`）と別の`gh-pages`配下へ配置され、
読者向けURLの成功を保証できないため廃止しています。公開確認はmainのPages URLを使用してください。

## ローカル品質ゲート

公開前に、書籍メタデータと公開ナビゲーションの整合性を確認します。

```bash
bundle install
npm ci --omit=optional
npm run check:security
npm run check:metadata
npm test
npm run build:validate
```

ローカル品質ゲートと通常の CI は Node.js 22.22.2 以上を前提とします。scheduled maintenance の
公開リンク監査だけは、link checker 用の分離runtimeとして Node.js 24 を使用します。runtime baseline と
依存バージョンの更新は別々にレビューし、実際に導入されるバージョンは `package.json` と
`package-lock.json` を正本とします。Node.js 22 を要求する品質ツールを扱うため、通常の CI を Node.js 20 へ戻さないでください。

`npm run check:security` は optional dependency を除外した `npm audit` を実行し、CI と同じ依存関係範囲で既知脆弱性がないことを確認します。
`npm run check:metadata` は `book-config.json`、`package.json`、
`package-lock.json`、Jekyll 設定、トップページ front matter、
`docs/_data/navigation.yml`、公開ルート、必要なレイアウト・アセットを
照合します。章や付録の公開パスを追加・変更した場合は、
`book-config.json` とナビゲーションを同じ PR で更新してください。
`build:validate` は正本の `docs/` を再生成せず、公開route、画像、anchorを含む内部リンクを検証します。

`npm run build` は `docs/` を正本として Jekyll で `_site/` に生成します。ビルド中に
追跡対象の `docs/` は変更されません。旧 `src/` から `docs/` を再生成する移行用処理が必要な場合だけ
`npm run build:legacy`（または競合検出付きの `npm run build:safe`）を使用してください。

## フィードバック（誤り指摘・改善提案）

誤字脱字、技術的な誤り、改善提案は Issue / PR で受け付けます。

- GitHub Issues: [itdojp/practical-auth-book/issues](https://github.com/itdojp/practical-auth-book/issues)
- Email: [knowledge@itdo.jp](mailto:knowledge@itdo.jp)

## ライセンス

本書は Creative Commons BY-NC-SA 4.0 で提供されています。詳細は `LICENSE.md` を参照してください。
