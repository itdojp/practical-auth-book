# 構成レビュー（Round1）

対象（参照した主なファイル）
- `README.md`
- `docs/index.md`
- `docs/_data/navigation.yml`
- `docs/introduction/index.md`
- `docs/chapters/chapter-01-overview/index.md` 〜 `docs/chapters/chapter-13-future/index.md`
- `docs/appendices/appendix-a-libraries/index.md` ほか `docs/appendices/*/index.md`

## 1. 書籍の概要

- 想定読者: `docs/introduction/index.md` より「Webアプリ開発者（経験1-3年）」「システムアーキテクト志望」「セキュリティエンジニア初級」「認証基盤の導入・運用担当者」。
- 本書のゴール: 認証・認可の基礎〜標準プロトコル（OAuth/OIDC/SAML等）〜設計/実装〜運用までを、技術選択の判断基準込みで体系化する（`docs/index.md`, `docs/introduction/index.md` より）。
- 入口（読者導線）の現状:
  - `docs/index.md` は書籍入口として整っている一方、リポジトリトップの `README.md` がテンプレート説明になっており、読者入口として不整合。
  - `docs/chapters/` と `docs/appendices/` に「同名の `.md` ファイル」と「ディレクトリ配下の `index.md`」が併存しており、どちらが正か（生成対象か）判別しづらい。`permalink: pretty` 設定下ではURL衝突の懸念もあるため要確認。

## 2. 現状の章構成サマリ

### はじめに（`docs/introduction/index.md`）
- 狙い / 主なトピック: 想定読者、前提知識、特徴（「なぜ」重視・段階的実装・運用まで）、全体構成（第I〜IV部）の提示。
- 学習目標: 章単位の箇条書きは無し（本文が目的に相当）。

### 第1章：認証認可システム概要（`docs/chapters/chapter-01-overview/index.md`）
- 狙い / 主なトピック: 認証/認可の必要性、基本用語整理、歴史的経緯とトレンド、本書の学習パス、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 第2章：認証システムの基礎（`docs/chapters/chapter-02-authentication/index.md`）
- 狙い / 主なトピック: 認証3要素、パスワード認証の限界、MFA、生体認証、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 第3章：認可システムの基礎（`docs/chapters/chapter-03-authorization/index.md`）
- 狙い / 主なトピック: 最小権限、認可モデル（ACL/RBAC/ABAC）、動的/静的認可、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 第4章：セッション管理（`docs/chapters/chapter-04-session/index.md`）
- 狙い / 主なトピック: HTTPステートレスとセッション、Cookie/セッション実装、脅威と対策、分散環境での管理、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 第5章：トークンベース認証（`docs/chapters/chapter-05-token-auth/index.md`）
- 狙い / 主なトピック: JWT、保存と管理（XSS/CSRF）、リフレッシュトークン設計、無効化戦略、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 第6章：OAuth 2.0（`docs/chapters/chapter-06-oauth2/index.md`）
- 狙い / 主なトピック: OAuthの設計思想、グラントタイプの使い分け、PKCE等のセキュリティ、実装の落とし穴、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 第7章：OpenID ConnectとSAML（`docs/chapters/chapter-07-oidc-saml/index.md`）
- 狙い / 主なトピック: フェデレーション認証、OIDCの仕組み、SAML比較、エンタープライズ活用、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 第8章：認証システムの設計（`docs/chapters/chapter-08-auth-system-design/index.md`）
- 狙い / 主なトピック: 要件定義/設計、DB設計、API設計、エラーハンドリングとUX、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 第9章：マイクロサービスにおける認証・認可（`docs/chapters/chapter-09-microservices-auth/index.md`）
- 狙い / 主なトピック: 分散システム課題、API Gateway、サービス間認証、Zero Trust、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 第10章：実装パターンとベストプラクティス（`docs/chapters/chapter-10-implementation-patterns/index.md`）
- 狙い / 主なトピック: 認証フロー、権限チェック、監査ログ、テスト戦略、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 第11章：セキュリティ脅威と対策（`docs/chapters/chapter-11-security-threats/index.md`）
- 狙い / 主なトピック: 攻撃手法と対策、ペネトレーションテスト、インシデント対応、監査、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 第12章：パフォーマンスと監視（`docs/chapters/chapter-12-performance/index.md`）
- 狙い / 主なトピック: ボトルネック、キャッシュ戦略、負荷分散と可用性、モニタリング、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 第13章：今後の展望（`docs/chapters/chapter-13-future/index.md`）
- 狙い / 主なトピック: パスワードレス、分散型アイデンティティ、AIとリスクベース認証、量子暗号時代、まとめ・演習。
- 学習目標（章頭）: 明示なし。

### 付録（`docs/appendices/*/index.md`）
- 付録A: 参考ライブラリ・ツール
- 付録B: トラブルシューティング
- 付録C: 用語集
- 付録D: 参考文献
- 付録E-1〜E-13: 各章の演習問題解答

## 3. 構成上の気になる点（候補）

- 入口不整合: `README.md` が書籍ではなくテンプレート説明になっている。
- 章/付録ファイルの二重管理:
  - `docs/chapters/chapter-xx-.../index.md` と `docs/chapters/chapter-xx-....md` が併存（付録も同様）。
  - `permalink: pretty` だとURL衝突し得るため、ビルド結果の正（どちらが公開されているか）の確認が必要。
- Stage2要件（導入→本論→まとめ）のうち「導入（章の狙い）」が章ごとに見えにくい:
  - 各章とも章末の `## まとめ` はある一方、章頭で「この章で何ができるようになるか」が固定の型としては見えにくい。
  - 既存の説明は `## 2.1 ...` のように本文が直ちに始まるため、初学者は「章の全体像」を掴む前に詳細へ入ってしまう可能性がある。
- ナビゲーションデータの重複:
  - `docs/_data/navigation.yml` の appendices に同一パスの重複エントリがある（タイトル表示の意図があるとしても、保守観点で要確認）。

## 4. 構成改善の提案（案）

- 入口の確定:
  - `README.md` を「読者入口」にし、`docs/index.md` と同一の書名/概要/オンライン版リンク/ライセンスに整合させる。
- 二重管理の解消（優先度: 高）:
  - 章/付録について、公開対象・編集対象の正（single source of truth）を決め、片系統に統一する。
  - まずは「どちらがサイトで配信されているか」をビルド結果で確認し、誤配信がある場合は早期に是正する（要確認）。
- 章テンプレートの統一（Stage2要件対応）:
  - 各章冒頭に「この章で学ぶこと（到達点）」を追加し、章の学習曲線と目標を明示する。
  - 「導入→本論→まとめ→演習」の型を固定し、章間で迷わない読み方を提供する。
- ナビゲーションの簡素化:
  - `docs/_data/navigation.yml` の重複エントリは、必要性が確認でき次第、削減（または生成ロジック側で一本化）を検討する。

