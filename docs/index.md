---
layout: book
order: 1
title: "実践 認証認可システム設計"
description: "認証・認可システムの設計と実装を体系的に学ぶ実践的な技術書"
author: "ITDO Inc.（株式会社アイティードゥ）"
version: "1.0.0"
permalink: /
---
# 実践 認証認可システム設計

## ゼロから学ぶアイデンティティ管理の実装

<div class="book-intro">
本書は、認証・認可システムの基礎から実装、運用まで、体系的に学ぶことを目的とした技術書です。単なる技術の解説にとどまらず、「なぜその技術が必要なのか」「どのような問題を解決するのか」という観点から、深い理解を促進します。
</div>

## 学習成果

- 認証・認可の基本概念（Authentication / Authorization）を整理し、代表的なプロトコルや方式の位置づけを説明できるようになる。
- セッション管理・トークンベース認証・OAuth 2.0・OpenID Connect・SAML といった主要技術の特徴と使いどころを比較し、自分のシステムに適した方式を選択できるようになる。
- 単一システムだけでなくマイクロサービス構成における認証・認可の設計パターンを理解し、実装・移行時の注意点を検討できるようになる。
- 実運用を想定したセキュリティ脅威・性能・監視の観点から、認証認可システム全体を見直し、改善ポイントを洗い出せるようになる。

## 実務適用とレビューゲート

この書籍のコード例と設計例を実務に適用する前に、次の確認を必須とする。

- **公式仕様の確認日を記録する**: OAuth 2.0 Security BCP（RFC 9700）、OAuth 2.1 draft、OpenID Connect Core、JWT BCP（RFC 8725）、NIST SP 800-63-4、OWASP Cheat Sheet Series の確認日を PR または設計記録に残す。
- **方式選定を明確にする**: ブラウザアプリ、サーバーサイド Web、ネイティブアプリ、M2M、管理者操作で、Authorization Code + PKCE、Client Credentials、Device Authorization Grant、セッション Cookie、BFF などの採用理由を分けて記録する。
- **トークン保管と失効を設計する**: アクセストークン、リフレッシュトークン、ID Token、セッション ID を混同せず、保存場所、有効期限、ローテーション、失効、監査ログ、鍵ローテーションを設計単位にする。
- **Cookie / CSRF / CORS をセットで確認する**: `Secure`、`HttpOnly`、`SameSite`、`__Host-` prefix、`CSRF token`、Origin / Referer 検証、`CORS allowlist` を、画面遷移と API 呼び出しごとに確認する。
- **レビュー完了をマージ条件にする**: `GitHub Copilot review` の本文、`inline comment`、`suggestion` を全件確認し、未解決 `review thread` が 0 件であることを記録してからマージする。

## 読み方ガイド

- 認証・認可そのものが初めての読者は、第 I 部（第1〜3章）を順に読み進めることで、用語と基本構造を一通り押さえてから第 II 部以降に進むことを推奨する。
- すでに基本用語は理解しており、「具体的なプロトコルの比較」を重視したい読者は、第4〜7章を軸に読み、必要に応じて第1〜3章に戻って背景概念を補完する読み方も有効である。
- 実装やアーキテクチャ設計に関心が高い読者は、[付録 0：環境構築と `runnable minimum`]({{ site.baseurl }}/appendices/appendix-0-environment-setup/) で検証前提を確認してから、第8〜10章（設計・マイクロサービス・実装パターン）を先に読み、その後前半章や付録で詳細仕様を確認する形でもよい。
- 実運用フェーズの課題に直面している読者は、第11〜12章（脅威・性能と監視）を優先し、第1〜10章は必要な部分をピックアップする読み方を想定している。

## 演習・付録の使い方

- 各章末の演習問題は、まず自力で解いたうえで、対応する [付録 E-1〜E-13]({{ site.baseurl }}/appendices/appendix-e-01/) の解答を参照すると理解を定着させやすい。
- 実装章を手元で確認する場合は、[付録 0：環境構築と `runnable minimum`]({{ site.baseurl }}/appendices/appendix-0-environment-setup/) の証跡テンプレートを使い、正常系と拒否系をセットで記録する。
- 実装や設定で詰まった場合は、[付録B：トラブルシューティング]({{ site.baseurl }}/appendices/appendix-b-troubleshooting/) を先に確認する。
- 用語や略語を確認したい場合は、[付録C：用語集]({{ site.baseurl }}/appendices/appendix-c-glossary/) を辞書として併用する。
- ライブラリ比較や追加調査を行う場合は、[付録A：参考ライブラリ・ツール]({{ site.baseurl }}/appendices/appendix-a-libraries/) と [付録D：参考資料]({{ site.baseurl }}/appendices/appendix-d-references/) を起点にすると判断しやすい。

## 想定読者
- Web / モバイルアプリケーションの開発者（ログイン / 権限管理を設計・実装する必要がある方）
- テックリード / アーキテクト（認証基盤の方式選定、移行、標準化を担う方）
- セキュリティ / プラットフォーム担当（脅威・監視・運用の観点から改善したい方）

## 前提知識
- HTTP の基礎（Cookie、ヘッダー、セッションの概念）
- 基本的なプログラミング経験（バックエンド / フロントエンドいずれか）
- セキュリティの基礎用語（脅威、攻撃手法、暗号の概要）
- （推奨）JWT / OAuth 2.0 / OIDC 等の用語に触れた経験（第 II 部で理解が進みやすい）

## 所要時間
- 通読: 約4〜5.5時間（本文量ベース概算。コードブロック除外、400〜600文字/分換算）
- 実装や設定を手元で検証しながら進める場合は、検証範囲により変動します。

## 目次

### はじめに
- [はじめに]({{ site.baseurl }}/introduction/)

### 第 I 部: 基礎概念編

- [第1章：認証・認可とは何か]({{ site.baseurl }}/chapters/chapter-01-overview/)
- [第2章：認証（Authentication）の基礎]({{ site.baseurl }}/chapters/chapter-02-authentication/)
- [第3章：認可（Authorization）の基礎]({{ site.baseurl }}/chapters/chapter-03-authorization/)

### 第 II 部: プロトコルと標準編

- [第4章：セッション管理]({{ site.baseurl }}/chapters/chapter-04-session/)
- [第5章：トークンベース認証]({{ site.baseurl }}/chapters/chapter-05-token-auth/)
- [第6章：OAuth 2.0]({{ site.baseurl }}/chapters/chapter-06-oauth2/)
- [第7章：OpenID Connect と SAML]({{ site.baseurl }}/chapters/chapter-07-oidc-saml/)

### 第 III 部: 実装編

- [第8章：認証システムの設計]({{ site.baseurl }}/chapters/chapter-08-auth-system-design/)
- [第9章：マイクロサービスにおける認証・認可]({{ site.baseurl }}/chapters/chapter-09-microservices-auth/)
- [第10章：実装パターンとベストプラクティス]({{ site.baseurl }}/chapters/chapter-10-implementation-patterns/)

### 第 IV 部: 応用編

- [第11章：セキュリティ脅威と対策]({{ site.baseurl }}/chapters/chapter-11-security-threats/)
- [第12章：パフォーマンスと監視]({{ site.baseurl }}/chapters/chapter-12-performance/)
- [第13章：今後の展望]({{ site.baseurl }}/chapters/chapter-13-future/)

### 付録

- [付録 0：環境構築と `runnable minimum`]({{ site.baseurl }}/appendices/appendix-0-environment-setup/)
- [付録A：参考ライブラリ・ツール]({{ site.baseurl }}/appendices/appendix-a-libraries/)
- [付録B：トラブルシューティング]({{ site.baseurl }}/appendices/appendix-b-troubleshooting/)
- [付録C：用語集]({{ site.baseurl }}/appendices/appendix-c-glossary/)
- [付録D：参考資料]({{ site.baseurl }}/appendices/appendix-d-references/)
- [付録E（E-1〜E-13）：各章演習問題の解答]({{ site.baseurl }}/appendices/appendix-e-01/)（左側の目次から各章の解答へ移動できます）

---

## 著者について

**ITDO Inc.**  
エンタープライズシステムの開発・コンサルティングを手がける技術集団。特に認証・認可システムの設計と実装において豊富な経験を持つ。

## フィードバック

本書へのご意見・ご感想は [GitHub リポジトリ]({{ site.repository.github | default: site.repository }}) までお寄せください。

## ライセンス

本書は **CC BY-NC-SA 4.0** ライセンスで公開しています。  
教育・研究・個人学習での利用は自由ですが、商用利用は別途契約が必要です。

[ライセンス条件の詳細](https://github.com/itdojp/it-engineer-knowledge-architecture/blob/main/LICENSE.md)

**お問い合わせ**  
株式会社アイティードゥ（ITDO Inc.）  
Email: [knowledge@itdo.jp](mailto:knowledge@itdo.jp)

---

© 2025 株式会社アイティードゥ (ITDO Inc.)
{% include page-navigation.html %}
