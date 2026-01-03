---
layout: book
order: 1
title: "実践 認証認可システム設計"
---
# 実践 認証認可システム設計
## ゼロから学ぶアイデンティティ管理の実装

<div class="book-intro">
本書は、認証・認可システムの基礎から実装、運用まで、体系的に学ぶことを目的とした技術書です。単なる技術の解説にとどまらず、「なぜその技術が必要なのか」「どのような問題を解決するのか」という観点から、深い理解を促進します。
</div>

## この本でできるようになること

- 認証・認可の基本概念（Authentication / Authorization）を整理し、代表的なプロトコルや方式の位置づけを説明できるようになる。
- セッション管理・トークンベース認証・OAuth 2.0・OpenID Connect・SAML といった主要技術の特徴と使いどころを比較し、自分のシステムに適した方式を選択できるようになる。
- 単一システムだけでなくマイクロサービス構成における認証・認可の設計パターンを理解し、実装・移行時の注意点を検討できるようになる。
- 実運用を想定したセキュリティ脅威・性能・監視の観点から、認証認可システム全体を見直し、改善ポイントを洗い出せるようになる。

## 読み方の目安

- 認証・認可そのものが初めての読者は、第I部（第1〜3章）を順に読み進めることで、用語と基本構造を一通り押さえてから第II部以降に進むことを推奨する。
- すでに基本用語は理解しており、「具体的なプロトコルの比較」を重視したい読者は、第4〜7章を軸に読み、必要に応じて第1〜3章に戻って背景概念を補完する読み方も有効である。
- 実装やアーキテクチャ設計に関心が高い読者は、第8〜10章（設計・マイクロサービス・実装パターン）を先に読み、その後前半章や付録で詳細仕様を確認する形でもよい。
- 実運用フェーズの課題に直面している読者は、第11〜12章（脅威・性能と監視）を優先し、第1〜10章は必要な部分をピックアップする読み方を想定している。

## 目次

### はじめに
- [はじめに]({{ site.baseurl }}/introduction/)

### 第I部: 基礎概念編

- [第1章：認証・認可とは何か]({{ site.baseurl }}/chapters/chapter-01-overview/)
- [第2章：認証（Authentication）の基礎]({{ site.baseurl }}/chapters/chapter-02-authentication/)
- [第3章：認可（Authorization）の基礎]({{ site.baseurl }}/chapters/chapter-03-authorization/)

### 第II部: プロトコルと標準編

- [第4章：セッション管理]({{ site.baseurl }}/chapters/chapter-04-session/)
- [第5章：トークンベース認証]({{ site.baseurl }}/chapters/chapter-05-token-auth/)
- [第6章：OAuth 2.0]({{ site.baseurl }}/chapters/chapter-06-oauth2/)
- [第7章：OpenID ConnectとSAML]({{ site.baseurl }}/chapters/chapter-07-oidc-saml/)

### 第III部: 実装編

- [第8章：認証システムの設計]({{ site.baseurl }}/chapters/chapter-08-auth-system-design/)
- [第9章：マイクロサービスにおける認証・認可]({{ site.baseurl }}/chapters/chapter-09-microservices-auth/)
- [第10章：実装パターンとベストプラクティス]({{ site.baseurl }}/chapters/chapter-10-implementation-patterns/)

### 第IV部: 応用編

- [第11章：セキュリティ脅威と対策]({{ site.baseurl }}/chapters/chapter-11-security-threats/)
- [第12章：パフォーマンスと監視]({{ site.baseurl }}/chapters/chapter-12-performance/)
- [第13章：今後の展望]({{ site.baseurl }}/chapters/chapter-13-future/)

### 付録

- [付録A：参考ライブラリ・ツール]({{ site.baseurl }}/appendices/appendix-a-libraries/)
- [付録B：トラブルシューティング]({{ site.baseurl }}/appendices/appendix-b-troubleshooting/)
- [付録C：用語集]({{ site.baseurl }}/appendices/appendix-c-glossary/)
- [付録D：参考文献]({{ site.baseurl }}/appendices/appendix-d-references/)

---

## 著者について

**ITDO Inc.**  
エンタープライズシステムの開発・コンサルティングを手がける技術集団。特に認証・認可システムの設計と実装において豊富な経験を持つ。

## フィードバック

本書へのご意見・ご感想は [GitHubリポジトリ]({{ site.repository.github | default: site.repository }}) までお寄せください。

## 📄 ライセンス

本書は **Creative Commons BY-NC-SA 4.0** ライセンスで公開されています。  
**🔓 教育・研究・個人学習での利用は自由** ですが、**💼 商用利用には事前許諾** が必要です。

📋 [詳細なライセンス条件](https://github.com/itdojp/it-engineer-knowledge-architecture/blob/main/LICENSE.md)

**お問い合わせ**  
株式会社アイティードゥ（ITDO Inc.）  
Email: [knowledge@itdo.jp](mailto:knowledge@itdo.jp)

---

© 2025 株式会社アイティードゥ (ITDO Inc.)
{% include page-navigation.html %}
