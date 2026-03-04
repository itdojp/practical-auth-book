---
layout: book
order: 19
title: "付録D: 参考資料"
---
# 付録D: 参考資料

## D.1 必読の仕様書・標準文書

### OAuth 2.0関連

#### 基本仕様
- **RFC 6749**: The OAuth 2.0 Authorization Framework
  - URL: https://datatracker.ietf.org/doc/html/rfc6749
  - 説明: OAuth 2.0の基本仕様。すべての実装者が読むべき文書

- **RFC 6750**: The OAuth 2.0 Bearer Token Usage
  - URL: https://datatracker.ietf.org/doc/html/rfc6750
  - 説明: Bearer Tokenの使用方法を定義

- **RFC 7636**: Proof Key for Code Exchange (PKCE)
  - URL: https://datatracker.ietf.org/doc/html/rfc7636
  - 説明: 公開クライアントのセキュリティ強化

#### セキュリティ関連
- **RFC 6819**: OAuth 2.0 Threat Model and Security Considerations
  - URL: https://datatracker.ietf.org/doc/html/rfc6819
  - 説明: OAuth 2.0の脅威モデルとセキュリティ考慮事項

- **OAuth 2.0 Security Best Current Practice**
  - URL: https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics/
  - 説明: 最新のセキュリティベストプラクティス

### OpenID Connect

- **OpenID Connect Core 1.0**
  - URL: https://openid.net/specs/openid-connect-core-1_0.html
  - 説明: OpenID Connectの中核仕様

- **OpenID Connect Discovery 1.0**
  - URL: https://openid.net/specs/openid-connect-discovery-1_0.html
  - 説明: プロバイダーの自動検出仕様

- **OpenID Connect Dynamic Registration 1.0**
  - URL: https://openid.net/specs/openid-connect-registration-1_0.html
  - 説明: クライアントの動的登録

### JWT/JWS/JWE

- **RFC 7519**: JSON Web Token (JWT)
  - URL: https://datatracker.ietf.org/doc/html/rfc7519
  - 説明: JWT形式の定義

- **RFC 7515**: JSON Web Signature (JWS)
  - URL: https://datatracker.ietf.org/doc/html/rfc7515
  - 説明: JSON署名の仕様

- **RFC 7516**: JSON Web Encryption (JWE)
  - URL: https://datatracker.ietf.org/doc/html/rfc7516
  - 説明: JSON暗号化の仕様

- **RFC 7517**: JSON Web Key (JWK)
  - URL: https://datatracker.ietf.org/doc/html/rfc7517
  - 説明: JSON形式の鍵表現

### FIDO2/WebAuthn

- **Web Authentication: W3C Recommendation**
  - URL: https://www.w3.org/TR/webauthn-2/
  - 説明: WebAuthn APIの仕様

- **FIDO2: CTAP Specification**
  - URL: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html
  - 説明: クライアントと認証器間のプロトコル

### SAML

- **SAML 2.0 Core**
  - URL: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
  - 説明: SAML 2.0の中核仕様

- **SAML 2.0 Profiles**
  - URL: http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
  - 説明: SAML 2.0の使用プロファイル

## D.2 実装ガイド・ベストプラクティス

### OWASP (Open Web Application Security Project)

- **OWASP Authentication Cheat Sheet**
  - URL: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
  - 内容: 認証実装のベストプラクティス集

- **OWASP Session Management Cheat Sheet**
  - URL: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
  - 内容: セッション管理のセキュリティガイド

- **OWASP Password Storage Cheat Sheet**
  - URL: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
  - 内容: パスワード保存のベストプラクティス

- **OWASP Top 10**
  - URL: https://owasp.org/www-project-top-ten/
  - 内容: Webアプリケーションの主要なセキュリティリスク

### NIST (National Institute of Standards and Technology)

- **NIST SP 800-63B: Digital Identity Guidelines - Authentication and Lifecycle Management**
  - URL: https://pages.nist.gov/800-63-3/sp800-63b.html
  - 内容: デジタルアイデンティティの認証ガイドライン

- **NIST SP 800-63C: Digital Identity Guidelines - Federation and Assertions**
  - URL: https://pages.nist.gov/800-63-3/sp800-63c.html
  - 内容: フェデレーション認証のガイドライン

### 企業・団体のガイド

- **Auth0 Identity Fundamentals**
  - URL: https://auth0.com/docs/get-started/identity-fundamentals
  - 内容: 認証・認可の基礎から実装まで

- **Okta Developer Documentation**
  - URL: https://developer.okta.com/docs/
  - 内容: エンタープライズ認証の実装ガイド

- **Google OAuth 2.0 Best Practices**
  - URL: https://developers.google.com/identity/protocols/oauth2/resources/best-practices
  - 内容: Google OAuth 2.0 の実装・運用ベストプラクティス

## D.3 書籍

### 基礎・入門書

1. **「OAuth徹底入門」**
   - 著者: Justin Richer, Antonio Sanso
   - 出版社: 翔泳社
   - 推奨理由: OAuth 2.0の仕組みを基礎から詳しく解説

2. **「体系的に学ぶ 安全なWebアプリケーションの作り方」**
   - 著者: 徳丸浩
   - 出版社: SBクリエイティブ
   - 推奨理由: 認証・セッション管理の脆弱性と対策を網羅

3. **「Real-World Cryptography」**
   - 著者: David Wong
   - 出版社: Manning
   - 推奨理由: 暗号技術の実践的な使い方を解説

### 実装・設計

4. **「Designing Secure Software」**
   - 著者: Loren Kohnfelder
   - 出版社: No Starch Press
   - 推奨理由: セキュアな設計の原則と実践

5. **「API Security in Action」**
   - 著者: Neil Madden
   - 出版社: Manning
   - 推奨理由: APIセキュリティの実装技術

6. **「Zero Trust Networks」**
   - 著者: Evan Gilman, Doug Barth
   - 出版社: O'Reilly
   - 推奨理由: ゼロトラストアーキテクチャの実装

### 専門書

7. **「Serious Cryptography」**
   - 著者: Jean-Philippe Aumasson
   - 出版社: No Starch Press
   - 推奨理由: 暗号アルゴリズムの深い理解

8. **「Applied Cryptography」**
   - 著者: Bruce Schneier
   - 出版社: Wiley
   - 推奨理由: 暗号技術の古典的名著

## D.4 オンラインリソース

### 学習サイト

- **MDN Web Docs - Web Authentication API**
  - URL: https://developer.mozilla.org/docs/Web/API/Web_Authentication_API
  - 内容: WebAuthnの詳細な解説とサンプルコード

- **JWT.io**
  - URL: https://jwt.io/
  - 内容: JWTのデバッガーと各言語のライブラリ一覧

- **OAuth.net**
  - URL: https://oauth.net/
  - 内容: OAuth関連の最新情報とリソース集

- **WebAuthn.io**
  - URL: https://webauthn.io/
  - 内容: WebAuthnのデモとテストツール

### コミュニティ・フォーラム

- **IETF OAuth Working Group**
  - URL: https://datatracker.ietf.org/wg/oauth/about/
  - 内容: OAuth標準の議論と最新動向

- **OpenID Foundation**
  - URL: https://openid.net/
  - 内容: OpenID Connectの最新情報

- **FIDO Alliance**
  - URL: https://fidoalliance.org/
  - 内容: FIDO2/WebAuthnの最新動向

- **Stack Overflow - Authentication Tag**
  - URL: https://stackoverflow.com/questions/tagged/authentication
  - 内容: 実装に関する Q&A

### ブログ・技術記事

- **Troy Hunt's Blog**
  - URL: https://www.troyhunt.com/
  - 推奨記事: パスワード管理、データ漏洩分析

- **Scott Brady's Blog**
  - URL: https://www.scottbrady91.com/
  - 推奨記事: OAuth、OpenID Connect実装

- **Vittorio Bertocci's Blog**
  - URL: https://www.vittoriobertocci.com/
  - 推奨記事: 認証プロトコルの詳細解説

- **Auth0 Blog**
  - URL: https://auth0.com/blog/
  - 推奨記事: 認証・認可の最新トレンド

## D.5 ツール・ライブラリ

### デバッグ・テストツール

- **Postman**
  - URL: https://www.postman.com/
  - 用途: OAuth/API認証フローのテスト

- **OAuth 2.0 Playground**
  - URL: https://developers.google.com/oauthplayground/
  - 用途: Google OAuth 2.0のテスト

- **SAML Tracer (Firefox Extension)**
  - URL: https://addons.mozilla.org/firefox/addon/saml-tracer/
  - 用途: SAMLフローのデバッグ

- **Chrome DevTools - WebAuthn Tab**
  - 用途: WebAuthn認証のデバッグ

### セキュリティ検証ツール

- **OWASP ZAP**
  - URL: https://www.zaproxy.org/
  - 用途: 認証・セッション管理の脆弱性スキャン

- **Burp Suite**
  - URL: https://portswigger.net/burp
  - 用途: 認証フローの詳細分析

- **JWT.io Debugger**
  - URL: https://jwt.io/#debugger
  - 用途: JWTのデコードと検証

### パフォーマンステストツール

- **Apache JMeter**
  - URL: https://jmeter.apache.org/
  - 用途: 認証システムの負荷テスト

- **k6**
  - URL: https://k6.io/
  - 用途: モダンな負荷テストツール

- **Gatling**
  - URL: https://gatling.io/
  - 用途: 高性能な負荷テスト

## D.6 認定・トレーニング

### 認定プログラム

- **Certified Information Systems Security Professional (CISSP)**
  - 提供: (ISC)²
  - 内容: 情報セキュリティの包括的な認定

- **Certified Ethical Hacker (CEH)**
  - 提供: EC-Council
  - 内容: 認証システムの脆弱性理解

- **OAuth 2.0 Certified Professional**
  - 提供: Cloud Security Alliance
  - 内容: OAuth 2.0の専門知識認定

### オンラインコース

- **Coursera - Applied Cryptography**
  - 提供: University of Maryland
  - 内容: 暗号技術の実践的応用

- **Pluralsight - OAuth 2.0 and OpenID Connect**
  - 内容: プロトコルの詳細と実装

- **Udemy - Web Authentication, Encryption, JWT, HMAC, & OAuth**
  - 内容: 認証技術の包括的学習

### ワークショップ・カンファレンス

- **RSA Conference**
  - URL: https://www.rsaconference.com/
  - 内容: セキュリティ業界最大のカンファレンス

- **OWASP Global AppSec**
  - URL: https://owasp.org/events/
  - 内容: アプリケーションセキュリティ

- **Identiverse**
  - URL: https://identiverse.com/
  - 内容: アイデンティティ管理専門

- **Authenticate Conference**
  - URL: https://authenticatecon.com/
  - 内容: 認証技術に特化

## D.7 規制・コンプライアンス

### データ保護規制

- **GDPR (General Data Protection Regulation)**
  - URL: https://gdpr.eu/
  - 関連: 認証データの取り扱い、同意管理

- **CCPA (California Consumer Privacy Act)**
  - URL: https://oag.ca.gov/privacy/ccpa
  - 関連: カリフォルニア州のプライバシー規制

- **個人情報保護法（日本）**
  - URL: https://www.ppc.go.jp/
  - 関連: 日本国内での個人情報取り扱い

### 業界標準

- **PCI DSS (Payment Card Industry Data Security Standard)**
  - URL: https://www.pcisecuritystandards.org/
  - 関連: 決済システムの認証要件

- **HIPAA (Health Insurance Portability and Accountability Act)**
  - URL: https://www.hhs.gov/hipaa/
  - 関連: 医療情報システムの認証要件

- **SOC 2 (Service Organization Control 2)**
  - URL: https://www.aicpa.org/soc4so
  - 関連: クラウドサービスのセキュリティ監査

## D.8 継続的な学習のために

### ニュースレター・メーリングリスト

- **tl;dr sec**
  - URL: https://tldrsec.com/
  - 内容: セキュリティニュースの要約

- **SANS NewsBites**
  - URL: https://www.sans.org/newsletters/newsbites/
  - 内容: セキュリティニュースと分析

### Podcast

- **Security Now!**
  - ホスト: Steve Gibson, Leo Laporte
  - 内容: セキュリティトピックの詳細解説

- **Risky Business**
  - ホスト: Patrick Gray
  - 内容: セキュリティニュースと分析

- **Identity, Unlocked**
  - ホスト: Auth0
  - 内容: アイデンティティとセキュリティ

### 研究論文・学術リソース

- **IEEE Xplore Digital Library**
  - URL: https://ieeexplore.ieee.org/
  - 内容: 認証技術の最新研究

- **ACM Digital Library**
  - URL: https://dl.acm.org/
  - 内容: コンピュータセキュリティ研究

- **IACR ePrint Archive**
  - URL: https://eprint.iacr.org/
  - 内容: 暗号学研究論文

### GitHubリポジトリ

- **awesome-auth**
  - URL: https://github.com/casbin/awesome-auth
  - 内容: 認証・認可リソースのキュレーション

- **awesome-oauth-sec**
  - URL: https://github.com/b1narygl1tch/awesome-oauth-sec
  - 内容: OAuth 2.0 / OpenID Connect のセキュリティ関連リソース集

- **WebAuthn Awesome**
  - URL: https://github.com/herrjemand/awesome-webauthn
  - 内容: WebAuthn/FIDO2リソース集
