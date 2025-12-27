---
layout: book
order: 18
title: "付録C: 用語集"
---
# 付録C: 用語集

## A

### AAA (Authentication, Authorization, Accounting)
認証、認可、アカウンティング（監査）の3つのセキュリティ機能を表す概念。ネットワークセキュリティの基本フレームワーク。

### ABAC (Attribute-Based Access Control)
属性ベースアクセス制御。ユーザー、リソース、環境の属性を組み合わせてアクセス制御を行う方式。

### Access Token
リソースへのアクセス権限を表すトークン。通常、短い有効期限を持ち、特定のスコープに制限される。

### ACL (Access Control List)
アクセス制御リスト。リソースごとに、誰がどのような操作を実行できるかを定義したリスト。

### Adaptive Authentication
リスクベース認証とも呼ばれる。アクセスコンテキストに基づいて認証強度を動的に調整する方式。

### API Key
APIへのアクセスを認証するための一意の識別子。通常、長い有効期限を持つが、スコープは限定的。

### Argon2
パスワードハッシュアルゴリズムの一つ。2015年のPassword Hashing Competitionで優勝。メモリハード関数。

### Assertion
認証や認可の文脈で、ユーザーやシステムの属性に関する主張。SAMLやJWTで使用される。

### Asymmetric Encryption
非対称暗号。公開鍵と秘密鍵のペアを使用する暗号方式。RSAやECDSAが代表例。

### Authentication
認証。ユーザーやシステムが主張する身元が正しいことを確認するプロセス。

### Authentication Factor
認証要素。知識（パスワード）、所持（トークン）、生体（指紋）の3つのカテゴリに分類される。

### Authenticator
認証器。FIDO2/WebAuthnにおいて、ユーザーの認証情報を生成・保管するデバイスまたはソフトウェア。

### Authorization
認可。認証されたユーザーが特定のリソースや操作にアクセスする権限を持っているか判定するプロセス。

### Authorization Code
OAuth 2.0のフローで使用される一時的なコード。アクセストークンと交換される。

### Authorization Server
OAuth 2.0において、アクセストークンを発行するサーバー。

## B

### Basic Authentication
HTTPベーシック認証。ユーザー名とパスワードをBase64エンコードしてHTTPヘッダーで送信する単純な認証方式。

### Bearer Token
HTTPのAuthorizationヘッダーで送信されるトークン。所持していることで認証を示す。

### bcrypt
パスワードハッシュアルゴリズム。Blowfish暗号を基にした、計算量的に安全なハッシュ関数。

### Biometric Authentication
生体認証。指紋、顔、虹彩などの生体情報を使用した認証方式。

### Brute Force Attack
総当たり攻撃。可能なすべての組み合わせを試してパスワードを破る攻撃手法。

## C

### CA (Certificate Authority)
認証局。デジタル証明書を発行する信頼できる第三者機関。

### CAPTCHA
Completely Automated Public Turing test to tell Computers and Humans Apart。人間とボットを区別するためのテスト。

### Certificate Pinning
証明書ピンニング。特定の証明書のみを信頼することで、中間者攻撃を防ぐ手法。

### Challenge-Response
チャレンジレスポンス認証。サーバーからのチャレンジに対して、クライアントが適切なレスポンスを返す認証方式。

### Claim
クレーム。JWTやSAMLにおいて、エンティティに関する情報の断片。

### Client Credentials
OAuth 2.0のグラントタイプの一つ。クライアントアプリケーション自体の認証に使用。

### Client ID
OAuth 2.0において、クライアントアプリケーションを識別するための公開識別子。

### Client Secret
OAuth 2.0において、クライアントアプリケーションを認証するための秘密情報。

### CORS (Cross-Origin Resource Sharing)
異なるオリジン間でのリソース共有を可能にするメカニズム。

### Credential
クレデンシャル。認証に使用される情報（パスワード、証明書、トークンなど）の総称。

### Credential Stuffing
漏洩したユーザー名とパスワードの組み合わせを、他のサービスで試す攻撃手法。

### CSRF (Cross-Site Request Forgery)
クロスサイトリクエストフォージェリ。ユーザーの意図しない操作を実行させる攻撃。

### CSP (Content Security Policy)
コンテンツセキュリティポリシー。XSS攻撃を防ぐためのセキュリティ機能。

## D

### Delegation
委譲。ユーザーが自身の権限の一部を他のエンティティに委譲すること。

### Device Fingerprinting
デバイスフィンガープリンティング。ブラウザやデバイスの特徴を組み合わせて一意に識別する技術。

### DID (Decentralized Identifier)
分散型識別子。中央管理者なしに、検証可能でユーザーが管理できる識別子。

### Digest Authentication
HTTPダイジェスト認証。Basic認証の改良版で、パスワードをハッシュ化して送信。

### Digital Signature
デジタル署名。データの完全性と送信者の認証を保証する暗号技術。

## E

### Encryption
暗号化。データを読めない形式に変換し、機密性を保護する技術。

### Entropy
エントロピー。パスワードやトークンのランダム性や予測困難性を表す尺度。

### Ephemeral Key
一時鍵。セッションごとに生成され、使用後に破棄される暗号鍵。

## F

### Factor (Authentication Factor)
認証要素。Something you know（知識）、Something you have（所持）、Something you are（生体）の分類。

### Federated Identity
フェデレーテッドアイデンティティ。複数の独立したシステム間でアイデンティティを共有する仕組み。

### FIDO (Fast IDentity Online)
パスワードレス認証の標準化を推進する業界団体、およびその規格。

### FIDO2
FIDOアライアンスの最新規格。WebAuthnとCTAPで構成される。

### Fingerprint (Device/Browser)
デバイスやブラウザの特徴的な情報の組み合わせ。一意識別に使用。

## G

### Grant Type
OAuth 2.0において、アクセストークンを取得する方法の種類。

### Group
グループ。権限管理において、複数のユーザーをまとめて管理する単位。

## H

### Hash Function
ハッシュ関数。任意長の入力から固定長の出力を生成する一方向関数。

### HMAC (Hash-based Message Authentication Code)
ハッシュベースメッセージ認証コード。秘密鍵とハッシュ関数を組み合わせた認証技術。

### HOTP (HMAC-based One-Time Password)
HMACベースのワンタイムパスワード。カウンターベースのOTP生成アルゴリズム。

### HTTP Basic Authentication
HTTPベーシック認証。最も単純なHTTP認証スキーム。

### HTTPS
HTTP over TLS/SSL。暗号化された安全なHTTP通信。

## I

### Identity
アイデンティティ。システム内でエンティティを一意に識別する属性の集合。

### Identity Provider (IdP)
アイデンティティプロバイダー。ユーザーの認証を行い、アイデンティティ情報を提供するシステム。

### Implicit Flow
OAuth 2.0の認可フローの一つ。現在は非推奨。

### Impersonation
なりすまし。他のユーザーやシステムの身元を偽る行為。

## J

### JSON Web Token (JWT)
JSON形式で表現される、署名または暗号化されたトークン。

### JWE (JSON Web Encryption)
JSONデータを暗号化するための標準。

### JWK (JSON Web Key)
暗号鍵をJSON形式で表現する標準。

### JWKS (JSON Web Key Set)
複数のJWKを含むJSONドキュメント。

### JWS (JSON Web Signature)
JSONデータに署名を付与するための標準。

## K

### Kerberos
ネットワーク認証プロトコル。チケットベースの認証システム。

### Key Derivation Function (KDF)
鍵導出関数。パスワードなどの入力から暗号鍵を生成する関数。

### Key Rotation
鍵のローテーション。セキュリティ向上のため定期的に暗号鍵を更新すること。

### Keychain
キーチェーン。認証情報を安全に保存・管理するシステム。

## L

### LDAP (Lightweight Directory Access Protocol)
ディレクトリサービスにアクセスするためのプロトコル。企業の認証システムでよく使用。

### Least Privilege
最小権限の原則。タスク実行に必要な最小限の権限のみを付与する原則。

### Login
ログイン。システムへの認証を行い、セッションを開始する行為。

### Logout
ログアウト。セッションを終了し、認証状態を解除する行為。

## M

### MAC (Message Authentication Code)
メッセージ認証コード。メッセージの完全性と認証を保証する短い情報。

### Magic Link
マジックリンク。パスワードの代わりにメールで送信される一時的な認証リンク。

### Man-in-the-Middle Attack (MITM)
中間者攻撃。通信を盗聴・改ざんする攻撃手法。

### MFA (Multi-Factor Authentication)
多要素認証。複数の認証要素を組み合わせた認証方式。

### Mutual TLS (mTLS)
相互TLS認証。クライアントとサーバーが互いに証明書で認証し合う方式。

## N

### Nonce
Number used once。リプレイ攻撃を防ぐために使用される一度だけ使用される値。

### Non-Repudiation
否認防止。行為を後で否定できないようにする仕組み。

## O

### OAuth 2.0
認可のための業界標準プロトコル。アクセス委譲のフレームワーク。

### OIDC (OpenID Connect)
OAuth 2.0の上に構築された認証レイヤー。

### One-Time Password (OTP)
ワンタイムパスワード。一度だけ使用可能なパスワード。

### Opaque Token
不透明トークン。内容が暗号化されているか、意味を持たない識別子のみのトークン。

## P

### PAM (Pluggable Authentication Modules)
プラガブル認証モジュール。Unixシステムの認証フレームワーク。

### Passkey
パスキー。FIDO2/WebAuthnベースのパスワードレス認証方式の消費者向け名称。

### Password
パスワード。最も一般的な知識ベースの認証要素。

### Password Hash
パスワードハッシュ。パスワードを不可逆的に変換した値。

### Password Policy
パスワードポリシー。パスワードの複雑性や有効期限に関する規則。

### PBAC (Policy-Based Access Control)
ポリシーベースアクセス制御。宣言的なポリシーによってアクセスを制御する方式。

### PBKDF2
Password-Based Key Derivation Function 2。パスワードから鍵を導出する標準的な関数。

### Phishing
フィッシング。偽のWebサイトやメールで認証情報を盗む攻撃。

### PKCE (Proof Key for Code Exchange)
OAuth 2.0の拡張。公開クライアントのセキュリティを向上させる。

### PKI (Public Key Infrastructure)
公開鍵基盤。公開鍵暗号を使用したセキュリティインフラ。

### Principal
プリンシパル。認証されたエンティティ（ユーザー、サービス、デバイスなど）を表す概念。

### Privilege Escalation
権限昇格。通常より高い権限を不正に取得すること。

## Q

### QR Code Authentication
QRコード認証。QRコードを使用した認証方式。

### Quantum-Resistant Cryptography
量子耐性暗号。量子コンピュータでも破れない暗号アルゴリズム。

## R

### Rainbow Table
レインボーテーブル。ハッシュ値から元のパスワードを逆引きするための事前計算済みテーブル。

### Rate Limiting
レート制限。一定時間内のリクエスト数を制限する仕組み。

### RBAC (Role-Based Access Control)
ロールベースアクセス制御。役割に基づいて権限を管理する方式。

### Realm
レルム。認証や認可の適用範囲を表す領域。

### Refresh Token
リフレッシュトークン。新しいアクセストークンを取得するための長期有効なトークン。

### Registration
登録。新しいユーザーアカウントを作成するプロセス。

### Relying Party (RP)
証明書利用者。OpenID ConnectやSAMLで、IdPからの認証情報を信頼して利用する側。

### Replay Attack
リプレイ攻撃。過去の正当な通信を再送信して認証を突破する攻撃。

### Resource Owner
リソースオーナー。OAuth 2.0において、保護されたリソースの所有者（通常はエンドユーザー）。

### Resource Server
リソースサーバー。OAuth 2.0において、保護されたリソースをホストするサーバー。

### Revocation
失効。トークンや証明書を無効化すること。

### Risk-Based Authentication
リスクベース認証。アクセスのリスクレベルに応じて認証要件を調整する方式。

### Role
ロール。権限管理において、複数の権限をまとめた単位。

### Root of Trust
信頼の起点。セキュリティシステムにおいて、他のすべての信頼の基礎となる要素。

### Rotation (Key/Secret)
ローテーション。セキュリティ向上のため、鍵や秘密情報を定期的に更新すること。

## S

### SAML (Security Assertion Markup Language)
セキュリティアサーションマークアップ言語。XMLベースの認証・認可情報交換標準。

### Salt
ソルト。パスワードハッシュに追加するランダムなデータ。レインボーテーブル攻撃を防ぐ。

### SCIM (System for Cross-domain Identity Management)
クロスドメインアイデンティティ管理システム。ユーザー情報の同期のための標準。

### Scope
スコープ。OAuth 2.0において、アクセス権限の範囲を定義する文字列。

### Secret
シークレット。認証に使用される秘密情報の総称。

### Secure Cookie
セキュアCookie。HTTPS接続でのみ送信されるCookie。

### Security Token
セキュリティトークン。認証や認可の情報を含むデータ構造。

### Session
セッション。ログインからログアウトまでの一連のインタラクション。

### Session Fixation
セッション固定攻撃。攻撃者が事前に用意したセッションIDを被害者に使用させる攻撃。

### Session Hijacking
セッションハイジャック。正当なユーザーのセッションを乗っ取る攻撃。

### Session ID
セッションID。セッションを一意に識別する識別子。

### SFA (Single Factor Authentication)
単一要素認証。一つの認証要素のみを使用する認証方式。

### SHA (Secure Hash Algorithm)
安全なハッシュアルゴリズム。SHA-1、SHA-256などのハッシュ関数ファミリー。

### Signature
署名。データの完全性と真正性を保証するための暗号学的な値。

### Single Sign-On (SSO)
シングルサインオン。一度の認証で複数のシステムにアクセスできる仕組み。

### Single Sign-Out (SLO)
シングルサインアウト。一度のログアウトで複数のシステムからログアウトする仕組み。

### SMTP
Simple Mail Transfer Protocol。メール送信プロトコル。パスワードリセット等で使用。

### Social Login
ソーシャルログイン。FacebookやGoogleなどのソーシャルメディアアカウントでログインする方式。

### SPNEGO
Simple and Protected GSSAPI Negotiation Mechanism。Kerberosベースの認証ネゴシエーション。

### SQL Injection
SQLインジェクション。SQLクエリに悪意のあるコードを挿入する攻撃。

### SRP (Secure Remote Password)
安全なリモートパスワードプロトコル。パスワードを送信せずに認証を行う方式。

### SSL/TLS
Secure Sockets Layer/Transport Layer Security。暗号化通信プロトコル。

### State Parameter
OAuth 2.0やOpenID Connectで、CSRF攻撃を防ぐために使用されるパラメータ。

### Step-up Authentication
ステップアップ認証。特定の操作時に追加の認証を要求する方式。

### Strong Authentication
強力な認証。複数要素や高強度の認証方式を使用した認証。

### Subject
サブジェクト。認証や認可の対象となるエンティティ。JWTではsubクレーム。

### Symmetric Encryption
対称暗号。暗号化と復号に同じ鍵を使用する暗号方式。

## T

### TAN (Transaction Authentication Number)
取引認証番号。特定の取引を認証するための一時的な番号。

### Tenant
テナント。マルチテナントシステムにおける論理的な分離単位。

### Third-Party Cookie
サードパーティCookie。訪問しているサイトとは異なるドメインから設定されるCookie。

### Threat Model
脅威モデル。システムに対する潜在的な脅威を体系的に分析したもの。

### Time-based One-Time Password (TOTP)
時間ベースワンタイムパスワード。現在時刻を基にOTPを生成するアルゴリズム。

### TLS (Transport Layer Security)
トランスポート層セキュリティ。SSLの後継となる暗号化通信プロトコル。

### Token
トークン。認証や認可の情報を含むデータの塊。

### Token Binding
トークンバインディング。トークンを特定のTLS接続に紐付ける技術。

### Token Endpoint
トークンエンドポイント。OAuth 2.0でアクセストークンを発行するエンドポイント。

### Token Introspection
トークンイントロスペクション。トークンの有効性や詳細情報を確認するプロセス。

### Token Revocation
トークン失効。発行済みトークンを無効化すること。

### Trust
信頼。セキュリティシステムにおいて、エンティティ間の信頼関係。

### Trusted Platform Module (TPM)
信頼できるプラットフォームモジュール。ハードウェアベースのセキュリティチップ。

### Two-Factor Authentication (2FA)
二要素認証。2つの異なる認証要素を使用する認証方式。

## U

### UAF (Universal Authentication Framework)
FIDO仕様の一つ。パスワードレス認証のためのフレームワーク。

### User
ユーザー。システムを利用する人間のエンドユーザー。

### User Agent
ユーザーエージェント。ユーザーの代理としてサーバーと通信するソフトウェア（ブラウザなど）。

### User Consent
ユーザー同意。データアクセスや処理に対するユーザーからの明示的な許可。

### Username
ユーザー名。ユーザーを識別するための一意の文字列。

## V

### Validation
検証。入力データやトークンが正しい形式や値であることを確認するプロセス。

### Vault
ボールト。秘密情報を安全に保管・管理するシステム。

### Verification
照合。提供された認証情報が正しいことを確認するプロセス。

### Verifiable Credentials
検証可能な資格情報。分散型アイデンティティで使用される、暗号学的に検証可能な属性情報。

## W

### Web Authentication API (WebAuthn)
W3C標準のブラウザAPIで、公開鍵暗号を使用したパスワードレス認証を実現。

### Web Credential
Webクレデンシャル。ブラウザに保存される認証情報。

### Whitelist
ホワイトリスト。許可されたエンティティのリスト。

## X

### X.509
公開鍵証明書の標準フォーマット。

### XSS (Cross-Site Scripting)
クロスサイトスクリプティング。悪意のあるスクリプトを注入する攻撃。

## Y

### Yubikey
ハードウェア認証デバイスの一種。FIDO2、OTP、スマートカードなど複数の認証方式をサポート。

## Z

### Zero Knowledge Proof
ゼロ知識証明。秘密情報を明かすことなく、その知識を持っていることを証明する暗号学的手法。

### Zero Trust
ゼロトラスト。「決して信頼せず、常に検証する」というセキュリティモデル。

### Zone
ゾーン。セキュリティ境界で区切られた領域。異なるセキュリティレベルを適用。
