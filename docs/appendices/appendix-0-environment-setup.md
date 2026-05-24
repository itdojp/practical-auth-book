---
layout: book
order: 15.5
title: "付録0 環境構築と runnable minimum"
---
# 付録0 環境構築と runnable minimum

この付録は、各実装章の runnable minimum を安全に確認するための入口です。
本書のコード例は設計・レビュー観点を説明するための抜粋を含むため、読者は自分の検証用アプリケーションまたはローカルモックに置き換えて確認してください。

## 0.1 原則

- 本番ユーザー、本番 client secret、本番 IdP の管理者権限を使わない。
- 検証用 tenant、検証用 client、短寿命のダミー鍵、ローカル callback URL を使う。
- 正常系だけでなく、拒否されるべき入力を必ず 1 件以上確認する。
- 実行結果は、コマンド、HTTP status、ログ、スクリーンショットのいずれかで残す。

## 0.2 最小ツール

| 用途 | 最小要件 | 確認コマンド例 |
| --- | --- | --- |
| Node.js 実装確認 | Node.js 20 以上 | `node --version && npm --version` |
| HTTP 確認 | `curl` またはブラウザ開発者ツール | `curl --version` |
| JSON 確認 | `jq` または同等ツール | `jq --version` |
| コンテナ検証 | Docker / Podman のいずれか | `docker --version` または `podman --version` |

## 0.3 ローカル環境変数の雛形

次の値は例です。本番値を貼り付けず、ローカル専用の値へ置き換えてください。

```bash
cat > .env.local <<'ENV'
AUTH_BASE_URL=http://localhost:3000
SESSION_COOKIE_NAME=__Host-dev-session
SESSION_SECRET=replace-with-local-random-value
OIDC_ISSUER=http://localhost:8080/realms/dev
OIDC_CLIENT_ID=local-dev-client
OIDC_CLIENT_SECRET=local-dev-only
TOKEN_AUDIENCE=local-api
ENV
```

## 0.4 runnable minimum 証跡テンプレート

各章で最小確認を行ったら、次の形式で PR または学習メモに残してください。

```text
対象章:
確認日:
入力:
起動条件:
期待結果:
実結果:
失敗系の確認:
未確認事項:
本番投入しない値:
```

## 0.5 章別の入口

- 第4章: セッション Cookie の属性、期限、失効、改ざん拒否を確認する。
- 第5章: JWT / token の issuer、audience、期限、署名鍵不一致を確認する。
- 第6章: OAuth 2.0 の state、redirect URI、PKCE、認可コード再利用拒否を確認する。
- 第7章: OIDC / SAML metadata、issuer、audience、署名鍵、callback の一致を確認する。
- 第8章: 方式選定表、境界図、保管場所、監査ログ方針を確認する。
- 第9章: 外部リクエストと内部呼び出しの認証責務を分けて確認する。
- 第10章: 401 / 403 / 成功 / credential 期限切れの 4 ケースを確認する。
