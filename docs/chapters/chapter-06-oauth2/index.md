---
layout: book
order: 8
title: "第6章：OAuth 2.0"
---

# 第6章：OAuth 2.0

## 6.1 OAuth 2.0の設計思想 - なぜOAuthが生まれたのか

### 6.1.1 パスワードアンチパターンの問題

OAuth登場以前、サードパーティアプリケーションがユーザーのリソースにアクセスする方法は問題だらけでした。

```python
class PreOAuthProblems:
    """OAuth以前の認可の問題"""
    
    def password_antipattern(self):
        """パスワードアンチパターンの実例"""
        
        # 2007年頃の典型的な実装
        bad_practice = {
            'scenario': '''
            TwitterクライアントアプリがTwitter APIを使う場合：
            1. アプリ：「Twitterのユーザー名とパスワードを入力してください」
            2. ユーザー：自分のパスワードをサードパーティアプリに渡す
            3. アプリ：受け取ったパスワードを保存（！）
            4. アプリ：ユーザーのパスワードでTwitter APIにアクセス
            ''',
            
            'problems': [
                {
                    'issue': 'パスワードの漏洩リスク',
                    'impact': 'アプリのDBが侵害されるとユーザーのパスワードが流出',
                    'example': '2009年、某Twitter管理ツールから10万件のパスワード流出'
                },
                {
                    'issue': '過剰な権限',
                    'impact': 'パスワードを持つ = すべての操作が可能',
                    'example': 'ツイート投稿だけしたいのにDM閲覧も可能に'
                },
                {
                    'issue': 'アクセス取り消しの困難さ',
                    'impact': 'パスワード変更しないとアクセスを止められない',
                    'example': '使わなくなったアプリが永続的にアクセス可能'
                },
                {
                    'issue': '信頼の連鎖の破綻',
                    'impact': 'ユーザーはすべてのアプリを信頼する必要',
                    'example': '悪意あるアプリがパスワードを悪用'
                }
            ]
        }
        
        return bad_practice
```

### 6.1.2 OAuthが解決する問題の本質

```python
class OAuthPhilosophy:
    """OAuth 2.0の設計哲学"""
    
    def core_principles(self):
        """OAuth 2.0の中核原則"""
        
        return {
            'delegation_not_impersonation': {
                'concept': '委任であって、なりすましではない',
                'meaning': '''
                # 従来：なりすまし
                app.login_as_user(username, password)  # アプリがユーザーになりすます
                
                # OAuth：委任
                user.grant_permission_to(app, scope=['read_tweets'])  # ユーザーが権限を委任
                ''',
                'benefit': 'ユーザーが主体的に権限をコントロール'
            },
            
            'separation_of_concerns': {
                'concept': '関心の分離',
                'roles': {
                    'resource_owner': 'リソースの所有者（エンドユーザー）',
                    'client': 'リソースにアクセスしたいアプリケーション',
                    'authorization_server': '認可を管理するサーバー',
                    'resource_server': 'リソースを提供するAPIサーバー'
                },
                'benefit': '各コンポーネントが単一の責任を持つ'
            },
            
            'limited_scope': {
                'concept': '権限の最小化',
                'example': '''
                # スコープによる権限制限
                scopes = {
                    'read:profile': 'プロフィール情報の読み取り',
                    'write:tweets': 'ツイートの投稿',
                    'read:dm': 'ダイレクトメッセージの読み取り'
                }
                
                # アプリは必要最小限のスコープのみ要求
                requested_scopes = ['read:profile', 'write:tweets']
                ''',
                'benefit': '過剰な権限付与を防ぐ'
            },
            
            'revocability': {
                'concept': 'いつでも取り消し可能',
                'implementation': '''
                # ユーザーはいつでもアクセスを取り消せる
                def revoke_access(user_id: str, client_id: str):
                    tokens = Token.query.filter_by(
                        user_id=user_id,
                        client_id=client_id
                    ).all()
                    
                    for token in tokens:
                        token.revoked = True
                    
                    db.session.commit()
                ''',
                'benefit': 'ユーザーが自分のデータをコントロール'
            }
        }
```

### 6.1.3 なぜOAuth 2.0なのか（1.0との違い）

```python
class OAuth2Evolution:
    """OAuth 1.0から2.0への進化"""
    
    def why_oauth2(self):
        """なぜOAuth 2.0が必要だったのか"""
        
        oauth1_problems = {
            'signature_complexity': {
                'issue': '署名の計算が複雑',
                'oauth1_example': '''
                # OAuth 1.0の署名計算
                def create_oauth1_signature(method, url, params, consumer_secret, token_secret):
                    # 1. パラメータの正規化
                    normalized_params = normalize_parameters(params)
                    
                    # 2. ベース文字列の作成
                    base_string = f"{method}&{percent_encode(url)}&{percent_encode(normalized_params)}"
                    
                    # 3. 署名キーの作成
                    signing_key = f"{percent_encode(consumer_secret)}&{percent_encode(token_secret)}"
                    
                    # 4. HMAC-SHA1で署名
                    signature = hmac.new(
                        signing_key.encode(),
                        base_string.encode(),
                        hashlib.sha1
                    ).digest()
                    
                    return base64.b64encode(signature).decode()
                ''',
                'developer_impact': '実装ミスが頻発、デバッグが困難'
            },
            
            'limited_client_types': {
                'issue': 'Webアプリケーション中心の設計',
                'limitations': [
                    'モバイルアプリでの実装が困難',
                    'JavaScriptアプリ（SPA）での使用が非現実的',
                    'IoTデバイスでの実装が複雑'
                ]
            },
            
            'performance_overhead': {
                'issue': '毎リクエストでの署名計算',
                'impact': 'API呼び出しのオーバーヘッド増大'
            }
        }
        
        oauth2_improvements = {
            'simplicity': {
                'change': 'Bearer Tokenによるシンプルな認可',
                'example': '''
                # OAuth 2.0のシンプルなAPI呼び出し
                headers = {
                    'Authorization': f'Bearer {access_token}'
                }
                response = requests.get('https://api.example.com/user', headers=headers)
                ''',
                'benefit': '実装が容易、エラーが少ない'
            },
            
            'flexibility': {
                'change': '複数のグラントタイプ',
                'types': {
                    'authorization_code': 'Webアプリ向け',
                    'implicit': 'SPAア向け（現在は非推奨）',
                    'client_credentials': 'サーバー間通信',
                    'resource_owner_password': 'レガシー対応'
                },
                'benefit': '様々なユースケースに対応'
            },
            
            'extensibility': {
                'change': '拡張可能な仕様',
                'extensions': [
                    'PKCE（Proof Key for Code Exchange）',
                    'Device Authorization Grant',
                    'Token Introspection',
                    'Token Revocation'
                ],
                'benefit': '進化する脅威への対応が可能'
            }
        }
        
        return {
            'oauth1_problems': oauth1_problems,
            'oauth2_improvements': oauth2_improvements,
            'migration_impact': 'OAuth 2.0は後方互換性を捨てて、より良い設計を選択'
        }
```

## 6.2 各種グラントタイプの使い分け - ユースケースに応じた選択

### 6.2.1 Authorization Code Grant - 最も安全な標準フロー

```python
class AuthorizationCodeGrant:
    """認可コードグラントの実装"""
    
    def __init__(self):
        self.flow_explanation = self._explain_flow()
        self.implementation = self._implement_flow()
        
    def _explain_flow(self):
        """なぜ認可コードグラントが安全なのか"""
        
        return {
            'security_features': {
                'code_exchange': {
                    'reason': 'アクセストークンがブラウザを経由しない',
                    'benefit': 'ブラウザ履歴やリファラーでの漏洩を防ぐ'
                },
                'client_authentication': {
                    'reason': 'トークンエンドポイントでクライアント認証',
                    'benefit': '認可コードを盗んでも、client_secretなしでは使えない'
                },
                'one_time_code': {
                    'reason': '認可コードは一度だけ使用可能',
                    'benefit': 'リプレイ攻撃を防ぐ'
                },
                'short_lived_code': {
                    'reason': '認可コードの有効期限は短い（通常10分）',
                    'benefit': '攻撃の時間窓を最小化'
                }
            },
            
            'flow_diagram': '''
            User        Browser         Client App      Auth Server    Resource Server
            │            │                 │               │              │
            │  1. Access App              │               │              │
            ├───────────────────────────▶│               │              │
            │            │                 │               │              │
            │            │  2. Redirect to Auth           │              │
            │            │◀────────────────┤               │              │
            │            │                 │               │              │
            │            │  3. Authorization Request       │              │
            │            ├────────────────────────────────▶│              │
            │            │                 │               │              │
            │  4. Login & Consent          │               │              │
            │◀───────────┼────────────────────────────────┤              │
            │            │                 │               │              │
            │  5. Approve │                │               │              │
            ├────────────┼───────────────────────────────▶│              │
            │            │                 │               │              │
            │            │  6. Redirect with Code          │              │
            │            │◀────────────────────────────────┤              │
            │            │                 │               │              │
            │            │  7. Code        │               │              │
            │            ├────────────────▶│               │              │
            │            │                 │               │              │
            │            │                 │  8. Exchange Code for Token │
            │            │                 ├──────────────▶│              │
            │            │                 │               │              │
            │            │                 │  9. Access Token            │
            │            │                 │◀──────────────┤              │
            │            │                 │               │              │
            │            │                 │  10. API Request            │
            │            │                 ├─────────────────────────────▶│
            │            │                 │               │              │
            │            │                 │  11. Protected Resource     │
            │            │                 │◀─────────────────────────────┤
            '''
        }
    
    def _implement_flow(self):
        """認可コードフローの実装"""
        
        from flask import Flask, request, redirect, session
        import secrets
        import requests
        from urllib.parse import urlencode
        
        class OAuthClient:
            def __init__(self, client_id: str, client_secret: str, 
                        auth_endpoint: str, token_endpoint: str):
                self.client_id = client_id
                self.client_secret = client_secret
                self.auth_endpoint = auth_endpoint
                self.token_endpoint = token_endpoint
                
            def create_authorization_url(self, redirect_uri: str, 
                                       scope: List[str], 
                                       state: Optional[str] = None) -> str:
                """認可URLの作成"""
                
                # CSRF対策のstate生成
                if not state:
                    state = secrets.token_urlsafe(32)
                    session['oauth_state'] = state
                
                params = {
                    'response_type': 'code',
                    'client_id': self.client_id,
                    'redirect_uri': redirect_uri,
                    'scope': ' '.join(scope),
                    'state': state
                }
                
                return f"{self.auth_endpoint}?{urlencode(params)}"
            
            def exchange_code_for_token(self, code: str, 
                                      redirect_uri: str, 
                                      state: str) -> Dict:
                """認可コードをアクセストークンに交換"""
                
                # State検証（CSRF対策）
                if state != session.get('oauth_state'):
                    raise ValueError("Invalid state parameter")
                
                # Stateを削除（再利用防止）
                session.pop('oauth_state', None)
                
                # トークンリクエスト
                token_data = {
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': redirect_uri,
                    'client_id': self.client_id,
                    'client_secret': self.client_secret
                }
                
                response = requests.post(
                    self.token_endpoint,
                    data=token_data,
                    headers={'Accept': 'application/json'}
                )
                
                if response.status_code != 200:
                    raise Exception(f"Token exchange failed: {response.text}")
                
                tokens = response.json()
                
                # トークンの検証
                self._validate_tokens(tokens)
                
                return tokens
            
            def _validate_tokens(self, tokens: Dict):
                """取得したトークンの基本検証"""
                
                required_fields = ['access_token', 'token_type']
                for field in required_fields:
                    if field not in tokens:
                        raise ValueError(f"Missing required field: {field}")
                
                if tokens['token_type'].lower() != 'bearer':
                    raise ValueError(f"Unsupported token type: {tokens['token_type']}")
                
                # トークンの有効期限確認
                if 'expires_in' in tokens and tokens['expires_in'] <= 0:
                    raise ValueError("Token already expired")
        
        return OAuthClient
```

### 6.2.2 Client Credentials Grant - サービス間認証

```python
class ClientCredentialsGrant:
    """クライアントクレデンシャルグラントの実装"""
    
    def explain_use_case(self):
        """いつClient Credentialsを使うべきか"""
        
        return {
            'appropriate_scenarios': [
                {
                    'scenario': 'マイクロサービス間通信',
                    'example': 'OrderServiceがUserServiceのAPIを呼ぶ',
                    'why': 'エンドユーザーが関与しない'
                },
                {
                    'scenario': 'バッチ処理',
                    'example': '夜間バッチがAPIを使ってデータ同期',
                    'why': 'ユーザーコンテキストが不要'
                },
                {
                    'scenario': 'システム管理タスク',
                    'example': '監視システムがメトリクスAPIにアクセス',
                    'why': 'システムレベルの操作'
                }
            ],
            
            'inappropriate_scenarios': [
                {
                    'scenario': 'ユーザー固有のリソースアクセス',
                    'why': 'ユーザーの認可が必要',
                    'correct_grant': 'Authorization Code'
                },
                {
                    'scenario': 'モバイルアプリからの直接アクセス',
                    'why': 'クライアントシークレットを安全に保存できない',
                    'correct_grant': 'Authorization Code + PKCE'
                }
            ]
        }
    
    def implement_grant(self):
        """Client Credentials実装"""
        
        class ServiceAuthClient:
            def __init__(self, client_id: str, client_secret: str, 
                        token_endpoint: str):
                self.client_id = client_id
                self.client_secret = client_secret
                self.token_endpoint = token_endpoint
                self.token_cache = {}
                
            async def get_access_token(self, scope: Optional[List[str]] = None) -> str:
                """アクセストークンの取得（キャッシュ付き）"""
                
                cache_key = f"{self.client_id}:{':'.join(scope or [])}"
                
                # キャッシュチェック
                cached_token = self._get_cached_token(cache_key)
                if cached_token:
                    return cached_token
                
                # 新規取得
                token_data = {
                    'grant_type': 'client_credentials',
                    'client_id': self.client_id,
                    'client_secret': self.client_secret
                }
                
                if scope:
                    token_data['scope'] = ' '.join(scope)
                
                response = await self._make_token_request(token_data)
                
                # キャッシュに保存
                self._cache_token(cache_key, response)
                
                return response['access_token']
            
            def _get_cached_token(self, cache_key: str) -> Optional[str]:
                """キャッシュからトークンを取得"""
                
                if cache_key not in self.token_cache:
                    return None
                
                cached = self.token_cache[cache_key]
                
                # 有効期限チェック（5分のバッファ）
                if time.time() < cached['expires_at'] - 300:
                    return cached['access_token']
                
                # 期限切れの場合は削除
                del self.token_cache[cache_key]
                return None
            
            def _cache_token(self, cache_key: str, token_response: Dict):
                """トークンをキャッシュに保存"""
                
                expires_in = token_response.get('expires_in', 3600)
                
                self.token_cache[cache_key] = {
                    'access_token': token_response['access_token'],
                    'expires_at': time.time() + expires_in
                }
            
            async def make_authenticated_request(self, 
                                               url: str, 
                                               method: str = 'GET',
                                               **kwargs) -> requests.Response:
                """認証付きHTTPリクエスト"""
                
                token = await self.get_access_token()
                
                headers = kwargs.get('headers', {})
                headers['Authorization'] = f'Bearer {token}'
                kwargs['headers'] = headers
                
                response = requests.request(method, url, **kwargs)
                
                # 401の場合はトークンをリフレッシュして再試行
                if response.status_code == 401:
                    # キャッシュクリア
                    self.token_cache.clear()
                    
                    # 新しいトークンで再試行
                    token = await self.get_access_token()
                    headers['Authorization'] = f'Bearer {token}'
                    response = requests.request(method, url, **kwargs)
                
                return response
        
        return ServiceAuthClient
```

### 6.2.3 Refresh Token Grant - トークンの更新

```python
class RefreshTokenGrant:
    """リフレッシュトークングラントの実装"""
    
    def explain_refresh_token_design(self):
        """なぜリフレッシュトークンが必要か"""
        
        return {
            'design_rationale': {
                'security_vs_usability': {
                    'problem': 'アクセストークンの有効期限のジレンマ',
                    'short_lived': {
                        'pros': 'セキュア（漏洩時の影響が限定的）',
                        'cons': '頻繁な再認証が必要'
                    },
                    'long_lived': {
                        'pros': 'ユーザビリティが高い',
                        'cons': '漏洩時の影響が大きい'
                    },
                    'solution': 'リフレッシュトークンによる両立'
                },
                
                'token_characteristics': {
                    'access_token': {
                        'lifetime': '15分〜1時間',
                        'usage': '頻繁（API呼び出しごと）',
                        'storage': 'メモリ推奨',
                        'scope': 'APIアクセス'
                    },
                    'refresh_token': {
                        'lifetime': '30日〜90日',
                        'usage': 'まれ（アクセストークン更新時のみ）',
                        'storage': 'セキュアストレージ',
                        'scope': '新しいアクセストークンの取得のみ'
                    }
                }
            }
        }
    
    def implement_refresh_flow(self):
        """リフレッシュフローの実装"""
        
        class TokenManager:
            def __init__(self, client_id: str, client_secret: str,
                        token_endpoint: str):
                self.client_id = client_id
                self.client_secret = client_secret
                self.token_endpoint = token_endpoint
                self.token_store = SecureTokenStore()
                
            async def refresh_access_token(self, refresh_token: str) -> Dict:
                """リフレッシュトークンを使用して新しいアクセストークンを取得"""
                
                refresh_data = {
                    'grant_type': 'refresh_token',
                    'refresh_token': refresh_token,
                    'client_id': self.client_id,
                    'client_secret': self.client_secret
                }
                
                try:
                    response = await self._make_token_request(refresh_data)
                    
                    # 新しいトークンの保存
                    await self._store_tokens(response)
                    
                    # リフレッシュトークンローテーション対応
                    if 'refresh_token' in response:
                        # 新しいリフレッシュトークンが発行された場合
                        await self._rotate_refresh_token(
                            old_token=refresh_token,
                            new_token=response['refresh_token']
                        )
                    
                    return response
                    
                except TokenExpiredError:
                    # リフレッシュトークン自体が期限切れ
                    raise ReAuthenticationRequired()
                except InvalidTokenError:
                    # リフレッシュトークンが無効（取り消されたなど）
                    raise ReAuthenticationRequired()
            
            async def _rotate_refresh_token(self, old_token: str, new_token: str):
                """リフレッシュトークンのローテーション処理"""
                
                # 古いトークンを無効化
                await self.token_store.revoke_token(old_token)
                
                # 新しいトークンを保存
                await self.token_store.store_refresh_token(new_token)
                
                # セキュリティログ
                logging.info(f"Refresh token rotated for client {self.client_id}")
            
            def implement_automatic_refresh(self):
                """自動リフレッシュの実装"""
                
                class AutoRefreshClient:
                    def __init__(self, token_manager: TokenManager):
                        self.token_manager = token_manager
                        self.access_token = None
                        self.token_expiry = None
                        self.refresh_token = None
                        self.refresh_lock = asyncio.Lock()
                        
                    async def make_request(self, url: str, **kwargs) -> Response:
                        """自動リフレッシュ機能付きリクエスト"""
                        
                        # トークンの有効性チェック
                        if await self._should_refresh():
                            await self._refresh_tokens()
                        
                        # リクエスト実行
                        headers = kwargs.get('headers', {})
                        headers['Authorization'] = f'Bearer {self.access_token}'
                        kwargs['headers'] = headers
                        
                        response = await aiohttp.request('GET', url, **kwargs)
                        
                        # 401エラーの場合は再度リフレッシュ
                        if response.status == 401:
                            await self._refresh_tokens()
                            
                            # 再試行
                            headers['Authorization'] = f'Bearer {self.access_token}'
                            response = await aiohttp.request('GET', url, **kwargs)
                        
                        return response
                    
                    async def _should_refresh(self) -> bool:
                        """リフレッシュが必要かチェック"""
                        
                        if not self.access_token:
                            return True
                        
                        # 有効期限の5分前にリフレッシュ
                        buffer_time = 300
                        return time.time() >= (self.token_expiry - buffer_time)
                    
                    async def _refresh_tokens(self):
                        """トークンのリフレッシュ（重複防止付き）"""
                        
                        async with self.refresh_lock:
                            # 別のコルーチンが既にリフレッシュしている場合
                            if not await self._should_refresh():
                                return
                            
                            tokens = await self.token_manager.refresh_access_token(
                                self.refresh_token
                            )
                            
                            self.access_token = tokens['access_token']
                            self.token_expiry = time.time() + tokens['expires_in']
                            
                            if 'refresh_token' in tokens:
                                self.refresh_token = tokens['refresh_token']
                
                return AutoRefreshClient
        
        return TokenManager
```

### 6.2.4 最新のグラントタイプ

```python
class ModernGrantTypes:
    """最新のOAuth 2.0グラントタイプ"""
    
    def device_authorization_grant(self):
        """Device Authorization Grant (RFC 8628)"""
        
        return {
            'use_case': 'キーボード入力が困難なデバイス',
            'examples': ['スマートTV', 'ゲーム機', 'IoTデバイス'],
            
            'flow': '''
            1. デバイス → 認可サーバー: デバイスコードをリクエスト
            2. 認可サーバー → デバイス: device_code, user_code, verification_uri
            3. デバイス → ユーザー: "https://example.com/device で ABCD-1234 を入力"
            4. ユーザー → ブラウザ: コード入力と認可
            5. デバイス → 認可サーバー: ポーリング（device_codeでトークン確認）
            6. 認可サーバー → デバイス: アクセストークン
            ''',
            
            'implementation': '''
            class DeviceAuthFlow:
                async def initiate_device_flow(self, client_id: str) -> Dict:
                    """デバイスフローの開始"""
                    
                    response = await self.http_client.post(
                        'https://auth.example.com/device/code',
                        data={
                            'client_id': client_id,
                            'scope': 'read write'
                        }
                    )
                    
                    return {
                        'device_code': response['device_code'],
                        'user_code': response['user_code'],
                        'verification_uri': response['verification_uri'],
                        'expires_in': response['expires_in'],
                        'interval': response.get('interval', 5)
                    }
                
                async def poll_for_token(self, device_code: str, 
                                       interval: int = 5) -> Dict:
                    """トークンのポーリング"""
                    
                    while True:
                        try:
                            response = await self.http_client.post(
                                'https://auth.example.com/token',
                                data={
                                    'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                                    'device_code': device_code,
                                    'client_id': self.client_id
                                }
                            )
                            
                            if response.status_code == 200:
                                return response.json()
                            elif response.json()['error'] == 'authorization_pending':
                                await asyncio.sleep(interval)
                            elif response.json()['error'] == 'slow_down':
                                interval += 5
                                await asyncio.sleep(interval)
                            else:
                                raise Exception(response.json()['error'])
                                
                        except Exception as e:
                            raise DeviceAuthError(f"Polling failed: {e}")
            '''
        }
```

## 6.3 セキュリティ考慮事項（PKCE等）- 脆弱性の歴史と対策の進化

### 6.3.1 Authorization Code Injection Attack

```python
class AuthCodeInjectionAttack:
    """認可コードインジェクション攻撃と対策"""
    
    def explain_vulnerability(self):
        """脆弱性の説明"""
        
        return {
            'attack_scenario': '''
            1. 攻撃者が正規のOAuthフローを開始
            2. 認可サーバーから認可コードを取得（自分のコード）
            3. 被害者に対して、攻撃者の認可コードを含むリダイレクトURLを送る
            4. 被害者がそのURLをクリック
            5. アプリが攻撃者の認可コードを使ってトークンを取得
            6. 被害者が攻撃者のアカウントでログインしてしまう
            ''',
            
            'impact': [
                '被害者が攻撃者のアカウントで操作してしまう',
                '被害者の情報が攻撃者のアカウントに保存される',
                'CSRF攻撃の一種として悪用可能'
            ],
            
            'traditional_mitigation': {
                'state_parameter': '''
                # stateパラメータによる対策
                def create_auth_url():
                    state = secrets.token_urlsafe(32)
                    session['oauth_state'] = state
                    
                    return f"{auth_url}?client_id={client_id}&state={state}"
                
                def handle_callback(code, state):
                    if state != session.get('oauth_state'):
                        raise SecurityError("Invalid state")
                ''',
                'limitation': 'stateは主にCSRF対策であり、code injection対策としては不完全'
            }
        }
    
    def implement_pkce(self):
        """PKCE (RFC 7636) の実装"""
        
        import hashlib
        import base64
        import secrets
        
        class PKCEClient:
            """Proof Key for Code Exchange実装"""
            
            def generate_pkce_pair(self) -> Tuple[str, str]:
                """PKCE用のcode_verifierとcode_challengeを生成"""
                
                # Code Verifier: 43-128文字のランダム文字列
                code_verifier = base64.urlsafe_b64encode(
                    secrets.token_bytes(32)
                ).decode('utf-8').rstrip('=')
                
                # Code Challenge: VerifierのSHA256ハッシュ
                challenge_bytes = hashlib.sha256(
                    code_verifier.encode('utf-8')
                ).digest()
                code_challenge = base64.urlsafe_b64encode(
                    challenge_bytes
                ).decode('utf-8').rstrip('=')
                
                return code_verifier, code_challenge
            
            def create_authorization_url_with_pkce(self, 
                                                 redirect_uri: str,
                                                 scope: List[str]) -> Tuple[str, str]:
                """PKCE対応の認可URL作成"""
                
                # PKCEペアの生成
                code_verifier, code_challenge = self.generate_pkce_pair()
                
                # セッションに保存（後で使用）
                session['pkce_verifier'] = code_verifier
                
                params = {
                    'response_type': 'code',
                    'client_id': self.client_id,
                    'redirect_uri': redirect_uri,
                    'scope': ' '.join(scope),
                    'state': secrets.token_urlsafe(32),
                    # PKCE パラメータ
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256'
                }
                
                auth_url = f"{self.auth_endpoint}?{urlencode(params)}"
                
                return auth_url, code_verifier
            
            def exchange_code_with_pkce(self, 
                                       code: str,
                                       redirect_uri: str) -> Dict:
                """PKCE検証付きでコードをトークンに交換"""
                
                # セッションからverifierを取得
                code_verifier = session.pop('pkce_verifier', None)
                if not code_verifier:
                    raise SecurityError("PKCE verifier not found")
                
                token_data = {
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': redirect_uri,
                    'client_id': self.client_id,
                    # PKCEパラメータ
                    'code_verifier': code_verifier
                }
                
                # パブリッククライアントの場合はclient_secretなし
                if self.client_secret:
                    token_data['client_secret'] = self.client_secret
                
                response = requests.post(self.token_endpoint, data=token_data)
                
                if response.status_code != 200:
                    raise OAuthError(f"Token exchange failed: {response.text}")
                
                return response.json()
            
            def explain_pkce_security(self):
                """PKCEがなぜ安全なのか"""
                
                return {
                    'attack_prevention': '''
                    1. 攻撃者が認可コードを盗んでも...
                    2. code_verifierを知らないため、トークン交換できない
                    3. code_challengeからcode_verifierを逆算することは不可能（SHA256）
                    ''',
                    
                    'flow_comparison': {
                        'without_pkce': '''
                        App → AS: code=ABCD
                        AS → App: access_token（攻撃者も同じcodeで取得可能）
                        ''',
                        
                        'with_pkce': '''
                        App → AS: code=ABCD, code_verifier=SECRET123
                        AS: SHA256(SECRET123) == stored_challenge? 
                        AS → App: access_token（verifierなしでは取得不可）
                        '''
                    }
                }
        
        return PKCEClient
```

### 6.3.2 その他の主要な脆弱性と対策

```python
class OAuthSecurityVulnerabilities:
    """OAuth 2.0の脆弱性と対策"""
    
    def open_redirect_vulnerability(self):
        """オープンリダイレクト脆弱性"""
        
        return {
            'vulnerability': {
                'description': 'redirect_uriの検証不足による任意のサイトへのリダイレクト',
                'attack': '''
                # 攻撃例
                https://auth.example.com/authorize?
                    client_id=abc123&
                    redirect_uri=https://evil.com&  # 悪意のあるサイト
                    response_type=code
                ''',
                'impact': '認可コードやトークンの窃取'
            },
            
            'mitigation': '''
            class RedirectURIValidator:
                def __init__(self):
                    # 事前登録されたredirect_uri
                    self.registered_uris = {
                        'client_abc123': [
                            'https://app.example.com/callback',
                            'https://app.example.com/oauth/callback'
                        ]
                    }
                
                def validate_redirect_uri(self, client_id: str, 
                                        redirect_uri: str) -> bool:
                    """redirect_uriの厳密な検証"""
                    
                    registered = self.registered_uris.get(client_id, [])
                    
                    # 完全一致のみ許可（部分一致は危険）
                    if redirect_uri not in registered:
                        return False
                    
                    # プロトコルのダウングレード防止
                    parsed = urlparse(redirect_uri)
                    if parsed.scheme != 'https':
                        # localhost開発環境のみ例外
                        if not (parsed.hostname == 'localhost' and 
                               parsed.port in [3000, 8080]):
                            return False
                    
                    return True
            '''
        }
    
    def token_leakage_in_referrer(self):
        """リファラーによるトークン漏洩"""
        
        return {
            'vulnerability': {
                'description': 'URLフラグメントのトークンがリファラーで漏洩',
                'scenario': 'Implicitフロー使用時の問題',
                'example': '''
                # ブラウザのアドレスバー
                https://app.example.com/#access_token=SECRET_TOKEN
                
                # このページから外部リンクをクリックすると...
                Referer: https://app.example.com/#access_token=SECRET_TOKEN
                '''
            },
            
            'mitigation': [
                {
                    'method': 'Implicitフローの廃止',
                    'recommendation': 'Authorization Code + PKCEを使用'
                },
                {
                    'method': 'Referrer-Policyの設定',
                    'implementation': '''
                    # HTMLメタタグ
                    <meta name="referrer" content="no-referrer">
                    
                    # HTTPヘッダー
                    Referrer-Policy: no-referrer
                    '''
                },
                {
                    'method': 'トークンの即座の処理',
                    'implementation': '''
                    // フラグメントからトークンを抽出して削除
                    if (window.location.hash) {
                        const params = new URLSearchParams(
                            window.location.hash.substring(1)
                        );
                        const token = params.get('access_token');
                        
                        // トークンを安全な場所に保存
                        tokenManager.store(token);
                        
                        // URLからトークンを削除
                        window.history.replaceState(
                            {}, 
                            document.title, 
                            window.location.pathname
                        );
                    }
                    '''
                }
            ]
        }
    
    def mix_up_attack(self):
        """Mix-Up攻撃"""
        
        return {
            'vulnerability': {
                'description': '複数のASを使う場合の混乱攻撃',
                'attack_flow': '''
                1. クライアントがAS1に認可リクエスト
                2. 攻撃者（AS2）が、AS1のclient_idでレスポンス
                3. クライアントが誤ってAS2にトークンリクエスト
                4. 攻撃者がトークンを取得
                '''
            },
            
            'mitigation': {
                'issuer_identification': '''
                # Authorization Response にissuerを含める
                def create_auth_response(code: str, state: str) -> str:
                    params = {
                        'code': code,
                        'state': state,
                        'iss': 'https://auth.example.com'  # 発行者の明示
                    }
                    return f"{redirect_uri}?{urlencode(params)}"
                
                # クライアント側での検証
                def validate_auth_response(params: Dict, expected_issuer: str):
                    if params.get('iss') != expected_issuer:
                        raise SecurityError("Issuer mismatch")
                '''
            }
        }
```

### 6.3.3 セキュリティベストプラクティス集

```python
class OAuthSecurityBestPractices:
    """OAuth 2.0セキュリティのベストプラクティス"""
    
    def comprehensive_security_checklist(self):
        """包括的なセキュリティチェックリスト"""
        
        return {
            'client_authentication': {
                'public_clients': [
                    'PKCEを必須とする',
                    'client_secretを使用しない',
                    'redirect_uriの厳密な検証'
                ],
                'confidential_clients': [
                    'client_secretの安全な管理',
                    'mTLSの検討',
                    'client assertion (JWT) の使用'
                ]
            },
            
            'token_handling': {
                'storage': [
                    'アクセストークンはメモリに保持',
                    'リフレッシュトークンは暗号化して保存',
                    'トークンのスコープを最小限に'
                ],
                'transmission': [
                    'HTTPSの必須化',
                    'Authorizationヘッダーの使用',
                    'URLパラメータでのトークン送信禁止'
                ],
                'validation': [
                    'トークンの署名検証',
                    '有効期限の確認',
                    'audience (aud) の検証'
                ]
            },
            
            'implementation_security': '''
            class SecureOAuthImplementation:
                def __init__(self):
                    self.security_config = {
                        'token_lifetime': 900,  # 15分
                        'refresh_token_lifetime': 2592000,  # 30日
                        'auth_code_lifetime': 600,  # 10分
                        'pkce_required': True,
                        'state_required': True
                    }
                
                def validate_client_request(self, request: Request) -> bool:
                    """クライアントリクエストの包括的検証"""
                    
                    # HTTPS必須
                    if not request.is_secure:
                        raise SecurityError("HTTPS required")
                    
                    # リクエストの完全性チェック
                    if self._detect_parameter_pollution(request):
                        raise SecurityError("Parameter pollution detected")
                    
                    # レート制限
                    if not self._check_rate_limit(request.client_id):
                        raise RateLimitError("Too many requests")
                    
                    return True
                
                def _detect_parameter_pollution(self, request: Request) -> bool:
                    """HTTPパラメータ汚染の検出"""
                    
                    for key in request.args:
                        if len(request.args.getlist(key)) > 1:
                            # 同じパラメータが複数回出現
                            return True
                    
                    return False
            '''
        }
```

## 6.4 実装時の落とし穴 - よくある実装ミスとその影響

### 6.4.1 State Parameter の誤用

```python
class StatePitfalls:
    """Stateパラメータの実装ミス"""
    
    def common_mistakes(self):
        """よくある間違いとその影響"""
        
        return [
            {
                'mistake': '予測可能なstate値',
                'bad_example': '''
                # ❌ 悪い例：予測可能
                state = str(int(time.time()))
                state = f"oauth_state_{user_id}"
                state = hashlib.md5(session_id.encode()).hexdigest()
                ''',
                'good_example': '''
                # ✅ 良い例：暗号学的に安全な乱数
                import secrets
                state = secrets.token_urlsafe(32)
                ''',
                'impact': 'CSRF攻撃が可能になる'
            },
            
            {
                'mistake': 'stateの再利用',
                'bad_example': '''
                # ❌ 悪い例：stateを使い回し
                class OAuthClient:
                    def __init__(self):
                        self.state = "my_oauth_state"  # 固定値
                    
                    def create_auth_url(self):
                        return f"{auth_url}?state={self.state}"
                ''',
                'good_example': '''
                # ✅ 良い例：毎回新しいstateを生成
                def create_auth_url():
                    state = secrets.token_urlsafe(32)
                    session['oauth_state'] = state
                    session['oauth_state_timestamp'] = time.time()
                    return f"{auth_url}?state={state}"
                ''',
                'impact': 'リプレイ攻撃の可能性'
            },
            
            {
                'mistake': 'stateの有効期限なし',
                'bad_example': '''
                # ❌ 悪い例：無期限に有効
                def verify_state(state):
                    return state == session.get('oauth_state')
                ''',
                'good_example': '''
                # ✅ 良い例：有効期限付き
                def verify_state(state):
                    stored_state = session.get('oauth_state')
                    timestamp = session.get('oauth_state_timestamp', 0)
                    
                    # 10分以内のみ有効
                    if time.time() - timestamp > 600:
                        return False
                    
                    # 一度だけ使用可能
                    if state == stored_state:
                        session.pop('oauth_state', None)
                        session.pop('oauth_state_timestamp', None)
                        return True
                    
                    return False
                '''
            }
        ]
```

### 6.4.2 トークンの取り扱いミス

```python
class TokenHandlingMistakes:
    """トークン取り扱いの実装ミス"""
    
    def insecure_token_storage(self):
        """安全でないトークン保存"""
        
        return {
            'localStorage_abuse': {
                'bad_example': '''
                // ❌ 悪い例：LocalStorageに生のトークン
                fetch('/oauth/callback?code=' + code)
                    .then(res => res.json())
                    .then(data => {
                        localStorage.setItem('access_token', data.access_token);
                        localStorage.setItem('refresh_token', data.refresh_token);
                    });
                ''',
                'problems': [
                    'XSS攻撃で簡単に盗まれる',
                    'ブラウザ拡張からアクセス可能',
                    'デバッグツールで誰でも見える'
                ],
                'good_example': '''
                // ✅ 良い例：メモリ内管理 + HttpOnly Cookie
                class TokenManager {
                    constructor() {
                        this.accessToken = null;
                        this.expiresAt = null;
                    }
                    
                    setAccessToken(token, expiresIn) {
                        this.accessToken = token;
                        this.expiresAt = Date.now() + (expiresIn * 1000);
                        
                        // リフレッシュトークンはHttpOnly Cookieで
                        // サーバー側で設定
                    }
                    
                    getAccessToken() {
                        if (Date.now() >= this.expiresAt) {
                            return this.refreshAccessToken();
                        }
                        return this.accessToken;
                    }
                }
                '''
            },
            
            'token_in_url': {
                'bad_example': '''
                # ❌ 悪い例：URLにトークン
                @app.route('/api/data')
                def get_data():
                    token = request.args.get('access_token')  # URLパラメータ
                    return fetch_user_data(token)
                
                # 呼び出し
                GET /api/data?access_token=SECRET_TOKEN
                ''',
                'problems': [
                    'サーバーログに記録される',
                    'ブラウザ履歴に残る',
                    'リファラーで漏洩',
                    'プロキシログに記録'
                ],
                'good_example': '''
                # ✅ 良い例：Authorizationヘッダー
                @app.route('/api/data')
                def get_data():
                    auth_header = request.headers.get('Authorization')
                    if not auth_header or not auth_header.startswith('Bearer '):
                        return {'error': 'Unauthorized'}, 401
                    
                    token = auth_header.split(' ')[1]
                    return fetch_user_data(token)
                
                # 呼び出し
                GET /api/data
                Authorization: Bearer SECRET_TOKEN
                '''
            }
        }
    
    def improper_token_validation(self):
        """不適切なトークン検証"""
        
        return {
            'no_expiration_check': {
                'bad_example': '''
                # ❌ 悪い例：有効期限チェックなし
                def validate_token(token):
                    try:
                        payload = jwt.decode(token, key, options={"verify_exp": False})
                        return payload
                    except:
                        return None
                ''',
                'good_example': '''
                # ✅ 良い例：適切な検証
                def validate_token(token):
                    try:
                        # 有効期限も含めて検証
                        payload = jwt.decode(
                            token, 
                            key, 
                            algorithms=['RS256'],
                            options={"verify_exp": True}
                        )
                        
                        # 追加の検証
                        if 'aud' in payload and payload['aud'] != expected_audience:
                            raise InvalidAudienceError()
                        
                        if 'iss' in payload and payload['iss'] != expected_issuer:
                            raise InvalidIssuerError()
                        
                        return payload
                        
                    except jwt.ExpiredSignatureError:
                        logging.warning("Token expired")
                        raise
                    except jwt.InvalidTokenError as e:
                        logging.error(f"Invalid token: {e}")
                        raise
                '''
            }
        }
```

### 6.4.3 エラーハンドリングの落とし穴

```python
class ErrorHandlingPitfalls:
    """エラーハンドリングの問題"""
    
    def information_disclosure(self):
        """情報漏洩につながるエラー処理"""
        
        return {
            'detailed_error_messages': {
                'bad_example': '''
                # ❌ 悪い例：詳細すぎるエラー情報
                @app.route('/oauth/token', methods=['POST'])
                def token_endpoint():
                    try:
                        client_id = request.form['client_id']
                        client_secret = request.form['client_secret']
                        
                        client = Client.query.filter_by(id=client_id).first()
                        if not client:
                            return {
                                'error': 'invalid_client',
                                'error_description': f'Client {client_id} not found in database'
                            }, 401
                        
                        if client.secret != client_secret:
                            return {
                                'error': 'invalid_client',
                                'error_description': 'Client secret mismatch. Expected: ' + client.secret[:4] + '...'
                            }, 401
                            
                    except Exception as e:
                        return {
                            'error': 'server_error',
                            'error_description': str(e),
                            'stack_trace': traceback.format_exc()  # 絶対ダメ！
                        }, 500
                ''',
                
                'good_example': '''
                # ✅ 良い例：最小限のエラー情報
                @app.route('/oauth/token', methods=['POST'])
                def token_endpoint():
                    try:
                        # クライアント認証
                        if not authenticate_client(request):
                            # 詳細を隠す
                            return {
                                'error': 'invalid_client'
                            }, 401
                        
                        # トークン処理
                        return process_token_request(request)
                        
                    except InvalidGrantError:
                        return {'error': 'invalid_grant'}, 400
                    except Exception as e:
                        # 内部エラーはログに記録
                        app.logger.error(f"Token endpoint error: {e}", exc_info=True)
                        
                        # クライアントには最小限の情報
                        return {'error': 'server_error'}, 500
                '''
            },
            
            'timing_attacks': {
                'bad_example': '''
                # ❌ 悪い例：タイミング攻撃に脆弱
                def verify_client_secret(client_id, provided_secret):
                    client = get_client(client_id)
                    if not client:
                        return False  # すぐに返る
                    
                    # 文字列比較（タイミングが異なる）
                    return client.secret == provided_secret
                ''',
                
                'good_example': '''
                # ✅ 良い例：定数時間比較
                import hmac
                
                def verify_client_secret(client_id, provided_secret):
                    client = get_client(client_id)
                    if not client:
                        # ダミーの比較を実行
                        expected = "dummy_secret_for_timing_protection"
                    else:
                        expected = client.secret
                    
                    # 定数時間比較
                    return hmac.compare_digest(expected, provided_secret)
                '''
            }
        }
```

### 6.4.4 設定ミスと実装の不整合

```python
class ConfigurationMistakes:
    """設定ミスと実装の問題"""
    
    def common_configuration_issues(self):
        """よくある設定ミス"""
        
        return {
            'development_settings_in_production': {
                'bad_example': '''
                # ❌ 悪い例：開発設定が本番に
                class OAuthConfig:
                    # デバッグモードが有効
                    DEBUG = True
                    
                    # HTTPSチェックが無効
                    REQUIRE_HTTPS = False
                    
                    # すべてのredirect_uriを許可
                    ALLOW_ANY_REDIRECT_URI = True
                    
                    # トークンの有効期限が長すぎる
                    ACCESS_TOKEN_LIFETIME = 86400  # 24時間
                ''',
                
                'good_example': '''
                # ✅ 良い例：環境別設定
                class OAuthConfig:
                    def __init__(self, env='production'):
                        self.env = env
                        
                        if env == 'production':
                            self.DEBUG = False
                            self.REQUIRE_HTTPS = True
                            self.ALLOW_ANY_REDIRECT_URI = False
                            self.ACCESS_TOKEN_LIFETIME = 900  # 15分
                            self.LOG_LEVEL = 'WARNING'
                        else:
                            # 開発環境
                            self.DEBUG = True
                            self.REQUIRE_HTTPS = False
                            self.ALLOW_ANY_REDIRECT_URI = False  # それでも制限
                            self.ACCESS_TOKEN_LIFETIME = 3600
                            self.LOG_LEVEL = 'DEBUG'
                '''
            },
            
            'grant_type_misconfiguration': {
                'scenario': '不要なグラントタイプの有効化',
                'bad_example': '''
                # ❌ 悪い例：すべてのグラントタイプを有効化
                ENABLED_GRANT_TYPES = [
                    'authorization_code',
                    'implicit',  # 非推奨
                    'password',  # 危険
                    'client_credentials',
                    'refresh_token'
                ]
                ''',
                
                'good_example': '''
                # ✅ 良い例：必要最小限のグラントタイプ
                def get_allowed_grant_types(client):
                    if client.type == 'public':
                        # パブリッククライアントは限定的
                        return ['authorization_code']  # + PKCE必須
                    elif client.type == 'confidential':
                        return ['authorization_code', 'refresh_token']
                    elif client.type == 'service':
                        return ['client_credentials']
                    else:
                        return []
                '''
            }
        }
```

## まとめ

この章では、OAuth 2.0の設計思想から実装の詳細まで学びました：

1. **OAuth 2.0の設計思想**
   - パスワードアンチパターンの問題
   - 委任による権限管理
   - OAuth 1.0からの進化

2. **グラントタイプの使い分け**
   - Authorization Code：最も安全な標準フロー
   - Client Credentials：サービス間認証
   - Refresh Token：トークンの更新
   - 最新のグラントタイプ

3. **セキュリティ考慮事項**
   - PKCEによるcode injection対策
   - 各種脆弱性と対策
   - セキュリティベストプラクティス

4. **実装時の落とし穴**
   - Stateパラメータの誤用
   - トークンの取り扱いミス
   - エラーハンドリングの問題
   - 設定ミスと実装の不整合

次章では、OpenID ConnectとSAMLについて、エンタープライズ環境でのSSO実現方法を学びます。

## 演習問題

### 問題1：OAuth 2.0クライアントの実装
以下の要件を満たすOAuth 2.0クライアントを実装しなさい：
- Authorization Code Grant with PKCE
- 自動的なトークンリフレッシュ
- 適切なエラーハンドリング
- セキュアなトークン保存

### 問題2：脆弱性の発見と修正
提供されたOAuth 2.0実装コードから脆弱性を見つけ、修正案を提示しなさい。

### 問題3：グラントタイプの選択
以下のシナリオに対して、適切なグラントタイプを選択し、理由を説明しなさい：
- モバイルアプリからのAPI利用
- 定期バッチ処理
- シングルページアプリケーション
- IoTデバイスの認証

### 問題4：PKCEの実装
PKCEを使用したAuthorization Code Grantの完全な実装を作成しなさい。サーバー側とクライアント側の両方を含むこと。

### 問題5：セキュリティ監査
既存のOAuth 2.0実装に対してセキュリティ監査を実施し、以下を報告しなさい：
- 発見された脆弱性
- リスク評価
- 修正優先度
- 実装改善案
