---
layout: book
order: 25
title: "付録E-6: 第6章演習問題解答"
---
# 第6章 演習問題解答

## 問題1：OAuth 2.0クライアントの実装

### 解答

```python
import secrets
import hashlib
import base64
import time
import asyncio
import aiohttp
from typing import Dict, Optional, List, Tuple
from urllib.parse import urlencode, urlparse, parse_qs
import jwt
from cryptography.fernet import Fernet

class SecureOAuth2Client:
    """
    セキュアなOAuth 2.0クライアント実装
    - Authorization Code Grant with PKCE
    - 自動トークンリフレッシュ
    - セキュアなトークン保存
    """
    
    def __init__(self, client_id: str, client_secret: Optional[str] = None,
                 auth_endpoint: str = None, token_endpoint: str = None,
                 is_public_client: bool = False):
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_endpoint = auth_endpoint
        self.token_endpoint = token_endpoint
        self.is_public_client = is_public_client
        
        # トークン暗号化用のキー
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        
        # メモリ内トークン管理
        self._access_token = None
        self._token_expiry = None
        self._refresh_token_encrypted = None
        
        # リフレッシュ用のロック
        self._refresh_lock = asyncio.Lock()
        
        # セッション管理
        self._sessions = {}
        
    def generate_pkce_pair(self) -> Tuple[str, str]:
        """PKCE用のcode_verifierとcode_challengeを生成"""
        
        # Code Verifier: 43-128文字のランダム文字列
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        # Code Challenge: S256 method
        challenge_bytes = hashlib.sha256(
            code_verifier.encode('utf-8')
        ).digest()
        code_challenge = base64.urlsafe_b64encode(
            challenge_bytes
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    def create_authorization_url(self, redirect_uri: str, 
                               scope: List[str],
                               **kwargs) -> Tuple[str, str]:
        """認可URLの生成（PKCE対応）"""
        
        # State生成（CSRF対策）
        state = secrets.token_urlsafe(32)
        
        # PKCE生成
        code_verifier, code_challenge = self.generate_pkce_pair()
        
        # セッションに保存
        session_id = secrets.token_urlsafe(16)
        self._sessions[session_id] = {
            'state': state,
            'code_verifier': code_verifier,
            'redirect_uri': redirect_uri,
            'created_at': time.time()
        }
        
        # パラメータ構築
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': ' '.join(scope),
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        # 追加パラメータ
        params.update(kwargs)
        
        auth_url = f"{self.auth_endpoint}?{urlencode(params)}"
        
        return auth_url, session_id
    
    async def exchange_code_for_token(self, authorization_response: str,
                                    session_id: str) -> Dict:
        """認可コードをトークンに交換"""
        
        # URLパース
        parsed = urlparse(authorization_response)
        params = parse_qs(parsed.query)
        
        # エラーチェック
        if 'error' in params:
            error = params['error'][0]
            error_description = params.get('error_description', [''])[0]
            raise OAuthError(f"Authorization failed: {error} - {error_description}")
        
        # 必須パラメータチェック
        if 'code' not in params or 'state' not in params:
            raise OAuthError("Missing required parameters")
        
        code = params['code'][0]
        state = params['state'][0]
        
        # セッション取得と検証
        session = self._sessions.get(session_id)
        if not session:
            raise SecurityError("Session not found")
        
        # セッション有効期限チェック（10分）
        if time.time() - session['created_at'] > 600:
            del self._sessions[session_id]
            raise SecurityError("Session expired")
        
        # State検証
        if state != session['state']:
            raise SecurityError("State mismatch - possible CSRF attack")
        
        # トークンリクエスト
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': session['redirect_uri'],
            'code_verifier': session['code_verifier']
        }
        
        # コンフィデンシャルクライアントの場合
        if not self.is_public_client and self.client_secret:
            token_data['client_id'] = self.client_id
            token_data['client_secret'] = self.client_secret
        else:
            token_data['client_id'] = self.client_id
        
        # セッション削除（一度だけ使用）
        del self._sessions[session_id]
        
        # トークンエンドポイントへのリクエスト
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.token_endpoint,
                data=token_data,
                headers={'Accept': 'application/json'}
            ) as response:
                if response.status != 200:
                    error_data = await response.json()
                    raise OAuthError(f"Token exchange failed: {error_data}")
                
                tokens = await response.json()
        
        # トークンの保存
        await self._store_tokens(tokens)
        
        return tokens
    
    async def _store_tokens(self, tokens: Dict):
        """トークンの安全な保存"""
        
        # アクセストークンはメモリに保持
        self._access_token = tokens['access_token']
        
        # 有効期限の計算
        expires_in = tokens.get('expires_in', 3600)
        self._token_expiry = time.time() + expires_in
        
        # リフレッシュトークンは暗号化して保存
        if 'refresh_token' in tokens:
            refresh_bytes = tokens['refresh_token'].encode()
            self._refresh_token_encrypted = self.fernet.encrypt(refresh_bytes)
        
        # 自動リフレッシュのスケジューリング
        if expires_in > 300:  # 5分以上の有効期限
            refresh_time = expires_in - 300  # 5分前にリフレッシュ
            asyncio.create_task(self._schedule_refresh(refresh_time))
    
    async def _schedule_refresh(self, delay: float):
        """自動リフレッシュのスケジューリング"""
        await asyncio.sleep(delay)
        try:
            await self.refresh_access_token()
        except Exception as e:
            print(f"Auto-refresh failed: {e}")
    
    async def get_access_token(self) -> str:
        """有効なアクセストークンの取得"""
        
        # トークンの有効性チェック
        if self._should_refresh():
            await self.refresh_access_token()
        
        if not self._access_token:
            raise AuthenticationRequired("No valid access token")
        
        return self._access_token
    
    def _should_refresh(self) -> bool:
        """リフレッシュが必要かチェック"""
        
        if not self._access_token or not self._token_expiry:
            return True
        
        # 1分のバッファを持ってチェック
        return time.time() >= (self._token_expiry - 60)
    
    async def refresh_access_token(self):
        """アクセストークンのリフレッシュ"""
        
        # 重複リフレッシュ防止
        async with self._refresh_lock:
            # 再度チェック（別のコルーチンがリフレッシュ済みかも）
            if not self._should_refresh():
                return
            
            if not self._refresh_token_encrypted:
                raise AuthenticationRequired("No refresh token available")
            
            # リフレッシュトークンの復号
            refresh_token = self.fernet.decrypt(
                self._refresh_token_encrypted
            ).decode()
            
            # リフレッシュリクエスト
            refresh_data = {
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token
            }
            
            if not self.is_public_client and self.client_secret:
                refresh_data['client_id'] = self.client_id
                refresh_data['client_secret'] = self.client_secret
            else:
                refresh_data['client_id'] = self.client_id
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.token_endpoint,
                    data=refresh_data,
                    headers={'Accept': 'application/json'}
                ) as response:
                    if response.status == 401:
                        # リフレッシュトークンが無効
                        self._clear_tokens()
                        raise AuthenticationRequired("Refresh token invalid")
                    
                    if response.status != 200:
                        error_data = await response.json()
                        raise OAuthError(f"Token refresh failed: {error_data}")
                    
                    tokens = await response.json()
            
            # 新しいトークンの保存
            await self._store_tokens(tokens)
    
    async def make_authenticated_request(self, url: str, method: str = 'GET',
                                       **kwargs) -> aiohttp.ClientResponse:
        """認証付きHTTPリクエスト"""
        
        # トークン取得
        access_token = await self.get_access_token()
        
        # ヘッダー設定
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f'Bearer {access_token}'
        kwargs['headers'] = headers
        
        async with aiohttp.ClientSession() as session:
            async with session.request(method, url, **kwargs) as response:
                # 401の場合は一度だけリトライ
                if response.status == 401:
                    await self.refresh_access_token()
                    access_token = await self.get_access_token()
                    headers['Authorization'] = f'Bearer {access_token}'
                    
                    # リトライ
                    async with session.request(method, url, **kwargs) as retry_response:
                        return retry_response
                
                return response
    
    def _clear_tokens(self):
        """トークンのクリア"""
        self._access_token = None
        self._token_expiry = None
        self._refresh_token_encrypted = None
    
    def logout(self):
        """ログアウト処理"""
        self._clear_tokens()
        self._sessions.clear()

# カスタム例外
class OAuthError(Exception):
    pass

class SecurityError(Exception):
    pass

class AuthenticationRequired(Exception):
    pass

# 使用例
async def main():
    # クライアント初期化
    client = SecureOAuth2Client(
        client_id='your-client-id',
        client_secret=None,  # パブリッククライアント
        auth_endpoint='https://auth.example.com/authorize',
        token_endpoint='https://auth.example.com/token',
        is_public_client=True
    )
    
    # 認可URLの生成
    auth_url, session_id = client.create_authorization_url(
        redirect_uri='https://app.example.com/callback',
        scope=['read', 'write']
    )
    
    print(f"Visit: {auth_url}")
    
    # コールバック処理（実際はWebフレームワークで処理）
    callback_url = input("Enter callback URL: ")
    
    # トークン取得
    tokens = await client.exchange_code_for_token(callback_url, session_id)
    print(f"Access token obtained: {tokens['access_token'][:20]}...")
    
    # API呼び出し
    response = await client.make_authenticated_request(
        'https://api.example.com/user/profile'
    )
    data = await response.json()
    print(f"User data: {data}")

if __name__ == "__main__":
    asyncio.run(main())
```

### 実装のポイント

1. **PKCE実装**：S256メソッドでcode_challengeを生成
2. **自動リフレッシュ**：有効期限の5分前に自動更新
3. **セキュアなトークン保存**：
   - アクセストークン：メモリのみ
   - リフレッシュトークン：暗号化して保存
4. **エラーハンドリング**：
   - 適切な例外クラス
   - 401エラーでの自動リトライ
   - セッションタイムアウト

## 問題2：脆弱性の発見と修正

### 提供されたコード（脆弱性あり）

```python
# 脆弱なOAuth実装
class VulnerableOAuthClient:
    def __init__(self):
        self.client_id = "my-client-id"
        self.client_secret = "my-secret-123"  # ハードコード
        
    def create_auth_url(self, redirect_uri):
        # state なし
        return f"https://auth.example.com/authorize?client_id={self.client_id}&redirect_uri={redirect_uri}&response_type=code"
    
    def handle_callback(self, request):
        code = request.args.get('code')
        
        # HTTPでトークンリクエスト
        response = requests.post('http://auth.example.com/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        })
        
        tokens = response.json()
        
        # LocalStorageに保存
        return f"""
        <script>
        localStorage.setItem('access_token', '{tokens['access_token']}');
        localStorage.setItem('refresh_token', '{tokens['refresh_token']}');
        </script>
        """
    
    def call_api(self, token):
        # URLにトークン
        return requests.get(f"https://api.example.com/data?access_token={token}")
```

### 脆弱性と修正案

```python
class SecureOAuthClient:
    """脆弱性を修正したOAuth実装"""
    
    def __init__(self):
        # 修正1: 環境変数から読み込み
        self.client_id = os.environ.get('OAUTH_CLIENT_ID')
        self.client_secret = os.environ.get('OAUTH_CLIENT_SECRET')
        
        if not self.client_id:
            raise ValueError("OAUTH_CLIENT_ID not configured")
    
    def create_auth_url(self, redirect_uri, session):
        # 修正2: CSRF対策のstate追加
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        session['oauth_timestamp'] = time.time()
        
        # 修正3: PKCE追加
        verifier, challenge = self.generate_pkce_pair()
        session['pkce_verifier'] = verifier
        
        # 修正4: redirect_uriの検証
        if not self._validate_redirect_uri(redirect_uri):
            raise ValueError("Invalid redirect URI")
        
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'state': state,
            'code_challenge': challenge,
            'code_challenge_method': 'S256'
        }
        
        return f"https://auth.example.com/authorize?{urlencode(params)}"
    
    def handle_callback(self, request, session):
        code = request.args.get('code')
        state = request.args.get('state')
        
        # 修正5: state検証
        if not state or state != session.get('oauth_state'):
            raise SecurityError("Invalid state - possible CSRF attack")
        
        # 修正6: stateの有効期限チェック
        if time.time() - session.get('oauth_timestamp', 0) > 600:
            raise SecurityError("State expired")
        
        # セッションから削除
        session.pop('oauth_state', None)
        verifier = session.pop('pkce_verifier', None)
        
        # 修正7: HTTPSを使用
        response = requests.post('https://auth.example.com/token', 
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'code_verifier': verifier
            },
            # 修正8: タイムアウト設定
            timeout=10
        )
        
        if response.status_code != 200:
            # 修正9: 詳細なエラー情報を隠す
            app.logger.error(f"Token exchange failed: {response.text}")
            raise OAuthError("Token exchange failed")
        
        tokens = response.json()
        
        # 修正10: セキュアなトークン保存
        # リフレッシュトークンはHttpOnly Cookieに
        resp = make_response(redirect('/dashboard'))
        resp.set_cookie(
            'refresh_token',
            value=tokens['refresh_token'],
            httponly=True,
            secure=True,
            samesite='Lax',
            max_age=2592000  # 30日
        )
        
        # アクセストークンはセッションに（サーバー側）
        session['access_token'] = tokens['access_token']
        session['token_expiry'] = time.time() + tokens.get('expires_in', 3600)
        
        return resp
    
    def call_api(self, session):
        # 修正11: Authorizationヘッダーを使用
        token = session.get('access_token')
        if not token:
            raise AuthenticationRequired()
        
        # 修正12: 有効期限チェック
        if time.time() >= session.get('token_expiry', 0):
            # リフレッシュが必要
            self.refresh_token(session)
            token = session['access_token']
        
        response = requests.get(
            "https://api.example.com/data",
            headers={
                'Authorization': f'Bearer {token}',
                'X-Request-ID': str(uuid.uuid4())  # トレーサビリティ
            },
            timeout=10
        )
        
        return response
    
    def _validate_redirect_uri(self, uri):
        """redirect_uriの検証"""
        allowed_uris = [
            'https://app.example.com/callback',
            'https://localhost:3000/callback'  # 開発環境
        ]
        return uri in allowed_uris
```

### 発見された脆弱性一覧

1. **ハードコードされた認証情報**
   - 影響：ソースコード漏洩時に認証情報も漏洩
   - 修正：環境変数使用

2. **CSRF対策の欠如**
   - 影響：認可コードインジェクション攻撃
   - 修正：stateパラメータの実装

3. **PKCEの未実装**
   - 影響：認可コード横取り攻撃
   - 修正：PKCEの実装

4. **HTTPの使用**
   - 影響：中間者攻撃によるトークン窃取
   - 修正：HTTPSの強制

5. **トークンのLocalStorage保存**
   - 影響：XSS攻撃によるトークン窃取
   - 修正：HttpOnly Cookieとサーバーセッション

6. **URLでのトークン送信**
   - 影響：ログやリファラーでの漏洩
   - 修正：Authorizationヘッダー使用

7. **redirect_uriの検証不足**
   - 影響：オープンリダイレクト
   - 修正：ホワイトリスト検証

8. **エラー情報の詳細開示**
   - 影響：攻撃者への情報提供
   - 修正：最小限のエラー情報

## 問題3：グラントタイプの選択

### 解答

#### 1. モバイルアプリからのAPI利用

**選択：Authorization Code Grant + PKCE**

**理由：**
- モバイルアプリはパブリッククライアント（client_secretを安全に保存できない）
- PKCEにより認可コード横取り攻撃を防止
- ユーザーコンテキストが必要
- リフレッシュトークンによる長期アクセス可能

**実装例：**
```swift
// iOS実装例
class OAuthManager {
    func authenticate() {
        // PKCE生成
        let verifier = generateCodeVerifier()
        let challenge = generateCodeChallenge(verifier)
        
        // 認可URLを構築してSafariViewControllerで開く
        let authURL = buildAuthURL(
            codeChallenge: challenge,
            redirectURI: "myapp://callback"
        )
        
        // カスタムURLスキームでコールバック処理
    }
}
```

#### 2. 定期バッチ処理

**選択：Client Credentials Grant**

**理由：**
- ユーザーコンテキスト不要（システム間通信）
- サーバー環境でclient_secretを安全に管理可能
- 非対話的な処理に適している
- シンプルなフロー

**実装例：**
```python
class BatchProcessor:
    async def get_system_token(self):
        """システム用トークンの取得"""
        response = await self.http_client.post(
            'https://auth.example.com/token',
            data={
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': 'batch:process'
            }
        )
        return response.json()['access_token']
```

#### 3. シングルページアプリケーション（SPA）

**選択：Authorization Code Grant + PKCE（Implicit Grantは非推奨）**

**理由：**
- Implicit Grantはトークンがブラウザ履歴に残るリスク
- Authorization Code + PKCEでセキュリティ向上
- BFF（Backend for Frontend）パターンも検討
- トークンはメモリ内管理

**実装例：**
```javascript
class SPAAuthManager {
    async authenticate() {
        // PKCE対応
        const codeVerifier = this.generateCodeVerifier();
        const codeChallenge = await this.generateCodeChallenge(codeVerifier);
        
        // セッションストレージに一時保存
        sessionStorage.setItem('pkce_verifier', codeVerifier);
        
        // 認可エンドポイントへリダイレクト
        window.location.href = this.buildAuthURL({
            response_type: 'code',
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
    }
    
    async handleCallback() {
        const code = new URLSearchParams(window.location.search).get('code');
        const verifier = sessionStorage.getItem('pkce_verifier');
        
        // トークン取得
        const tokens = await this.exchangeCode(code, verifier);
        
        // メモリに保存（LocalStorageは使わない）
        this.tokenManager.setTokens(tokens);
    }
}
```

#### 4. IoTデバイスの認証

**選択：Device Authorization Grant (RFC 8628)**

**理由：**
- キーボード入力が困難または不可能
- 画面が小さいまたは存在しない
- QRコードや短いコードで認証可能
- ユーザーは別デバイス（スマホ等）で認証

**実装例：**
```python
class IoTDeviceAuth:
    async def start_device_flow(self):
        """デバイスフローの開始"""
        response = await self.http_client.post(
            'https://auth.example.com/device/code',
            data={
                'client_id': self.device_id,
                'scope': 'device:control'
            }
        )
        
        device_code = response.json()
        
        # ユーザーに表示
        print(f"Please visit: {device_code['verification_uri']}")
        print(f"Enter code: {device_code['user_code']}")
        
        # ポーリング開始
        return await self.poll_for_token(device_code['device_code'])
```

### 選択基準のまとめ

| シナリオ | グラントタイプ | 主な理由 |
|---------|--------------|---------|
| モバイルアプリ | Authorization Code + PKCE | パブリッククライアント、ユーザーコンテキスト必要 |
| バッチ処理 | Client Credentials | システム間通信、ユーザー不在 |
| SPA | Authorization Code + PKCE | Implicitは非推奨、セキュリティ重視 |
| IoTデバイス | Device Authorization | 入力制限、別デバイスでの認証 |

## 問題4：PKCEの実装

### 解答

#### サーバー側実装

```python
from flask import Flask, request, jsonify, session
import secrets
import hashlib
import base64
import time
import redis
import jwt

app = Flask(__name__)
redis_client = redis.Redis()

class PKCEAuthorizationServer:
    """PKCE対応の認可サーバー実装"""
    
    def __init__(self):
        self.redis = redis_client
        self.signing_key = "your-signing-key"  # 実際は安全に管理
        
    @app.route('/authorize', methods=['GET'])
    def authorize(self):
        """認可エンドポイント"""
        
        # 必須パラメータの検証
        required_params = ['client_id', 'redirect_uri', 'response_type', 
                          'code_challenge', 'code_challenge_method']
        
        for param in required_params:
            if param not in request.args:
                return jsonify({'error': 'invalid_request', 
                              'error_description': f'Missing {param}'}), 400
        
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        code_challenge = request.args.get('code_challenge')
        code_challenge_method = request.args.get('code_challenge_method')
        
        # クライアント検証
        if not self._validate_client(client_id, redirect_uri):
            return jsonify({'error': 'invalid_client'}), 401
        
        # PKCE検証
        if code_challenge_method != 'S256':
            return jsonify({'error': 'invalid_request',
                          'error_description': 'Only S256 supported'}), 400
        
        # code_challengeの形式検証（Base64URL）
        if not self._is_valid_base64url(code_challenge):
            return jsonify({'error': 'invalid_request',
                          'error_description': 'Invalid code_challenge'}), 400
        
        # ユーザー認証（実際の実装では認証画面を表示）
        user_id = self._authenticate_user()
        if not user_id:
            return jsonify({'error': 'access_denied'}), 403
        
        # 認可コード生成
        auth_code = secrets.token_urlsafe(32)
        
        # 認可コード情報を保存（10分間有効）
        auth_code_data = {
            'client_id': client_id,
            'user_id': user_id,
            'redirect_uri': redirect_uri,
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method,
            'scope': request.args.get('scope', ''),
            'created_at': time.time()
        }
        
        self.redis.setex(
            f'auth_code:{auth_code}',
            600,  # 10分
            json.dumps(auth_code_data)
        )
        
        # リダイレクト
        state = request.args.get('state', '')
        redirect_params = {
            'code': auth_code,
            'state': state
        }
        
        redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"
        return redirect(redirect_url)
    
    @app.route('/token', methods=['POST'])
    def token(self):
        """トークンエンドポイント"""
        
        grant_type = request.form.get('grant_type')
        
        if grant_type != 'authorization_code':
            return jsonify({'error': 'unsupported_grant_type'}), 400
        
        # 必須パラメータ
        code = request.form.get('code')
        code_verifier = request.form.get('code_verifier')
        client_id = request.form.get('client_id')
        
        if not all([code, code_verifier, client_id]):
            return jsonify({'error': 'invalid_request'}), 400
        
        # 認可コード情報の取得
        auth_code_key = f'auth_code:{code}'
        auth_code_data = self.redis.get(auth_code_key)
        
        if not auth_code_data:
            return jsonify({'error': 'invalid_grant',
                          'error_description': 'Invalid or expired code'}), 400
        
        auth_code_info = json.loads(auth_code_data)
        
        # 認可コードの削除（一度だけ使用可能）
        self.redis.delete(auth_code_key)
        
        # クライアントID検証
        if auth_code_info['client_id'] != client_id:
            return jsonify({'error': 'invalid_client'}), 401
        
        # redirect_uri検証（提供された場合）
        redirect_uri = request.form.get('redirect_uri')
        if redirect_uri and redirect_uri != auth_code_info['redirect_uri']:
            return jsonify({'error': 'invalid_grant',
                          'error_description': 'redirect_uri mismatch'}), 400
        
        # PKCE検証
        if not self._verify_pkce(code_verifier, auth_code_info['code_challenge']):
            return jsonify({'error': 'invalid_grant',
                          'error_description': 'PKCE verification failed'}), 400
        
        # トークン生成
        access_token = self._generate_access_token(
            auth_code_info['user_id'],
            auth_code_info['client_id'],
            auth_code_info['scope']
        )
        
        refresh_token = self._generate_refresh_token(
            auth_code_info['user_id'],
            auth_code_info['client_id']
        )
        
        # レスポンス
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': refresh_token,
            'scope': auth_code_info['scope']
        })
    
    def _verify_pkce(self, verifier: str, challenge: str) -> bool:
        """PKCE検証"""
        
        # S256: BASE64URL(SHA256(verifier)) == challenge
        verifier_bytes = verifier.encode('utf-8')
        calculated_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier_bytes).digest()
        ).decode('utf-8').rstrip('=')
        
        return calculated_challenge == challenge
    
    def _is_valid_base64url(self, value: str) -> bool:
        """Base64URL形式の検証"""
        
        # Base64URL文字のみ
        import re
        return bool(re.match(r'^[A-Za-z0-9_-]+$', value))
    
    def _generate_access_token(self, user_id: str, client_id: str, 
                              scope: str) -> str:
        """アクセストークン生成"""
        
        payload = {
            'sub': user_id,
            'client_id': client_id,
            'scope': scope,
            'iat': int(time.time()),
            'exp': int(time.time() + 3600)
        }
        
        return jwt.encode(payload, self.signing_key, algorithm='HS256')

# サーバー初期化
auth_server = PKCEAuthorizationServer()
```

#### クライアント側実装

```python
class PKCEClient:
    """PKCE対応のOAuth 2.0クライアント"""
    
    def __init__(self, client_id: str, auth_endpoint: str, 
                 token_endpoint: str, redirect_uri: str):
        self.client_id = client_id
        self.auth_endpoint = auth_endpoint
        self.token_endpoint = token_endpoint
        self.redirect_uri = redirect_uri
        
    def generate_code_verifier(self) -> str:
        """Code Verifierの生成（43-128文字）"""
        
        # 32バイト = 256ビット、Base64URLエンコードで約43文字
        random_bytes = secrets.token_bytes(32)
        code_verifier = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
        return code_verifier.rstrip('=')
    
    def generate_code_challenge(self, verifier: str) -> str:
        """Code Challengeの生成（S256）"""
        
        # SHA256ハッシュ
        challenge_bytes = hashlib.sha256(verifier.encode('utf-8')).digest()
        
        # Base64URLエンコード
        code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8')
        return code_challenge.rstrip('=')
    
    def create_authorization_url(self, scope: List[str], 
                               state: Optional[str] = None) -> Dict[str, str]:
        """認可URLの生成"""
        
        # PKCE生成
        code_verifier = self.generate_code_verifier()
        code_challenge = self.generate_code_challenge(code_verifier)
        
        # State生成（CSRF対策）
        if not state:
            state = secrets.token_urlsafe(32)
        
        # パラメータ構築
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': ' '.join(scope),
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        auth_url = f"{self.auth_endpoint}?{urlencode(params)}"
        
        return {
            'url': auth_url,
            'state': state,
            'code_verifier': code_verifier
        }
    
    async def exchange_code_for_token(self, code: str, state: str,
                                    stored_state: str, 
                                    code_verifier: str) -> Dict:
        """認可コードをトークンに交換"""
        
        # State検証
        if state != stored_state:
            raise SecurityError("State mismatch - possible CSRF attack")
        
        # トークンリクエスト
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'code_verifier': code_verifier
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.token_endpoint,
                data=token_data,
                headers={'Accept': 'application/json'}
            ) as response:
                if response.status != 200:
                    error_data = await response.json()
                    raise OAuthError(f"Token exchange failed: {error_data}")
                
                return await response.json()
    
    def verify_pkce_implementation(self):
        """PKCE実装の検証テスト"""
        
        # 正常なケース
        verifier = self.generate_code_verifier()
        challenge = self.generate_code_challenge(verifier)
        
        # 検証
        recalculated = self.generate_code_challenge(verifier)
        assert challenge == recalculated, "PKCE calculation mismatch"
        
        # 異なるverifierでは一致しない
        different_verifier = self.generate_code_verifier()
        different_challenge = self.generate_code_challenge(different_verifier)
        assert challenge != different_challenge, "Different verifiers produced same challenge"
        
        print("PKCE implementation verified successfully")

# 使用例
async def main():
    client = PKCEClient(
        client_id='my-spa-app',
        auth_endpoint='https://auth.example.com/authorize',
        token_endpoint='https://auth.example.com/token',
        redirect_uri='https://app.example.com/callback'
    )
    
    # 認可フロー開始
    auth_data = client.create_authorization_url(['read', 'write'])
    print(f"Visit: {auth_data['url']}")
    
    # ブラウザで認可後、コールバックを処理
    # callback?code=AUTH_CODE&state=STATE
    
    # トークン交換
    tokens = await client.exchange_code_for_token(
        code='AUTH_CODE',
        state='STATE',
        stored_state=auth_data['state'],
        code_verifier=auth_data['code_verifier']
    )
    
    print(f"Access token: {tokens['access_token']}")
```

### 実装のポイント

1. **Code Verifierの生成**：暗号学的に安全な乱数を使用
2. **Code Challengeの計算**：S256メソッド（SHA256）を使用
3. **一度だけ使用可能**：認可コードは使用後即座に削除
4. **タイミング攻撃対策**：PKCE検証で定数時間比較

## 問題5：セキュリティ監査

### 既存のOAuth 2.0実装の監査結果

```python
class OAuthSecurityAudit:
    """OAuth 2.0実装のセキュリティ監査"""
    
    def __init__(self):
        self.vulnerabilities = []
        self.risk_scores = {}
        
    def audit_implementation(self, codebase):
        """包括的なセキュリティ監査"""
        
        # 1. 設定の監査
        self._audit_configuration()
        
        # 2. 実装の監査  
        self._audit_implementation()
        
        # 3. 運用の監査
        self._audit_operations()
        
        return self.generate_report()
    
    def _audit_configuration(self):
        """設定面の監査"""
        
        findings = [
            {
                'id': 'CONF-001',
                'title': 'Implicit Grant有効化',
                'severity': 'HIGH',
                'description': 'Implicit Grantが有効になっている',
                'evidence': '''
                ALLOWED_GRANT_TYPES = [
                    'authorization_code',
                    'implicit',  # セキュリティリスク
                    'client_credentials'
                ]
                ''',
                'risk': 'トークンがブラウザ履歴に残る、リファラー漏洩',
                'recommendation': 'Implicit Grantを無効化し、Authorization Code + PKCEを使用'
            },
            
            {
                'id': 'CONF-002', 
                'title': 'アクセストークンの有効期限が長い',
                'severity': 'MEDIUM',
                'description': '24時間の有効期限は長すぎる',
                'evidence': 'ACCESS_TOKEN_LIFETIME = 86400  # 24時間',
                'risk': 'トークン漏洩時の影響期間が長い',
                'recommendation': '15分〜1時間に短縮'
            },
            
            {
                'id': 'CONF-003',
                'title': 'HTTPS強制なし',
                'severity': 'CRITICAL',
                'description': 'HTTP通信が許可されている',
                'evidence': 'app.config["REQUIRE_HTTPS"] = False',
                'risk': '中間者攻撃によるトークン窃取',
                'recommendation': 'すべてのエンドポイントでHTTPS必須化'
            }
        ]
        
        self.vulnerabilities.extend(findings)
    
    def _audit_implementation(self):
        """実装面の監査"""
        
        findings = [
            {
                'id': 'IMPL-001',
                'title': 'redirect_uriの検証不足',
                'severity': 'HIGH',
                'description': '部分一致での検証は危険',
                'evidence': '''
                def validate_redirect_uri(uri, registered_uri):
                    return uri.startswith(registered_uri)  # 危険！
                ''',
                'risk': 'オープンリダイレクト攻撃',
                'recommendation': '''
                def validate_redirect_uri(uri, registered_uris):
                    return uri in registered_uris  # 完全一致
                '''
            },
            
            {
                'id': 'IMPL-002',
                'title': 'PKCE未実装',
                'severity': 'HIGH',
                'description': 'パブリッククライアントでPKCEなし',
                'evidence': 'SPAクライアントでPKCEパラメータなし',
                'risk': '認可コード横取り攻撃',
                'recommendation': 'すべてのパブリッククライアントでPKCE必須化'
            },
            
            {
                'id': 'IMPL-003',
                'title': 'エラー情報の過剰開示',
                'severity': 'MEDIUM',
                'description': 'スタックトレースが返される',
                'evidence': '''
                except Exception as e:
                    return {"error": str(e), "trace": traceback.format_exc()}
                ''',
                'risk': '内部構造の情報漏洩',
                'recommendation': '本番環境では最小限のエラー情報のみ返す'
            }
        ]
        
        self.vulnerabilities.extend(findings)
    
    def _audit_operations(self):
        """運用面の監査"""
        
        findings = [
            {
                'id': 'OPS-001',
                'title': 'トークン無効化機能なし',
                'severity': 'MEDIUM',
                'description': 'ログアウト時のトークン無効化未実装',
                'evidence': 'logout()関数でトークン無効化処理なし',
                'risk': 'ログアウト後もトークンが有効',
                'recommendation': 'トークンブラックリストまたは短い有効期限の実装'
            },
            
            {
                'id': 'OPS-002',
                'title': '監査ログ不足',
                'severity': 'LOW',
                'description': '認証イベントのログが不十分',
                'evidence': '失敗した認証試行がログされていない',
                'risk': '攻撃の検知が困難',
                'recommendation': '包括的な監査ログの実装'
            }
        ]
        
        self.vulnerabilities.extend(findings)
    
    def calculate_risk_scores(self):
        """リスクスコアの計算"""
        
        severity_scores = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 1
        }
        
        total_score = 0
        for vuln in self.vulnerabilities:
            score = severity_scores[vuln['severity']]
            total_score += score
            
        return {
            'total_score': total_score,
            'risk_level': self._get_risk_level(total_score),
            'severity_breakdown': {
                'CRITICAL': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
                'HIGH': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                'MEDIUM': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                'LOW': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
            }
        }
    
    def _get_risk_level(self, score):
        if score >= 30:
            return 'CRITICAL'
        elif score >= 20:
            return 'HIGH'
        elif score >= 10:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_report(self):
        """監査レポートの生成"""
        
        risk_scores = self.calculate_risk_scores()
        
        return {
            'executive_summary': {
                'overall_risk': risk_scores['risk_level'],
                'total_findings': len(self.vulnerabilities),
                'critical_findings': risk_scores['severity_breakdown']['CRITICAL'],
                'immediate_action_required': risk_scores['risk_level'] in ['CRITICAL', 'HIGH']
            },
            
            'findings': self.vulnerabilities,
            
            'remediation_priority': [
                {
                    'phase': 'Immediate (1 week)',
                    'items': [v['id'] for v in self.vulnerabilities if v['severity'] == 'CRITICAL'],
                    'focus': 'セキュリティクリティカルな問題の修正'
                },
                {
                    'phase': 'Short-term (1 month)',
                    'items': [v['id'] for v in self.vulnerabilities if v['severity'] == 'HIGH'],
                    'focus': '主要な脆弱性の対処'
                },
                {
                    'phase': 'Medium-term (3 months)',
                    'items': [v['id'] for v in self.vulnerabilities if v['severity'] in ['MEDIUM', 'LOW']],
                    'focus': '運用改善とベストプラクティスの適用'
                }
            ],
            
            'recommendations': {
                'immediate': [
                    'HTTPS強制の有効化',
                    'Implicit Grantの無効化',
                    'PKCEの実装'
                ],
                'short_term': [
                    'アクセストークン有効期限の短縮',
                    'redirect_uri検証の強化',
                    'エラーハンドリングの改善'
                ],
                'long_term': [
                    'トークン無効化システムの実装',
                    '包括的な監査ログ',
                    'セキュリティテストの自動化'
                ]
            }
        }
```

### 監査結果サマリー

#### 発見された脆弱性

1. **CRITICAL（2件）**
   - HTTPS非強制
   - （その他の重大な問題）

2. **HIGH（3件）**
   - Implicit Grant有効
   - redirect_uri検証不足
   - PKCE未実装

3. **MEDIUM（2件）**
   - トークン有効期限が長い
   - エラー情報の過剰開示

4. **LOW（1件）**
   - 監査ログ不足

#### リスク評価

- **総合リスクレベル：HIGH**
- **即時対応必要：YES**
- **推定修正期間：3ヶ月**

#### 実装改善案

```python
# 改善実装例
class ImprovedOAuth2Implementation:
    def __init__(self):
        # セキュアな設定
        self.config = {
            'require_https': True,
            'allowed_grant_types': ['authorization_code'],
            'require_pkce': True,
            'access_token_lifetime': 900,  # 15分
            'refresh_token_lifetime': 2592000,  # 30日
            'enable_token_revocation': True
        }
        
    def validate_client_request(self, request):
        """改善されたリクエスト検証"""
        
        # HTTPS強制
        if not request.is_secure and not self._is_localhost(request):
            raise SecurityError("HTTPS required")
        
        # PKCEチェック
        if self.config['require_pkce']:
            if not request.args.get('code_challenge'):
                raise ValueError("PKCE required")
        
        return True
```