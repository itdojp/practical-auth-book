---
layout: book
order: 26
title: "付録E-7: 第7章演習問題解答"
---
# 付録E-7: 第7章演習問題解答

## 問題1：OpenID Connect実装

### 解答

```python
import json
import time
import secrets
from typing import Dict, Optional, List
from urllib.parse import urlencode, urlparse, parse_qs
import requests
import jwt
from flask import Flask, request, redirect, session, url_for, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)

class OpenIDConnectRP:
    """
    OpenID Connect Relying Party実装
    - ディスカバリによる自動設定
    - IDトークンの完全な検証
    - UserInfoエンドポイントの利用
    - セッション管理
    """
    
    def __init__(self, client_id: str, client_secret: str, 
                 issuer: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.issuer = issuer
        self.redirect_uri = redirect_uri
        
        # ディスカバリ実行
        self.provider_config = self._discover_provider()
        self.jwks = self._fetch_jwks()
        
        # セッション管理
        self.sessions = {}  # 実運用ではRedis等を使用
        
    def _discover_provider(self) -> Dict:
        """OpenID Provider のディスカバリ"""
        
        discovery_url = f"{self.issuer}/.well-known/openid-configuration"
        
        try:
            response = requests.get(discovery_url, timeout=10)
            response.raise_for_status()
            
            config = response.json()
            
            # 必須エンドポイントの確認
            required_endpoints = [
                'authorization_endpoint',
                'token_endpoint',
                'jwks_uri',
                'issuer'
            ]
            
            for endpoint in required_endpoints:
                if endpoint not in config:
                    raise ValueError(f"Missing required endpoint: {endpoint}")
            
            # issuerの検証
            if config['issuer'] != self.issuer:
                raise ValueError(f"Issuer mismatch: {config['issuer']} != {self.issuer}")
            
            return config
            
        except Exception as e:
            raise Exception(f"Discovery failed: {e}")
    
    def _fetch_jwks(self) -> Dict:
        """JWKS（JSON Web Key Set）の取得"""
        
        jwks_uri = self.provider_config['jwks_uri']
        
        try:
            response = requests.get(jwks_uri, timeout=10)
            response.raise_for_status()
            
            jwks = response.json()
            
            # JWKSをキーIDでインデックス化
            key_dict = {}
            for key in jwks.get('keys', []):
                if 'kid' in key:
                    key_dict[key['kid']] = key
            
            return key_dict
            
        except Exception as e:
            raise Exception(f"JWKS fetch failed: {e}")
    
    def create_authorization_url(self, scope: List[str] = None,
                               **kwargs) -> str:
        """認可URLの作成"""
        
        if scope is None:
            scope = ['openid', 'profile', 'email']
        
        # セキュリティパラメータ生成
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        
        # セッションに保存
        session_id = secrets.token_urlsafe(16)
        self.sessions[session_id] = {
            'state': state,
            'nonce': nonce,
            'created_at': time.time()
        }
        
        # 認可リクエストパラメータ
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': ' '.join(scope),
            'state': state,
            'nonce': nonce
        }
        
        # 追加パラメータ
        params.update(kwargs)
        
        # PKCEサポート確認
        if 'code_challenge_methods_supported' in self.provider_config:
            if 'S256' in self.provider_config['code_challenge_methods_supported']:
                verifier, challenge = self._generate_pkce()
                self.sessions[session_id]['code_verifier'] = verifier
                params['code_challenge'] = challenge
                params['code_challenge_method'] = 'S256'
        
        auth_url = f"{self.provider_config['authorization_endpoint']}?{urlencode(params)}"
        
        # セッションIDをFlaskセッションに保存
        session['oidc_session_id'] = session_id
        
        return auth_url
    
    def _generate_pkce(self) -> tuple:
        """PKCE生成"""
        import hashlib
        import base64
        
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        return verifier, challenge
    
    def handle_authorization_response(self, authorization_response_url: str) -> Dict:
        """認可レスポンスの処理"""
        
        # URLパラメータ解析
        parsed = urlparse(authorization_response_url)
        params = parse_qs(parsed.query)
        
        # エラーチェック
        if 'error' in params:
            error = params['error'][0]
            error_description = params.get('error_description', [''])[0]
            raise Exception(f"Authorization error: {error} - {error_description}")
        
        # 必須パラメータ確認
        if 'code' not in params or 'state' not in params:
            raise ValueError("Missing required parameters")
        
        code = params['code'][0]
        state = params['state'][0]
        
        # セッション取得
        session_id = session.get('oidc_session_id')
        if not session_id or session_id not in self.sessions:
            raise SecurityError("Session not found")
        
        oidc_session = self.sessions[session_id]
        
        # セッション有効期限（10分）
        if time.time() - oidc_session['created_at'] > 600:
            del self.sessions[session_id]
            raise SecurityError("Session expired")
        
        # State検証
        if state != oidc_session['state']:
            raise SecurityError("State mismatch - possible CSRF attack")
        
        # トークン交換
        tokens = self._exchange_code_for_tokens(code, oidc_session)
        
        # IDトークン検証
        id_token_claims = self._verify_id_token(
            tokens['id_token'],
            oidc_session['nonce']
        )
        
        # UserInfo取得
        user_info = {}
        if 'userinfo_endpoint' in self.provider_config and 'access_token' in tokens:
            user_info = self._fetch_userinfo(tokens['access_token'])
        
        # セッション情報更新
        self.sessions[session_id] = {
            'authenticated': True,
            'id_token_claims': id_token_claims,
            'user_info': user_info,
            'access_token': tokens.get('access_token'),
            'refresh_token': tokens.get('refresh_token'),
            'authenticated_at': time.time(),
            'expires_at': time.time() + tokens.get('expires_in', 3600)
        }
        
        return {
            'id_token_claims': id_token_claims,
            'user_info': user_info,
            'session_id': session_id
        }
    
    def _exchange_code_for_tokens(self, code: str, oidc_session: Dict) -> Dict:
        """認可コードをトークンに交換"""
        
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        # PKCE使用時
        if 'code_verifier' in oidc_session:
            token_data['code_verifier'] = oidc_session['code_verifier']
        
        response = requests.post(
            self.provider_config['token_endpoint'],
            data=token_data,
            headers={'Accept': 'application/json'},
            timeout=10
        )
        
        if response.status_code != 200:
            raise Exception(f"Token exchange failed: {response.text}")
        
        return response.json()
    
    def _verify_id_token(self, id_token: str, nonce: str) -> Dict:
        """IDトークンの完全な検証"""
        
        # ヘッダー解析
        header = jwt.get_unverified_header(id_token)
        
        # 署名鍵の取得
        kid = header.get('kid')
        if not kid or kid not in self.jwks:
            raise ValueError(f"Unknown key ID: {kid}")
        
        jwk = self.jwks[kid]
        
        # 公開鍵の構築（RSA）
        if jwk['kty'] == 'RSA':
            public_key = self._jwk_to_rsa_public_key(jwk)
        else:
            raise ValueError(f"Unsupported key type: {jwk['kty']}")
        
        # トークン検証
        try:
            claims = jwt.decode(
                id_token,
                public_key,
                algorithms=[header['alg']],
                audience=self.client_id,
                issuer=self.issuer,
                options={
                    'verify_signature': True,
                    'verify_aud': True,
                    'verify_iss': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'require_exp': True,
                    'require_iat': True
                }
            )
        except jwt.PyJWTError as e:
            raise SecurityError(f"ID token verification failed: {e}")
        
        # Nonce検証
        if claims.get('nonce') != nonce:
            raise SecurityError("Nonce mismatch")
        
        # 追加検証
        self._validate_id_token_claims(claims)
        
        return claims
    
    def _jwk_to_rsa_public_key(self, jwk: Dict):
        """JWKからRSA公開鍵への変換"""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        import base64
        
        # Base64URLデコード
        def b64url_decode(data):
            padding = len(data) % 4
            if padding:
                data += '=' * (4 - padding)
            return base64.urlsafe_b64decode(data)
        
        # RSAパラメータ取得
        n = int.from_bytes(b64url_decode(jwk['n']), byteorder='big')
        e = int.from_bytes(b64url_decode(jwk['e']), byteorder='big')
        
        # 公開鍵構築
        public_numbers = rsa.RSAPublicNumbers(e, n)
        public_key = public_numbers.public_key(default_backend())
        
        return public_key
    
    def _validate_id_token_claims(self, claims: Dict):
        """IDトークンクレームの追加検証"""
        
        current_time = int(time.time())
        
        # 発行時刻の検証（未来でないこと）
        if 'iat' in claims and claims['iat'] > current_time + 60:
            raise SecurityError("Token issued in the future")
        
        # 認証時刻の検証（max_ageが指定された場合）
        if 'auth_time' in claims:
            # デフォルトmax_age = 1時間
            max_age = 3600
            if current_time - claims['auth_time'] > max_age:
                raise SecurityError("Authentication too old")
        
        # azp（Authorized Party）の検証
        if 'azp' in claims and claims['azp'] != self.client_id:
            raise SecurityError("Authorized party mismatch")
    
    def _fetch_userinfo(self, access_token: str) -> Dict:
        """UserInfoエンドポイントからユーザー情報取得"""
        
        response = requests.get(
            self.provider_config['userinfo_endpoint'],
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        
        if response.status_code != 200:
            raise Exception(f"UserInfo fetch failed: {response.text}")
        
        return response.json()
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """セッション情報の取得"""
        
        session_data = self.sessions.get(session_id)
        
        if not session_data:
            return None
        
        # 有効期限チェック
        if session_data.get('expires_at', 0) < time.time():
            # セッション期限切れ
            if 'refresh_token' in session_data:
                # リフレッシュ試行
                try:
                    self._refresh_session(session_id)
                    session_data = self.sessions[session_id]
                except:
                    del self.sessions[session_id]
                    return None
            else:
                del self.sessions[session_id]
                return None
        
        return session_data
    
    def _refresh_session(self, session_id: str):
        """セッションのリフレッシュ"""
        
        session_data = self.sessions[session_id]
        refresh_token = session_data.get('refresh_token')
        
        if not refresh_token:
            raise ValueError("No refresh token available")
        
        # トークンリフレッシュ
        token_data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        response = requests.post(
            self.provider_config['token_endpoint'],
            data=token_data,
            headers={'Accept': 'application/json'},
            timeout=10
        )
        
        if response.status_code != 200:
            raise Exception(f"Token refresh failed: {response.text}")
        
        tokens = response.json()
        
        # セッション更新
        session_data['access_token'] = tokens['access_token']
        session_data['expires_at'] = time.time() + tokens.get('expires_in', 3600)
        
        if 'refresh_token' in tokens:
            session_data['refresh_token'] = tokens['refresh_token']
        
        if 'id_token' in tokens:
            # 新しいIDトークンの検証
            id_token_claims = self._verify_id_token(tokens['id_token'], None)
            session_data['id_token_claims'] = id_token_claims
    
    def logout(self, session_id: str):
        """ログアウト処理"""
        
        session_data = self.sessions.get(session_id)
        
        if not session_data:
            return
        
        # エンドセッションエンドポイントの確認
        if 'end_session_endpoint' in self.provider_config:
            # OPでのログアウト
            id_token = session_data.get('id_token')
            if id_token:
                logout_url = self._create_logout_url(id_token)
                # 実際はリダイレクトを返す
        
        # ローカルセッション削除
        del self.sessions[session_id]
    
    def _create_logout_url(self, id_token: str) -> str:
        """ログアウトURLの作成"""
        
        params = {
            'id_token_hint': id_token,
            'post_logout_redirect_uri': f"{request.host_url}logout_callback"
        }
        
        return f"{self.provider_config['end_session_endpoint']}?{urlencode(params)}"

# Flask統合
oidc_client = None

def init_oidc(app):
    """OpenID Connect初期化"""
    global oidc_client
    
    oidc_client = OpenIDConnectRP(
        client_id=app.config['OIDC_CLIENT_ID'],
        client_secret=app.config['OIDC_CLIENT_SECRET'],
        issuer=app.config['OIDC_ISSUER'],
        redirect_uri=app.config['OIDC_REDIRECT_URI']
    )

def require_auth(f):
    """認証デコレータ"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = session.get('oidc_session_id')
        
        if not session_id:
            return redirect(url_for('login'))
        
        session_data = oidc_client.get_session(session_id)
        
        if not session_data or not session_data.get('authenticated'):
            return redirect(url_for('login'))
        
        # リクエストコンテキストにユーザー情報を追加
        request.oidc_user = {
            'claims': session_data['id_token_claims'],
            'userinfo': session_data.get('user_info', {})
        }
        
        return f(*args, **kwargs)
    
    return decorated_function

@app.route('/login')
def login():
    """ログイン開始"""
    auth_url = oidc_client.create_authorization_url(
        scope=['openid', 'profile', 'email'],
        prompt='select_account'  # アカウント選択を強制
    )
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """認可コールバック"""
    try:
        result = oidc_client.handle_authorization_response(request.url)
        
        # ログイン成功
        session['oidc_session_id'] = result['session_id']
        
        return redirect(url_for('profile'))
        
    except Exception as e:
        return f"Authentication failed: {e}", 400

@app.route('/profile')
@require_auth
def profile():
    """プロフィール表示"""
    return jsonify({
        'claims': request.oidc_user['claims'],
        'userinfo': request.oidc_user['userinfo']
    })

@app.route('/logout')
@require_auth
def logout():
    """ログアウト"""
    session_id = session.get('oidc_session_id')
    
    if session_id:
        oidc_client.logout(session_id)
        session.pop('oidc_session_id', None)
    
    return redirect('/')

if __name__ == '__main__':
    # 設定
    app.config.update({
        'OIDC_CLIENT_ID': 'your-client-id',
        'OIDC_CLIENT_SECRET': 'your-client-secret',
        'OIDC_ISSUER': 'https://accounts.google.com',
        'OIDC_REDIRECT_URI': 'http://localhost:5000/callback'
    })
    
    init_oidc(app)
    app.run(debug=True)
```

### 実装のポイント

1. **ディスカバリ機能**：`.well-known/openid-configuration`から自動設定取得
2. **IDトークン検証**：署名、有効期限、nonce、発行者、audienceの完全検証
3. **UserInfo利用**：アクセストークンを使用した追加情報取得
4. **セッション管理**：有効期限管理、自動リフレッシュ、ログアウト処理

## 問題2：SAML統合

### 解答

```python
from saml2 import (
    BINDING_HTTP_POST, 
    BINDING_HTTP_REDIRECT,
    entity
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.metadata import create_metadata_string
import os

class SAMLServiceProviderIntegration:
    """
    既存WebアプリケーションへのSAML SP統合設計
    """
    
    def __init__(self, app_config):
        self.app_config = app_config
        self.saml_config = self._create_saml_config()
        self.saml_client = Saml2Client(config=self.saml_config)
        
    def _create_saml_config(self):
        """SAML設定の作成"""
        
        config = {
            # サービスプロバイダの基本情報
            'entityid': self.app_config['SP_ENTITY_ID'],
            'description': 'SAML Service Provider',
            
            # サービス設定
            'service': {
                'sp': {
                    'name': self.app_config['SP_NAME'],
                    'endpoints': {
                        # アサーションコンシューマーサービス
                        'assertion_consumer_service': [
                            (
                                f"{self.app_config['BASE_URL']}/saml/acs",
                                BINDING_HTTP_POST
                            ),
                        ],
                        # シングルログアウトサービス
                        'single_logout_service': [
                            (
                                f"{self.app_config['BASE_URL']}/saml/sls",
                                BINDING_HTTP_REDIRECT
                            ),
                            (
                                f"{self.app_config['BASE_URL']}/saml/sls",
                                BINDING_HTTP_POST
                            ),
                        ],
                    },
                    
                    # セキュリティ設定
                    'authn_requests_signed': True,
                    'want_assertions_signed': True,
                    'want_response_signed': True,
                    
                    # NameIDフォーマット
                    'name_id_format': [
                        NAMEID_FORMAT_PERSISTENT,
                        "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"
                    ],
                    
                    # 必須属性
                    'required_attributes': [
                        'email',
                        'displayName',
                        'employeeID'
                    ],
                    
                    # オプション属性
                    'optional_attributes': [
                        'department',
                        'title',
                        'manager'
                    ],
                }
            },
            
            # IdPメタデータ
            'metadata': {
                'local': [self.app_config['IDP_METADATA_FILE']],
                # または
                # 'remote': [
                #     {
                #         'url': self.app_config['IDP_METADATA_URL'],
                #         'cert': self.app_config['METADATA_CERT']
                #     }
                # ]
            },
            
            # 証明書と鍵
            'key_file': self.app_config['SP_KEY_FILE'],
            'cert_file': self.app_config['SP_CERT_FILE'],
            
            # 暗号化設定
            'encryption_keypairs': [{
                'key_file': self.app_config['SP_KEY_FILE'],
                'cert_file': self.app_config['SP_CERT_FILE'],
            }],
            
            # デバッグ設定
            'debug': self.app_config.get('DEBUG', False),
            'xmlsec_binary': '/usr/bin/xmlsec1',
        }
        
        return Saml2Config().load(config)
    
    def generate_sp_metadata(self):
        """SPメタデータの生成"""
        
        metadata = create_metadata_string(
            configfile=None,
            config=self.saml_config,
            valid=96,  # 96時間有効
            cert=self.app_config['SP_CERT_FILE'],
            keyfile=self.app_config['SP_KEY_FILE'],
            id=None,
            name=self.app_config['SP_NAME'],
            sign=True
        )
        
        return metadata
    
    def integrate_with_app(self, app):
        """既存アプリケーションとの統合"""
        
        from flask import Flask, request, redirect, session, make_response
        
        # メタデータエンドポイント
        @app.route('/saml/metadata')
        def saml_metadata():
            metadata = self.generate_sp_metadata()
            response = make_response(metadata)
            response.headers['Content-Type'] = 'text/xml'
            return response
        
        # SSO開始
        @app.route('/saml/login')
        def saml_login():
            # RelayStateで元のURLを保存
            relay_state = request.args.get('next', '/')
            
            # 認証リクエスト作成
            session_id, auth_request_info = self.saml_client.prepare_for_authenticate(
                relay_state=relay_state
            )
            
            # セッションに保存
            session['saml_session_id'] = session_id
            session['saml_relay_state'] = relay_state
            
            # IdPへリダイレクト
            redirect_url = None
            for key, value in auth_request_info['headers']:
                if key == 'Location':
                    redirect_url = value
            
            return redirect(redirect_url)
        
        # アサーションコンシューマーサービス
        @app.route('/saml/acs', methods=['POST'])
        def saml_acs():
            try:
                # SAMLレスポンス取得
                saml_response = request.form.get('SAMLResponse')
                relay_state = request.form.get('RelayState', '/')
                
                # レスポンス検証
                authn_response = self.saml_client.parse_authn_request_response(
                    saml_response,
                    BINDING_HTTP_POST
                )
                
                # 検証成功
                user_info = self._process_saml_response(authn_response)
                
                # セッション作成
                session['user'] = user_info
                session['saml_session_index'] = authn_response.session_index
                session['saml_nameid'] = authn_response.name_id.text
                session['saml_nameid_format'] = authn_response.name_id.format
                
                # 元のページへリダイレクト
                return redirect(relay_state)
                
            except Exception as e:
                app.logger.error(f"SAML authentication failed: {e}")
                return "Authentication failed", 400
        
        # シングルログアウト
        @app.route('/saml/logout')
        def saml_logout():
            # ログアウトリクエスト作成
            session_id = session.get('saml_session_index')
            name_id = session.get('saml_nameid')
            name_id_format = session.get('saml_nameid_format')
            
            if session_id and name_id:
                logout_request = self.saml_client.create_logout_request(
                    name_id=name_id,
                    session_index=session_id,
                    name_id_format=name_id_format
                )
                
                # セッションクリア
                session.clear()
                
                # IdPへリダイレクト
                return redirect(logout_request)
            
            # ローカルログアウトのみ
            session.clear()
            return redirect('/')
        
        # シングルログアウトサービス
        @app.route('/saml/sls', methods=['GET', 'POST'])
        def saml_sls():
            # ログアウトレスポンス/リクエストの処理
            
            if request.method == 'GET':
                # Redirect binding
                saml_request = request.args.get('SAMLRequest')
                saml_response = request.args.get('SAMLResponse')
            else:
                # POST binding
                saml_request = request.form.get('SAMLRequest')
                saml_response = request.form.get('SAMLResponse')
            
            if saml_request:
                # IdPからのログアウトリクエスト
                self._handle_logout_request(saml_request)
            elif saml_response:
                # IdPからのログアウトレスポンス
                self._handle_logout_response(saml_response)
            
            session.clear()
            return redirect('/')
    
    def _process_saml_response(self, authn_response):
        """SAMLレスポンスの処理と属性マッピング"""
        
        # 属性マッピング設定
        attribute_mapping = {
            # SAML属性名 -> アプリケーション属性名
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'email',
            'http://schemas.microsoft.com/identity/claims/displayname': 'display_name',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'username',
            'employeeID': 'employee_id',
            'department': 'department',
            'title': 'job_title',
            'manager': 'manager_email',
            
            # 追加の標準属性
            'urn:oid:0.9.2342.19200300.100.1.3': 'email',  # mail
            'urn:oid:2.5.4.42': 'first_name',  # givenName
            'urn:oid:2.5.4.4': 'last_name',   # sn (surname)
            'urn:oid:2.5.4.3': 'common_name',  # cn
        }
        
        # ユーザー情報の抽出
        user_info = {
            'nameid': authn_response.name_id.text,
            'nameid_format': authn_response.name_id.format,
            'session_index': authn_response.session_index,
            'attributes': {}
        }
        
        # 属性のマッピング
        for saml_attr, values in authn_response.ava.items():
            # マッピングに基づいて変換
            app_attr = attribute_mapping.get(saml_attr, saml_attr)
            
            # 単一値か複数値かの処理
            if isinstance(values, list):
                if len(values) == 1:
                    user_info['attributes'][app_attr] = values[0]
                else:
                    user_info['attributes'][app_attr] = values
            else:
                user_info['attributes'][app_attr] = values
        
        # 必須属性の検証
        required_attrs = ['email', 'employee_id']
        missing_attrs = []
        
        for attr in required_attrs:
            if attr not in user_info['attributes']:
                missing_attrs.append(attr)
        
        if missing_attrs:
            raise ValueError(f"Missing required attributes: {missing_attrs}")
        
        # ユーザー識別子の決定
        user_info['user_id'] = user_info['attributes'].get(
            'employee_id',
            user_info['nameid']
        )
        
        return user_info
    
    def _handle_logout_request(self, saml_request):
        """IdPからのログアウトリクエスト処理"""
        
        # ログアウトリクエストの解析
        logout_request = self.saml_client.parse_logout_request(
            saml_request,
            BINDING_HTTP_REDIRECT
        )
        
        # 該当セッションの特定と無効化
        session_index = logout_request.session_index
        
        # ログアウトレスポンスの作成
        logout_response = self.saml_client.create_logout_response(
            logout_request.id,
            status={
                'status_code': {
                    'value': 'urn:oasis:names:tc:SAML:2.0:status:Success'
                }
            }
        )
        
        return logout_response
    
    def monitoring_and_troubleshooting(self):
        """監視とトラブルシューティング"""
        
        return {
            'logging_configuration': '''
            import logging
            
            # SAML専用ロガー
            saml_logger = logging.getLogger('saml2')
            saml_logger.setLevel(logging.DEBUG)
            
            # ハンドラー設定
            handler = logging.FileHandler('saml.log')
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            saml_logger.addHandler(handler)
            ''',
            
            'common_issues': {
                'signature_verification_failed': {
                    'cause': '証明書の不一致',
                    'solution': 'IdPメタデータの更新、証明書の確認'
                },
                'time_skew': {
                    'cause': 'サーバー間の時刻のずれ',
                    'solution': 'NTP同期、NotBefore/NotOnOrAfterの許容範囲調整'
                },
                'attribute_missing': {
                    'cause': 'IdPが必要な属性を送信していない',
                    'solution': 'IdP管理者に属性マッピングの確認を依頼'
                }
            },
            
            'debug_tools': [
                'SAML Chrome Panel (ブラウザ拡張)',
                'SAML-tracer (Firefox拡張)',
                'xmlsec1コマンドラインツール'
            ]
        }

# 使用例
app_config = {
    'SP_ENTITY_ID': 'https://myapp.example.com',
    'SP_NAME': 'My Application',
    'BASE_URL': 'https://myapp.example.com',
    'IDP_METADATA_FILE': '/path/to/idp_metadata.xml',
    'SP_KEY_FILE': '/path/to/sp.key',
    'SP_CERT_FILE': '/path/to/sp.crt',
    'DEBUG': True
}

saml_integration = SAMLServiceProviderIntegration(app_config)
```

### 設計のポイント

1. **メタデータ管理**：自動生成と手動/リモート取得の両対応
2. **属性マッピング**：柔軟な属性変換と必須属性の検証
3. **シングルログアウト**：IdP起動とSP起動の両方に対応
4. **既存アプリとの統合**：最小限の変更で統合可能な設計

## 問題3：プロトコル選択

### 解答

#### 1. 大学間の学術リソース共有

**選択：SAML**

**理由：**
- **既存のフェデレーション**：eduGAIN等の学術フェデレーションはSAMLベース
- **成熟したエコシステム**：Shibbolethなど実績のある実装
- **詳細な属性情報**：所属、役職、研究分野など複雑な属性の交換
- **信頼関係の確立**：大学間の正式な契約に基づく信頼関係

**実装例：**
```xml
<!-- 学術用属性の例 -->
<saml:Attribute Name="eduPersonAffiliation">
    <saml:AttributeValue>faculty</saml:AttributeValue>
    <saml:AttributeValue>member</saml:AttributeValue>
</saml:Attribute>
<saml:Attribute Name="eduPersonScopedAffiliation">
    <saml:AttributeValue>faculty@university.edu</saml:AttributeValue>
</saml:Attribute>
<saml:Attribute Name="eduPersonEntitlement">
    <saml:AttributeValue>urn:mace:example.edu:library:premium</saml:AttributeValue>
</saml:Attribute>
```

#### 2. スタートアップのSaaS統合

**選択：OpenID Connect**

**理由：**
- **開発速度**：RESTful APIで実装が簡単
- **モダンスタック**：JWT、OAuth 2.0ベース
- **ソーシャルログイン**：Google、GitHubなどとの統合が容易
- **開発者体験**：豊富なライブラリとドキュメント

**実装例：**
```javascript
// Next.js + NextAuth.jsの例
import NextAuth from 'next-auth'
import GoogleProvider from 'next-auth/providers/google'

export default NextAuth({
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      authorization: {
        params: {
          scope: 'openid email profile https://www.googleapis.com/auth/calendar.readonly'
        }
      }
    })
  ],
  callbacks: {
    async jwt({ token, account, user }) {
      if (account?.access_token) {
        token.accessToken = account.access_token
      }
      return token
    }
  }
})
```

#### 3. 銀行のモバイルアプリ

**選択：OpenID Connect**

**理由：**
- **モバイル最適化**：コンパクトなJWTトークン
- **PKCE対応**：モバイルアプリのセキュリティ強化
- **API統合**：RESTful APIとの親和性
- **生体認証統合**：FIDO2等との組み合わせが容易

**実装考慮事項：**
```python
class BankingMobileAuth:
    def __init__(self):
        self.required_aal = 'aal3'  # 高い認証保証レベル
        self.token_lifetime = 300   # 5分（短い有効期限）
        
    def create_mobile_auth_request(self):
        return {
            'response_type': 'code',
            'scope': 'openid profile accounts:read transactions:read',
            'acr_values': 'urn:banking:psd2:sca',  # 強力な認証要求
            'max_age': 0,  # 強制再認証
            'prompt': 'login consent'
        }
```

#### 4. 製造業のサプライチェーン連携

**選択：SAML（既存システム）+ OpenID Connect（新規API）のハイブリッド**

**理由：**
- **レガシー対応**：既存のERP/SCMシステムはSAML対応が多い
- **API連携**：新しいマイクロサービスはOIDC/OAuth 2.0
- **B2B要件**：企業間の正式な契約と詳細な属性交換
- **段階的移行**：既存システムを維持しながら新技術導入

**ハイブリッドアーキテクチャ：**
```python
class SupplyChainAuthGateway:
    """SAMLとOIDCのブリッジ"""
    
    def __init__(self):
        self.saml_handler = SAMLHandler()
        self.oidc_handler = OIDCHandler()
        
    def authenticate(self, request):
        if request.is_legacy_system():
            # レガシーシステム向けSAML
            return self.saml_handler.process(request)
        else:
            # 新システム向けOIDC
            return self.oidc_handler.process(request)
    
    def token_exchange(self, saml_assertion):
        """SAMLアサーションをOIDCトークンに変換"""
        # アサーションの検証
        claims = self.saml_handler.validate_assertion(saml_assertion)
        
        # OIDCトークンの生成
        return self.oidc_handler.create_token({
            'sub': claims['nameid'],
            'company': claims['organization'],
            'role': claims['supply_chain_role'],
            'permissions': self.map_permissions(claims)
        })
```

### 選択基準のまとめ

| シナリオ | プロトコル | 決定要因 |
|---------|-----------|---------|
| 大学間連携 | SAML | 既存フェデレーション、複雑な属性 |
| スタートアップ | OIDC | 開発効率、モダンスタック |
| 銀行モバイル | OIDC | モバイル最適化、API統合 |
| サプライチェーン | ハイブリッド | レガシー対応＋将来性 |

## 問題4：ハイブリッド実装

### 解答

```python
import time
import uuid
from typing import Dict, Optional, Union
from abc import ABC, abstractmethod
import jwt
from saml2 import saml, sigver
from saml2.s_utils import factory

class ProtocolHandler(ABC):
    """プロトコルハンドラーの基底クラス"""
    
    @abstractmethod
    def authenticate(self, request):
        pass
    
    @abstractmethod
    def create_response(self, user_info):
        pass

class HybridIdentityProvider:
    """
    SAMLとOpenID Connectの両方をサポートするIdP
    """
    
    def __init__(self, config):
        self.config = config
        self.user_store = UserStore()
        self.session_store = SessionStore()
        
        # プロトコルハンドラー
        self.saml_handler = SAMLProtocolHandler(config)
        self.oidc_handler = OIDCProtocolHandler(config)
        
        # 共通認証エンジン
        self.auth_engine = CommonAuthenticationEngine(config)
        
    def handle_request(self, request):
        """リクエストのルーティング"""
        
        # プロトコルの判定
        protocol_type = self._detect_protocol(request)
        
        if protocol_type == 'saml':
            return self.saml_handler.process(request, self.auth_engine)
        elif protocol_type == 'oidc':
            return self.oidc_handler.process(request, self.auth_engine)
        else:
            raise ValueError(f"Unknown protocol: {protocol_type}")
    
    def _detect_protocol(self, request):
        """プロトコルの自動検出"""
        
        # SAMLの判定
        if 'SAMLRequest' in request.params:
            return 'saml'
        
        # OIDCの判定
        if request.path.startswith('/authorize') and 'openid' in request.params.get('scope', ''):
            return 'oidc'
        
        # エンドポイントベース
        if request.path in ['/saml/sso', '/saml/slo']:
            return 'saml'
        elif request.path in ['/authorize', '/token', '/userinfo']:
            return 'oidc'
        
        return 'unknown'

class CommonAuthenticationEngine:
    """共通認証エンジン"""
    
    def __init__(self, config):
        self.config = config
        self.mfa_provider = MFAProvider()
        
    def authenticate(self, credentials):
        """共通の認証処理"""
        
        # 基本認証
        user = self._verify_credentials(credentials)
        
        if not user:
            raise AuthenticationError("Invalid credentials")
        
        # リスクベース認証
        risk_score = self._assess_risk(credentials, user)
        
        # MFA要求の判定
        if risk_score > 30 or user.require_mfa:
            mfa_result = self.mfa_provider.challenge(user)
            if not mfa_result:
                raise AuthenticationError("MFA failed")
        
        # 認証コンテキストの作成
        auth_context = {
            'user': user,
            'auth_time': int(time.time()),
            'auth_methods': self._get_auth_methods(user, risk_score),
            'auth_level': self._determine_auth_level(user, risk_score),
            'session_id': str(uuid.uuid4())
        }
        
        return auth_context
    
    def _verify_credentials(self, credentials):
        """クレデンシャル検証"""
        # 実装省略
        pass
    
    def _assess_risk(self, credentials, user):
        """リスクアセスメント"""
        score = 0
        
        # IPアドレスチェック
        if not self._is_known_ip(credentials.ip_address, user):
            score += 20
        
        # デバイスチェック
        if not self._is_known_device(credentials.device_id, user):
            score += 30
        
        # 時間帯チェック
        if self._is_unusual_time(user):
            score += 20
        
        return score

class SAMLProtocolHandler(ProtocolHandler):
    """SAMLプロトコルハンドラー"""
    
    def __init__(self, config):
        self.config = config
        self.saml_config = self._init_saml_config()
        
    def process(self, request, auth_engine):
        """SAMLリクエストの処理"""
        
        # SAMLリクエストの解析
        saml_request = self._parse_saml_request(request)
        
        # 認証が必要な場合
        if not request.session.get('authenticated'):
            # 認証ページへリダイレクト
            return self._redirect_to_auth(saml_request)
        
        # 認証済みの場合
        auth_context = request.session['auth_context']
        
        # SAMLレスポンスの作成
        saml_response = self._create_saml_response(saml_request, auth_context)
        
        return saml_response
    
    def _create_saml_response(self, saml_request, auth_context):
        """SAMLレスポンスの作成"""
        
        # アサーションの作成
        assertion = self._create_assertion(auth_context)
        
        # 属性の追加
        attributes = self._map_to_saml_attributes(auth_context['user'])
        assertion.attribute_statement = [self._create_attribute_statement(attributes)]
        
        # レスポンスの作成
        response = saml.Response()
        response.id = f"_{uuid.uuid4()}"
        response.in_response_to = saml_request.id
        response.issue_instant = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        response.issuer = saml.Issuer(text=self.config['entity_id'])
        response.status = self._create_success_status()
        response.assertion = [assertion]
        
        # 署名
        signed_response = self._sign_response(response)
        
        return signed_response
    
    def _map_to_saml_attributes(self, user):
        """ユーザー属性をSAML属性にマッピング"""
        
        attribute_mapping = {
            'email': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
            'name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
            'given_name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
            'family_name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
            'employee_id': 'employeeID',
            'department': 'department',
            'role': 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
        }
        
        saml_attributes = {}
        
        for attr_name, attr_value in user.attributes.items():
            saml_name = attribute_mapping.get(attr_name, attr_name)
            saml_attributes[saml_name] = attr_value
        
        return saml_attributes

class OIDCProtocolHandler(ProtocolHandler):
    """OpenID Connectプロトコルハンドラー"""
    
    def __init__(self, config):
        self.config = config
        self.signing_key = config['signing_key']
        
    def process(self, request, auth_engine):
        """OIDCリクエストの処理"""
        
        if request.path == '/authorize':
            return self._handle_authorization(request, auth_engine)
        elif request.path == '/token':
            return self._handle_token(request)
        elif request.path == '/userinfo':
            return self._handle_userinfo(request)
    
    def _handle_authorization(self, request, auth_engine):
        """認可エンドポイント"""
        
        # リクエストの検証
        self._validate_authorization_request(request)
        
        # 認証が必要な場合
        if not request.session.get('authenticated'):
            return self._redirect_to_auth(request)
        
        # 認証済みの場合
        auth_context = request.session['auth_context']
        
        # 認可コードの生成
        code = self._generate_authorization_code(request, auth_context)
        
        # リダイレクト
        redirect_uri = request.params['redirect_uri']
        state = request.params.get('state', '')
        
        return f"{redirect_uri}?code={code}&state={state}"
    
    def _handle_token(self, request):
        """トークンエンドポイント"""
        
        grant_type = request.params.get('grant_type')
        
        if grant_type == 'authorization_code':
            return self._exchange_code_for_tokens(request)
        elif grant_type == 'refresh_token':
            return self._refresh_tokens(request)
        else:
            raise ValueError(f"Unsupported grant type: {grant_type}")
    
    def _create_id_token(self, auth_context, client_id, nonce=None):
        """IDトークンの作成"""
        
        claims = {
            'iss': self.config['issuer'],
            'sub': auth_context['user'].id,
            'aud': client_id,
            'exp': int(time.time() + 3600),
            'iat': int(time.time()),
            'auth_time': auth_context['auth_time']
        }
        
        if nonce:
            claims['nonce'] = nonce
        
        # 認証方法の追加
        if auth_context.get('auth_methods'):
            claims['amr'] = auth_context['auth_methods']
        
        # 認証コンテキストクラス
        claims['acr'] = self._map_to_acr(auth_context['auth_level'])
        
        # ユーザー属性の追加
        user_claims = self._map_to_oidc_claims(auth_context['user'])
        claims.update(user_claims)
        
        # JWTとして署名
        id_token = jwt.encode(claims, self.signing_key, algorithm='RS256')
        
        return id_token
    
    def _map_to_oidc_claims(self, user):
        """ユーザー属性をOIDCクレームにマッピング"""
        
        claim_mapping = {
            'email': 'email',
            'email_verified': 'email_verified',
            'name': 'name',
            'given_name': 'given_name',
            'family_name': 'family_name',
            'picture': 'picture',
            'locale': 'locale',
            'zoneinfo': 'zoneinfo'
        }
        
        oidc_claims = {}
        
        for attr_name, attr_value in user.attributes.items():
            claim_name = claim_mapping.get(attr_name, attr_name)
            if claim_name in claim_mapping.values():
                oidc_claims[claim_name] = attr_value
        
        # カスタムクレーム（名前空間付き）
        for attr_name, attr_value in user.attributes.items():
            if attr_name not in claim_mapping:
                oidc_claims[f"https://{self.config['issuer']}/claims/{attr_name}"] = attr_value
        
        return oidc_claims

class AttributeMapper:
    """属性の相互マッピング"""
    
    def __init__(self):
        # 共通属性定義
        self.common_attributes = {
            'user_id': {'type': 'string', 'required': True},
            'email': {'type': 'string', 'required': True},
            'name': {'type': 'string', 'required': True},
            'given_name': {'type': 'string'},
            'family_name': {'type': 'string'},
            'department': {'type': 'string'},
            'employee_id': {'type': 'string'},
            'roles': {'type': 'array'}
        }
        
        # プロトコル別マッピング
        self.saml_mapping = {
            'user_id': 'urn:oid:0.9.2342.19200300.100.1.1',  # uid
            'email': 'urn:oid:0.9.2342.19200300.100.1.3',    # mail
            'name': 'urn:oid:2.5.4.3',                       # cn
            'given_name': 'urn:oid:2.5.4.42',                # givenName
            'family_name': 'urn:oid:2.5.4.4',                # sn
            'department': 'urn:oid:2.5.4.11',                # ou
            'employee_id': 'employeeNumber',
            'roles': 'eduPersonAffiliation'
        }
        
        self.oidc_mapping = {
            'user_id': 'sub',
            'email': 'email',
            'name': 'name',
            'given_name': 'given_name',
            'family_name': 'family_name',
            'department': 'https://example.com/claims/department',
            'employee_id': 'https://example.com/claims/employee_id',
            'roles': 'https://example.com/claims/roles'
        }
    
    def to_saml(self, common_attrs):
        """共通属性をSAML属性に変換"""
        saml_attrs = {}
        
        for attr_name, attr_value in common_attrs.items():
            if attr_name in self.saml_mapping:
                saml_name = self.saml_mapping[attr_name]
                saml_attrs[saml_name] = attr_value
        
        return saml_attrs
    
    def to_oidc(self, common_attrs):
        """共通属性をOIDCクレームに変換"""
        oidc_claims = {}
        
        for attr_name, attr_value in common_attrs.items():
            if attr_name in self.oidc_mapping:
                claim_name = self.oidc_mapping[attr_name]
                oidc_claims[claim_name] = attr_value
        
        return oidc_claims
    
    def from_saml(self, saml_attrs):
        """SAML属性を共通属性に変換"""
        common_attrs = {}
        reverse_mapping = {v: k for k, v in self.saml_mapping.items()}
        
        for saml_name, saml_value in saml_attrs.items():
            if saml_name in reverse_mapping:
                attr_name = reverse_mapping[saml_name]
                common_attrs[attr_name] = saml_value
        
        return common_attrs
    
    def from_oidc(self, oidc_claims):
        """OIDCクレームを共通属性に変換"""
        common_attrs = {}
        reverse_mapping = {v: k for k, v in self.oidc_mapping.items()}
        
        for claim_name, claim_value in oidc_claims.items():
            if claim_name in reverse_mapping:
                attr_name = reverse_mapping[claim_name]
                common_attrs[attr_name] = claim_value
        
        return common_attrs

# 設定とメタデータ
class HybridIdPConfiguration:
    def __init__(self):
        self.config = {
            'entity_id': 'https://idp.example.com',
            'issuer': 'https://idp.example.com',
            
            # エンドポイント
            'endpoints': {
                # SAML
                'saml_sso': '/saml/sso',
                'saml_slo': '/saml/slo',
                'saml_metadata': '/saml/metadata',
                
                # OIDC
                'authorization': '/authorize',
                'token': '/token',
                'userinfo': '/userinfo',
                'jwks': '/jwks',
                'discovery': '/.well-known/openid-configuration'
            },
            
            # 証明書と鍵
            'signing_key': 'path/to/private_key.pem',
            'signing_cert': 'path/to/certificate.pem',
            
            # セキュリティ設定
            'token_lifetime': 3600,
            'session_lifetime': 28800,
            'require_signed_requests': True,
            'require_encrypted_assertions': False
        }
    
    def generate_metadata(self):
        """SAMLメタデータとOIDC Discoveryの生成"""
        
        # SAMLメタデータ
        saml_metadata = f'''
        <EntityDescriptor entityID="{self.config['entity_id']}">
            <IDPSSODescriptor>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
                                   Location="{self.config['entity_id']}/saml/sso"/>
                <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" 
                                   Location="{self.config['entity_id']}/saml/slo"/>
            </IDPSSODescriptor>
        </EntityDescriptor>
        '''
        
        # OIDC Discovery
        oidc_discovery = {
            'issuer': self.config['issuer'],
            'authorization_endpoint': f"{self.config['issuer']}/authorize",
            'token_endpoint': f"{self.config['issuer']}/token",
            'userinfo_endpoint': f"{self.config['issuer']}/userinfo",
            'jwks_uri': f"{self.config['issuer']}/jwks",
            'scopes_supported': ['openid', 'profile', 'email'],
            'response_types_supported': ['code', 'id_token', 'code id_token'],
            'subject_types_supported': ['public', 'pairwise'],
            'id_token_signing_alg_values_supported': ['RS256']
        }
        
        return {
            'saml': saml_metadata,
            'oidc': oidc_discovery
        }
```

### 設計のポイント

1. **共通認証基盤**：プロトコルに依存しない認証エンジン
2. **プロトコル変換**：共通属性モデルを介した相互変換
3. **属性マッピング**：標準とカスタム属性の柔軟な対応
4. **統一管理**：設定、セッション、監査ログの一元化

## 問題5：セキュリティ監査

### 解答

```python
class SSOSecurityAudit:
    """SSO実装のセキュリティ監査"""
    
    def __init__(self):
        self.findings = []
        self.risk_levels = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
    def audit_sso_implementation(self, implementation):
        """包括的なSSO監査"""
        
        # 1. プロトコル実装の監査
        self._audit_protocol_implementation(implementation)
        
        # 2. 証明書と鍵管理
        self._audit_key_management(implementation)
        
        # 3. セッション管理
        self._audit_session_management(implementation)
        
        # 4. ログと監視
        self._audit_logging_and_monitoring(implementation)
        
        return self.generate_report()
    
    def _audit_protocol_implementation(self, impl):
        """プロトコル実装の監査"""
        
        # SAML固有のチェック
        if impl.supports_saml:
            self._check_saml_security(impl)
        
        # OIDC固有のチェック
        if impl.supports_oidc:
            self._check_oidc_security(impl)
    
    def _check_saml_security(self, impl):
        """SAML セキュリティチェック"""
        
        # 署名検証
        if not impl.saml_config.get('verify_signatures', False):
            self.findings.append({
                'id': 'SAML-001',
                'severity': 'CRITICAL',
                'title': 'SAML署名検証が無効',
                'description': 'SAMLアサーションの署名検証が行われていない',
                'impact': 'なりすましによる不正アクセスの可能性',
                'recommendation': '''
                config['verify_signatures'] = True
                config['require_signed_assertions'] = True
                config['require_signed_response'] = True
                '''
            })
            self.risk_levels['CRITICAL'] += 1
        
        # XMLインジェクション対策
        if not impl.saml_config.get('disable_dtd', False):
            self.findings.append({
                'id': 'SAML-002',
                'severity': 'HIGH',
                'title': 'XML外部エンティティ（XXE）攻撃の脆弱性',
                'description': 'DTDが無効化されていない',
                'impact': 'ファイル読み取りやSSRFの可能性',
                'recommendation': '''
                # lxmlの設定
                parser = etree.XMLParser(
                    no_network=True,
                    dtd_validation=False,
                    resolve_entities=False
                )
                '''
            })
            self.risk_levels['HIGH'] += 1
        
        # リプレイ攻撃対策
        if not impl.saml_config.get('check_assertion_timeframe', False):
            self.findings.append({
                'id': 'SAML-003',
                'severity': 'HIGH',
                'title': 'リプレイ攻撃への脆弱性',
                'description': 'アサーションの時刻検証が不十分',
                'impact': '古いアサーションの再利用による不正アクセス',
                'recommendation': '''
                # NotBefore/NotOnOrAfterの厳密な検証
                def validate_timeframe(assertion):
                    current_time = time.time()
                    not_before = assertion.conditions.not_before
                    not_on_or_after = assertion.conditions.not_on_or_after
                    
                    # 時刻のスキュー許容（5分）
                    skew = 300
                    
                    if current_time < (not_before - skew):
                        raise SecurityError("Assertion not yet valid")
                    
                    if current_time >= (not_on_or_after + skew):
                        raise SecurityError("Assertion expired")
                '''
            })
            self.risk_levels['HIGH'] += 1
    
    def _check_oidc_security(self, impl):
        """OIDC セキュリティチェック"""
        
        # nonce検証
        if not impl.oidc_config.get('require_nonce', False):
            self.findings.append({
                'id': 'OIDC-001',
                'severity': 'HIGH',
                'title': 'Nonce検証の欠如',
                'description': 'リプレイ攻撃対策のnonceが検証されていない',
                'impact': 'IDトークンの再利用による攻撃',
                'recommendation': '''
                def verify_id_token(token, expected_nonce):
                    claims = jwt.decode(token, key, algorithms=['RS256'])
                    
                    if claims.get('nonce') != expected_nonce:
                        raise SecurityError("Nonce mismatch")
                '''
            })
            self.risk_levels['HIGH'] += 1
        
        # at_hash検証
        if impl.uses_implicit_flow and not impl.oidc_config.get('verify_at_hash', False):
            self.findings.append({
                'id': 'OIDC-002',
                'severity': 'MEDIUM',
                'title': 'at_hash検証の欠如',
                'description': 'アクセストークンとIDトークンの関連性が検証されていない',
                'impact': 'トークン置換攻撃の可能性',
                'recommendation': '''
                def verify_at_hash(id_token, access_token):
                    claims = jwt.decode(id_token, key)
                    
                    if 'at_hash' in claims:
                        # アクセストークンのハッシュ計算
                        hash_digest = hashlib.sha256(access_token.encode()).digest()
                        at_hash = base64.urlsafe_b64encode(hash_digest[:16]).decode().rstrip('=')
                        
                        if claims['at_hash'] != at_hash:
                            raise SecurityError("at_hash mismatch")
                '''
            })
            self.risk_levels['MEDIUM'] += 1
    
    def _audit_key_management(self, impl):
        """鍵管理の監査"""
        
        # 鍵のローテーション
        if not impl.has_key_rotation:
            self.findings.append({
                'id': 'KEY-001',
                'severity': 'MEDIUM',
                'title': '鍵ローテーションの未実装',
                'description': '署名鍵が定期的にローテーションされていない',
                'impact': '鍵漏洩時の影響期間が長い',
                'recommendation': '''
                class KeyRotationManager:
                    def __init__(self):
                        self.rotation_interval = 90 * 24 * 3600  # 90日
                        
                    def should_rotate(self, key):
                        return (time.time() - key.created_at) > self.rotation_interval
                    
                    def rotate_keys(self):
                        new_key = self.generate_new_key()
                        self.keys = {
                            'current': new_key,
                            'previous': self.keys.get('current')
                        }
                        self.update_jwks()
                '''
            })
            self.risk_levels['MEDIUM'] += 1
        
        # 鍵の保管
        if impl.stores_keys_in_code:
            self.findings.append({
                'id': 'KEY-002',
                'severity': 'CRITICAL',
                'title': '鍵のハードコーディング',
                'description': 'ソースコード内に秘密鍵が含まれている',
                'impact': 'ソースコード漏洩時に全システムが危険',
                'recommendation': '''
                # 環境変数またはシークレット管理サービスを使用
                import os
                from azure.keyvault.secrets import SecretClient
                
                # 環境変数
                private_key = os.environ.get('IDP_PRIVATE_KEY')
                
                # Azure Key Vault
                client = SecretClient(vault_url, credential)
                private_key = client.get_secret('idp-private-key').value
                '''
            })
            self.risk_levels['CRITICAL'] += 1
    
    def _audit_session_management(self, impl):
        """セッション管理の監査"""
        
        # セッション固定攻撃
        if not impl.regenerates_session_id:
            self.findings.append({
                'id': 'SESS-001',
                'severity': 'HIGH',
                'title': 'セッション固定攻撃への脆弱性',
                'description': '認証後にセッションIDが再生成されていない',
                'impact': '攻撃者が事前に用意したセッションIDでなりすまし',
                'recommendation': '''
                def authenticate_user(credentials):
                    user = verify_credentials(credentials)
                    
                    # セッションIDの再生成
                    session.regenerate_id()
                    
                    session['user'] = user
                    session['authenticated_at'] = time.time()
                '''
            })
            self.risk_levels['HIGH'] += 1
        
        # グローバルログアウト
        if not impl.supports_global_logout:
            self.findings.append({
                'id': 'SESS-002',
                'severity': 'MEDIUM',
                'title': 'グローバルログアウトの未実装',
                'description': '一箇所でのログアウトが他のSPに伝播しない',
                'impact': 'ユーザーの期待に反してセッションが残る',
                'recommendation': '''
                # バックチャネルログアウトの実装
                async def propagate_logout(user_id, session_index):
                    active_sessions = get_user_sessions(user_id)
                    
                    for sp_session in active_sessions:
                        logout_token = create_logout_token(
                            user_id,
                            session_index,
                            sp_session.client_id
                        )
                        
                        await send_backchannel_logout(
                            sp_session.logout_uri,
                            logout_token
                        )
                '''
            })
            self.risk_levels['MEDIUM'] += 1
    
    def _audit_logging_and_monitoring(self, impl):
        """ログと監視の監査"""
        
        # 認証イベントのログ
        required_events = [
            'login_success',
            'login_failure',
            'logout',
            'token_issued',
            'mfa_challenge',
            'permission_denied'
        ]
        
        missing_events = []
        for event in required_events:
            if not impl.logs_event(event):
                missing_events.append(event)
        
        if missing_events:
            self.findings.append({
                'id': 'LOG-001',
                'severity': 'MEDIUM',
                'title': '不十分な監査ログ',
                'description': f'以下のイベントがログされていない: {missing_events}',
                'impact': 'セキュリティインシデントの検知と調査が困難',
                'recommendation': '''
                class AuditLogger:
                    def log_auth_event(self, event_type, context):
                        log_entry = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'event_type': event_type,
                            'user_id': context.get('user_id'),
                            'client_id': context.get('client_id'),
                            'ip_address': context.get('ip_address'),
                            'user_agent': context.get('user_agent'),
                            'result': context.get('result'),
                            'error': context.get('error')
                        }
                        
                        # 構造化ログ
                        logger.info(json.dumps(log_entry))
                        
                        # SIEM転送
                        siem_client.send(log_entry)
                '''
            })
            self.risk_levels['MEDIUM'] += 1
    
    def generate_report(self):
        """監査レポートの生成"""
        
        return {
            'executive_summary': {
                'total_findings': len(self.findings),
                'risk_distribution': self.risk_levels,
                'overall_risk': self._calculate_overall_risk(),
                'compliance_status': self._check_compliance()
            },
            
            'findings': sorted(
                self.findings,
                key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x['severity'])
            ),
            
            'recommendations': {
                'immediate_actions': [
                    f for f in self.findings 
                    if f['severity'] in ['CRITICAL', 'HIGH']
                ],
                
                'remediation_timeline': {
                    'week_1': 'CRITICAL findings',
                    'week_2-4': 'HIGH findings',
                    'month_2': 'MEDIUM findings',
                    'month_3': 'LOW findings and hardening'
                }
            },
            
            'positive_findings': [
                'HTTPSの強制',
                '適切なトークン有効期限',
                'CSRFトークンの実装'
            ]
        }
    
    def _calculate_overall_risk(self):
        """総合リスクの計算"""
        
        score = (
            self.risk_levels['CRITICAL'] * 10 +
            self.risk_levels['HIGH'] * 5 +
            self.risk_levels['MEDIUM'] * 2 +
            self.risk_levels['LOW'] * 1
        )
        
        if score >= 20:
            return 'CRITICAL'
        elif score >= 10:
            return 'HIGH'
        elif score >= 5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _check_compliance(self):
        """コンプライアンスチェック"""
        
        return {
            'oauth2_security_bcp': {
                'status': 'PARTIAL',
                'missing': ['PKCE for public clients', 'Token binding']
            },
            'oidc_certification': {
                'status': 'FAIL',
                'missing': ['Dynamic client registration', 'Request objects']
            },
            'saml2_conformance': {
                'status': 'PASS',
                'level': 'Basic Web SSO Profile'
            }
        }

# 改善提案の実装例
class ImprovedSSOImplementation:
    """セキュリティ監査結果に基づく改善実装"""
    
    def __init__(self):
        # セキュアな設定
        self.config = {
            # SAML
            'saml': {
                'verify_signatures': True,
                'require_signed_assertions': True,
                'require_signed_requests': True,
                'check_assertion_timeframe': True,
                'assertion_valid_duration': 300,  # 5分
                'disable_dtd': True,
                'replay_prevention': True
            },
            
            # OIDC
            'oidc': {
                'require_nonce': True,
                'verify_at_hash': True,
                'require_pkce': True,
                'supported_algorithms': ['RS256', 'ES256'],
                'id_token_lifetime': 3600,
                'access_token_lifetime': 900
            },
            
            # セッション
            'session': {
                'regenerate_id_on_auth': True,
                'absolute_timeout': 28800,  # 8時間
                'idle_timeout': 1800,       # 30分
                'secure_cookie': True,
                'http_only': True,
                'same_site': 'Lax'
            },
            
            # ログ
            'logging': {
                'log_all_auth_events': True,
                'include_request_details': True,
                'exclude_sensitive_data': True,
                'structured_format': True
            }
        }
        
        # 鍵管理
        self.key_manager = SecureKeyManager()
        
        # 監査ログ
        self.audit_logger = StructuredAuditLogger()
```

### 監査結果のサマリー

1. **発見された脆弱性**
   - CRITICAL: 2件（署名検証無効、鍵のハードコーディング）
   - HIGH: 4件（XXE、リプレイ攻撃、nonce検証、セッション固定）
   - MEDIUM: 4件（鍵ローテーション、ログ不足等）

2. **総合リスク評価：HIGH**
   - 即座の対応が必要
   - 特に署名検証と鍵管理は最優先

3. **改善提案**
   - 1週目：CRITICAL項目の修正
   - 2-4週目：HIGH項目の対処
   - 2ヶ月目：MEDIUM項目とセキュリティ強化

4. **ポジティブな発見**
   - HTTPS強制は実装済み
   - 基本的なCSRF対策あり
   - トークン有効期限は適切
