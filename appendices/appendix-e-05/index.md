---
layout: book
title: "第5章 演習問題解答"
---

# 第5章 演習問題解答

## 問題1：JWT実装

### 解答

```python
import jwt
import time
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from typing import Dict, Tuple, Optional
import redis

class JWTAuthSystem:
    """RS256を使用したJWT認証システム"""
    
    def __init__(self):
        # RSA鍵ペアの生成
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Redis接続（トークン管理用）
        self.redis = redis.Redis(decode_responses=True)
        
        # 設定
        self.ACCESS_TOKEN_LIFETIME = 900  # 15分
        self.REFRESH_TOKEN_LIFETIME = 604800  # 7日
        
    def generate_token_pair(self, user_id: str) -> Dict[str, str]:
        """アクセストークンとリフレッシュトークンのペアを生成"""
        
        # 共通のトークンファミリーID
        family_id = str(uuid.uuid4())
        
        # アクセストークンの生成
        access_payload = {
            'user_id': user_id,
            'type': 'access',
            'family_id': family_id,
            'jti': str(uuid.uuid4()),
            'iat': int(time.time()),
            'exp': int(time.time() + self.ACCESS_TOKEN_LIFETIME)
        }
        
        access_token = self._encode_token(access_payload)
        
        # リフレッシュトークンの生成
        refresh_payload = {
            'user_id': user_id,
            'type': 'refresh',
            'family_id': family_id,
            'jti': str(uuid.uuid4()),
            'iat': int(time.time()),
            'exp': int(time.time() + self.REFRESH_TOKEN_LIFETIME),
            'rotation_count': 0
        }
        
        refresh_token = self._encode_token(refresh_payload)
        
        # リフレッシュトークンをRedisに保存
        self._store_refresh_token(refresh_payload)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': self.ACCESS_TOKEN_LIFETIME
        }
    
    def refresh_tokens(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """トークンローテーションを実装したリフレッシュ処理"""
        
        try:
            # リフレッシュトークンの検証
            payload = self._decode_token(refresh_token)
            
            # トークンタイプの確認
            if payload.get('type') != 'refresh':
                raise ValueError("Invalid token type")
            
            # Redisでトークンの状態確認
            stored_token = self._get_stored_token(payload['jti'])
            if not stored_token:
                # トークンが既に使用済みまたは無効
                self._handle_token_reuse_detection(payload)
                return None
            
            # 新しいトークンペアの生成
            new_tokens = self.generate_token_pair(payload['user_id'])
            
            # 新しいリフレッシュトークンにローテーション回数を引き継ぐ
            new_refresh_payload = self._decode_token(new_tokens['refresh_token'])
            new_refresh_payload['rotation_count'] = payload.get('rotation_count', 0) + 1
            new_refresh_payload['family_id'] = payload['family_id']
            
            # 古いリフレッシュトークンを無効化
            self._revoke_token(payload['jti'])
            
            return new_tokens
            
        except jwt.ExpiredSignatureError:
            return None
        except Exception as e:
            print(f"Token refresh error: {e}")
            return None
    
    def _encode_token(self, payload: Dict) -> str:
        """RS256でトークンをエンコード"""
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return jwt.encode(payload, private_pem, algorithm='RS256')
    
    def _decode_token(self, token: str) -> Dict:
        """RS256でトークンをデコード"""
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return jwt.decode(token, public_pem, algorithms=['RS256'])
    
    def _store_refresh_token(self, payload: Dict):
        """リフレッシュトークンをRedisに保存"""
        key = f"refresh_token:{payload['jti']}"
        ttl = payload['exp'] - int(time.time())
        
        self.redis.setex(
            key,
            ttl,
            json.dumps({
                'user_id': payload['user_id'],
                'family_id': payload['family_id'],
                'rotation_count': payload.get('rotation_count', 0)
            })
        )
    
    def _get_stored_token(self, jti: str) -> Optional[Dict]:
        """保存されたトークン情報を取得"""
        data = self.redis.get(f"refresh_token:{jti}")
        return json.loads(data) if data else None
    
    def _revoke_token(self, jti: str):
        """トークンを無効化"""
        self.redis.delete(f"refresh_token:{jti}")
    
    def _handle_token_reuse_detection(self, payload: Dict):
        """トークン再利用検出時の処理"""
        # 同じファミリーのすべてのトークンを無効化
        pattern = f"refresh_token:*"
        for key in self.redis.scan_iter(match=pattern):
            token_data = json.loads(self.redis.get(key))
            if token_data.get('family_id') == payload['family_id']:
                self.redis.delete(key)
        
        # セキュリティアラートをログ
        print(f"SECURITY ALERT: Token reuse detected for user {payload['user_id']}")
    
    def verify_access_token(self, token: str) -> Optional[Dict]:
        """アクセストークンの検証"""
        try:
            payload = self._decode_token(token)
            
            if payload.get('type') != 'access':
                return None
                
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except Exception:
            return None

# エラーハンドリングを含む使用例
def main():
    auth_system = JWTAuthSystem()
    
    try:
        # 初回ログイン
        tokens = auth_system.generate_token_pair("user123")
        print(f"Initial tokens generated")
        
        # アクセストークンの検証
        user_info = auth_system.verify_access_token(tokens['access_token'])
        if user_info:
            print(f"Access token valid for user: {user_info['user_id']}")
        
        # トークンのリフレッシュ
        new_tokens = auth_system.refresh_tokens(tokens['refresh_token'])
        if new_tokens:
            print("Tokens refreshed successfully")
        else:
            print("Token refresh failed")
            
    except Exception as e:
        print(f"Authentication error: {e}")
```

### 実装のポイント

1. **RS256アルゴリズム**：公開鍵暗号を使用し、検証者が署名を作成できない
2. **トークンローテーション**：リフレッシュトークンは一度使用すると無効化
3. **ファミリーベースの無効化**：再利用検出時に関連トークンすべてを無効化
4. **適切なエラーハンドリング**：各種例外を適切に処理

## 問題2：トークン保存戦略

### 解答

```javascript
// SPAアプリケーション向けトークン保存戦略
class SecureTokenStorage {
    constructor() {
        // メモリ内でアクセストークンを保持
        this.accessToken = null;
        this.tokenExpiry = null;
        
        // リフレッシュ処理の状態管理
        this.refreshPromise = null;
        
        // CSRFトークン
        this.csrfToken = this.generateCSRFToken();
    }
    
    // トークン保存戦略の実装
    async initialize() {
        // 1. CSRFトークンをメタタグから取得
        const metaTag = document.querySelector('meta[name="csrf-token"]');
        if (metaTag) {
            this.csrfToken = metaTag.content;
        }
        
        // 2. 初回のトークン取得（リフレッシュトークンはHttpOnly Cookieに保存済み）
        await this.refreshAccessToken();
        
        // 3. 自動リフレッシュの設定
        this.setupAutoRefresh();
        
        // 4. XSS対策の追加レイヤー
        this.setupSecurityHeaders();
    }
    
    // アクセストークンの取得（メモリのみ）
    async getAccessToken() {
        // 有効期限チェック
        if (!this.accessToken || this.isTokenExpiring()) {
            await this.refreshAccessToken();
        }
        
        return this.accessToken;
    }
    
    // トークンのリフレッシュ
    async refreshAccessToken() {
        // 重複リフレッシュを防ぐ
        if (this.refreshPromise) {
            return this.refreshPromise;
        }
        
        this.refreshPromise = fetch('/api/auth/refresh', {
            method: 'POST',
            credentials: 'include', // HttpOnly Cookieを含める
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': this.csrfToken // CSRF対策
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Token refresh failed');
            }
            return response.json();
        })
        .then(data => {
            // メモリにのみ保存
            this.accessToken = data.access_token;
            this.tokenExpiry = Date.now() + (data.expires_in * 1000);
            
            // CSRFトークンが更新された場合
            if (data.csrf_token) {
                this.csrfToken = data.csrf_token;
            }
            
            this.refreshPromise = null;
            return this.accessToken;
        })
        .catch(error => {
            this.refreshPromise = null;
            this.handleAuthError(error);
            throw error;
        });
        
        return this.refreshPromise;
    }
    
    // APIリクエストラッパー（XSS/CSRF対策込み）
    async secureApiRequest(url, options = {}) {
        const token = await this.getAccessToken();
        
        // デフォルトヘッダーの設定
        const headers = {
            ...options.headers,
            'Authorization': `Bearer ${token}`,
            'X-CSRF-Token': this.csrfToken,
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY'
        };
        
        // Content-Type の検証
        if (options.body && typeof options.body === 'object') {
            headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(options.body);
        }
        
        try {
            const response = await fetch(url, {
                ...options,
                headers,
                credentials: 'include'
            });
            
            // レスポンスヘッダーの検証
            this.validateResponseHeaders(response);
            
            // 401の場合は自動リトライ
            if (response.status === 401 && !options._retry) {
                await this.refreshAccessToken();
                return this.secureApiRequest(url, { ...options, _retry: true });
            }
            
            return response;
            
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }
    
    // XSS対策：Content Security Policy の動的設定
    setupSecurityHeaders() {
        // メタタグでCSPを設定
        const cspMeta = document.createElement('meta');
        cspMeta.httpEquiv = 'Content-Security-Policy';
        cspMeta.content = [
            "default-src 'self'",
            "script-src 'self' 'nonce-" + this.generateNonce() + "'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'"
        ].join('; ');
        document.head.appendChild(cspMeta);
    }
    
    // トークン有効期限のチェック
    isTokenExpiring() {
        if (!this.tokenExpiry) return true;
        
        // 5分前にリフレッシュ
        const bufferTime = 5 * 60 * 1000;
        return Date.now() >= (this.tokenExpiry - bufferTime);
    }
    
    // 自動リフレッシュの設定
    setupAutoRefresh() {
        // 可視性変更時のリフレッシュ
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && this.isTokenExpiring()) {
                this.refreshAccessToken();
            }
        });
        
        // 定期的なチェック（1分ごと）
        setInterval(() => {
            if (this.isTokenExpiring()) {
                this.refreshAccessToken();
            }
        }, 60000);
    }
    
    // レスポンスヘッダーの検証
    validateResponseHeaders(response) {
        const contentType = response.headers.get('content-type');
        
        // JSONレスポンスの検証
        if (contentType && contentType.includes('application/json')) {
            // XSS対策：JSONレスポンスの検証
            const xContentType = response.headers.get('x-content-type-options');
            if (xContentType !== 'nosniff') {
                console.warn('Missing X-Content-Type-Options header');
            }
        }
    }
    
    // CSRFトークンの生成
    generateCSRFToken() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    // ナンスの生成（CSP用）
    generateNonce() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array));
    }
    
    // 認証エラーの処理
    handleAuthError(error) {
        // トークンをクリア
        this.accessToken = null;
        this.tokenExpiry = null;
        
        // ユーザーに通知
        this.showAuthErrorNotification();
        
        // ログイン画面へリダイレクト
        setTimeout(() => {
            window.location.href = '/login';
        }, 2000);
    }
    
    // エラー通知の表示（XSS対策済み）
    showAuthErrorNotification() {
        const notification = document.createElement('div');
        notification.className = 'auth-error-notification';
        notification.textContent = 'セッションの有効期限が切れました。再度ログインしてください。';
        
        // スタイルの安全な適用
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #f44336;
            color: white;
            padding: 16px;
            border-radius: 4px;
            z-index: 1000;
        `;
        
        document.body.appendChild(notification);
        
        // 自動削除
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }
    
    // ログアウト処理
    async logout() {
        try {
            await fetch('/api/auth/logout', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'X-CSRF-Token': this.csrfToken
                }
            });
        } finally {
            // トークンをクリア
            this.accessToken = null;
            this.tokenExpiry = null;
            
            // ログイン画面へ
            window.location.href = '/login';
        }
    }
}

// 使用例
const tokenStorage = new SecureTokenStorage();

// アプリケーション初期化時
document.addEventListener('DOMContentLoaded', async () => {
    try {
        await tokenStorage.initialize();
        
        // APIリクエストの例
        const response = await tokenStorage.secureApiRequest('/api/user/profile');
        const userData = await response.json();
        
    } catch (error) {
        console.error('Initialization failed:', error);
    }
});
```

### 実装の詳細

1. **XSS対策**
   - アクセストークンはメモリのみに保持
   - Content Security Policy（CSP）の実装
   - レスポンスヘッダーの検証
   - DOM操作時のtextContent使用

2. **CSRF対策**
   - カスタムヘッダーによるCSRFトークン送信
   - SameSite Cookieの活用（サーバー側）
   - リクエストの origin 検証

3. **ユーザビリティ**
   - 自動トークンリフレッシュ
   - タブ切り替え時の状態確認
   - エラー時の適切なフィードバック

4. **実装の詳細**
   - 重複リフレッシュの防止
   - 401エラーの自動リトライ
   - セキュアなエラーハンドリング

## 問題3：無効化システムの設計

### 解答

```python
# 1000万ユーザー規模のトークン無効化システム設計

class ScalableTokenRevocationSystem:
    """
    大規模トークン無効化システム
    
    要件:
    - 1000万ユーザー
    - レイテンシ < 10ms
    - 高可用性（99.99%）
    - コスト最適化
    """
    
    def __init__(self):
        self.architecture = self._design_architecture()
        self.implementation = self._implement_system()
    
    def _design_architecture(self):
        """システムアーキテクチャの設計"""
        
        return {
            'overview': '''
            ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
            │   Client    │────▶│ API Gateway  │────▶│ Auth Service│
            └─────────────┘     └──────────────┘     └─────────────┘
                                        │                     │
                                        ▼                     ▼
                              ┌─────────────────┐    ┌──────────────┐
                              │  Local Cache    │    │ Redis Cluster│
                              │   (In-Memory)   │    │  (Primary)   │
                              └─────────────────┘    └──────────────┘
                                        │                     │
                                        ▼                     ▼
                              ┌─────────────────┐    ┌──────────────┐
                              │ Bloom Filter    │    │  DynamoDB    │
                              │  (Probabilistic)│    │  (Backup)    │
                              └─────────────────┘    └──────────────┘
            ''',
            
            'components': {
                'api_gateway': {
                    'purpose': 'エントリーポイント、初期フィルタリング',
                    'technology': 'AWS API Gateway / Kong',
                    'features': [
                        'レート制限',
                        'ローカルキャッシュ（1分）',
                        '基本的なトークン検証'
                    ]
                },
                
                'local_cache': {
                    'purpose': '超高速アクセス用キャッシュ',
                    'technology': 'Go gcache / Caffeine (Java)',
                    'config': {
                        'size': '100MB per instance',
                        'ttl': '60 seconds',
                        'eviction': 'LRU'
                    }
                },
                
                'bloom_filter': {
                    'purpose': '存在しないトークンの高速除外',
                    'technology': 'Redis BloomFilter',
                    'config': {
                        'false_positive_rate': 0.001,
                        'expected_elements': 50_000_000,
                        'memory_usage': '~90MB'
                    }
                },
                
                'redis_cluster': {
                    'purpose': 'プライマリ無効化ストア',
                    'topology': {
                        'shards': 10,
                        'replicas_per_shard': 2,
                        'total_nodes': 30
                    },
                    'features': [
                        'パーティショニング（CRC16）',
                        '自動フェイルオーバー',
                        'パイプライニング対応'
                    ]
                },
                
                'dynamodb': {
                    'purpose': '永続化とディザスタリカバリ',
                    'config': {
                        'read_capacity': 5000,
                        'write_capacity': 1000,
                        'on_demand': True
                    }
                }
            }
        }
    
    def _implement_system(self):
        """実装の詳細"""
        
        return {
            'token_check_flow': '''
            async def check_token_revocation(token_jti: str) -> bool:
                """
                トークン無効化チェックフロー
                目標レイテンシ: < 10ms
                """
                
                # Level 1: ローカルキャッシュ (< 0.1ms)
                if local_cache.contains(f"revoked:{token_jti}"):
                    return True
                
                # Level 2: Bloom Filter (< 1ms)
                if not bloom_filter.might_contain(token_jti):
                    # 確実に存在しない
                    return False
                
                # Level 3: Redis Cluster (< 5ms)
                try:
                    is_revoked = await redis_cluster.exists(
                        f"revoked:{token_jti}"
                    )
                    
                    # ローカルキャッシュに結果を保存
                    if is_revoked:
                        local_cache.set(
                            f"revoked:{token_jti}", 
                            True, 
                            ttl=60
                        )
                    
                    return is_revoked
                    
                except RedisTimeoutError:
                    # Level 4: DynamoDB フォールバック (< 10ms)
                    return await check_dynamodb_fallback(token_jti)
            ''',
            
            'revocation_flow': '''
            async def revoke_token(token_jti: str, user_id: str, reason: str):
                """トークン無効化フロー"""
                
                revocation_data = {
                    'jti': token_jti,
                    'user_id': user_id,
                    'revoked_at': time.time(),
                    'reason': reason
                }
                
                # 並行実行で高速化
                await asyncio.gather(
                    # Redis への書き込み
                    redis_cluster.setex(
                        f"revoked:{token_jti}",
                        86400,  # 24時間
                        json.dumps(revocation_data)
                    ),
                    
                    # Bloom Filter への追加
                    bloom_filter.add(token_jti),
                    
                    # DynamoDB への非同期書き込み
                    queue_dynamodb_write(revocation_data),
                    
                    # キャッシュの無効化
                    broadcast_cache_invalidation(token_jti)
                )
            ''',
            
            'optimization_strategies': {
                'batching': '''
                # バッチ処理による効率化
                class RevocationBatcher:
                    def __init__(self):
                        self.batch = []
                        self.lock = asyncio.Lock()
                        self.flush_task = None
                    
                    async def add_revocation(self, token_jti: str):
                        async with self.lock:
                            self.batch.append(token_jti)
                            
                            if len(self.batch) >= 100:
                                await self._flush()
                            elif not self.flush_task:
                                self.flush_task = asyncio.create_task(
                                    self._scheduled_flush()
                                )
                    
                    async def _flush(self):
                        if not self.batch:
                            return
                        
                        # パイプライン実行
                        pipeline = redis_cluster.pipeline()
                        for jti in self.batch:
                            pipeline.setex(f"revoked:{jti}", 86400, "1")
                        
                        await pipeline.execute()
                        self.batch.clear()
                ''',
                
                'connection_pooling': '''
                # コネクションプール最適化
                redis_pool = ConnectionPool(
                    max_connections=1000,
                    max_connections_per_node=100,
                    socket_keepalive=True,
                    socket_keepalive_options={
                        1: 1,  # TCP_KEEPIDLE
                        2: 1,  # TCP_KEEPINTVL
                        3: 3,  # TCP_KEEPCNT
                    }
                )
                ''',
                
                'circuit_breaker': '''
                # サーキットブレーカーパターン
                class RedisCircuitBreaker:
                    def __init__(self):
                        self.failure_count = 0
                        self.last_failure_time = 0
                        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
                    
                    async def call(self, func, *args, **kwargs):
                        if self.state == 'OPEN':
                            if time.time() - self.last_failure_time > 30:
                                self.state = 'HALF_OPEN'
                            else:
                                raise CircuitOpenError()
                        
                        try:
                            result = await func(*args, **kwargs)
                            self._on_success()
                            return result
                        except Exception as e:
                            self._on_failure()
                            raise
                '''
            }
        }
    
    def calculate_cost_optimization(self):
        """コスト最適化の計算"""
        
        return {
            'redis_cluster': {
                'instance_type': 'cache.r6g.xlarge',
                'instances': 30,
                'monthly_cost': '$150 * 30 = $4,500',
                'optimization': [
                    'リザーブドインスタンスで30%削減',
                    'オフピーク時のスケールダウン'
                ]
            },
            
            'dynamodb': {
                'storage': '10GB',
                'monthly_cost': '$250',
                'optimization': [
                    'オンデマンド料金でコスト変動に対応',
                    'TTLによる自動削除でストレージ削減'
                ]
            },
            
            'data_transfer': {
                'monthly_estimate': '$500',
                'optimization': [
                    'VPCエンドポイントで転送料金削減',
                    'キャッシュヒット率向上'
                ]
            },
            
            'total_monthly_cost': '$5,250',
            'cost_per_user': '$0.000525'
        }
    
    def monitoring_and_alerting(self):
        """監視とアラート設定"""
        
        return {
            'metrics': {
                'latency': {
                    'p50': '< 2ms',
                    'p95': '< 8ms',
                    'p99': '< 10ms',
                    'alert_threshold': 'p99 > 15ms for 5 minutes'
                },
                
                'availability': {
                    'target': '99.99%',
                    'measurement': 'successful_checks / total_checks',
                    'alert_threshold': '< 99.95% for 5 minutes'
                },
                
                'cache_hit_rate': {
                    'target': '> 95%',
                    'layers': {
                        'local_cache': '> 60%',
                        'bloom_filter': '> 30%',
                        'redis': '> 5%'
                    }
                }
            },
            
            'dashboards': [
                'Token revocation latency',
                'System availability',
                'Cache performance',
                'Error rates',
                'Cost tracking'
            ]
        }
```

### 設計のポイント

1. **マルチレイヤーキャッシング**
   - ローカルキャッシュで60%以上のリクエストを処理
   - Bloom Filterで存在しないトークンを高速除外
   - Redis Clusterで分散処理

2. **スケーラビリティ**
   - 水平スケーリング可能な設計
   - シャーディングによる負荷分散
   - 非同期処理による高速化

3. **障害時の動作**
   - Circuit Breakerパターンでカスケード障害を防止
   - DynamoDBへのフォールバック
   - グレースフルデグラデーション

4. **コスト最適化**
   - 効率的なキャッシング戦略
   - 適切なインスタンスサイズ選択
   - 自動スケーリングの活用

## 問題4：セキュリティ監査

### 解答

```python
# 既存JWT実装のセキュリティ監査レポート

class JWTSecurityAudit:
    """JWT実装のセキュリティ監査"""
    
    def __init__(self):
        self.vulnerabilities = []
        self.risk_matrix = {}
        
    def audit_jwt_implementation(self, codebase):
        """包括的なセキュリティ監査の実施"""
        
        audit_report = {
            'executive_summary': self._executive_summary(),
            'vulnerabilities': self._identify_vulnerabilities(),
            'risk_assessment': self._assess_risks(),
            'recommendations': self._provide_recommendations(),
            'implementation_priority': self._prioritize_fixes()
        }
        
        return audit_report
    
    def _identify_vulnerabilities(self):
        """脆弱性の特定"""
        
        return [
            {
                'id': 'VULN-001',
                'title': 'アルゴリズムコンフュージョン攻撃への脆弱性',
                'severity': 'CRITICAL',
                'description': '''
                実装がalg="none"を受け入れる可能性がある。
                攻撃者が署名なしトークンを作成可能。
                ''',
                'affected_code': '''
                # 脆弱なコード
                def verify_token(token, secret):
                    header = decode_header(token)
                    if header['alg'] == 'none':
                        return decode_without_verification(token)
                    # ...
                ''',
                'exploitation': '''
                # 攻撃例
                malicious_token = base64url_encode('{"alg":"none"}') + '.' + 
                                 base64url_encode('{"user_id":"admin"}') + '.'
                ''',
                'cve_reference': 'CVE-2015-2951'
            },
            
            {
                'id': 'VULN-002',
                'title': '弱い秘密鍵の使用',
                'severity': 'HIGH',
                'description': '''
                HS256で短い秘密鍵（< 256 bits）を使用。
                ブルートフォース攻撃に脆弱。
                ''',
                'affected_code': '''
                SECRET_KEY = "mysecret123"  # 11文字 = 88 bits
                ''',
                'mitigation': '''
                import secrets
                SECRET_KEY = secrets.token_hex(32)  # 256 bits
                '''
            },
            
            {
                'id': 'VULN-003',
                'title': 'トークン有効期限の未検証',
                'severity': 'HIGH',
                'description': '''
                exp クレームの検証が実装されていない。
                期限切れトークンが永続的に有効。
                ''',
                'affected_code': '''
                def verify_token(token):
                    payload = jwt.decode(token, verify=False)  # 危険！
                    return payload
                '''
            },
            
            {
                'id': 'VULN-004',
                'title': 'JTI（JWT ID）の未実装',
                'severity': 'MEDIUM',
                'description': '''
                トークンの一意性が保証されない。
                リプレイ攻撃への対策不足。
                ''',
                'recommendation': '''
                payload['jti'] = str(uuid.uuid4())
                payload['iat'] = int(time.time())
                '''
            },
            
            {
                'id': 'VULN-005',
                'title': 'クライアント側でのトークン生成',
                'severity': 'CRITICAL',
                'description': '''
                秘密鍵がクライアントコードに含まれている。
                任意のトークン作成が可能。
                ''',
                'affected_code': '''
                // client.js - 絶対にダメ！
                const token = jwt.sign(payload, 'secret123');
                '''
            },
            
            {
                'id': 'VULN-006',
                'title': 'Kid Header Injection',
                'severity': 'HIGH',
                'description': '''
                kid（Key ID）ヘッダーの検証不足。
                SQLインジェクションやパストラバーサルの可能性。
                ''',
                'vulnerable_pattern': '''
                key = load_key_from_db(f"SELECT key FROM keys WHERE id = '{kid}'")
                '''
            }
        ]
    
    def _assess_risks(self):
        """リスク評価"""
        
        return {
            'risk_matrix': {
                'critical': {
                    'count': 2,
                    'items': ['VULN-001', 'VULN-005'],
                    'business_impact': '完全な認証バイパス、全データへの不正アクセス',
                    'likelihood': 'HIGH',
                    'risk_score': 10
                },
                'high': {
                    'count': 3,
                    'items': ['VULN-002', 'VULN-003', 'VULN-006'],
                    'business_impact': 'セッションハイジャック、権限昇格',
                    'likelihood': 'MEDIUM',
                    'risk_score': 7
                },
                'medium': {
                    'count': 1,
                    'items': ['VULN-004'],
                    'business_impact': 'トークン管理の複雑化、監査困難',
                    'likelihood': 'LOW',
                    'risk_score': 4
                }
            },
            
            'overall_risk': 'CRITICAL',
            
            'compliance_impact': {
                'gdpr': '個人データ保護違反のリスク',
                'pci_dss': 'requirement 6.5.10 違反',
                'iso27001': 'A.14.2.5 セキュアシステム開発の不備'
            }
        }
    
    def _provide_recommendations(self):
        """改善提案"""
        
        return {
            'immediate_actions': [
                {
                    'action': 'アルゴリズムホワイトリストの実装',
                    'code': '''
                    ALLOWED_ALGORITHMS = ['RS256', 'ES256']
                    
                    def verify_token(token, public_key):
                        return jwt.decode(
                            token, 
                            public_key, 
                            algorithms=ALLOWED_ALGORITHMS
                        )
                    ''',
                    'effort': '2 hours',
                    'risk_reduction': 'CRITICAL → LOW'
                },
                
                {
                    'action': '強力な秘密鍵への移行',
                    'implementation': '''
                    # 1. 新しい鍵の生成
                    openssl rand -hex 32 > jwt_secret.key
                    
                    # 2. 環境変数での管理
                    JWT_SECRET=$(cat jwt_secret.key)
                    
                    # 3. キーローテーションの実装
                    class KeyRotation:
                        def __init__(self):
                            self.current_key = load_from_vault('jwt/current')
                            self.previous_key = load_from_vault('jwt/previous')
                        
                        def verify(self, token):
                            try:
                                return jwt.decode(token, self.current_key)
                            except:
                                return jwt.decode(token, self.previous_key)
                    ''',
                    'effort': '4 hours'
                }
            ],
            
            'medium_term_improvements': [
                {
                    'action': 'JWTライブラリのアップグレード',
                    'rationale': '既知の脆弱性の修正',
                    'steps': [
                        'ライブラリバージョンの確認',
                        'テスト環境での検証',
                        '段階的なロールアウト'
                    ]
                },
                
                {
                    'action': 'トークン無効化システムの実装',
                    'components': [
                        'Redisベースのブラックリスト',
                        'JTIによるトークン追跡',
                        '自動クリーンアップ'
                    ]
                }
            ],
            
            'long_term_strategy': [
                'OAuth 2.0 + OpenID Connectへの移行検討',
                'ハードウェアセキュリティモジュール（HSM）の導入',
                'Zero Trust Architectureの採用'
            ]
        }
    
    def _prioritize_fixes(self):
        """実装優先度"""
        
        return {
            'phase_1_immediate': {
                'duration': '1 week',
                'tasks': [
                    'アルゴリズムコンフュージョンの修正',
                    'クライアント側トークン生成の削除',
                    '秘密鍵の強化'
                ],
                'risk_reduction': '70%'
            },
            
            'phase_2_short_term': {
                'duration': '2 weeks',
                'tasks': [
                    'トークン有効期限の適切な検証',
                    'JTI実装による一意性保証',
                    'セキュリティヘッダーの追加'
                ],
                'risk_reduction': '20%'
            },
            
            'phase_3_medium_term': {
                'duration': '1 month',
                'tasks': [
                    'トークン無効化システム',
                    'キーローテーション',
                    '包括的なテストスイート'
                ],
                'risk_reduction': '10%'
            }
        }
```

### 監査結果のサマリー

1. **重大な脆弱性**：アルゴリズムコンフュージョンとクライアント側トークン生成
2. **リスク評価**：現状はCRITICALレベル、即時対応が必要
3. **改善提案**：段階的な修正計画で1ヶ月以内にリスクを許容レベルまで低減
4. **実装優先度**：セキュリティクリティカルな項目から順次対応

## 問題5：マイグレーション計画

### 解答

```python
# セッションベース認証からJWT認証への段階的移行計画

class AuthenticationMigrationPlan:
    """認証方式の段階的移行計画"""
    
    def __init__(self):
        self.migration_phases = self._define_phases()
        self.rollback_procedures = self._define_rollback()
        
    def _define_phases(self):
        """移行フェーズの定義"""
        
        return {
            'phase_0_preparation': {
                'duration': '2 weeks',
                'description': '移行準備とインフラ整備',
                'tasks': [
                    {
                        'task': 'JWT実装の開発とテスト',
                        'implementation': '''
                        # デュアル認証ミドルウェアの実装
                        class DualAuthMiddleware:
                            def __init__(self):
                                self.session_auth = SessionAuthentication()
                                self.jwt_auth = JWTAuthentication()
                                self.migration_config = MigrationConfig()
                            
                            async def authenticate(self, request):
                                # 移行フラグをチェック
                                user_id = self._extract_user_id(request)
                                migration_status = self.migration_config.get_status(user_id)
                                
                                if migration_status == 'jwt_enabled':
                                    # JWT認証を試行
                                    user = await self.jwt_auth.authenticate(request)
                                    if user:
                                        return user
                                
                                # セッション認証にフォールバック
                                return await self.session_auth.authenticate(request)
                        '''
                    },
                    {
                        'task': '監視ダッシュボードの構築',
                        'metrics': [
                            'auth_method_distribution',
                            'migration_progress',
                            'error_rates_by_method',
                            'performance_comparison'
                        ]
                    }
                ]
            },
            
            'phase_1_canary': {
                'duration': '1 week',
                'description': '社内ユーザーでのカナリーテスト',
                'percentage': '0.1%',
                'implementation': '''
                # カナリーデプロイメント設定
                class CanaryMigration:
                    def __init__(self):
                        self.canary_users = set()
                        self.metrics = MetricsCollector()
                    
                    def should_use_jwt(self, user_id):
                        # 社内ユーザーのみ
                        if self.is_internal_user(user_id):
                            self.canary_users.add(user_id)
                            return True
                        return False
                    
                    def collect_metrics(self, user_id, auth_method, success, latency):
                        self.metrics.record({
                            'user_id': user_id,
                            'method': auth_method,
                            'success': success,
                            'latency': latency,
                            'timestamp': time.time()
                        })
                ''',
                'success_criteria': {
                    'error_rate': '< 0.1%',
                    'latency_p95': '< 50ms',
                    'user_complaints': 0
                }
            },
            
            'phase_2_gradual_rollout': {
                'duration': '4 weeks',
                'description': '段階的な全ユーザー展開',
                'rollout_schedule': [
                    {'week': 1, 'percentage': '5%', 'segment': 'power_users'},
                    {'week': 2, 'percentage': '20%', 'segment': 'active_users'},
                    {'week': 3, 'percentage': '50%', 'segment': 'regular_users'},
                    {'week': 4, 'percentage': '100%', 'segment': 'all_users'}
                ],
                'implementation': '''
                class GradualRollout:
                    def __init__(self):
                        self.rollout_config = {
                            'current_percentage': 0,
                            'user_segments': {},
                            'feature_flags': FeatureFlagService()
                        }
                    
                    async def migrate_user_batch(self, percentage, segment):
                        # ユーザーセグメントの選択
                        users = await self.select_users(segment, percentage)
                        
                        for user in users:
                            try:
                                # セッションからJWTへの変換
                                session_data = await self.get_session_data(user.id)
                                jwt_tokens = await self.create_jwt_tokens(user, session_data)
                                
                                # 新しい認証方式を有効化
                                await self.enable_jwt_auth(user.id)
                                
                                # 通知を送信
                                await self.notify_user(user, jwt_tokens)
                                
                            except Exception as e:
                                await self.handle_migration_error(user, e)
                    
                    async def create_jwt_tokens(self, user, session_data):
                        """セッションデータからJWTトークンを生成"""
                        return {
                            'access_token': self.jwt_service.create_access_token({
                                'user_id': user.id,
                                'email': user.email,
                                'roles': session_data.get('roles', []),
                                'session_id': session_data.get('session_id')  # 移行追跡用
                            }),
                            'refresh_token': self.jwt_service.create_refresh_token({
                                'user_id': user.id,
                                'migration_date': datetime.utcnow().isoformat()
                            })
                        }
                '''
            },
            
            'phase_3_session_deprecation': {
                'duration': '2 weeks',
                'description': 'セッション認証の段階的廃止',
                'steps': [
                    {
                        'step': 'read_only_sessions',
                        'description': '新規セッション作成の停止',
                        'implementation': '''
                        class SessionDeprecation:
                            def create_session(self, user):
                                # 新規セッションの作成を防ぐ
                                logger.warning(f"Session creation attempted for user {user.id}")
                                
                                # JWTにリダイレクト
                                return self.create_jwt_instead(user)
                            
                            def extend_session(self, session_id):
                                # 既存セッションの延長は許可（一時的）
                                if self.is_valid_legacy_session(session_id):
                                    return self.extend_with_warning(session_id)
                                
                                raise SessionDeprecatedError()
                        '''
                    }
                ]
            },
            
            'phase_4_cleanup': {
                'duration': '1 week',
                'description': 'クリーンアップと最適化',
                'tasks': [
                    'セッション関連コードの削除',
                    'データベースのクリーンアップ',
                    'ドキュメントの更新',
                    'パフォーマンスチューニング'
                ]
            }
        }
    
    def _define_rollback(self):
        """ロールバック手順の定義"""
        
        return {
            'triggers': [
                'error_rate > 1%',
                'latency_p95 > 200ms',
                'security_incident',
                'major_user_complaints'
            ],
            
            'procedures': {
                'immediate_rollback': '''
                async def emergency_rollback():
                    # 1. Feature Flagの即時切り替え
                    await feature_flags.disable('jwt_authentication')
                    
                    # 2. トラフィックの切り替え
                    await load_balancer.route_all_to('session_auth_servers')
                    
                    # 3. キャッシュのクリア
                    await cache.clear_pattern('jwt:*')
                    
                    # 4. アラート送信
                    await alert_team('Emergency rollback initiated')
                ''',
                
                'data_recovery': '''
                async def recover_user_sessions():
                    # JWTからセッションへの逆変換
                    affected_users = await get_jwt_only_users()
                    
                    for user in affected_users:
                        jwt_data = await extract_jwt_claims(user)
                        session = await recreate_session(jwt_data)
                        await notify_user_rollback(user)
                '''
            }
        }
    
    def performance_impact_assessment(self):
        """性能影響の評価"""
        
        return {
            'expected_improvements': {
                'latency': {
                    'session_auth_p50': '20ms',
                    'jwt_auth_p50': '5ms',
                    'improvement': '75%'
                },
                'throughput': {
                    'session_auth_rps': '10,000',
                    'jwt_auth_rps': '50,000',
                    'improvement': '400%'
                },
                'resource_usage': {
                    'session_storage': '50GB',
                    'jwt_storage': '1GB',
                    'reduction': '98%'
                }
            },
            
            'monitoring_plan': '''
            # Grafanaダッシュボード設定
            dashboards:
              - name: "Auth Migration Metrics"
                panels:
                  - title: "Auth Method Distribution"
                    query: |
                      sum by (method) (
                        rate(auth_requests_total[5m])
                      )
                  
                  - title: "Error Rates by Method"
                    query: |
                      sum by (method) (
                        rate(auth_errors_total[5m])
                      ) / 
                      sum by (method) (
                        rate(auth_requests_total[5m])
                      )
                  
                  - title: "Migration Progress"
                    query: |
                      count(user_auth_method{method="jwt"}) / 
                      count(user_auth_method)
            '''
        }
```

### 移行計画のポイント

1. **段階的移行戦略**
   - カナリーデプロイメントから開始
   - セグメント別の段階的展開
   - 常にロールバック可能な状態を維持

2. **後方互換性の維持**
   - デュアル認証システムの実装
   - 既存セッションの尊重
   - グレースフルな移行

3. **ロールバック手順**
   - 明確なトリガー条件
   - 自動化されたロールバック
   - データ整合性の保証

4. **性能影響の評価**
   - 詳細なメトリクス収集
   - A/Bテストによる検証
   - 継続的なモニタリング

## チャレンジ問題：分散環境でのトークン管理

### 解答

```yaml
# マイクロサービス環境でのトークン管理システム設計

apiVersion: v1
kind: Architecture
metadata:
  name: distributed-token-management
spec:
  overview: |
    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │   Client    │────▶│ API Gateway │────▶│Auth Service │
    └─────────────┘     └─────────────┘     └─────────────┘
                               │                      │
                               ▼                      ▼
                        ┌──────────────┐      ┌───────────┐
                        │Service Mesh  │      │Token Store│
                        │  (Istio)     │      │ (Redis)   │
                        └──────────────┘      └───────────┘
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
    ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
    │ User Service │  │Order Service  │  │Payment Service│
    └───────────────┘  └───────────────┘  └───────────────┘
```

```python
# 分散トークン管理システムの実装

class DistributedTokenManagement:
    """マイクロサービス環境でのトークン管理"""
    
    def __init__(self):
        self.architecture = self._design_architecture()
        self.implementation = self._implement_system()
        
    def _design_architecture(self):
        """システムアーキテクチャ"""
        
        return {
            'components': {
                'api_gateway': {
                    'responsibility': 'エントリーポイント、初期認証',
                    'implementation': '''
                    # Kong Gateway設定
                    plugins:
                      - name: jwt
                        config:
                          uri_param_names: []
                          cookie_names: []
                          header_names:
                            - authorization
                          claims_to_verify:
                            - exp
                          maximum_expiration: 900
                          
                      - name: request-transformer
                        config:
                          add:
                            headers:
                              - X-User-ID:$(jwt.sub)
                              - X-User-Roles:$(jwt.roles)
                              - X-Request-ID:$(request_id)
                    '''
                },
                
                'auth_service': {
                    'responsibility': 'トークン発行、検証、管理',
                    'implementation': '''
                    from fastapi import FastAPI, Depends
                    from typing import Optional
                    import asyncio
                    
                    class AuthService:
                        def __init__(self):
                            self.token_store = RedisTokenStore()
                            self.key_manager = DistributedKeyManager()
                            self.event_bus = EventBus()
                            
                        async def issue_service_token(self, 
                                                    service_name: str,
                                                    target_service: str) -> str:
                            """サービス間認証用トークンの発行"""
                            
                            # サービスの検証
                            if not await self.verify_service(service_name):
                                raise UnauthorizedError()
                            
                            # 短命なトークンを発行
                            token_data = {
                                'iss': 'auth-service',
                                'sub': service_name,
                                'aud': target_service,
                                'exp': int(time.time() + 60),  # 1分
                                'jti': str(uuid.uuid4()),
                                'scope': self.get_service_scope(service_name)
                            }
                            
                            # 分散キー管理から鍵を取得
                            signing_key = await self.key_manager.get_current_key()
                            
                            token = jwt.encode(token_data, signing_key, algorithm='RS256')
                            
                            # イベント発行
                            await self.event_bus.publish('token.issued', {
                                'service': service_name,
                                'target': target_service,
                                'jti': token_data['jti']
                            })
                            
                            return token
                        
                        async def propagate_token(self, 
                                                user_token: str,
                                                target_services: List[str]) -> Dict:
                            """ユーザートークンの伝播"""
                            
                            # オリジナルトークンの検証
                            user_claims = await self.verify_token(user_token)
                            
                            # 各サービス用の派生トークンを生成
                            derived_tokens = {}
                            
                            for service in target_services:
                                derived_token = await self.create_derived_token(
                                    user_claims, 
                                    service
                                )
                                derived_tokens[service] = derived_token
                            
                            return derived_tokens
                        
                        async def create_derived_token(self, 
                                                     original_claims: Dict,
                                                     target_service: str) -> str:
                            """派生トークンの生成"""
                            
                            # 必要最小限の情報のみ含める
                            derived_claims = {
                                'iss': 'auth-service',
                                'sub': original_claims['sub'],
                                'aud': target_service,
                                'original_jti': original_claims['jti'],
                                'exp': min(
                                    original_claims['exp'],
                                    int(time.time() + 300)  # 最大5分
                                ),
                                'scope': self.filter_scope_for_service(
                                    original_claims.get('scope', []),
                                    target_service
                                )
                            }
                            
                            return jwt.encode(
                                derived_claims,
                                self.signing_key,
                                algorithm='RS256'
                            )
                    '''
                },
                
                'service_mesh': {
                    'responsibility': 'サービス間通信の認証・認可',
                    'implementation': '''
                    # Istio設定
                    apiVersion: security.istio.io/v1beta1
                    kind: AuthorizationPolicy
                    metadata:
                      name: service-auth
                    spec:
                      selector:
                        matchLabels:
                          app: microservice
                      rules:
                      - from:
                        - source:
                            requestPrincipals: ["cluster.local/ns/default/sa/*"]
                        to:
                        - operation:
                            methods: ["GET", "POST"]
                        when:
                        - key: request.auth.claims[iss]
                          values: ["auth-service"]
                        - key: request.auth.claims[exp]
                          values: [">", "now"]
                    
                    ---
                    apiVersion: security.istio.io/v1beta1
                    kind: RequestAuthentication
                    metadata:
                      name: jwt-auth
                    spec:
                      selector:
                        matchLabels:
                          app: microservice
                      jwtRules:
                      - issuer: "auth-service"
                        jwksUri: "http://auth-service/jwks"
                        audiences:
                        - "user-service"
                        - "order-service"
                        - "payment-service"
                    '''
                },
                
                'token_store': {
                    'responsibility': '分散トークン状態管理',
                    'implementation': '''
                    class DistributedTokenStore:
                        def __init__(self):
                            self.redis_cluster = RedisCluster(
                                startup_nodes=[
                                    {"host": "redis-1", "port": 6379},
                                    {"host": "redis-2", "port": 6379},
                                    {"host": "redis-3", "port": 6379}
                                ],
                                decode_responses=True,
                                skip_full_coverage_check=True
                            )
                            self.consistency_level = 'eventual'
                            
                        async def store_token_state(self, jti: str, state: Dict):
                            """トークン状態の保存"""
                            
                            key = f"token:{jti}"
                            
                            # 分散ロックを取得
                            lock = await self.acquire_lock(key)
                            
                            try:
                                # CRDTを使用した状態管理
                                current_state = await self.get_state(key)
                                merged_state = self.merge_states(current_state, state)
                                
                                # パイプラインで原子性を保証
                                pipe = self.redis_cluster.pipeline()
                                pipe.hset(key, mapping=merged_state)
                                pipe.expire(key, 3600)  # 1時間
                                pipe.publish(f"token_update:{jti}", json.dumps(state))
                                await pipe.execute()
                                
                            finally:
                                await self.release_lock(lock)
                        
                        def merge_states(self, current: Dict, new: Dict) -> Dict:
                            """CRDT風の状態マージ"""
                            
                            merged = current.copy()
                            
                            for key, value in new.items():
                                if key == 'revoked':
                                    # revokedフラグは一度trueになったら変更不可
                                    merged[key] = current.get(key, False) or value
                                elif key == 'last_used':
                                    # タイムスタンプは最新を採用
                                    merged[key] = max(
                                        current.get(key, 0), 
                                        value
                                    )
                                elif key == 'usage_count':
                                    # カウンターは加算
                                    merged[key] = current.get(key, 0) + value
                                else:
                                    merged[key] = value
                            
                            return merged
                    '''
                }
            }
        }
    
    def _implement_system(self):
        """システム実装"""
        
        return {
            'service_authentication': '''
            # 各マイクロサービスでの実装
            class MicroserviceAuth:
                def __init__(self, service_name: str):
                    self.service_name = service_name
                    self.auth_client = AuthServiceClient()
                    self.token_cache = TTLCache(maxsize=1000, ttl=60)
                    
                async def make_authenticated_request(self, 
                                                   target_service: str,
                                                   endpoint: str,
                                                   user_context: Optional[Dict] = None):
                    """認証付きサービス間リクエスト"""
                    
                    # サービストークンの取得（キャッシュ付き）
                    service_token = await self._get_service_token(target_service)
                    
                    headers = {
                        'Authorization': f'Bearer {service_token}',
                        'X-Service-Name': self.service_name,
                        'X-Request-ID': str(uuid.uuid4())
                    }
                    
                    # ユーザーコンテキストがある場合は伝播
                    if user_context:
                        propagated_token = await self._propagate_user_context(
                            user_context, 
                            target_service
                        )
                        headers['X-User-Context'] = propagated_token
                    
                    # サーキットブレーカー付きリクエスト
                    async with CircuitBreaker(
                        failure_threshold=5,
                        recovery_timeout=30
                    ) as cb:
                        return await cb.call(
                            self._make_request,
                            target_service,
                            endpoint,
                            headers
                        )
                
                async def _get_service_token(self, target_service: str) -> str:
                    """サービストークンの取得（キャッシュ付き）"""
                    
                    cache_key = f"{self.service_name}:{target_service}"
                    
                    # キャッシュチェック
                    cached_token = self.token_cache.get(cache_key)
                    if cached_token:
                        return cached_token
                    
                    # 新規取得
                    token = await self.auth_client.get_service_token(
                        self.service_name,
                        target_service
                    )
                    
                    self.token_cache[cache_key] = token
                    return token
            ''',
            
            'monitoring_and_troubleshooting': '''
            # 分散トレーシングの実装
            class TokenTracingSystem:
                def __init__(self):
                    self.tracer = init_tracer('token-management')
                    
                def trace_token_flow(self, token_jti: str):
                    """トークンフローの追跡"""
                    
                    with self.tracer.start_span('token_flow') as span:
                        span.set_tag('token.jti', token_jti)
                        
                        # トークン発行の追跡
                        issue_span = self.tracer.start_span(
                            'token_issued',
                            child_of=span
                        )
                        
                        # サービス間伝播の追跡
                        propagation_spans = []
                        for service in self.get_token_usage(token_jti):
                            prop_span = self.tracer.start_span(
                                f'token_propagated_to_{service}',
                                child_of=span
                            )
                            propagation_spans.append(prop_span)
                        
                        # 無効化の追跡
                        if self.is_token_revoked(token_jti):
                            revoke_span = self.tracer.start_span(
                                'token_revoked',
                                child_of=span
                            )
                
                def create_monitoring_dashboard(self):
                    """監視ダッシュボードの設定"""
                    
                    return {
                        'metrics': [
                            {
                                'name': 'token_issued_total',
                                'type': 'counter',
                                'labels': ['service', 'token_type']
                            },
                            {
                                'name': 'token_validation_duration',
                                'type': 'histogram',
                                'labels': ['service', 'result']
                            },
                            {
                                'name': 'token_propagation_errors',
                                'type': 'counter',
                                'labels': ['source', 'target', 'error_type']
                            },
                            {
                                'name': 'active_tokens',
                                'type': 'gauge',
                                'labels': ['service']
                            }
                        ],
                        
                        'alerts': [
                            {
                                'name': 'HighTokenValidationLatency',
                                'expr': 'histogram_quantile(0.95, token_validation_duration) > 100',
                                'for': '5m',
                                'severity': 'warning'
                            },
                            {
                                'name': 'TokenPropagationFailure',
                                'expr': 'rate(token_propagation_errors[5m]) > 0.01',
                                'for': '5m',
                                'severity': 'critical'
                            }
                        ]
                    }
            '''
        }
```

### 設計のポイント

1. **サービス間認証**
   - 短命なサービストークン
   - mTLSとの組み合わせ
   - 最小権限の原則

2. **トークンの伝播**
   - 派生トークンによるスコープ制限
   - コンテキスト情報の安全な伝達
   - 自動的な有効期限短縮

3. **一貫性のある無効化**
   - 分散キャッシュによる状態共有
   - イベント駆動の無効化通知
   - 結果整合性の許容

4. **監視とトラブルシューティング**
   - 分散トレーシングによる可視化
   - メトリクスベースのアラート
   - トークンライフサイクルの追跡