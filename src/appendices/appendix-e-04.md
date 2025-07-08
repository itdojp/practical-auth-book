# 第4章 演習問題解答

## 問題1：セキュアなセッション実装

### 完全なセキュアセッション実装

```python
import secrets
import time
import hmac
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import ipaddress

class SecureSessionManager:
    """セキュアなセッション管理システムの実装"""
    
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key
        self.sessions = {}  # 実際はRedis等を使用
        self.csrf_tokens = {}
        self.config = {
            'session_timeout': 1800,  # 30分
            'absolute_timeout': 86400,  # 24時間
            'regenerate_interval': 300,  # 5分
            'max_sessions_per_user': 3,
            'ip_binding': True,
            'user_agent_binding': True
        }
    
    def create_session(self, user_id: str, request_context: dict) -> dict:
        """セキュアなセッション作成"""
        
        # 1. セッション固定攻撃対策：常に新しいIDを生成
        session_id = self._generate_secure_session_id()
        
        # 2. 既存セッションの管理
        self._manage_user_sessions(user_id)
        
        # 3. セッションデータの作成
        session_data = {
            'session_id': session_id,
            'user_id': user_id,
            'created_at': time.time(),
            'last_accessed': time.time(),
            'last_regenerated': time.time(),
            
            # セッションハイジャック対策
            'binding': {
                'ip_address': request_context['ip_address'],
                'user_agent': request_context['user_agent'],
                'accept_language': request_context.get('accept_language', ''),
                'fingerprint': self._calculate_fingerprint(request_context)
            },
            
            # CSRF対策
            'csrf_token': self._generate_csrf_token(session_id),
            
            # セッション管理
            'access_count': 0,
            'is_elevated': False,
            'data': {}
        }
        
        # 4. セッションの保存
        self.sessions[session_id] = session_data
        
        # 5. レスポンスの準備
        cookie_value = self._create_secure_cookie(session_id)
        
        return {
            'session_id': session_id,
            'cookie': cookie_value,
            'csrf_token': session_data['csrf_token']
        }
    
    def validate_session(self, session_id: str, request_context: dict) -> Optional[dict]:
        """セッションの検証"""
        
        # 1. セッションの存在確認
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        # 2. タイムアウトチェック
        current_time = time.time()
        
        # アイドルタイムアウト
        if current_time - session['last_accessed'] > self.config['session_timeout']:
            self.destroy_session(session_id)
            return None
        
        # 絶対タイムアウト
        if current_time - session['created_at'] > self.config['absolute_timeout']:
            self.destroy_session(session_id)
            return None
        
        # 3. セッションハイジャック対策：バインディング検証
        if not self._verify_binding(session, request_context):
            # 疑わしいアクセスとして記録
            self._log_suspicious_activity(session_id, request_context)
            return None
        
        # 4. セッションの更新
        session['last_accessed'] = current_time
        session['access_count'] += 1
        
        # 5. セッションID再生成のチェック
        if self._should_regenerate_id(session):
            new_session_id = self._regenerate_session_id(session)
            return {
                'session': session,
                'new_session_id': new_session_id,
                'new_cookie': self._create_secure_cookie(new_session_id)
            }
        
        return {'session': session}
    
    def verify_csrf_token(self, session_id: str, token: str) -> bool:
        """CSRFトークンの検証"""
        
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        expected_token = session.get('csrf_token')
        
        # タイミング攻撃対策：定数時間比較
        return hmac.compare_digest(token, expected_token)
    
    def _generate_secure_session_id(self) -> str:
        """セキュアなセッションID生成"""
        # 256ビットのランダム値
        return secrets.token_urlsafe(32)
    
    def _generate_csrf_token(self, session_id: str) -> str:
        """CSRFトークンの生成"""
        # セッションIDと秘密鍵から生成
        message = f"{session_id}:{int(time.time() // 3600)}".encode()
        token = hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()
        return token
    
    def _calculate_fingerprint(self, request_context: dict) -> str:
        """デバイスフィンガープリントの計算"""
        # 複数の要素を組み合わせてフィンガープリント生成
        components = [
            request_context.get('user_agent', ''),
            request_context.get('accept_language', ''),
            request_context.get('accept_encoding', ''),
            str(request_context.get('screen_resolution', '')),
            str(request_context.get('timezone_offset', '')),
            str(request_context.get('plugin_list', []))
        ]
        
        fingerprint_data = '|'.join(components)
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
    
    def _verify_binding(self, session: dict, request_context: dict) -> bool:
        """セッションバインディングの検証"""
        
        binding = session['binding']
        
        # IPアドレスの検証
        if self.config['ip_binding']:
            # 同一サブネットかチェック（厳密すぎない）
            try:
                stored_ip = ipaddress.ip_address(binding['ip_address'])
                current_ip = ipaddress.ip_address(request_context['ip_address'])
                
                # IPv4の場合は/24、IPv6の場合は/64で比較
                if isinstance(stored_ip, ipaddress.IPv4Address):
                    stored_network = ipaddress.ip_network(f"{stored_ip}/24", strict=False)
                    if current_ip not in stored_network:
                        return False
                else:
                    stored_network = ipaddress.ip_network(f"{stored_ip}/64", strict=False)
                    if current_ip not in stored_network:
                        return False
                        
            except ValueError:
                return False
        
        # User-Agentの検証
        if self.config['user_agent_binding']:
            if binding['user_agent'] != request_context.get('user_agent'):
                return False
        
        # フィンガープリントの検証（一定の変動を許容）
        current_fingerprint = self._calculate_fingerprint(request_context)
        stored_fingerprint = binding['fingerprint']
        
        # 完全一致または部分一致
        if current_fingerprint != stored_fingerprint:
            # 類似度チェック（簡易版）
            similarity = sum(a == b for a, b in zip(current_fingerprint, stored_fingerprint))
            if similarity < len(stored_fingerprint) * 0.7:  # 70%以上の一致
                return False
        
        return True
    
    def _should_regenerate_id(self, session: dict) -> bool:
        """セッションID再生成が必要か判定"""
        
        # 定期的な再生成
        if time.time() - session['last_regenerated'] > self.config['regenerate_interval']:
            return True
        
        # 権限昇格時
        if session.get('privilege_changed', False):
            return True
        
        return False
    
    def _regenerate_session_id(self, session: dict) -> str:
        """セッションIDの再生成"""
        
        old_id = session['session_id']
        new_id = self._generate_secure_session_id()
        
        # セッションデータをコピー
        new_session = session.copy()
        new_session['session_id'] = new_id
        new_session['last_regenerated'] = time.time()
        new_session['csrf_token'] = self._generate_csrf_token(new_id)
        
        # 新しいIDで保存
        self.sessions[new_id] = new_session
        
        # 古いIDを削除（グレース期間を設けることも可能）
        del self.sessions[old_id]
        
        return new_id
    
    def _create_secure_cookie(self, session_id: str) -> str:
        """セキュアなCookie文字列の作成"""
        
        cookie_parts = [
            f"session_id={session_id}",
            "HttpOnly",  # XSS対策
            "Secure",    # HTTPS必須
            "SameSite=Lax",  # CSRF対策
            "Path=/",
            f"Max-Age={self.config['session_timeout']}"
        ]
        
        return "; ".join(cookie_parts)
    
    def _manage_user_sessions(self, user_id: str):
        """ユーザーのセッション数管理"""
        
        # ユーザーのアクティブセッション取得
        user_sessions = [
            (sid, s) for sid, s in self.sessions.items() 
            if s['user_id'] == user_id
        ]
        
        # セッション数制限
        if len(user_sessions) >= self.config['max_sessions_per_user']:
            # 最も古いセッションを削除
            oldest = min(user_sessions, key=lambda x: x[1]['last_accessed'])
            self.destroy_session(oldest[0])
    
    def destroy_session(self, session_id: str):
        """セッションの破棄"""
        
        if session_id in self.sessions:
            # ログ記録
            self._log_session_destruction(session_id)
            
            # セッションデータ削除
            del self.sessions[session_id]
            
            # 関連データの削除
            if session_id in self.csrf_tokens:
                del self.csrf_tokens[session_id]
    
    def _log_suspicious_activity(self, session_id: str, request_context: dict):
        """疑わしいアクティビティのログ"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event': 'suspicious_session_access',
            'session_id': session_id,
            'request_context': request_context,
            'action': 'session_invalidated'
        }
        # 実際のログシステムに記録
        print(f"SECURITY ALERT: {log_entry}")
    
    def _log_session_destruction(self, session_id: str):
        """セッション破棄のログ"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event': 'session_destroyed',
            'session_id': session_id
        }
        # 実際のログシステムに記録
        print(f"SESSION LOG: {log_entry}")

# 使用例とテスト
def test_secure_session():
    """セキュアセッション実装のテスト"""
    
    manager = SecureSessionManager(b'super-secret-key-32-bytes-long!!')
    
    # セッション作成
    request_context = {
        'ip_address': '192.168.1.100',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'accept_language': 'ja-JP,ja;q=0.9,en;q=0.8'
    }
    
    result = manager.create_session('user123', request_context)
    print(f"Session created: {result['session_id']}")
    print(f"Cookie: {result['cookie']}")
    print(f"CSRF Token: {result['csrf_token']}")
    
    # セッション検証
    validation = manager.validate_session(result['session_id'], request_context)
    assert validation is not None
    print("Session validation: PASS")
    
    # CSRF検証
    csrf_valid = manager.verify_csrf_token(result['session_id'], result['csrf_token'])
    assert csrf_valid
    print("CSRF validation: PASS")
    
    # 異なるIPからのアクセス（セッションハイジャック試行）
    hijack_context = request_context.copy()
    hijack_context['ip_address'] = '10.0.0.1'
    
    hijack_validation = manager.validate_session(result['session_id'], hijack_context)
    assert hijack_validation is None
    print("Session hijack prevention: PASS")
```

## 問題2：Cookie属性の設定

### ECサイト向けCookie設定

```python
class ECCookieConfiguration:
    """ECサイト向けのCookie設定"""
    
    def __init__(self, environment: str = 'production'):
        self.environment = environment
        self.domain_config = self._setup_domain_config()
    
    def _setup_domain_config(self):
        """環境別ドメイン設定"""
        
        return {
            'development': {
                'main_domain': 'localhost',
                'cookie_domain': None,  # 現在のドメインのみ
                'secure': False,  # HTTPでの開発を許可
                'subdomains': []
            },
            'staging': {
                'main_domain': 'staging.example.com',
                'cookie_domain': '.staging.example.com',
                'secure': True,
                'subdomains': ['app', 'api', 'cdn']
            },
            'production': {
                'main_domain': 'example.com',
                'cookie_domain': '.example.com',
                'secure': True,
                'subdomains': ['www', 'app', 'api', 'cdn', 'shop']
            }
        }
    
    def get_session_cookie_config(self):
        """セッションCookieの設定"""
        
        config = self.domain_config[self.environment]
        
        return {
            'name': 'session_id',
            'attributes': {
                'HttpOnly': True,  # XSS防止（必須）
                'Secure': config['secure'],  # HTTPS必須（本番では必須）
                'SameSite': 'Lax',  # CSRF対策とユーザビリティのバランス
                'Domain': config['cookie_domain'],  # サブドメイン共有
                'Path': '/',
                'Max-Age': None  # ブラウザセッション（ブラウザ終了で削除）
            },
            'explanation': {
                'HttpOnly': 'JavaScriptからアクセス不可。XSS攻撃を防ぐ',
                'Secure': 'HTTPS接続でのみ送信。盗聴を防ぐ',
                'SameSite=Lax': 'CSRF攻撃を防ぎつつ、通常のリンク遷移は許可',
                'Domain': 'サブドメイン間でセッション共有',
                'No Max-Age': 'ブラウザ終了でセッション終了（セキュリティ重視）'
            }
        }
    
    def get_cart_cookie_config(self):
        """カートCookieの設定（非ログインユーザー用）"""
        
        config = self.domain_config[self.environment]
        
        return {
            'name': 'cart_id',
            'attributes': {
                'HttpOnly': True,  # JSアクセス不要
                'Secure': config['secure'],
                'SameSite': 'Lax',
                'Domain': config['cookie_domain'],
                'Path': '/',
                'Max-Age': 604800  # 7日間（利便性重視）
            },
            'explanation': {
                'Max-Age=7days': 'カートは長期保存して利便性向上',
                'HttpOnly': 'カートIDもJSアクセス不要でセキュア',
                'Domain': 'サブドメイン間でカート共有'
            }
        }
    
    def get_preference_cookie_config(self):
        """ユーザー設定Cookieの設定"""
        
        config = self.domain_config[self.environment]
        
        return {
            'name': 'user_prefs',
            'attributes': {
                'HttpOnly': False,  # JSからアクセス必要
                'Secure': config['secure'],
                'SameSite': 'Lax',
                'Domain': config['cookie_domain'],
                'Path': '/',
                'Max-Age': 31536000  # 1年間
            },
            'explanation': {
                'No HttpOnly': 'JSで言語切り替えなどに使用',
                'Max-Age=1year': '設定は長期保存',
                'Content': '機密情報は含めない（言語、テーマなど）'
            }
        }
    
    def get_analytics_cookie_config(self):
        """分析用Cookieの設定"""
        
        return {
            'name': '_ga',
            'attributes': {
                'HttpOnly': False,
                'Secure': True,
                'SameSite': 'None',  # クロスサイトトラッキング用
                'Domain': '.example.com',
                'Path': '/',
                'Max-Age': 63072000  # 2年間
            },
            'explanation': {
                'SameSite=None': '第三者Cookie として動作',
                'Secure必須': 'SameSite=Noneには Secure が必須',
                'Privacy': 'GDPRに準拠した同意取得が必要'
            }
        }
    
    def generate_cookie_policy_matrix(self):
        """Cookie ポリシーマトリックスの生成"""
        
        return {
            'cookie_types': {
                'essential': {
                    'cookies': ['session_id', 'cart_id', 'csrf_token'],
                    'consent_required': False,
                    'retention': 'Session or specified',
                    'purpose': 'サイトの基本機能に必要'
                },
                'functional': {
                    'cookies': ['user_prefs', 'language', 'currency'],
                    'consent_required': False,  # 議論の余地あり
                    'retention': '1 year',
                    'purpose': 'ユーザー体験の向上'
                },
                'analytics': {
                    'cookies': ['_ga', '_gid', 'utm_*'],
                    'consent_required': True,
                    'retention': '2 years',
                    'purpose': 'サイトの利用状況分析'
                },
                'marketing': {
                    'cookies': ['_fbp', 'ads_*'],
                    'consent_required': True,
                    'retention': 'Various',
                    'purpose': 'ターゲティング広告'
                }
            }
        }
    
    def implement_cookie_consent_handler(self):
        """Cookie同意ハンドラーの実装"""
        
        class CookieConsentHandler:
            def __init__(self):
                self.consent_cookie_name = 'cookie_consent'
                
            def check_consent(self, cookie_type: str) -> bool:
                """同意状態の確認"""
                consent = self.get_consent_settings()
                
                # 必須Cookieは常に許可
                if cookie_type == 'essential':
                    return True
                
                return consent.get(cookie_type, False)
            
            def set_consent(self, consent_settings: dict) -> str:
                """同意設定の保存"""
                
                # 同意内容をエンコード
                import json
                import base64
                
                consent_data = {
                    'version': '1.0',
                    'timestamp': time.time(),
                    'settings': consent_settings
                }
                
                encoded = base64.b64encode(
                    json.dumps(consent_data).encode()
                ).decode()
                
                # Cookie属性
                cookie = f"{self.consent_cookie_name}={encoded}; "
                cookie += "Path=/; "
                cookie += "Max-Age=31536000; "  # 1年
                cookie += "SameSite=Lax; "
                
                if self.is_production():
                    cookie += "Secure; "
                
                return cookie
            
            def get_consent_settings(self) -> dict:
                """現在の同意設定を取得"""
                # Cookie から同意情報を読み取り
                # 実装は省略
                pass
        
        return CookieConsentHandler()
```

## 問題3：分散セッションストアの設計

### 高性能分散セッションストア

```python
import asyncio
import aioredis
import pickle
import json
from typing import Optional, Dict, Any, List
import logging

class DistributedSessionStore:
    """1000req/s対応の分散セッションストア"""
    
    def __init__(self):
        self.redis_cluster = None
        self.local_cache = {}  # L1キャッシュ
        self.config = {
            'redis_nodes': [
                {'host': 'redis-1', 'port': 6379},
                {'host': 'redis-2', 'port': 6379},
                {'host': 'redis-3', 'port': 6379},
            ],
            'cache_ttl': 60,  # L1キャッシュTTL
            'connection_pool_size': 100,
            'read_timeout': 0.005,  # 5ms
            'write_timeout': 0.010,  # 10ms
        }
        self.metrics = SessionMetrics()
        
    async def initialize(self):
        """Redis クラスターの初期化"""
        
        # Redis Sentinel を使用した高可用性構成
        sentinels = [
            ('sentinel-1', 26379),
            ('sentinel-2', 26379),
            ('sentinel-3', 26379),
        ]
        
        self.redis_master = await aioredis.create_sentinel(
            sentinels,
            master_name='mymaster',
            password='redis_password',
            socket_keepalive=True,
            socket_keepalive_options={
                1: 1,  # TCP_KEEPIDLE
                2: 3,  # TCP_KEEPINTVL
                3: 5,  # TCP_KEEPCNT
            }
        )
        
        # 読み取り用レプリカプール
        self.redis_replicas = await aioredis.create_redis_pool(
            'redis://redis-replica-lb:6379',
            minsize=20,
            maxsize=self.config['connection_pool_size'],
            timeout=self.config['read_timeout']
        )
        
        # ウォームアップ
        await self._warmup_connections()
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """セッション取得（レスポンスタイム最適化）"""
        
        start_time = time.time()
        
        # L1キャッシュチェック（<0.001ms）
        cached = self._get_from_local_cache(session_id)
        if cached:
            self.metrics.record_l1_hit()
            return cached
        
        # Redis から取得
        try:
            # タイムアウト付き読み取り
            session_data = await asyncio.wait_for(
                self._get_from_redis(session_id),
                timeout=self.config['read_timeout']
            )
            
            if session_data:
                # L1キャッシュに保存
                self._set_local_cache(session_id, session_data)
                self.metrics.record_redis_hit()
                
                # レスポンスタイム記録
                elapsed = (time.time() - start_time) * 1000
                self.metrics.record_latency('get', elapsed)
                
                return session_data
            
            self.metrics.record_miss()
            return None
            
        except asyncio.TimeoutError:
            # タイムアウト時はレプリカから読み取り
            self.metrics.record_timeout()
            return await self._get_from_replica(session_id)
            
        except Exception as e:
            logging.error(f"Session get error: {e}")
            self.metrics.record_error()
            return None
    
    async def set_session(self, session_id: str, session_data: Dict[str, Any], 
                         ttl: int = 1800) -> bool:
        """セッション保存"""
        
        start_time = time.time()
        
        try:
            # パイプラインで効率化
            pipe = self.redis_master.pipeline()
            
            # セッションデータ保存
            serialized = self._serialize(session_data)
            pipe.setex(f"session:{session_id}", ttl, serialized)
            
            # インデックス更新
            pipe.zadd("sessions:active", {session_id: time.time()})
            pipe.sadd(f"user:{session_data['user_id']}:sessions", session_id)
            
            # 実行
            await asyncio.wait_for(
                pipe.execute(),
                timeout=self.config['write_timeout']
            )
            
            # L1キャッシュ更新
            self._set_local_cache(session_id, session_data)
            
            # メトリクス記録
            elapsed = (time.time() - start_time) * 1000
            self.metrics.record_latency('set', elapsed)
            
            return True
            
        except Exception as e:
            logging.error(f"Session set error: {e}")
            self.metrics.record_error()
            return False
    
    async def _get_from_redis(self, session_id: str) -> Optional[Dict]:
        """Redisからの取得"""
        
        # 読み取りはレプリカ優先
        data = await self.redis_replicas.get(f"session:{session_id}")
        
        if data:
            return self._deserialize(data)
        return None
    
    async def _get_from_replica(self, session_id: str) -> Optional[Dict]:
        """レプリカからのフォールバック読み取り"""
        
        # 複数のレプリカに並列クエリ
        tasks = []
        for replica in self.redis_replicas._pool:
            task = replica.get(f"session:{session_id}")
            tasks.append(task)
        
        # 最初に成功したものを使用
        done, pending = await asyncio.wait(
            tasks, 
            return_when=asyncio.FIRST_COMPLETED
        )
        
        # 残りをキャンセル
        for task in pending:
            task.cancel()
        
        # 結果を返す
        for task in done:
            result = await task
            if result:
                return self._deserialize(result)
        
        return None
    
    def _get_from_local_cache(self, session_id: str) -> Optional[Dict]:
        """ローカルキャッシュから取得"""
        
        cached = self.local_cache.get(session_id)
        if cached:
            # TTLチェック
            if time.time() - cached['cached_at'] < self.config['cache_ttl']:
                return cached['data']
            else:
                # 期限切れは削除
                del self.local_cache[session_id]
        
        return None
    
    def _set_local_cache(self, session_id: str, data: Dict):
        """ローカルキャッシュに保存"""
        
        # LRU的な動作（簡易版）
        if len(self.local_cache) > 10000:
            # 最も古いものを削除
            oldest = min(self.local_cache.items(), 
                        key=lambda x: x[1]['cached_at'])
            del self.local_cache[oldest[0]]
        
        self.local_cache[session_id] = {
            'data': data,
            'cached_at': time.time()
        }
    
    def _serialize(self, data: Dict) -> bytes:
        """高速シリアライズ"""
        # MessagePack の方が高速だが、ここでは pickle を使用
        return pickle.dumps(data, protocol=pickle.HIGHEST_PROTOCOL)
    
    def _deserialize(self, data: bytes) -> Dict:
        """高速デシリアライズ"""
        return pickle.loads(data)
    
    async def _warmup_connections(self):
        """接続プールのウォームアップ"""
        
        # ダミーリクエストで接続を確立
        tasks = []
        for i in range(20):
            task = self.redis_replicas.ping()
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)

class SessionMetrics:
    """パフォーマンスメトリクス"""
    
    def __init__(self):
        self.counters = {
            'l1_hits': 0,
            'redis_hits': 0,
            'misses': 0,
            'errors': 0,
            'timeouts': 0
        }
        self.latencies = {
            'get': [],
            'set': []
        }
        self.last_reset = time.time()
    
    def record_l1_hit(self):
        self.counters['l1_hits'] += 1
    
    def record_redis_hit(self):
        self.counters['redis_hits'] += 1
    
    def record_miss(self):
        self.counters['misses'] += 1
    
    def record_error(self):
        self.counters['errors'] += 1
    
    def record_timeout(self):
        self.counters['timeouts'] += 1
    
    def record_latency(self, operation: str, latency_ms: float):
        self.latencies[operation].append(latency_ms)
        
        # 定期的にクリーンアップ
        if len(self.latencies[operation]) > 10000:
            self.latencies[operation] = self.latencies[operation][-5000:]
    
    def get_stats(self) -> Dict:
        """統計情報の取得"""
        
        import numpy as np
        
        total_requests = sum(self.counters.values())
        
        stats = {
            'hit_rate': {
                'l1': self.counters['l1_hits'] / max(total_requests, 1),
                'redis': self.counters['redis_hits'] / max(total_requests, 1),
                'overall': (self.counters['l1_hits'] + self.counters['redis_hits']) / max(total_requests, 1)
            },
            'error_rate': self.counters['errors'] / max(total_requests, 1),
            'timeout_rate': self.counters['timeouts'] / max(total_requests, 1),
            'latency': {}
        }
        
        # レイテンシ統計
        for op, latencies in self.latencies.items():
            if latencies:
                stats['latency'][op] = {
                    'p50': np.percentile(latencies, 50),
                    'p95': np.percentile(latencies, 95),
                    'p99': np.percentile(latencies, 99),
                    'avg': np.mean(latencies)
                }
        
        return stats

# モニタリング設定
class SessionStoreMonitoring:
    """モニタリングとアラート"""
    
    def __init__(self, session_store: DistributedSessionStore):
        self.store = session_store
        self.thresholds = {
            'latency_p99_ms': 10,
            'error_rate': 0.001,
            'hit_rate_min': 0.95
        }
    
    async def health_check(self):
        """ヘルスチェック"""
        
        try:
            # テストセッション作成
            test_id = f"health_check_{int(time.time())}"
            test_data = {'health': 'check', 'timestamp': time.time()}
            
            # 書き込みテスト
            write_success = await self.store.set_session(test_id, test_data, ttl=60)
            if not write_success:
                return {'status': 'unhealthy', 'reason': 'write_failed'}
            
            # 読み取りテスト
            read_data = await self.store.get_session(test_id)
            if not read_data:
                return {'status': 'unhealthy', 'reason': 'read_failed'}
            
            # メトリクスチェック
            stats = self.store.metrics.get_stats()
            
            if stats['latency']['get']['p99'] > self.thresholds['latency_p99_ms']:
                return {'status': 'degraded', 'reason': 'high_latency'}
            
            if stats['error_rate'] > self.thresholds['error_rate']:
                return {'status': 'degraded', 'reason': 'high_error_rate'}
            
            return {'status': 'healthy', 'metrics': stats}
            
        except Exception as e:
            return {'status': 'unhealthy', 'reason': str(e)}
```

## 問題4：セッション移行計画

### ダウンタイムゼロの移行計画

```python
class SessionMigrationPlan:
    """サーバーローカルから分散セッションストアへの移行"""
    
    def __init__(self):
        self.phases = []
        self.rollback_procedures = []
        self.validation_tests = []
    
    def create_migration_plan(self):
        """完全な移行計画の作成"""
        
        return {
            'phase_0_preparation': {
                'duration': '2 weeks',
                'tasks': [
                    {
                        'task': 'インフラ準備',
                        'details': [
                            'Redisクラスターのセットアップ（3マスター、3レプリカ）',
                            'Sentinelの設定（自動フェイルオーバー）',
                            'バックアップシステムの構築',
                            'モニタリングダッシュボードの作成'
                        ]
                    },
                    {
                        'task': 'アプリケーション改修',
                        'details': [
                            'デュアルセッションマネージャーの実装',
                            'フィーチャーフラグの実装',
                            'メトリクス収集の実装'
                        ]
                    },
                    {
                        'task': 'テスト環境構築',
                        'details': [
                            '本番同等の負荷テスト環境',
                            'カオスエンジニアリングツール',
                            '移行スクリプトのテスト'
                        ]
                    }
                ],
                'deliverables': [
                    'インフラ構築完了',
                    'アプリケーションのリリース準備',
                    'テスト計画書'
                ]
            },
            
            'phase_1_shadow_mode': {
                'duration': '1 week',
                'description': 'リードはローカル、ライトは両方',
                'implementation': self._implement_shadow_mode(),
                'monitoring': [
                    'レイテンシ比較',
                    'エラー率',
                    '一貫性チェック'
                ],
                'rollback': '設定変更のみでローカルのみに戻る'
            },
            
            'phase_2_dual_write_read': {
                'duration': '1 week',
                'description': '書き込みは両方、読み取りも両方で検証',
                'implementation': self._implement_dual_mode(),
                'validation': [
                    'データ一貫性の確認',
                    'パフォーマンス劣化なし',
                    'エラー率 < 0.01%'
                ],
                'rollback': '読み取りをローカルのみに変更'
            },
            
            'phase_3_gradual_migration': {
                'duration': '2 weeks',
                'description': '段階的にトラフィックを移行',
                'stages': [
                    {'percentage': 10, 'duration': '2 days', 'target': '内部ユーザー'},
                    {'percentage': 25, 'duration': '2 days', 'target': '一般ユーザーの一部'},
                    {'percentage': 50, 'duration': '3 days', 'target': '半数のユーザー'},
                    {'percentage': 90, 'duration': '3 days', 'target': 'ほぼ全ユーザー'},
                    {'percentage': 100, 'duration': '4 days', 'target': '完全移行'}
                ],
                'monitoring': 'リアルタイムダッシュボード',
                'rollback': 'パーセンテージを前の値に戻す'
            },
            
            'phase_4_cleanup': {
                'duration': '1 week',
                'tasks': [
                    'ローカルセッションストアの無効化',
                    '不要なコードの削除',
                    'パフォーマンスチューニング',
                    'ドキュメント更新'
                ]
            }
        }
    
    def _implement_shadow_mode(self):
        """シャドーモードの実装"""
        
        class ShadowModeSessionManager:
            def __init__(self, local_store, distributed_store):
                self.local = local_store
                self.distributed = distributed_store
                self.metrics = MigrationMetrics()
            
            async def get_session(self, session_id: str):
                """ローカルから読み取り、分散にも書き込み"""
                
                # メインはローカル
                start = time.time()
                session = self.local.get_session(session_id)
                local_time = time.time() - start
                
                # 非同期で分散ストアにも書き込み（ベストエフォート）
                if session:
                    asyncio.create_task(
                        self._shadow_write(session_id, session)
                    )
                
                self.metrics.record_read('local', local_time, bool(session))
                return session
            
            async def set_session(self, session_id: str, data: dict):
                """両方に書き込み"""
                
                # ローカルに書き込み
                local_result = self.local.set_session(session_id, data)
                
                # 分散ストアにも書き込み（非同期）
                dist_task = asyncio.create_task(
                    self.distributed.set_session(session_id, data)
                )
                
                # ローカルの結果を優先
                return local_result
            
            async def _shadow_write(self, session_id: str, data: dict):
                """バックグラウンドでの書き込み"""
                try:
                    start = time.time()
                    await self.distributed.set_session(session_id, data)
                    elapsed = time.time() - start
                    self.metrics.record_shadow_write(elapsed, True)
                except Exception as e:
                    self.metrics.record_shadow_write(0, False)
                    logging.error(f"Shadow write failed: {e}")
        
        return ShadowModeSessionManager
    
    def _implement_dual_mode(self):
        """デュアルモードの実装"""
        
        class DualModeSessionManager:
            def __init__(self, local_store, distributed_store):
                self.local = local_store
                self.distributed = distributed_store
                self.consistency_checker = ConsistencyChecker()
            
            async def get_session(self, session_id: str):
                """両方から読み取って比較"""
                
                # 並列読み取り
                local_task = asyncio.create_task(
                    self.local.get_session(session_id)
                )
                dist_task = asyncio.create_task(
                    self.distributed.get_session(session_id)
                )
                
                local_data, dist_data = await asyncio.gather(
                    local_task, dist_task
                )
                
                # 一貫性チェック
                if not self.consistency_checker.check(local_data, dist_data):
                    self.consistency_checker.log_inconsistency(
                        session_id, local_data, dist_data
                    )
                
                # プライマリ（この段階ではまだローカル）を返す
                return local_data
            
            async def set_session(self, session_id: str, data: dict):
                """両方に書き込み、両方成功を確認"""
                
                # 並列書き込み
                results = await asyncio.gather(
                    self.local.set_session(session_id, data),
                    self.distributed.set_session(session_id, data),
                    return_exceptions=True
                )
                
                # 両方成功した場合のみ成功
                return all(
                    r is True for r in results 
                    if not isinstance(r, Exception)
                )
        
        return DualModeSessionManager
    
    def create_traffic_router(self):
        """トラフィック段階移行ルーター"""
        
        class TrafficRouter:
            def __init__(self, local_store, distributed_store):
                self.local = local_store
                self.distributed = distributed_store
                self.migration_percentage = 0
                
            def set_migration_percentage(self, percentage: int):
                """移行パーセンテージの設定"""
                self.migration_percentage = max(0, min(100, percentage))
                logging.info(f"Migration percentage set to {self.migration_percentage}%")
            
            async def get_session(self, session_id: str):
                """パーセンテージに基づいてルーティング"""
                
                # ユーザーIDのハッシュ値で一貫した振り分け
                use_distributed = self._should_use_distributed(session_id)
                
                if use_distributed:
                    return await self.distributed.get_session(session_id)
                else:
                    return await self.local.get_session(session_id)
            
            def _should_use_distributed(self, session_id: str) -> bool:
                """分散ストアを使用するか判定"""
                
                # セッションIDのハッシュ値を使用
                hash_value = int(hashlib.md5(session_id.encode()).hexdigest(), 16)
                threshold = (hash_value % 100)
                
                return threshold < self.migration_percentage
        
        return TrafficRouter
    
    def create_rollback_plan(self):
        """ロールバック計画"""
        
        return {
            'triggers': [
                'エラー率が1%を超過',
                'レイテンシが50ms を超過',
                'データ不整合の検出',
                '可用性が99.9%を下回る'
            ],
            
            'procedures': {
                'immediate': [
                    'フィーチャーフラグでローカルモードに切り替え',
                    'アラート通知',
                    'インシデント記録開始'
                ],
                
                'investigation': [
                    'エラーログの収集',
                    'メトリクスの分析',
                    '根本原因の特定'
                ],
                
                'recovery': [
                    '問題の修正',
                    'ステージング環境での検証',
                    '段階的な再移行'
                ]
            },
            
            'communication': [
                'ステークホルダーへの通知',
                'ユーザーへの影響説明（必要な場合）',
                'ポストモーテムの実施'
            ]
        }
```

## 問題5：セキュリティ監査

### セッション管理セキュリティ監査チェックリスト

```python
class SessionSecurityAudit:
    """セッション管理システムのセキュリティ監査"""
    
    def __init__(self):
        self.audit_categories = [
            'session_generation',
            'session_storage',
            'session_transmission',
            'session_validation',
            'session_termination'
        ]
    
    def create_audit_checklist(self):
        """包括的な監査チェックリスト"""
        
        return {
            'session_generation': {
                'checks': [
                    {
                        'id': 'SG-001',
                        'description': 'セッションIDは暗号学的に安全な乱数生成器を使用',
                        'test': self._test_session_randomness,
                        'severity': 'CRITICAL'
                    },
                    {
                        'id': 'SG-002',
                        'description': 'セッションIDは十分な長さ（128ビット以上）',
                        'test': self._test_session_length,
                        'severity': 'HIGH'
                    },
                    {
                        'id': 'SG-003',
                        'description': 'ログイン成功後に新しいセッションIDを生成',
                        'test': self._test_session_regeneration,
                        'severity': 'CRITICAL'
                    }
                ]
            },
            
            'session_storage': {
                'checks': [
                    {
                        'id': 'SS-001',
                        'description': 'セッションデータは暗号化して保存',
                        'test': self._test_session_encryption,
                        'severity': 'HIGH'
                    },
                    {
                        'id': 'SS-002',
                        'description': 'セッションストアへのアクセス制御',
                        'test': self._test_storage_access_control,
                        'severity': 'HIGH'
                    },
                    {
                        'id': 'SS-003',
                        'description': 'セッションデータのバックアップも暗号化',
                        'test': self._test_backup_encryption,
                        'severity': 'MEDIUM'
                    }
                ]
            },
            
            'session_transmission': {
                'checks': [
                    {
                        'id': 'ST-001',
                        'description': 'HTTPS必須（Secure属性設定）',
                        'test': self._test_secure_transmission,
                        'severity': 'CRITICAL'
                    },
                    {
                        'id': 'ST-002',
                        'description': 'HttpOnly属性の設定',
                        'test': self._test_httponly_flag,
                        'severity': 'HIGH'
                    },
                    {
                        'id': 'ST-003',
                        'description': 'SameSite属性の適切な設定',
                        'test': self._test_samesite_attribute,
                        'severity': 'HIGH'
                    }
                ]
            },
            
            'session_validation': {
                'checks': [
                    {
                        'id': 'SV-001',
                        'description': 'タイムアウトの実装（アイドル・絶対）',
                        'test': self._test_timeout_implementation,
                        'severity': 'HIGH'
                    },
                    {
                        'id': 'SV-002',
                        'description': 'IPアドレス変更の検出',
                        'test': self._test_ip_validation,
                        'severity': 'MEDIUM'
                    },
                    {
                        'id': 'SV-003',
                        'description': 'User-Agent変更の検出',
                        'test': self._test_useragent_validation,
                        'severity': 'MEDIUM'
                    },
                    {
                        'id': 'SV-004',
                        'description': '並行セッション数の制限',
                        'test': self._test_concurrent_session_limit,
                        'severity': 'MEDIUM'
                    }
                ]
            },
            
            'session_termination': {
                'checks': [
                    {
                        'id': 'SE-001',
                        'description': 'ログアウト時の完全なセッション無効化',
                        'test': self._test_logout_completeness,
                        'severity': 'HIGH'
                    },
                    {
                        'id': 'SE-002',
                        'description': 'サーバー側セッションデータの削除',
                        'test': self._test_server_side_cleanup,
                        'severity': 'HIGH'
                    },
                    {
                        'id': 'SE-003',
                        'description': 'ブラウザ側Cookieのクリア',
                        'test': self._test_cookie_cleanup,
                        'severity': 'MEDIUM'
                    }
                ]
            }
        }
    
    def _test_session_randomness(self, session_manager):
        """セッションIDのランダム性テスト"""
        
        # 1000個のセッションIDを生成
        session_ids = []
        for _ in range(1000):
            sid = session_manager._generate_session_id()
            session_ids.append(sid)
        
        # 重複チェック
        if len(set(session_ids)) != len(session_ids):
            return False, "Duplicate session IDs detected"
        
        # エントロピー計算
        import math
        
        # 文字の分布を確認
        char_count = {}
        for sid in session_ids:
            for char in sid:
                char_count[char] = char_count.get(char, 0) + 1
        
        total_chars = sum(char_count.values())
        entropy = 0
        
        for count in char_count.values():
            if count > 0:
                probability = count / total_chars
                entropy -= probability * math.log2(probability)
        
        # 高いエントロピーを期待（理想は文字種類数の対数）
        expected_entropy = math.log2(len(char_count))
        
        if entropy < expected_entropy * 0.95:
            return False, f"Low entropy: {entropy:.2f} (expected: {expected_entropy:.2f})"
        
        return True, "Good randomness"
    
    def _test_session_fixation(self, test_client):
        """セッション固定攻撃のテスト"""
        
        # 1. 攻撃者がセッションIDを取得
        attacker_session = test_client.get('/').cookies.get('session_id')
        
        # 2. 被害者に同じセッションIDを設定させる
        victim_client = test_client
        victim_client.set_cookie('session_id', attacker_session)
        
        # 3. 被害者がログイン
        login_response = victim_client.post('/login', data={
            'username': 'victim',
            'password': 'password'
        })
        
        # 4. セッションIDが変更されているか確認
        new_session_id = login_response.cookies.get('session_id')
        
        if new_session_id == attacker_session:
            return False, "Session fixation vulnerability detected"
        
        return True, "Protected against session fixation"
    
    def perform_penetration_tests(self):
        """ペネトレーションテスト"""
        
        tests = [
            {
                'name': 'Session Hijacking',
                'description': '別のIPからのセッション使用',
                'test': self._test_session_hijacking
            },
            {
                'name': 'Session Fixation',
                'description': 'セッションID固定攻撃',
                'test': self._test_session_fixation
            },
            {
                'name': 'CSRF Attack',
                'description': 'クロスサイトリクエストフォージェリ',
                'test': self._test_csrf_protection
            },
            {
                'name': 'Cookie Injection',
                'description': 'Cookie値の改ざん',
                'test': self._test_cookie_injection
            },
            {
                'name': 'Timing Attack',
                'description': 'タイミング攻撃',
                'test': self._test_timing_attack
            }
        ]
        
        return tests
    
    def generate_audit_report(self, results):
        """監査レポートの生成"""
        
        report = {
            'audit_date': datetime.now().isoformat(),
            'summary': {
                'total_checks': 0,
                'passed': 0,
                'failed': 0,
                'critical_issues': 0
            },
            'detailed_results': {},
            'recommendations': []
        }
        
        # 結果の集計
        for category, checks in results.items():
            report['detailed_results'][category] = []
            
            for check in checks:
                report['total_checks'] += 1
                
                if check['result']:
                    report['passed'] += 1
                else:
                    report['failed'] += 1
                    
                    if check['severity'] == 'CRITICAL':
                        report['critical_issues'] += 1
                
                report['detailed_results'][category].append(check)
        
        # 推奨事項の生成
        if report['critical_issues'] > 0:
            report['recommendations'].append({
                'priority': 'IMMEDIATE',
                'action': 'Critical security issues must be fixed immediately'
            })
        
        return report
```

## チャレンジ問題：マイクロサービスでのセッション管理

### マイクロサービス対応セッション管理システム

```python
import jwt
import json
from typing import Dict, Optional, List
import asyncio
import aiohttp

class MicroserviceSessionManager:
    """マイクロサービスアーキテクチャ向けセッション管理"""
    
    def __init__(self):
        self.config = {
            'auth_service_url': 'http://auth-service:8000',
            'session_service_url': 'http://session-service:8001',
            'token_issuer': 'auth.example.com',
            'token_audience': ['api.example.com'],
            'public_key_cache_ttl': 3600
        }
        self.public_keys = {}
        self.service_mesh = ServiceMeshIntegration()
    
    async def create_distributed_session(self, user_id: str, 
                                       auth_context: Dict) -> Dict:
        """分散セッションの作成"""
        
        # 1. 認証サービスでトークン生成
        auth_token = await self._request_auth_token(user_id, auth_context)
        
        # 2. セッションサービスでセッション作成
        session_data = await self._create_session_data(user_id, auth_token)
        
        # 3. 各マイクロサービスへの伝播設定
        await self._propagate_session_context(session_data)
        
        return {
            'access_token': auth_token['access_token'],
            'refresh_token': auth_token['refresh_token'],
            'session_id': session_data['session_id'],
            'expires_in': auth_token['expires_in']
        }
    
    async def validate_service_request(self, request_headers: Dict) -> Optional[Dict]:
        """サービス間リクエストの検証"""
        
        # 1. トークンの抽出
        token = self._extract_token(request_headers)
        if not token:
            return None
        
        # 2. トークンの検証
        try:
            # 公開鍵の取得（キャッシュ付き）
            public_key = await self._get_public_key(token)
            
            # JWT検証
            payload = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                audience=self.config['token_audience'],
                issuer=self.config['token_issuer']
            )
            
            # 3. セッション情報の取得
            session_info = await self._get_session_info(payload['session_id'])
            
            # 4. コンテキストの構築
            return {
                'user_id': payload['sub'],
                'session_id': payload['session_id'],
                'permissions': payload.get('permissions', []),
                'service_context': session_info.get('context', {}),
                'trace_id': request_headers.get('X-Trace-ID')
            }
            
        except jwt.InvalidTokenError as e:
            logging.error(f"Token validation failed: {e}")
            return None
    
    def implement_service_mesh_integration(self):
        """サービスメッシュ統合"""
        
        class ServiceMeshIntegration:
            def __init__(self):
                self.envoy_config = self._generate_envoy_config()
                self.istio_policies = self._generate_istio_policies()
            
            def _generate_envoy_config(self):
                """Envoyプロキシ設定"""
                
                return {
                    'static_resources': {
                        'listeners': [{
                            'name': 'service_listener',
                            'address': {
                                'socket_address': {
                                    'address': '0.0.0.0',
                                    'port_value': 8080
                                }
                            },
                            'filter_chains': [{
                                'filters': [{
                                    'name': 'envoy.filters.network.http_connection_manager',
                                    'typed_config': {
                                        'http_filters': [
                                            {
                                                'name': 'envoy.filters.http.jwt_authn',
                                                'typed_config': {
                                                    'providers': {
                                                        'auth_service': {
                                                            'issuer': 'auth.example.com',
                                                            'remote_jwks': {
                                                                'http_uri': {
                                                                    'uri': 'http://auth-service:8000/.well-known/jwks.json'
                                                                }
                                                            }
                                                        }
                                                    },
                                                    'rules': [{
                                                        'match': {'prefix': '/'},
                                                        'requires': {'provider_name': 'auth_service'}
                                                    }]
                                                }
                                            }
                                        ]
                                    }
                                }]
                            }]
                        }]
                    }
                }
            
            def _generate_istio_policies(self):
                """Istio認証ポリシー"""
                
                return {
                    'apiVersion': 'security.istio.io/v1beta1',
                    'kind': 'PeerAuthentication',
                    'metadata': {
                        'name': 'default',
                        'namespace': 'production'
                    },
                    'spec': {
                        'mtls': {
                            'mode': 'STRICT'
                        }
                    }
                }
        
        return ServiceMeshIntegration()
    
    async def implement_session_sharing(self):
        """サービス間セッション共有"""
        
        class SessionSharingStrategy:
            def __init__(self):
                self.strategies = {
                    'redis_backed': self._redis_strategy,
                    'token_propagation': self._token_strategy,
                    'sidecar_cache': self._sidecar_strategy
                }
            
            async def _redis_strategy(self):
                """Redis バックエンドストラテジー"""
                
                return {
                    'implementation': '''
                    # 各サービスがRedisを参照
                    class RedisSessionStore:
                        async def get_session(self, session_id):
                            return await self.redis.get(f"session:{session_id}")
                        
                        async def set_session(self, session_id, data):
                            return await self.redis.setex(
                                f"session:{session_id}", 
                                3600, 
                                json.dumps(data)
                            )
                    ''',
                    'pros': ['シンプル', '一貫性が高い'],
                    'cons': ['単一障害点', 'レイテンシ']
                }
            
            async def _token_strategy(self):
                """トークン伝播ストラテジー"""
                
                return {
                    'implementation': '''
                    # JWTトークンにセッション情報を含める
                    class TokenPropagation:
                        def create_service_token(self, session_data):
                            return jwt.encode({
                                'session_id': session_data['id'],
                                'user_id': session_data['user_id'],
                                'permissions': session_data['permissions'],
                                'exp': time.time() + 300  # 5分
                            }, self.private_key, algorithm='RS256')
                    ''',
                    'pros': ['ステートレス', 'スケーラブル'],
                    'cons': ['トークンサイズ', '更新の伝播が困難']
                }
            
            async def _sidecar_strategy(self):
                """サイドカーキャッシュストラテジー"""
                
                return {
                    'implementation': '''
                    # 各Podにサイドカーコンテナでキャッシュ
                    class SidecarCache:
                        def __init__(self):
                            self.local_cache = TTLCache(maxsize=1000, ttl=60)
                            self.upstream = SessionService()
                        
                        async def get_session(self, session_id):
                            # L1: ローカルキャッシュ
                            if session_id in self.local_cache:
                                return self.local_cache[session_id]
                            
                            # L2: アップストリーム
                            session = await self.upstream.get_session(session_id)
                            self.local_cache[session_id] = session
                            return session
                    ''',
                    'pros': ['低レイテンシ', '障害耐性'],
                    'cons': ['一貫性の課題', 'リソース使用']
                }
        
        return SessionSharingStrategy()
    
    def create_observability_setup(self):
        """オブザーバビリティ設定"""
        
        return {
            'tracing': {
                'implementation': 'OpenTelemetry',
                'config': {
                    'service_name': 'session-manager',
                    'traces_endpoint': 'http://jaeger:4318/v1/traces',
                    'propagators': ['tracecontext', 'baggage']
                },
                'instrumentation': '''
                from opentelemetry import trace
                
                tracer = trace.get_tracer(__name__)
                
                @tracer.start_as_current_span("validate_session")
                async def validate_session(session_id):
                    span = trace.get_current_span()
                    span.set_attribute("session.id", session_id)
                    # ... validation logic ...
                '''
            },
            
            'metrics': {
                'implementation': 'Prometheus',
                'key_metrics': [
                    {
                        'name': 'session_validation_duration',
                        'type': 'Histogram',
                        'labels': ['service', 'method', 'status']
                    },
                    {
                        'name': 'active_sessions',
                        'type': 'Gauge',
                        'labels': ['service']
                    },
                    {
                        'name': 'session_errors_total',
                        'type': 'Counter',
                        'labels': ['service', 'error_type']
                    }
                ]
            },
            
            'logging': {
                'format': 'JSON',
                'correlation': 'trace_id',
                'example': {
                    'timestamp': '2024-01-15T10:30:45Z',
                    'level': 'INFO',
                    'service': 'session-manager',
                    'trace_id': '1234567890abcdef',
                    'span_id': 'abcdef123456',
                    'message': 'Session validated',
                    'session_id': 'sess_abc123',
                    'user_id': 'user_123',
                    'duration_ms': 5.2
                }
            }
        }
    
    def handle_failure_scenarios(self):
        """障害シナリオの処理"""
        
        return {
            'auth_service_down': {
                'detection': 'Circuit breaker opens after 5 consecutive failures',
                'fallback': 'Use cached public keys for token validation',
                'recovery': 'Gradual recovery with exponential backoff'
            },
            
            'session_store_unavailable': {
                'detection': 'Health check failures',
                'fallback': 'Degrade to stateless token-only auth',
                'alert': 'PagerDuty high priority'
            },
            
            'network_partition': {
                'detection': 'Split-brain detection via gossip protocol',
                'handling': 'Continue with local partition data',
                'reconciliation': 'CRDT-based merge on recovery'
            },
            
            'token_expiry_during_request': {
                'detection': 'Mid-request token validation failure',
                'handling': 'Complete current request with grace period',
                'client_notification': 'Include refresh hint in response'
            }
        }
```

これで第4章の演習問題解答が完了しました。各解答では実践的な実装例を提供し、なぜそのような実装が必要なのか、どのような脅威に対する対策なのかを明確にしています。