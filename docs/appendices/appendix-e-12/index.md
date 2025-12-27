---
layout: book
order: 31
title: "付録E-12: 第12章演習問題解答"
---
# 付録E-12: 第12章演習問題解答

## 問題1：ボトルネック分析

### 解答

**分析結果**：

1. **異常な処理時間**：
   - Permission loading (230ms) - 最大のボトルネック
   - User query (120ms) - 過度に遅い
   - Session creation (85ms) - 改善余地あり

2. **セキュリティ上の問題**：
   - MD5ハッシュ (15ms) - 脆弱で高速すぎる

**改善策**：

```python
class OptimizedAuthService:
    async def authenticate(self, username, password):
        # 1. コネクションプーリングの活用
        async with self.db_pool.acquire() as conn:
            # 2. 効率的なクエリ（JOINで1回のクエリに）
            user_with_permissions = await conn.fetchone("""
                SELECT u.*, array_agg(p.permission) as permissions
                FROM users u
                LEFT JOIN user_permissions up ON u.id = up.user_id
                LEFT JOIN permissions p ON up.permission_id = p.id
                WHERE u.username = $1
                GROUP BY u.id
            """, username)
            
        # 3. bcryptへの移行（セキュリティ強化）
        if not await self.verify_password_async(
            password, user_with_permissions['password_hash']
        ):
            raise AuthenticationError()
        
        # 4. 非同期セッション作成
        session_task = self.create_session_async(user_with_permissions)
        
        # 5. 権限情報はすでに取得済み
        permissions = user_with_permissions['permissions']
        
        session = await session_task
        
        return session, permissions
```

**期待される改善**：
- Total: 495ms → 150ms以下
- 並列処理により、全体的な処理時間を削減
- セキュリティの向上（MD5→bcrypt）

## 問題2：キャッシュ戦略の設計

### 解答

**キャッシュアーキテクチャ**：

```python
class CacheStrategy:
    def __init__(self):
        # L1: ローカルメモリキャッシュ
        self.l1_config = {
            'user_basic': {'ttl': 60, 'max_size': 10000},
            'session': {'ttl': 300, 'max_size': 50000}
        }
        
        # L2: Redis クラスター
        self.l2_config = {
            'user_permissions': {'ttl': 3600},  # 1時間
            'user_profile': {'ttl': 1800},      # 30分
            'session_data': {'ttl': 1800},      # 30分
            'role_definitions': {'ttl': 86400}   # 24時間
        }
    
    def get_cache_key(self, data_type, identifier):
        """キャッシュキーの生成"""
        version = self.get_cache_version(data_type)
        return f"{data_type}:v{version}:{identifier}"
    
    def invalidation_strategy(self):
        """キャッシュ無効化戦略"""
        return {
            'user_update': [
                'user_basic:*',
                'user_permissions:*',
                'user_profile:*'
            ],
            'permission_change': [
                'user_permissions:*',
                'role_definitions:*'
            ],
            'session_logout': [
                'session:*',
                'session_data:*'
            ]
        }
```

**実装設計**：

```yaml
# Redis Cluster構成
redis_cluster:
  nodes: 6  # 3マスター、3スレーブ
  replication_factor: 1
  eviction_policy: allkeys-lru
  maxmemory: 8gb
  
# キャッシュウォーミング戦略
cache_warming:
  - target: active_users
    schedule: "*/15 * * * *"  # 15分ごと
    query: |
      SELECT u.id, u.username, array_agg(p.permission) as permissions
      FROM users u
      JOIN user_permissions up ON u.id = up.user_id
      JOIN permissions p ON up.permission_id = p.id
      WHERE u.last_login > NOW() - INTERVAL '1 hour'
      GROUP BY u.id
```

## 問題3：負荷試験シナリオ

### 解答

**テストシナリオ**：

```python
# シナリオ1: 通常ログインパターン
class NormalLoginScenario:
    """朝の出社時を想定したログインラッシュ"""
    config = {
        'duration': '30m',
        'users': 10000,
        'ramp_up': '5m',
        'pattern': 'gradual'
    }
    
    async def execute(self, user):
        # 1. ログイン
        token = await self.login(user.username, user.password)
        await asyncio.sleep(random.uniform(1, 3))
        
        # 2. プロフィール取得（認証必要）
        profile = await self.get_profile(token)
        await asyncio.sleep(random.uniform(2, 5))
        
        # 3. 作業（トークン更新含む）
        for _ in range(random.randint(5, 15)):
            await self.do_work(token)
            await asyncio.sleep(random.uniform(10, 30))
        
        # 4. ログアウト
        await self.logout(token)

# シナリオ2: トークンリフレッシュ集中
class TokenRefreshScenario:
    """トークン有効期限付近での更新集中"""
    config = {
        'duration': '15m',
        'users': 50000,
        'token_lifetime': '5m',
        'refresh_window': '30s'
    }
    
    async def execute(self, user):
        token = await self.login(user.username, user.password)
        
        # トークン有効期限まで待機
        await asyncio.sleep(270)  # 4.5分
        
        # 同時リフレッシュ
        new_token = await self.refresh_token(token)

# シナリオ3: 異常系混在
class MixedErrorScenario:
    """正常系と異常系の混在"""
    config = {
        'duration': '20m',
        'users': 5000,
        'error_rate': 0.3
    }
    
    async def execute(self, user):
        if random.random() < 0.3:
            # 異常系：間違ったパスワード
            try:
                await self.login(user.username, "wrong_password")
            except AuthenticationError:
                pass
        else:
            # 正常系
            token = await self.login(user.username, user.password)
            await self.get_profile(token)
```

**測定メトリクス**：

```yaml
metrics:
  performance:
    - response_time_p50
    - response_time_p95
    - response_time_p99
    - requests_per_second
    - concurrent_users
    
  reliability:
    - error_rate
    - timeout_rate
    - success_rate_by_endpoint
    
  resource:
    - cpu_usage_api
    - memory_usage_api
    - db_connections_active
    - db_query_time
    - cache_hit_rate
    
  business:
    - login_success_rate
    - average_session_duration
    - token_refresh_success_rate

performance_criteria:
  response_time_p95: < 500ms
  response_time_p99: < 1000ms
  error_rate: < 0.1%
  cpu_usage: < 80%
  cache_hit_rate: > 90%
```

## 問題4：モニタリング実装

### 解答

```python
import time
import logging
from prometheus_client import Counter, Histogram, Gauge
from opentelemetry import trace
from functools import wraps

# メトリクス定義
auth_requests = Counter(
    'auth_requests_total', 
    'Total authentication requests',
    ['status', 'error_type']
)

auth_duration = Histogram(
    'auth_duration_seconds',
    'Authentication request duration',
    ['operation'],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
)

active_sessions = Gauge(
    'active_sessions',
    'Number of active sessions'
)

cache_operations = Counter(
    'cache_operations_total',
    'Cache operations',
    ['operation', 'result']
)

# トレーサー設定
tracer = trace.get_tracer(__name__)

# デコレーターヘルパー
def monitor_operation(operation_name):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            with tracer.start_as_current_span(operation_name) as span:
                start_time = time.time()
                try:
                    result = await func(*args, **kwargs)
                    auth_duration.labels(operation=operation_name).observe(
                        time.time() - start_time
                    )
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(trace.Status(trace.StatusCode.ERROR))
                    raise
        return wrapper
    return decorator

class MonitoredAuthenticationService:
    def __init__(self):
        self.db = DatabaseConnection()
        self.cache = RedisCache()
        self.logger = logging.getLogger(__name__)
    
    async def authenticate(self, username, password):
        with tracer.start_as_current_span("authenticate") as span:
            span.set_attribute("user.username", username)
            start_time = time.time()
            
            try:
                # ユーザー取得（キャッシュチェック付き）
                user = await self._get_user_with_cache(username)
                
                # パスワード検証
                if not await self._verify_password(password, user.password_hash):
                    auth_requests.labels(
                        status='failure',
                        error_type='invalid_password'
                    ).inc()
                    raise InvalidPasswordError()
                
                # セッション作成
                session = await self._create_session(user)
                
                # 成功メトリクス
                auth_requests.labels(
                    status='success',
                    error_type='none'
                ).inc()
                
                auth_duration.labels(operation='authenticate').observe(
                    time.time() - start_time
                )
                
                self.logger.info(
                    f"Authentication successful",
                    extra={
                        'user_id': user.id,
                        'duration': time.time() - start_time,
                        'method': 'password'
                    }
                )
                
                return session
                
            except UserNotFoundError:
                auth_requests.labels(
                    status='failure',
                    error_type='user_not_found'
                ).inc()
                span.set_attribute("error.type", "user_not_found")
                raise
                
            except Exception as e:
                auth_requests.labels(
                    status='error',
                    error_type=type(e).__name__
                ).inc()
                span.record_exception(e)
                self.logger.error(
                    f"Authentication error: {str(e)}",
                    exc_info=True,
                    extra={'username': username}
                )
                raise
    
    @monitor_operation("get_user")
    async def _get_user_with_cache(self, username):
        # キャッシュチェック
        cache_key = f"user:{username}"
        cached_user = await self.cache.get(cache_key)
        
        if cached_user:
            cache_operations.labels(
                operation='get',
                result='hit'
            ).inc()
            return cached_user
        
        cache_operations.labels(
            operation='get',
            result='miss'
        ).inc()
        
        # DBから取得
        user = await self.db.get_user(username)
        if not user:
            raise UserNotFoundError()
        
        # キャッシュに保存
        await self.cache.set(cache_key, user, ttl=300)
        cache_operations.labels(
            operation='set',
            result='success'
        ).inc()
        
        return user
    
    @monitor_operation("verify_password")
    async def _verify_password(self, password, password_hash):
        return await verify_password(password, password_hash)
    
    @monitor_operation("create_session")
    async def _create_session(self, user):
        session = create_session(user)
        await self.cache.set(
            f"session:{session.id}",
            session,
            ttl=1800
        )
        active_sessions.inc()
        return session
```

## 問題5：スケーラビリティ改善

### 解答

**問題点**：
1. 単一障害点（SPOF）: 認証API、DB、Redisがすべて単一インスタンス
2. ボトルネック: 認証APIのCPU使用率80%は限界に近い
3. レスポンス時間: 800msは過度に遅い
4. 将来の負荷（6倍）に対応不可能

**改善アーキテクチャ**：

```yaml
# 改善後のアーキテクチャ
architecture:
  load_balancer:
    type: "Application Load Balancer"
    health_check: "/health"
    
  web_tier:
    instances: 6  # 倍増
    auto_scaling:
      min: 6
      max: 20
      target_cpu: 60%
      
  auth_api_tier:
    instances: 4  # 水平スケーリング
    deployment: "Blue-Green"
    auto_scaling:
      min: 4
      max: 12
      target_cpu: 50%
      
  database:
    primary:
      type: "PostgreSQL 14"
      instance_type: "db.r6g.2xlarge"
    read_replicas: 2
    connection_pooling:
      pgbouncer:
        pool_mode: "transaction"
        max_connections: 1000
        
  cache:
    redis_cluster:
      nodes: 6  # 3マスター、3レプリカ
      instance_type: "cache.r6g.large"
      
  additional_components:
    - api_gateway:  # 認証の前段処理
        rate_limiting: true
        caching: true
    - cdn:  # 静的コンテンツ配信
        provider: "CloudFront"
```

**実装の改善点**：

```python
class ScalableAuthArchitecture:
    def __init__(self):
        # コネクションプール（読み書き分離）
        self.db_write = create_pool(master_db_url, max_size=50)
        self.db_read = create_pool(replica_db_urls, max_size=100)
        
        # Redis Cluster
        self.redis = RedisCluster(
            startup_nodes=redis_nodes,
            decode_responses=False,
            skip_full_coverage_check=True
        )
        
        # 非同期ワーカープール
        self.worker_pool = ThreadPoolExecutor(max_workers=10)
    
    async def authenticate(self, username, password):
        # 読み取り専用クエリはレプリカへ
        async with self.db_read.acquire() as conn:
            user = await conn.fetchone(
                "SELECT * FROM users WHERE username = $1",
                username
            )
        
        # CPU集約的な処理は別スレッドで
        loop = asyncio.get_event_loop()
        is_valid = await loop.run_in_executor(
            self.worker_pool,
            verify_password,
            password,
            user['password_hash']
        )
        
        if is_valid:
            # 書き込みはマスターへ
            async with self.db_write.acquire() as conn:
                await conn.execute(
                    "UPDATE users SET last_login = NOW() WHERE id = $1",
                    user['id']
                )
            
            return await self.create_session(user)
```

## チャレンジ問題：サーキットブレーカーの実装

### 解答

```python
import asyncio
import time
from collections import deque
from enum import Enum
from threading import Lock
import logging

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreakerMetrics:
    def __init__(self):
        self.total_calls = 0
        self.success_calls = 0
        self.failed_calls = 0
        self.rejected_calls = 0
        self.state_changes = []
        
    def to_dict(self):
        return {
            'total_calls': self.total_calls,
            'success_calls': self.success_calls,
            'failed_calls': self.failed_calls,
            'rejected_calls': self.rejected_calls,
            'success_rate': self.success_calls / max(1, self.total_calls),
            'state_changes': self.state_changes[-10:]  # 最新10件
        }

class AdvancedCircuitBreaker:
    def __init__(self, 
                 failure_rate_threshold=0.5,
                 window_size=60,
                 half_open_requests=3,
                 min_calls_in_window=10,
                 recovery_timeout=30):
        
        self.failure_rate_threshold = failure_rate_threshold
        self.window_size = window_size
        self.half_open_requests = half_open_requests
        self.min_calls_in_window = min_calls_in_window
        self.recovery_timeout = recovery_timeout
        
        # 状態管理
        self.state = CircuitState.CLOSED
        self.state_lock = Lock()
        
        # 統計情報（時間窓）
        self.calls = deque()  # (timestamp, success)のタプル
        self.calls_lock = Lock()
        
        # 半開状態の管理
        self.half_open_count = 0
        self.half_open_successes = 0
        
        # 最後の状態変更時刻
        self.last_state_change = time.time()
        self.last_failure_time = None
        
        # メトリクス
        self.metrics = CircuitBreakerMetrics()
        self.logger = logging.getLogger(__name__)
    
    def _clean_window(self):
        """古いエントリを削除"""
        current_time = time.time()
        cutoff_time = current_time - self.window_size
        
        with self.calls_lock:
            while self.calls and self.calls[0][0] < cutoff_time:
                self.calls.popleft()
    
    def _calculate_failure_rate(self):
        """現在の失敗率を計算"""
        self._clean_window()
        
        if len(self.calls) < self.min_calls_in_window:
            return 0.0
        
        failures = sum(1 for _, success in self.calls if not success)
        return failures / len(self.calls)
    
    def _should_attempt_reset(self):
        """リセット試行のタイミングチェック"""
        return (
            self.state == CircuitState.OPEN and
            self.last_failure_time and
            time.time() - self.last_failure_time >= self.recovery_timeout
        )
    
    def _record_call(self, success):
        """呼び出し結果を記録"""
        with self.calls_lock:
            self.calls.append((time.time(), success))
        
        # メトリクス更新
        self.metrics.total_calls += 1
        if success:
            self.metrics.success_calls += 1
        else:
            self.metrics.failed_calls += 1
    
    def _change_state(self, new_state):
        """状態変更とログ記録"""
        old_state = self.state
        self.state = new_state
        self.last_state_change = time.time()
        
        self.metrics.state_changes.append({
            'timestamp': self.last_state_change,
            'from': old_state.value,
            'to': new_state.value
        })
        
        self.logger.info(
            f"Circuit breaker state changed: {old_state.value} -> {new_state.value}"
        )
    
    async def call(self, func, *args, **kwargs):
        """サーキットブレーカー経由での関数呼び出し"""
        
        # 状態チェックと処理
        with self.state_lock:
            # OPEN状態のチェック
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._change_state(CircuitState.HALF_OPEN)
                    self.half_open_count = 0
                    self.half_open_successes = 0
                else:
                    self.metrics.rejected_calls += 1
                    raise Exception(
                        f"Circuit breaker is OPEN. "
                        f"Retry after {self.recovery_timeout}s"
                    )
            
            # HALF_OPEN状態のチェック
            elif self.state == CircuitState.HALF_OPEN:
                if self.half_open_count >= self.half_open_requests:
                    # 評価フェーズ
                    if self.half_open_successes == self.half_open_requests:
                        self._change_state(CircuitState.CLOSED)
                    else:
                        self._change_state(CircuitState.OPEN)
                        self.last_failure_time = time.time()
                        self.metrics.rejected_calls += 1
                        raise Exception("Circuit breaker is OPEN after test")
                
                self.half_open_count += 1
        
        # 実際の関数呼び出し
        try:
            # 非同期関数の場合
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                # 同期関数の場合は別スレッドで実行
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None, func, *args, **kwargs
                )
            
            # 成功の記録
            self._record_call(True)
            
            with self.state_lock:
                if self.state == CircuitState.HALF_OPEN:
                    self.half_open_successes += 1
            
            return result
            
        except Exception as e:
            # 失敗の記録
            self._record_call(False)
            self.last_failure_time = time.time()
            
            with self.state_lock:
                # CLOSED状態で失敗率チェック
                if self.state == CircuitState.CLOSED:
                    failure_rate = self._calculate_failure_rate()
                    if failure_rate >= self.failure_rate_threshold:
                        self._change_state(CircuitState.OPEN)
                
                # HALF_OPEN状態での失敗は即座にOPENへ
                elif self.state == CircuitState.HALF_OPEN:
                    self._change_state(CircuitState.OPEN)
            
            raise e
    
    def get_metrics(self):
        """メトリクスの取得"""
        self._clean_window()
        
        metrics = self.metrics.to_dict()
        metrics.update({
            'current_state': self.state.value,
            'failure_rate': self._calculate_failure_rate(),
            'calls_in_window': len(self.calls),
            'time_since_last_change': time.time() - self.last_state_change
        })
        
        return metrics
    
    def reset(self):
        """手動リセット（テスト用）"""
        with self.state_lock:
            self._change_state(CircuitState.CLOSED)
            self.calls.clear()
            self.half_open_count = 0
            self.half_open_successes = 0
            self.last_failure_time = None

# 使用例とテスト
async def test_circuit_breaker():
    # 失敗する関数
    call_count = 0
    
    async def flaky_service():
        nonlocal call_count
        call_count += 1
        if call_count <= 6:  # 最初の6回は失敗
            raise Exception("Service unavailable")
        return "Success"
    
    cb = AdvancedCircuitBreaker(
        failure_rate_threshold=0.5,
        window_size=60,
        half_open_requests=3,
        min_calls_in_window=5
    )
    
    # テスト実行
    for i in range(15):
        try:
            result = await cb.call(flaky_service)
            print(f"Call {i+1}: {result}")
        except Exception as e:
            print(f"Call {i+1}: Failed - {str(e)}")
        
        # メトリクス表示
        if i % 5 == 4:
            metrics = cb.get_metrics()
            print(f"Metrics: {metrics}")
        
        await asyncio.sleep(0.1)
```

この実装の特徴：
1. **スレッドセーフ**: Lockを使用した適切な同期
2. **効率的な統計計算**: dequeを使用した時間窓管理
3. **段階的回復**: 半開状態での慎重な回復プロセス
4. **包括的なメトリクス**: 詳細な統計情報の提供
5. **非同期対応**: async/awaitと同期関数の両方をサポート
