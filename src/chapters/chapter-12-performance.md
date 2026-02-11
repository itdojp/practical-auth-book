# 第12章 パフォーマンスとスケーラビリティ

## なぜこの章が重要か

認証認可システムは、アプリケーションへのすべてのアクセスの入り口となるため、そのパフォーマンスがシステム全体のユーザー体験を大きく左右します。1秒の認証遅延が、ビジネスに与える影響は計り知れません。この章では、認証認可システムのパフォーマンスボトルネックを特定し、スケーラブルなシステムを構築するための実践的な知識を習得します。

## 12.1 認証処理のボトルネック

### 12.1.1 ボトルネックが生まれる理由

認証処理は本質的に計算集約的な処理を含みます。なぜなら、セキュリティを確保するために意図的に計算コストを高くしているからです。

**主要なボトルネック要因**：

1. **パスワードハッシュ検証**
   ```python
   # bcryptの例：意図的に遅い処理
   import bcrypt
   
   # コスト係数12の場合、1回の検証に約250ms
   password = "user_password"
   hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12))
   
   # この検証処理がボトルネック
   bcrypt.checkpw(password.encode('utf-8'), hashed)  # 250ms
   ```

2. **データベースアクセス**
   ```sql
   -- 複数テーブルの結合を伴う認証クエリ
   SELECT u.*, r.permissions, s.session_data
   FROM users u
   LEFT JOIN user_roles ur ON u.id = ur.user_id
   LEFT JOIN roles r ON ur.role_id = r.id
   LEFT JOIN sessions s ON u.id = s.user_id
   WHERE u.email = ? AND u.active = true;
   ```

3. **暗号処理**
   - JWT署名の生成/検証
   - TLS/SSL通信のオーバーヘッド
   - 暗号化されたセッションデータの復号

### 12.1.2 ボトルネックの測定と分析

**測定アプローチ**：

```python
import time
import statistics
from contextlib import contextmanager

@contextmanager
def measure_time(operation_name):
    """処理時間を測定するコンテキストマネージャー"""
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        print(f"{operation_name}: {elapsed*1000:.2f}ms")

class AuthenticationProfiler:
    def __init__(self):
        self.metrics = {}
    
    def profile_authentication(self, username, password):
        with measure_time("Total Authentication"):
            # 1. ユーザー検索
            with measure_time("User Lookup"):
                user = self.find_user(username)
            
            # 2. パスワード検証
            with measure_time("Password Verification"):
                is_valid = self.verify_password(password, user.password_hash)
            
            # 3. セッション作成
            with measure_time("Session Creation"):
                session = self.create_session(user)
            
            # 4. 権限取得
            with measure_time("Permission Loading"):
                permissions = self.load_permissions(user)
            
            return session, permissions
```

**典型的な測定結果**：
```
User Lookup: 15.23ms
Password Verification: 251.45ms  # ボトルネック
Session Creation: 8.12ms
Permission Loading: 22.34ms
Total Authentication: 297.14ms
```

### 12.1.3 ボトルネック解消戦略

**1. 非同期処理の活用**
```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

class OptimizedAuthService:
    def __init__(self):
        # CPU集約的なタスク用のスレッドプール
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    async def authenticate(self, username, password):
        # 並列実行可能な処理を識別
        user_task = self.find_user_async(username)
        
        # ユーザー取得を待つ
        user = await user_task
        
        # パスワード検証は別スレッドで実行
        loop = asyncio.get_event_loop()
        is_valid = await loop.run_in_executor(
            self.executor,
            bcrypt.checkpw,
            password.encode('utf-8'),
            user.password_hash
        )
        
        if is_valid:
            # セッション作成と権限取得を並列実行
            session_task = self.create_session_async(user)
            permissions_task = self.load_permissions_async(user)
            
            session, permissions = await asyncio.gather(
                session_task, permissions_task
            )
            return session, permissions
        
        return None, None
```

**2. コネクションプーリング**
```python
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

# 適切なプールサイズの設定
engine = create_engine(
    'postgresql://user:pass@localhost/db',
    poolclass=QueuePool,
    pool_size=20,        # 常時接続数
    max_overflow=10,     # 追加接続数
    pool_timeout=30,     # タイムアウト
    pool_recycle=3600    # 接続リサイクル
)
```

## 12.2 キャッシング戦略

### 12.2.1 キャッシュすべきデータの識別

認証認可システムにおいて、キャッシュは劇的なパフォーマンス向上をもたらしますが、セキュリティとの適切なバランスが必要です。

**キャッシュ適性の評価基準**：

```python
class CacheabilityAnalyzer:
    @staticmethod
    def analyze(data_type):
        """データタイプのキャッシュ適性を分析"""
        cache_matrix = {
            # データタイプ: (読取頻度, 更新頻度, セキュリティリスク, 推奨TTL)
            "user_permissions": (HIGH, LOW, MEDIUM, 300),    # 5分
            "password_hash": (HIGH, VERY_LOW, HIGH, 0),      # キャッシュ不可
            "session_data": (VERY_HIGH, MEDIUM, HIGH, 60),   # 1分
            "role_definitions": (HIGH, VERY_LOW, LOW, 3600), # 1時間
            "jwt_public_keys": (HIGH, VERY_LOW, LOW, 86400), # 24時間
        }
        
        freq_read, freq_write, security_risk, ttl = cache_matrix.get(
            data_type, (LOW, HIGH, HIGH, 0)
        )
        
        # キャッシュ推奨度の計算
        cache_score = (freq_read * 3 - freq_write * 2 - security_risk * 4) / 10
        
        return {
            "cacheable": cache_score > 0,
            "ttl_seconds": ttl,
            "cache_score": cache_score
        }
```

### 12.2.2 多層キャッシュアーキテクチャ

**実装例**：

```python
import redis
from functools import lru_cache
import pickle

class MultiLayerCache:
    def __init__(self):
        # L1: プロセス内メモリキャッシュ
        self.l1_cache = {}
        
        # L2: Redis（共有キャッシュ）
        self.redis_client = redis.Redis(
            host='localhost',
            port=6379,
            decode_responses=False,
            connection_pool_kwargs={
                'max_connections': 50,
                'socket_keepalive': True
            }
        )
    
    async def get_with_cache(self, key, fetch_func, ttl=300):
        """多層キャッシュを使用したデータ取得"""
        
        # L1キャッシュチェック
        if key in self.l1_cache:
            entry = self.l1_cache[key]
            if time.time() < entry['expires']:
                return entry['value']
        
        # L2キャッシュチェック
        redis_value = self.redis_client.get(key)
        if redis_value:
            value = pickle.loads(redis_value)
            # L1キャッシュに昇格
            self.l1_cache[key] = {
                'value': value,
                'expires': time.time() + 60  # L1は短めのTTL
            }
            return value
        
        # キャッシュミス：データ取得
        value = await fetch_func()
        
        # 両層にキャッシュ
        self.redis_client.setex(key, ttl, pickle.dumps(value))
        self.l1_cache[key] = {
            'value': value,
            'expires': time.time() + 60
        }
        
        return value
```

### 12.2.3 キャッシュ無効化戦略

```python
class CacheInvalidationStrategy:
    def __init__(self, cache):
        self.cache = cache
        
    def invalidate_user_cache(self, user_id):
        """ユーザー関連のキャッシュを無効化"""
        patterns = [
            f"user:{user_id}:*",
            f"permissions:{user_id}",
            f"session:*:user:{user_id}"
        ]
        
        for pattern in patterns:
            # Redisのパターンマッチング削除
            for key in self.cache.redis_client.scan_iter(match=pattern):
                self.cache.redis_client.delete(key)
        
        # L1キャッシュからも削除
        keys_to_remove = [k for k in self.cache.l1_cache if user_id in k]
        for key in keys_to_remove:
            del self.cache.l1_cache[key]
    
    def setup_cache_invalidation_events(self):
        """イベント駆動型キャッシュ無効化"""
        # Redis Pub/Subを使用
        pubsub = self.cache.redis_client.pubsub()
        pubsub.subscribe('cache_invalidation')
        
        def handle_invalidation():
            for message in pubsub.listen():
                if message['type'] == 'message':
                    event = pickle.loads(message['data'])
                    if event['type'] == 'user_updated':
                        self.invalidate_user_cache(event['user_id'])
```

## 12.3 負荷分散と可用性

### 12.3.1 認証サービスの負荷分散設計

**マルチリージョン展開の実装**：

```python
class GeoDistributedAuthService:
    def __init__(self):
        self.regions = {
            'us-east': {'endpoint': 'auth-us-east.example.com', 'weight': 1.0},
            'eu-west': {'endpoint': 'auth-eu-west.example.com', 'weight': 1.0},
            'asia-pacific': {'endpoint': 'auth-ap.example.com', 'weight': 1.0}
        }
        
    def get_optimal_endpoint(self, client_ip):
        """クライアントIPに基づく最適なエンドポイント選択"""
        client_location = self.geoip_lookup(client_ip)
        
        # レイテンシベースのルーティング
        latencies = {}
        for region, config in self.regions.items():
            latency = self.estimate_latency(client_location, region)
            latencies[region] = latency
        
        # 最小レイテンシのリージョンを選択
        optimal_region = min(latencies, key=latencies.get)
        return self.regions[optimal_region]['endpoint']
```

### 12.3.2 セッションレプリケーション

```python
class DistributedSessionManager:
    def __init__(self):
        # Redis Clusterを使用
        self.redis_cluster = rediscluster.RedisCluster(
            startup_nodes=[
                {"host": "redis-1", "port": "7000"},
                {"host": "redis-2", "port": "7000"},
                {"host": "redis-3", "port": "7000"}
            ],
            decode_responses=False,
            skip_full_coverage_check=True
        )
    
    async def create_session(self, user_id, metadata):
        """分散環境でのセッション作成"""
        session_id = self.generate_session_id()
        session_data = {
            'user_id': user_id,
            'created_at': time.time(),
            'metadata': metadata,
            'last_accessed': time.time()
        }
        
        # プライマリ書き込み
        pipe = self.redis_cluster.pipeline()
        pipe.setex(
            f"session:{session_id}",
            3600,  # 1時間
            pickle.dumps(session_data)
        )
        
        # インデックスの更新
        pipe.sadd(f"user_sessions:{user_id}", session_id)
        pipe.execute()
        
        # 非同期レプリケーション確認
        asyncio.create_task(self.verify_replication(session_id))
        
        return session_id
```

### 12.3.3 サーキットブレーカーパターン

```python
import time
from enum import Enum

class CircuitState(Enum):
    CLOSED = 1  # 正常
    OPEN = 2    # 遮断
    HALF_OPEN = 3  # 回復試行

class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED
    
    async def call(self, func, *args, **kwargs):
        """サーキットブレーカー経由での関数呼び出し"""
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
            else:
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = await func(*args, **kwargs)
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
            return result
            
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN
                
            raise e

# 使用例
auth_circuit = CircuitBreaker(failure_threshold=5, recovery_timeout=60)

async def authenticate_with_circuit_breaker(username, password):
    return await auth_circuit.call(
        remote_auth_service.authenticate,
        username,
        password
    )
```

## 12.4 モニタリングとアラート

### 12.4.1 認証システム固有のメトリクス

**重要メトリクスの定義と収集**：

```python
import prometheus_client as prom

# メトリクスの定義
auth_attempts = prom.Counter(
    'auth_attempts_total',
    'Total authentication attempts',
    ['method', 'result']
)

auth_duration = prom.Histogram(
    'auth_duration_seconds',
    'Authentication duration in seconds',
    ['method'],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

active_sessions = prom.Gauge(
    'active_sessions_total',
    'Number of active sessions'
)

permission_cache_hits = prom.Counter(
    'permission_cache_hits_total',
    'Permission cache hit rate',
    ['cache_level']
)

class MonitoredAuthService:
    @auth_duration.labels(method='password').time()
    async def authenticate(self, username, password):
        try:
            result = await self._authenticate_internal(username, password)
            auth_attempts.labels(method='password', result='success').inc()
            return result
        except AuthenticationError:
            auth_attempts.labels(method='password', result='failure').inc()
            raise
        except Exception:
            auth_attempts.labels(method='password', result='error').inc()
            raise
```

### 12.4.2 アラート設定の実践

```yaml
# Prometheus アラートルール
groups:
  - name: authentication_alerts
    rules:
      # 認証成功率の低下
      - alert: HighAuthenticationFailureRate
        expr: |
          sum(rate(auth_attempts_total{result="failure"}[5m])) /
          sum(rate(auth_attempts_total[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate detected"
          description: "Authentication failure rate is {{ $value | humanizePercentage }}"
      
      # 認証遅延
      - alert: SlowAuthentication
        expr: |
          histogram_quantile(0.95, rate(auth_duration_seconds_bucket[5m])) > 1.0
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Authentication is slow"
          description: "95th percentile authentication time is {{ $value }}s"
      
      # セッション数の異常
      - alert: AbnormalSessionCount
        expr: |
          abs(delta(active_sessions_total[10m])) > 10000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Abnormal session count change"
          description: "Session count changed by {{ $value }} in 10 minutes"
```

### 12.4.3 分散トレーシングの実装

```python
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# トレーシングの設定
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

# OTLPエクスポーター設定
otlp_exporter = OTLPSpanExporter(
    endpoint="localhost:4317",
    insecure=True
)

span_processor = BatchSpanProcessor(otlp_exporter)
trace.get_tracer_provider().add_span_processor(span_processor)

class TracedAuthService:
    async def authenticate(self, username, password):
        with tracer.start_as_current_span("authentication") as span:
            span.set_attribute("auth.method", "password")
            span.set_attribute("user.username", username)
            
            # ユーザー検索のトレース
            with tracer.start_as_current_span("user_lookup"):
                user = await self.find_user(username)
            
            # パスワード検証のトレース
            with tracer.start_as_current_span("password_verification"):
                is_valid = await self.verify_password(password, user.password_hash)
            
            if is_valid:
                # セッション作成のトレース
                with tracer.start_as_current_span("session_creation"):
                    session = await self.create_session(user)
                
                span.set_attribute("auth.result", "success")
                return session
            else:
                span.set_attribute("auth.result", "failure")
                raise AuthenticationError()
```

### 12.4.4 ダッシュボードの構築

```python
# Grafanaダッシュボード用のクエリ例
dashboard_queries = {
    "authentication_rate": """
        sum(rate(auth_attempts_total[5m])) by (method)
    """,
    
    "success_rate": """
        sum(rate(auth_attempts_total{result="success"}[5m])) /
        sum(rate(auth_attempts_total[5m])) * 100
    """,
    
    "p95_latency": """
        histogram_quantile(0.95, 
            sum(rate(auth_duration_seconds_bucket[5m])) by (le, method)
        )
    """,
    
    "cache_hit_rate": """
        sum(rate(permission_cache_hits_total{cache_level="hit"}[5m])) /
        sum(rate(permission_cache_hits_total[5m])) * 100
    """,
    
    "active_users": """
        count(count by (user_id) (active_sessions_total))
    """
}
```

## まとめ

この章では、認証認可システムのパフォーマンスとスケーラビリティについて、以下の重要な概念を学びました：

**パフォーマンス最適化の要点**：
1. ボトルネックの特定と測定が最初のステップ
2. 非同期処理とコネクションプーリングによる並列性の向上
3. 多層キャッシュによる応答時間の短縮
4. 適切なキャッシュ無効化戦略の重要性

**スケーラビリティ確保の方法**：
1. 地理的分散による可用性の向上
2. セッションレプリケーションによる耐障害性
3. サーキットブレーカーによる連鎖障害の防止
4. 水平スケーリングを前提とした設計

**運用の可視化**：
1. 認証システム固有のメトリクス収集
2. プロアクティブなアラート設定
3. 分散トレーシングによる問題の特定
4. ダッシュボードによる継続的な監視

次章では、これらの基盤の上に構築される最新の認証技術動向について探求します。パスワードレス認証、分散型アイデンティティ、AIを活用したリスクベース認証など、未来の認証システムがどのような形になるのかを見ていきましょう。

## 演習問題

### 問題1：ボトルネック分析
以下の認証処理のプロファイリング結果を分析し、改善策を提案しなさい。

```
Database connection: 45ms
User query: 120ms
Password hash verification: 15ms (MD5)
Session creation: 85ms
Permission loading: 230ms
Total: 495ms
```

考慮すべき点：
- 各処理の適正な処理時間
- 並列化可能な処理の特定
- セキュリティへの影響

### 問題2：キャッシュ戦略の設計
以下の要件を持つ認証システムのキャッシュ戦略を設計しなさい。

**システム要件**：
- 同時接続ユーザー数：10万人
- 認証リクエスト：1000 req/sec
- ユーザー権限の更新頻度：1日1回程度
- セッションタイムアウト：30分
- 可用性要求：99.9%

設計に含めるべき項目：
1. キャッシュする対象データ
2. 各データのTTL設定
3. キャッシュレイヤーの構成
4. キャッシュ無効化のタイミング

### 問題3：負荷試験シナリオ
認証システムの負荷試験計画を作成しなさい。

**テスト対象システム**：
- Webアプリケーション（REST API）
- 認証方式：JWT + リフレッシュトークン
- 想定ピーク負荷：5000 req/sec
- データベース：PostgreSQL（マスター・スレーブ構成）

以下を含めること：
1. テストシナリオ（最低3パターン）
2. 測定すべきメトリクス
3. 性能基準値
4. ボトルネック特定方法

### 問題4：モニタリング実装
以下のコードに適切なモニタリングを追加しなさい。

```python
class AuthenticationService:
    def __init__(self):
        self.db = DatabaseConnection()
        self.cache = RedisCache()
    
    async def authenticate(self, username, password):
        # ユーザー取得
        user = await self.db.get_user(username)
        if not user:
            raise UserNotFoundError()
        
        # パスワード検証
        if not verify_password(password, user.password_hash):
            raise InvalidPasswordError()
        
        # セッション作成
        session = create_session(user)
        await self.cache.set(f"session:{session.id}", session)
        
        return session
```

追加すべきモニタリング：
- メトリクス収集
- トレーシング
- エラーレート追跡
- パフォーマンス測定

### 問題5：スケーラビリティ改善
以下の認証システムアーキテクチャの問題点を指摘し、改善案を提示しなさい。

**現在のアーキテクチャ**：
```
[ロードバランサー]
    ↓
[Webサーバー×3]
    ↓
[認証API（単一インスタンス）]
    ↓
[PostgreSQL（単一インスタンス）]
    ↓
[Redis（単一インスタンス）]
```

**システム状況**：
- 現在の負荷：500 req/sec
- 1年後の予測：3000 req/sec
- 認証API CPU使用率：80%
- DB CPU使用率：60%
- 平均レスポンス時間：800ms

### チャレンジ問題：サーキットブレーカーの実装
以下の要件を満たすサーキットブレーカーを実装しなさい。

**要件**：
1. 失敗率ベースの遮断（50%以上で遮断）
2. 時間窓（直近1分間の統計）
3. 半開状態での段階的回復
4. メトリクス出力機能
5. 非同期処理対応

**インターフェース**：
```python
class AdvancedCircuitBreaker:
    def __init__(self, 
                 failure_rate_threshold=0.5,
                 window_size=60,
                 half_open_requests=3):
        pass
    
    async def call(self, func, *args, **kwargs):
        pass
    
    def get_metrics(self):
        pass
```

実装には以下を含めること：
- スレッドセーフな実装
- 効率的な統計計算
- 適切なエラーハンドリング

## 12.5 CI/CDパイプライン統合

### 12.5.1 認証システムのCI/CD戦略

```python
class AuthSystemCICDStrategy:
    """認証システムのCI/CD戦略"""
    
    def continuous_integration_pipeline(self):
        """継続的インテグレーションパイプライン"""
        
        return {
            'github_actions_workflow': '''
            name: Auth System CI/CD Pipeline
            
            on:
              push:
                branches: [ main, develop ]
              pull_request:
                branches: [ main ]
            
            jobs:
              security-checks:
                name: Security Vulnerability Checks
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  
                  - name: Run Security Audit
                    run: |
                      # 依存関係の脆弱性チェック
                      npm audit --production
                      pip install safety
                      safety check
                      
                  - name: SAST - Static Application Security Testing
                    uses: github/super-linter@v4
                    env:
                      DEFAULT_BRANCH: main
                      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
                      VALIDATE_PYTHON_BLACK: true
                      VALIDATE_JAVASCRIPT_ES: true
                      
                  - name: Secret Scanning
                    uses: trufflesecurity/trufflehog@main
                    with:
                      path: ./
                      base: ${{ github.event.repository.default_branch }}
                      head: HEAD
                      
                  - name: Container Security Scan
                    uses: aquasecurity/trivy-action@0.33.1
                    with:
                      image-ref: 'auth-service:${{ github.sha }}'
                      format: 'sarif'
                      output: 'trivy-results.sarif'
              
              unit-tests:
                name: Unit Tests with Coverage
                runs-on: ubuntu-latest
                strategy:
                  matrix:
                    python-version: [3.9, 3.10, 3.11]
                    node-version: [16, 18, 20]
                
                steps:
                  - uses: actions/checkout@v4
                  
                  - name: Set up Python ${{ matrix.python-version }}
                    uses: actions/setup-python@v6
                    with:
                      python-version: ${{ matrix.python-version }}
                      
                  - name: Install Python dependencies
                    run: |
                      python -m pip install --upgrade pip
                      pip install -r requirements.txt
                      pip install -r requirements-test.txt
                      
                  - name: Run Python tests with coverage
                    run: |
                      pytest tests/unit/ \
                        --cov=auth_service \
                        --cov-report=xml \
                        --cov-report=html \
                        --cov-fail-under=80
                      
                  - name: Set up Node.js ${{ matrix.node-version }}
                    uses: actions/setup-node@v6
                    with:
                      node-version: ${{ matrix.node-version }}
                      
                  - name: Run JavaScript tests
                    run: |
                      npm ci
                      npm run test:unit -- --coverage
                      
                  - name: Upload coverage reports
                    uses: codecov/codecov-action@v5
                    with:
                      token: ${{ secrets.CODECOV_TOKEN }}
                      files: ./coverage.xml,./coverage/lcov.info
              
              integration-tests:
                name: Integration Tests
                runs-on: ubuntu-latest
                needs: [security-checks, unit-tests]
                
                services:
                  postgres:
                    image: postgres:15
                    env:
                      POSTGRES_PASSWORD: testpass
                      POSTGRES_DB: auth_test
                    options: >-
                      --health-cmd pg_isready
                      --health-interval 10s
                      --health-timeout 5s
                      --health-retries 5
                    ports:
                      - 5432:5432
                      
                  redis:
                    image: redis:7-alpine
                    options: >-
                      --health-cmd "redis-cli ping"
                      --health-interval 10s
                      --health-timeout 5s
                      --health-retries 5
                    ports:
                      - 6379:6379
                
                steps:
                  - uses: actions/checkout@v4
                  
                  - name: Run integration tests
                    env:
                      DATABASE_URL: postgresql://postgres:testpass@localhost:5432/auth_test
                      REDIS_URL: redis://localhost:6379
                    run: |
                      python -m pytest tests/integration/ -v
                      npm run test:integration
                      
                  - name: Run E2E authentication flow tests
                    run: |
                      docker compose -f docker-compose.test.yml up -d
                      npm run test:e2e
                      docker compose -f docker-compose.test.yml down
              
              performance-tests:
                name: Performance and Load Tests
                runs-on: ubuntu-latest
                needs: [integration-tests]
                
                steps:
                  - uses: actions/checkout@v4
                  
                  - name: Run performance benchmarks
                    run: |
                      # JWT生成/検証ベンチマーク
                      python benchmarks/jwt_benchmark.py
                      
                      # パスワードハッシュベンチマーク
                      python benchmarks/password_hash_benchmark.py
                      
                      # 認証フロー全体のベンチマーク
                      python benchmarks/auth_flow_benchmark.py
                      
                  - name: Load testing with k6
                    uses: grafana/k6-action@v0.3.0
                    with:
                      filename: tests/load/auth_scenarios.js
                      flags: --out json=results.json
                      
                  - name: Analyze performance results
                    run: |
                      python scripts/analyze_performance.py results.json
                      
                  - name: Comment PR with performance impact
                    if: github.event_name == 'pull_request'
                    uses: actions/github-script@v6
                    with:
                      script: |
                        const fs = require('fs');
                        const results = JSON.parse(fs.readFileSync('performance-summary.json'));
                        
                        const comment = `## Performance Impact Analysis
                        
                        | Metric | Baseline | This PR | Change |
                        |--------|----------|---------|--------|
                        | Auth Latency (p95) | ${results.baseline.p95}ms | ${results.current.p95}ms | ${results.change.p95}% |
                        | Throughput | ${results.baseline.rps} rps | ${results.current.rps} rps | ${results.change.rps}% |
                        | CPU Usage | ${results.baseline.cpu}% | ${results.current.cpu}% | ${results.change.cpu}% |
                        | Memory Usage | ${results.baseline.memory}MB | ${results.current.memory}MB | ${results.change.memory}% |
                        `;
                        
                        github.rest.issues.createComment({
                          issue_number: context.issue.number,
                          owner: context.repo.owner,
                          repo: context.repo.repo,
                          body: comment
                        });
              
              build-and-push:
                name: Build and Push Container Images
                runs-on: ubuntu-latest
                needs: [performance-tests]
                if: github.ref == 'refs/heads/main'
                
                steps:
                  - uses: actions/checkout@v4
                  
                  - name: Set up Docker Buildx
                    uses: docker/setup-buildx-action@v3
                    
                  - name: Log in to Container Registry
                    uses: docker/login-action@v3
                    with:
                      registry: ${{ secrets.REGISTRY_URL }}
                      username: ${{ secrets.REGISTRY_USERNAME }}
                      password: ${{ secrets.REGISTRY_PASSWORD }}
                      
                  - name: Build and push auth service
                    uses: docker/build-push-action@v4
                    with:
                      context: ./services/auth
                      push: true
                      tags: |
                        ${{ secrets.REGISTRY_URL }}/auth-service:${{ github.sha }}
                        ${{ secrets.REGISTRY_URL }}/auth-service:latest
                      cache-from: type=gha
                      cache-to: type=gha,mode=max
                      build-args: |
                        VERSION=${{ github.sha }}
                        BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
            ''',
            
            'gitlab_ci_pipeline': '''
            stages:
              - security
              - test
              - build
              - deploy
              - monitor
            
            variables:
              DOCKER_DRIVER: overlay2
              DOCKER_TLS_CERTDIR: ""
            
            # セキュリティステージ
            dependency-check:
              stage: security
              image: owasp/dependency-check:latest
              script:
                - dependency-check.sh --project "Auth Service" --scan . --format ALL
              artifacts:
                reports:
                  dependency_scanning: dependency-check-report.json
              only:
                - merge_requests
                - main
            
            sast:
              stage: security
              image: 
                name: "registry.gitlab.com/gitlab-org/security-products/sast:latest"
              script:
                - /analyzer run
              artifacts:
                reports:
                  sast: gl-sast-report.json
            
            # テストステージ
            test:auth-unit:
              stage: test
              image: python:3.10
              services:
                - postgres:15
                - redis:7
              variables:
                POSTGRES_DB: test_db
                POSTGRES_USER: test_user
                POSTGRES_PASSWORD: test_pass
                DATABASE_URL: postgresql://test_user:test_pass@postgres:5432/test_db
                REDIS_URL: redis://redis:6379
              before_script:
                - pip install -r requirements.txt
                - pip install -r requirements-test.txt
              script:
                - pytest tests/unit/ --junitxml=report.xml --cov=auth_service --cov-report=xml
              coverage: '/(?i)total.*? (100(?:\.0+)?\%|[1-9]?\d(?:\.\d+)?\%)$/'
              artifacts:
                reports:
                  junit: report.xml
                  coverage_report:
                    coverage_format: cobertura
                    path: coverage.xml
            
            # ビルドステージ
            build:auth-service:
              stage: build
              image: docker:latest
              services:
                - docker:dind
              before_script:
                - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
              script:
                - docker build -t $CI_REGISTRY_IMAGE/auth-service:$CI_COMMIT_SHA ./services/auth
                - docker push $CI_REGISTRY_IMAGE/auth-service:$CI_COMMIT_SHA
                - |
                  if [ "$CI_COMMIT_BRANCH" == "main" ]; then
                    docker tag $CI_REGISTRY_IMAGE/auth-service:$CI_COMMIT_SHA $CI_REGISTRY_IMAGE/auth-service:latest
                    docker push $CI_REGISTRY_IMAGE/auth-service:latest
                  fi
              only:
                - main
                - develop
            '''
        }
    
    def continuous_deployment_pipeline(self):
        """継続的デプロイメントパイプライン"""
        
        return {
            'kubernetes_deployment': '''
            class KubernetesDeploymentPipeline:
                """Kubernetesへの継続的デプロイメント"""
                
                def __init__(self):
                    self.helm_chart_path = "./charts/auth-service"
                    self.environments = ["dev", "staging", "production"]
                
                def generate_github_action_deploy(self):
                    """GitHub Actionデプロイメントワークフロー"""
                    
                    return """
              deploy:
                name: Deploy to Kubernetes
                runs-on: ubuntu-latest
                needs: [build-and-push]
                strategy:
                  matrix:
                    environment: [dev, staging]
                
                steps:
                  - uses: actions/checkout@v4
                  
                  - name: Set up Kubectl
                    uses: azure/setup-kubectl@v4
                    with:
                      version: 'v1.28.0'
                      
                  - name: Set up Helm
                    uses: azure/setup-helm@v4
                    with:
                      version: 'v3.12.0'
                      
                  - name: Configure AWS credentials
                    uses: aws-actions/configure-aws-credentials@v4
                    with:
                      aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
                      aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
                      aws-region: us-east-1
                      
                  - name: Update kubeconfig
                    run: |
                      aws eks update-kubeconfig --name auth-cluster-${{ matrix.environment }}
                      
                  - name: Deploy with Helm
                    run: |
                      helm upgrade --install auth-service ./charts/auth-service \
                        --namespace auth-${{ matrix.environment }} \
                        --create-namespace \
                        --set image.tag=${{ github.sha }} \
                        --set environment=${{ matrix.environment }} \
                        --values ./charts/auth-service/values.${{ matrix.environment }}.yaml \
                        --wait \
                        --timeout 10m
                        
                  - name: Run smoke tests
                    run: |
                      kubectl run smoke-test-${{ github.run_id }} \
                        --image=curlimages/curl:latest \
                        --rm \
                        --attach \
                        --restart=Never \
                        --namespace=auth-${{ matrix.environment }} \
                        -- /bin/sh -c "
                          curl -f http://auth-service/health || exit 1
                          curl -f http://auth-service/api/v1/auth/login \
                            -X POST \
                            -H 'Content-Type: application/json' \
                            -d '{\"username\":\"test@example.com\",\"password\":\"test\"}' || exit 1
                        "
                        
                  - name: Rollback on failure
                    if: failure()
                    run: |
                      helm rollback auth-service -n auth-${{ matrix.environment }}
                      
              deploy-production:
                name: Deploy to Production
                runs-on: ubuntu-latest
                needs: [deploy]
                environment: production
                if: github.ref == 'refs/heads/main'
                
                steps:
                  - uses: actions/checkout@v4
                  
                  - name: Create deployment record
                    uses: actions/github-script@v6
                    with:
                      script: |
                        const deployment = await github.rest.repos.createDeployment({
                          owner: context.repo.owner,
                          repo: context.repo.repo,
                          ref: context.sha,
                          environment: 'production',
                          required_contexts: [],
                          auto_merge: false
                        });
                        
                        core.setOutput('deployment_id', deployment.data.id);
                        
                  - name: Deploy to production
                    run: |
                      # Blue-Green deployment
                      ./scripts/deploy-blue-green.sh production ${{ github.sha }}
                      
                  - name: Update deployment status
                    if: always()
                    uses: actions/github-script@v6
                    with:
                      script: |
                        await github.rest.repos.createDeploymentStatus({
                          owner: context.repo.owner,
                          repo: context.repo.repo,
                          deployment_id: ${{ steps.create-deployment.outputs.deployment_id }},
                          state: '${{ job.status }}',
                          environment_url: 'https://auth.production.example.com',
                          description: 'Deployment ${{ job.status }}'
                        });
                    """
                
                def generate_argocd_config(self):
                    """ArgoCD Application設定"""
                    
                    return {
                        'argocd_application': '''
            apiVersion: argoproj.io/v1alpha1
            kind: Application
            metadata:
              name: auth-service
              namespace: argocd
            spec:
              project: default
              source:
                repoURL: https://github.com/your-org/auth-service
                targetRevision: HEAD
                path: charts/auth-service
                helm:
                  valueFiles:
                    - values.production.yaml
                  parameters:
                    - name: image.tag
                      value: $ARGOCD_APP_REVISION
              destination:
                server: https://kubernetes.default.svc
                namespace: auth-production
              syncPolicy:
                automated:
                  prune: true
                  selfHeal: true
                  allowEmpty: false
                syncOptions:
                  - CreateNamespace=true
                  - PruneLast=true
                retry:
                  limit: 5
                  backoff:
                    duration: 5s
                    factor: 2
                    maxDuration: 3m
              revisionHistoryLimit: 10
                        ''',
                        
                        'rollout_strategy': '''
            apiVersion: argoproj.io/v1alpha1
            kind: Rollout
            metadata:
              name: auth-service
              namespace: auth-production
            spec:
              replicas: 10
              strategy:
                canary:
                  steps:
                    - setWeight: 10
                    - pause: {duration: 5m}
                    - analysis:
                        templates:
                          - templateName: auth-service-analysis
                        args:
                          - name: service-name
                            value: auth-service
                    - setWeight: 25
                    - pause: {duration: 5m}
                    - setWeight: 50
                    - pause: {duration: 5m}
                    - setWeight: 75
                    - pause: {duration: 5m}
                  trafficRouting:
                    istio:
                      virtualServices:
                        - name: auth-service-vsvc
                          routes:
                            - primary
                      destinationRule:
                        name: auth-service-dest
                        canarySubsetName: canary
                        stableSubsetName: stable
              selector:
                matchLabels:
                  app: auth-service
              template:
                metadata:
                  labels:
                    app: auth-service
                spec:
                  containers:
                    - name: auth-service
                      image: registry.example.com/auth-service:latest
                      ports:
                        - containerPort: 8080
                      env:
                        - name: ENVIRONMENT
                          value: production
                      livenessProbe:
                        httpGet:
                          path: /health
                          port: 8080
                        initialDelaySeconds: 30
                        periodSeconds: 10
                      readinessProbe:
                        httpGet:
                          path: /ready
                          port: 8080
                        initialDelaySeconds: 5
                        periodSeconds: 5
                        '''
                    }
            ''',
            
            'monitoring_and_alerting': '''
            class MonitoringIntegration:
                """CI/CDパイプラインでのモニタリング統合"""
                
                def generate_prometheus_rules(self):
                    """Prometheusアラートルール"""
                    
                    return """
            groups:
              - name: auth_service_deployment
                interval: 30s
                rules:
                  - alert: DeploymentFailureRate
                    expr: |
                      rate(deployment_failures_total[5m]) > 0.1
                    for: 5m
                    labels:
                      severity: critical
                      team: platform
                    annotations:
                      summary: "High deployment failure rate"
                      description: "Deployment failure rate is {{ $value }} failures/sec"
                      
                  - alert: AuthServiceRollback
                    expr: |
                      increase(helm_rollback_total{service="auth-service"}[1h]) > 0
                    labels:
                      severity: warning
                      team: platform
                    annotations:
                      summary: "Auth service was rolled back"
                      description: "Auth service deployment was rolled back in {{ $labels.environment }}"
                      
                  - alert: CanaryDeploymentFailed
                    expr: |
                      auth_service_canary_success_rate < 0.95
                    for: 5m
                    labels:
                      severity: critical
                      team: platform
                    annotations:
                      summary: "Canary deployment health check failed"
                      description: "Canary success rate is {{ $value }}"
                    """
                
                def generate_datadog_monitors(self):
                    """Datadog モニター設定"""
                    
                    return {
                        'deployment_monitor': '''
            {
              "name": "Auth Service Deployment Health",
              "type": "metric alert",
              "query": "avg(last_5m):avg:kubernetes.deployment.replicas.available{deployment:auth-service} by {environment} < 0.8 * avg:kubernetes.deployment.replicas.desired{deployment:auth-service} by {environment}",
              "message": "Auth service deployment health degraded in {{environment.name}}\\n\\nAvailable replicas: {{value}}\\nDesired replicas: {{comparator_value}}\\n\\n@slack-platform-alerts @pagerduty",
              "tags": ["service:auth", "team:platform"],
              "options": {
                "thresholds": {
                  "critical": 0.8,
                  "warning": 0.9
                },
                "notify_no_data": true,
                "no_data_timeframe": 10
              }
            }
                        ''',
                        
                        'performance_regression_monitor': '''
            {
              "name": "Auth Service Performance Regression",
              "type": "anomaly",
              "query": "avg(last_30m):avg:trace.auth.login.duration{env:production} by {version}",
              "message": "Potential performance regression detected after deployment\\n\\nVersion: {{version.name}}\\nCurrent p95 latency: {{value}}ms\\n\\nCompare with previous version metrics and consider rollback if necessary.\\n\\n@slack-platform-alerts",
              "tags": ["service:auth", "regression-detection"],
              "options": {
                "threshold_windows": {
                  "recovery_window": "last_15m",
                  "trigger_window": "last_5m"
                }
              }
            }
                        '''
                    }
            '''
        }
    
    def security_in_pipeline(self):
        """パイプラインでのセキュリティ実装"""
        
        return {
            'security_gates': '''
            class SecurityGates:
                """デプロイメント前のセキュリティゲート"""
                
                def __init__(self):
                    self.required_checks = [
                        "dependency_scan",
                        "sast_scan",
                        "container_scan",
                        "secrets_scan",
                        "license_compliance"
                    ]
                
                async def validate_deployment(self, deployment_request: DeploymentRequest) -> ValidationResult:
                    """デプロイメント前の包括的なセキュリティ検証"""
                    
                    results = []
                    
                    # 1. 脆弱性スキャン結果の確認
                    vuln_check = await self.check_vulnerability_scan(
                        deployment_request.image_tag
                    )
                    results.append(vuln_check)
                    
                    # 2. セキュリティポリシーの確認
                    policy_check = await self.validate_security_policies(
                        deployment_request
                    )
                    results.append(policy_check)
                    
                    # 3. 認証設定の検証
                    auth_config_check = await self.validate_auth_configuration(
                        deployment_request.config
                    )
                    results.append(auth_config_check)
                    
                    # 4. TLS/証明書の有効性確認
                    tls_check = await self.validate_tls_configuration(
                        deployment_request.environment
                    )
                    results.append(tls_check)
                    
                    # 5. シークレット管理の確認
                    secrets_check = await self.validate_secrets_management(
                        deployment_request
                    )
                    results.append(secrets_check)
                    
                    # すべてのチェックに合格した場合のみデプロイを許可
                    all_passed = all(r.passed for r in results)
                    
                    return ValidationResult(
                        passed=all_passed,
                        checks=results,
                        deployment_allowed=all_passed,
                        risk_score=self.calculate_risk_score(results)
                    )
                
                async def check_vulnerability_scan(self, image_tag: str) -> CheckResult:
                    """コンテナイメージの脆弱性チェック"""
                    
                    scan_results = await self.trivy_scan(image_tag)
                    
                    critical_vulns = scan_results.get_critical_vulnerabilities()
                    high_vulns = scan_results.get_high_vulnerabilities()
                    
                    # クリティカルな脆弱性は許可しない
                    if critical_vulns:
                        return CheckResult(
                            name="vulnerability_scan",
                            passed=False,
                            message=f"Found {len(critical_vulns)} critical vulnerabilities",
                            details=critical_vulns
                        )
                    
                    # 高リスクの脆弱性は3個まで許容
                    if len(high_vulns) > 3:
                        return CheckResult(
                            name="vulnerability_scan",
                            passed=False,
                            message=f"Found {len(high_vulns)} high vulnerabilities (max allowed: 3)",
                            details=high_vulns
                        )
                    
                    return CheckResult(
                        name="vulnerability_scan",
                        passed=True,
                        message="Vulnerability scan passed"
                    )
                
                async def validate_auth_configuration(self, config: dict) -> CheckResult:
                    """認証設定の妥当性検証"""
                    
                    required_settings = {
                        "jwt_algorithm": ["RS256", "ES256"],  # 安全なアルゴリズムのみ
                        "password_min_length": lambda x: x >= 12,
                        "mfa_enabled": lambda x: x is True,
                        "session_timeout_minutes": lambda x: x <= 480,  # 最大8時間
                        "bcrypt_rounds": lambda x: x >= 12
                    }
                    
                    violations = []
                    
                    for setting, requirement in required_settings.items():
                        value = config.get(setting)
                        
                        if isinstance(requirement, list):
                            if value not in requirement:
                                violations.append(f"{setting} must be one of {requirement}")
                        elif callable(requirement):
                            if not requirement(value):
                                violations.append(f"{setting} does not meet requirements")
                        else:
                            if value != requirement:
                                violations.append(f"{setting} must be {requirement}")
                    
                    if violations:
                        return CheckResult(
                            name="auth_configuration",
                            passed=False,
                            message="Invalid authentication configuration",
                            details=violations
                        )
                    
                    return CheckResult(
                        name="auth_configuration",
                        passed=True,
                        message="Authentication configuration is valid"
                    )
            ''',
            
            'automated_security_tests': '''
            class AutomatedSecurityTests:
                """パイプラインでの自動セキュリティテスト"""
                
                def generate_security_test_suite(self):
                    """包括的なセキュリティテストスイート"""
                    
                    return """
            security-test-suite:
              stage: security-test
              image: owasp/zap2docker-stable
              services:
                - name: $CI_REGISTRY_IMAGE/auth-service:$CI_COMMIT_SHA
                  alias: auth-service
              variables:
                AUTH_SERVICE_URL: http://auth-service:8080
              script:
                # OWASP ZAP による動的セキュリティテスト
                - |
                  zap-baseline.py \
                    -t $AUTH_SERVICE_URL \
                    -g gen.conf \
                    -J zap-report.json \
                    -r zap-report.html \
                    --auto
                
                # 認証バイパステスト
                - python security-tests/test_auth_bypass.py
                
                # SQLインジェクションテスト
                - python security-tests/test_sql_injection.py
                
                # XSSテスト
                - python security-tests/test_xss.py
                
                # CSRF対策テスト
                - python security-tests/test_csrf_protection.py
                
                # レート制限テスト
                - python security-tests/test_rate_limiting.py
                
                # JWT セキュリティテスト
                - python security-tests/test_jwt_security.py
                
              artifacts:
                reports:
                  dast: zap-report.json
                paths:
                  - zap-report.html
                  - security-test-results/
              only:
                - merge_requests
                - main
                    """
                
                def generate_penetration_test_automation(self):
                    """自動ペネトレーションテスト"""
                    
                    return {
                        'nuclei_scan': '''
            - name: Run Nuclei Security Scan
              run: |
                nuclei -u ${{ env.TARGET_URL }} \
                  -t nuclei-templates/cves/ \
                  -t nuclei-templates/vulnerabilities/ \
                  -t nuclei-templates/misconfiguration/ \
                  -severity critical,high,medium \
                  -o nuclei-report.json \
                  -json
                        ''',
                        
                        'custom_auth_tests': '''
            import asyncio
            import aiohttp
            from typing import List, Dict
            
            class AuthSecurityTester:
                """認証システム専用のセキュリティテスト"""
                
                def __init__(self, base_url: str):
                    self.base_url = base_url
                    self.session = None
                
                async def run_all_tests(self) -> Dict[str, List[str]]:
                    """すべてのセキュリティテストを実行"""
                    
                    results = {
                        "passed": [],
                        "failed": [],
                        "warnings": []
                    }
                    
                    tests = [
                        self.test_jwt_none_algorithm,
                        self.test_jwt_key_confusion,
                        self.test_password_timing_attack,
                        self.test_session_fixation,
                        self.test_brute_force_protection,
                        self.test_account_enumeration,
                        self.test_concurrent_session_limit,
                        self.test_token_replay_attack
                    ]
                    
                    async with aiohttp.ClientSession() as self.session:
                        for test in tests:
                            try:
                                test_name = test.__name__
                                await test()
                                results["passed"].append(test_name)
                            except AssertionError as e:
                                results["failed"].append(f"{test_name}: {str(e)}")
                            except Exception as e:
                                results["warnings"].append(f"{test_name}: {str(e)}")
                    
                    return results
                
                async def test_jwt_none_algorithm(self):
                    """JWT 'none' アルゴリズム攻撃テスト"""
                    
                    # 正常なログインでJWTを取得
                    login_response = await self.session.post(
                        f"{self.base_url}/auth/login",
                        json={"username": "test@example.com", "password": "testpass"}
                    )
                    token = (await login_response.json())["access_token"]
                    
                    # JWTを改ざん（algをnoneに変更）
                    parts = token.split('.')
                    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                    header['alg'] = 'none'
                    
                    tampered_token = (
                        base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=') +
                        '.' + parts[1] + '.'
                    )
                    
                    # 改ざんされたトークンでアクセス
                    response = await self.session.get(
                        f"{self.base_url}/api/profile",
                        headers={"Authorization": f"Bearer {tampered_token}"}
                    )
                    
                    assert response.status == 401, "JWT none algorithm attack succeeded!"
                        '''
                    }
            '''
        }
```

### 12.5.2 パフォーマンステストの自動化

```python
class PerformanceTestAutomation:
    """CI/CDでのパフォーマンステスト自動化"""
    
    def generate_k6_test_scenarios(self):
        """k6によるロードテストシナリオ"""
        
        return {
            'auth_load_test': '''
            import http from 'k6/http';
            import { check, sleep } from 'k6';
            import { Rate } from 'k6/metrics';
            
            // カスタムメトリクス
            const errorRate = new Rate('errors');
            const authSuccessRate = new Rate('auth_success');
            const jwtValidationTime = new Trend('jwt_validation_time');
            
            // テストシナリオ設定
            export const options = {
              scenarios: {
                // ステージ1: 通常負荷
                normal_load: {
                  executor: 'ramping-vus',
                  startVUs: 0,
                  stages: [
                    { duration: '2m', target: 100 },  // Ramp up
                    { duration: '5m', target: 100 },  // Stay at 100 users
                    { duration: '2m', target: 0 },    // Ramp down
                  ],
                  gracefulRampDown: '30s',
                },
                
                // ステージ2: スパイク負荷
                spike_test: {
                  executor: 'ramping-vus',
                  startVUs: 0,
                  stages: [
                    { duration: '30s', target: 500 },  // Sudden spike
                    { duration: '1m', target: 500 },   // Hold
                    { duration: '30s', target: 0 },    // Quick drop
                  ],
                  startTime: '10m',  // Start after normal load
                },
                
                // ステージ3: 持続負荷
                sustained_load: {
                  executor: 'constant-vus',
                  vus: 200,
                  duration: '30m',
                  startTime: '15m',
                },
              },
              
              thresholds: {
                // パフォーマンス基準
                http_req_duration: ['p(95)<500', 'p(99)<1000'],  // 95%が500ms以下
                http_req_failed: ['rate<0.01'],  // エラー率1%未満
                errors: ['rate<0.01'],
                auth_success: ['rate>0.99'],  // 認証成功率99%以上
                jwt_validation_time: ['p(95)<50'],  // JWT検証95%が50ms以下
              },
            };
            
            // テストデータ
            const users = JSON.parse(open('./test-users.json'));
            const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
            
            export default function () {
              // ランダムユーザー選択
              const user = users[Math.floor(Math.random() * users.length)];
              
              // 1. ログインテスト
              const loginRes = http.post(
                `${BASE_URL}/api/v1/auth/login`,
                JSON.stringify({
                  email: user.email,
                  password: user.password,
                }),
                {
                  headers: { 'Content-Type': 'application/json' },
                  tags: { name: 'login' },
                }
              );
              
              const loginSuccess = check(loginRes, {
                'login status is 200': (r) => r.status === 200,
                'login has token': (r) => r.json('access_token') !== '',
                'login response time < 500ms': (r) => r.timings.duration < 500,
              });
              
              errorRate.add(!loginSuccess);
              authSuccessRate.add(loginSuccess);
              
              if (!loginSuccess) return;
              
              const authToken = loginRes.json('access_token');
              const refreshToken = loginRes.json('refresh_token');
              
              // 2. 認証が必要なAPIへのアクセス
              const headers = {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json',
              };
              
              // プロファイル取得
              const profileRes = http.get(`${BASE_URL}/api/v1/profile`, { headers });
              check(profileRes, {
                'profile status is 200': (r) => r.status === 200,
                'profile has user data': (r) => r.json('user_id') !== '',
              });
              
              sleep(1);
              
              // 3. トークンリフレッシュテスト
              if (Math.random() > 0.7) {  // 30%の確率でリフレッシュ
                const refreshStart = new Date();
                const refreshRes = http.post(
                  `${BASE_URL}/api/v1/auth/refresh`,
                  JSON.stringify({ refresh_token: refreshToken }),
                  { headers: { 'Content-Type': 'application/json' } }
                );
                
                const refreshDuration = new Date() - refreshStart;
                jwtValidationTime.add(refreshDuration);
                
                check(refreshRes, {
                  'refresh status is 200': (r) => r.status === 200,
                  'refresh has new token': (r) => r.json('access_token') !== '',
                });
              }
              
              // 4. 並行セッションテスト
              if (__VU % 10 === 0) {  // 10%のVUで実行
                const batch = http.batch([
                  ['GET', `${BASE_URL}/api/v1/profile`, null, { headers }],
                  ['GET', `${BASE_URL}/api/v1/settings`, null, { headers }],
                  ['GET', `${BASE_URL}/api/v1/permissions`, null, { headers }],
                ]);
                
                check(batch[0], {
                  'batch requests successful': (r) => r.status === 200,
                });
              }
              
              sleep(Math.random() * 3 + 1);  // 1〜4秒のランダム待機
            }
            
            export function handleSummary(data) {
              return {
                'stdout': textSummary(data, { indent: ' ', enableColors: true }),
                'summary.json': JSON.stringify(data),
                'summary.html': htmlReport(data),
              };
            }
            ''',
            
            'grafana_dashboard': '''
            {
              "dashboard": {
                "title": "Auth Service CI/CD Performance",
                "panels": [
                  {
                    "title": "Request Rate",
                    "targets": [{
                      "expr": "rate(http_requests_total{service=\"auth-service\"}[5m])"
                    }]
                  },
                  {
                    "title": "Response Time (p95)",
                    "targets": [{
                      "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{service=\"auth-service\"}[5m]))"
                    }]
                  },
                  {
                    "title": "Error Rate",
                    "targets": [{
                      "expr": "rate(http_requests_total{service=\"auth-service\",status=~\"5..\"}[5m])"
                    }]
                  },
                  {
                    "title": "JWT Validation Performance",
                    "targets": [{
                      "expr": "histogram_quantile(0.95, rate(jwt_validation_duration_seconds_bucket[5m]))"
                    }]
                  },
                  {
                    "title": "Database Connection Pool",
                    "targets": [{
                      "expr": "db_connection_pool_size{service=\"auth-service\"}"
                    }]
                  }
                ],
                "annotations": [
                  {
                    "datasource": "prometheus",
                    "expr": "ALERTS{alertname=\"DeploymentStarted\",service=\"auth-service\"}",
                    "titleFormat": "Deployment Started"
                  }
                ]
              }
            }
            '''
        }
```
