---
layout: book
title: "第8章 演習問題解答"
---

# 第8章 演習問題解答

## 問題1：要件定義

### 解答

**スタートアップSaaSプロダクト（B2B、想定ユーザー1万社）の認証システム要件定義**

#### ビジネス要件

**ユーザーストーリー**
```
1. 企業管理者として、従業員アカウントを一括管理したい
   - CSV一括登録機能
   - 組織階層に応じた権限設定
   - 利用状況の可視化

2. 一般ユーザーとして、簡単かつ安全にログインしたい
   - SSO対応（Google Workspace、Microsoft 365）
   - パスワードレスオプション
   - モバイルアプリ対応

3. セキュリティ管理者として、コンプライアンスを確保したい
   - 監査ログの完全性
   - アクセス制御の細粒度設定
   - 異常検知とアラート
```

**成功指標**
- 初回ログイン成功率 > 90%
- 平均ログイン時間 < 3秒
- パスワードリセット率 < 5%/月
- セキュリティインシデント 0件/年

#### セキュリティ要件

**認証要件**
```yaml
authentication:
  methods:
    primary:
      - email_password
      - sso_saml
      - sso_oidc
    mfa:
      - totp
      - webauthn
      - push_notification
  
  password_policy:
    min_length: 10
    complexity: "NIST SP 800-63B準拠"
    breach_detection: true
    rotation: "リスクベース"
  
  session:
    idle_timeout: 30m
    absolute_timeout: 8h
    concurrent_limit: 3
```

**脅威モデル**
```
主要脅威:
1. アカウント乗っ取り
   対策: MFA必須化、異常検知、デバイス認証
2. 内部不正
   対策: 最小権限、職務分離、監査ログ
3. API悪用
   対策: レート制限、APIキー管理、OAuth 2.0
```

#### 技術要件

**パフォーマンス要件**
```
- 認証API: p99 < 100ms
- 同時接続: 10,000セッション
- 可用性: 99.95%（年間ダウンタイム < 4.5時間）
```

**スケーラビリティ要件**
```
- 水平スケール対応
- マルチリージョン展開準備
- 10倍成長（10万社）への対応
```

**段階的実装計画**
```
Phase 1 (3ヶ月): MVP
- 基本的なメール/パスワード認証
- 企業単位の管理機能
- 基本的なRBAC

Phase 2 (3ヶ月): エンタープライズ機能
- SSO統合（SAML/OIDC）
- MFA導入
- 高度な監査機能

Phase 3 (6ヶ月): 拡張機能
- API認証（OAuth 2.0）
- パスワードレス認証
- AI異常検知
```

## 問題2：データベース設計

### 解答

**マルチテナント対応データベース設計**

```sql
-- テナント管理
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subdomain VARCHAR(63) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    plan VARCHAR(50) DEFAULT 'standard',
    
    -- コンプライアンス
    data_residency VARCHAR(2) DEFAULT 'JP',
    data_retention_days INTEGER DEFAULT 365,
    
    -- 状態管理
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- パーティショニングキー
    partition_key INTEGER GENERATED ALWAYS AS (abs(hashtext(id::text)) % 100) STORED
);

-- ユーザーテーブル（テナント別パーティション）
CREATE TABLE users (
    id UUID DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    email VARCHAR(255) NOT NULL,
    
    -- 認証情報
    password_hash VARCHAR(255),
    mfa_secret VARCHAR(255),
    
    -- GDPR対応
    personal_data JSONB, -- 暗号化して保存
    consent_version VARCHAR(20),
    deletion_requested_at TIMESTAMP,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, email)
) PARTITION BY HASH (tenant_id);

-- 100個のパーティション作成
DO $$
BEGIN
    FOR i IN 0..99 LOOP
        EXECUTE format('CREATE TABLE users_%s PARTITION OF users FOR VALUES WITH (modulus 100, remainder %s)', i, i);
    END LOOP;
END $$;

-- 監査ログ（時系列パーティション）
CREATE TABLE audit_logs (
    id BIGSERIAL,
    tenant_id UUID NOT NULL,
    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- イベント情報
    event_type VARCHAR(50) NOT NULL,
    user_id UUID,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    
    -- コンテキスト
    ip_address INET,
    user_agent TEXT,
    
    -- データ
    event_data JSONB,
    
    PRIMARY KEY (event_time, id, tenant_id)
) PARTITION BY RANGE (event_time);

-- 月次パーティションの自動作成
CREATE OR REPLACE FUNCTION create_monthly_partition()
RETURNS void AS $$
DECLARE
    start_date DATE;
    end_date DATE;
    partition_name TEXT;
BEGIN
    start_date := date_trunc('month', CURRENT_DATE);
    end_date := start_date + INTERVAL '1 month';
    partition_name := 'audit_logs_' || to_char(start_date, 'YYYY_MM');
    
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_logs FOR VALUES FROM (%L) TO (%L)',
        partition_name, start_date, end_date
    );
END;
$$ LANGUAGE plpgsql;

-- GDPR準拠機能
CREATE OR REPLACE FUNCTION anonymize_user_data(p_tenant_id UUID, p_user_id UUID)
RETURNS void AS $$
BEGIN
    UPDATE users SET
        email = 'deleted_' || extract(epoch from now()) || '@example.com',
        personal_data = '{"status": "anonymized"}',
        password_hash = NULL,
        mfa_secret = NULL
    WHERE tenant_id = p_tenant_id AND id = p_user_id;
    
    -- 監査ログは保持（法的要件）
    INSERT INTO audit_logs (tenant_id, event_type, user_id, event_data)
    VALUES (p_tenant_id, 'user_data_anonymized', p_user_id, '{"reason": "gdpr_request"}');
END;
$$ LANGUAGE plpgsql;

-- 高速化のためのインデックス
CREATE INDEX idx_users_email ON users(tenant_id, email) WHERE status = 'active';
CREATE INDEX idx_audit_logs_lookup ON audit_logs(tenant_id, user_id, event_time DESC);
CREATE INDEX idx_audit_logs_type ON audit_logs(tenant_id, event_type, event_time DESC);

-- 読み取り専用レプリカ用のマテリアライズドビュー
CREATE MATERIALIZED VIEW user_login_stats AS
SELECT 
    tenant_id,
    user_id,
    date_trunc('day', event_time) as login_date,
    count(*) as login_count,
    array_agg(DISTINCT ip_address) as ip_addresses
FROM audit_logs
WHERE event_type = 'login_success'
    AND event_time > CURRENT_DATE - INTERVAL '30 days'
GROUP BY tenant_id, user_id, date_trunc('day', event_time);

CREATE INDEX idx_login_stats ON user_login_stats(tenant_id, user_id, login_date);
```

**スケーラビリティ対策**
```yaml
architecture:
  primary_db:
    type: "PostgreSQL 15"
    specs: "db.r6g.8xlarge"
    storage: "10TB GP3 SSD"
    
  read_replicas:
    count: 3
    distribution: "cross-az"
    
  caching:
    redis_cluster:
      nodes: 6
      type: "cache.r6g.xlarge"
    
  monitoring:
    - pg_stat_statements
    - custom_metrics
    - slow_query_log
```

## 問題3：API設計

### 解答

**企業向けSSO対応認証API設計**

```yaml
openapi: 3.0.0
info:
  title: Enterprise Authentication API
  version: 1.0.0

paths:
  /auth/login:
    post:
      summary: 統一ログインエンドポイント
      requestBody:
        content:
          application/json:
            schema:
              oneOf:
                - $ref: '#/components/schemas/PasswordLogin'
                - $ref: '#/components/schemas/SSOLogin'
      responses:
        200:
          description: 認証成功
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthResponse'
        302:
          description: SSO認証へのリダイレクト
          headers:
            Location:
              schema:
                type: string
              example: https://idp.example.com/saml/auth?SAMLRequest=...

  /auth/sso/callback:
    post:
      summary: SSO認証コールバック
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties:
                SAMLResponse:
                  type: string
                RelayState:
                  type: string

  /auth/sso/metadata/{tenant_id}:
    get:
      summary: SAML SP メタデータ取得
      parameters:
        - name: tenant_id
          in: path
          required: true
          schema:
            type: string

components:
  schemas:
    PasswordLogin:
      type: object
      required: [type, email, password]
      properties:
        type:
          type: string
          enum: [password]
        email:
          type: string
          format: email
        password:
          type: string
        tenant_id:
          type: string

    SSOLogin:
      type: object
      required: [type, provider]
      properties:
        type:
          type: string
          enum: [sso]
        provider:
          type: string
          enum: [saml, oidc, google, microsoft]
        tenant_id:
          type: string
        return_url:
          type: string

    AuthResponse:
      type: object
      properties:
        access_token:
          type: string
        refresh_token:
          type: string
        token_type:
          type: string
          default: Bearer
        expires_in:
          type: integer
        user:
          $ref: '#/components/schemas/User'
```

**実装の統一インターフェース**

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class AuthRequest:
    tenant_id: str
    return_url: Optional[str] = None
    session_data: Dict[str, Any] = None

@dataclass
class AuthResult:
    success: bool
    user_id: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    redirect_url: Optional[str] = None
    error: Optional[str] = None

class AuthProvider(ABC):
    @abstractmethod
    async def authenticate(self, request: AuthRequest) -> AuthResult:
        pass

class PasswordAuthProvider(AuthProvider):
    async def authenticate(self, request: AuthRequest) -> AuthResult:
        # パスワード認証の実装
        pass

class SAMLAuthProvider(AuthProvider):
    async def authenticate(self, request: AuthRequest) -> AuthResult:
        # SAML認証の実装
        pass

class OIDCAuthProvider(AuthProvider):
    async def authenticate(self, request: AuthRequest) -> AuthResult:
        # OIDC認証の実装
        pass

class UnifiedAuthService:
    def __init__(self):
        self.providers = {
            'password': PasswordAuthProvider(),
            'saml': SAMLAuthProvider(),
            'oidc': OIDCAuthProvider(),
        }
    
    async def authenticate(self, method: str, request: AuthRequest) -> AuthResult:
        provider = self.providers.get(method)
        if not provider:
            return AuthResult(success=False, error="Unsupported auth method")
        
        # 共通の前処理
        await self.pre_auth_checks(request)
        
        # プロバイダ固有の認証
        result = await provider.authenticate(request)
        
        # 共通の後処理
        if result.success:
            await self.post_auth_process(result, request)
        
        return result
```

## 問題4：エラー設計

### 解答

**多言語対応エラーメッセージ体系**

```python
from enum import Enum
from typing import Dict, Optional

class ErrorCode(Enum):
    # 認証エラー
    INVALID_CREDENTIALS = "AUTH001"
    ACCOUNT_LOCKED = "AUTH002"
    SESSION_EXPIRED = "AUTH003"
    MFA_REQUIRED = "AUTH004"
    
    # 認可エラー
    INSUFFICIENT_PERMISSIONS = "AUTHZ001"
    RESOURCE_NOT_FOUND = "AUTHZ002"
    
    # 検証エラー
    INVALID_EMAIL = "VAL001"
    WEAK_PASSWORD = "VAL002"
    
    # システムエラー
    INTERNAL_ERROR = "SYS001"
    SERVICE_UNAVAILABLE = "SYS002"

class ErrorMessages:
    messages = {
        "ja": {
            ErrorCode.INVALID_CREDENTIALS: {
                "message": "メールアドレスまたはパスワードが正しくありません",
                "action": "入力内容を確認してください",
                "support": False
            },
            ErrorCode.ACCOUNT_LOCKED: {
                "message": "セキュリティ上の理由によりアカウントが一時的にロックされています",
                "action": "{retry_after}分後に再度お試しください",
                "support": True
            },
            ErrorCode.WEAK_PASSWORD: {
                "message": "パスワードが安全ではありません",
                "action": "より強力なパスワードを設定してください",
                "details": [
                    "10文字以上で設定してください",
                    "過去に使用したパスワードは使用できません",
                    "一般的な単語は避けてください"
                ],
                "support": False
            }
        },
        "en": {
            ErrorCode.INVALID_CREDENTIALS: {
                "message": "Invalid email or password",
                "action": "Please check your credentials",
                "support": False
            },
            ErrorCode.ACCOUNT_LOCKED: {
                "message": "Account temporarily locked for security reasons",
                "action": "Please try again in {retry_after} minutes",
                "support": True
            }
        },
        "zh": {
            ErrorCode.INVALID_CREDENTIALS: {
                "message": "邮箱或密码不正确",
                "action": "请检查您的输入",
                "support": False
            }
        }
    }

class LocalizedError:
    def __init__(self, code: ErrorCode, lang: str = "ja", **kwargs):
        self.code = code
        self.lang = lang
        self.params = kwargs
        
    def to_response(self) -> Dict:
        error_def = ErrorMessages.messages.get(self.lang, {}).get(self.code)
        
        if not error_def:
            # フォールバック
            error_def = ErrorMessages.messages["en"].get(
                self.code,
                {"message": "Unknown error", "action": "Contact support"}
            )
        
        # パラメータ置換
        message = error_def["message"]
        action = error_def.get("action", "")
        
        for key, value in self.params.items():
            message = message.replace(f"{{% raw %}}{{{key}}}{% endraw %}}", str(value))
            action = action.replace(f"{{% raw %}}{{{key}}}{% endraw %}}", str(value))
        
        response = {
            "error": {
                "code": self.code.value,
                "message": message,
                "action": action,
                "support_required": error_def.get("support", False),
                "request_id": self.params.get("request_id")
            }
        }
        
        if "details" in error_def:
            response["error"]["details"] = error_def["details"]
            
        return response

# セキュリティを考慮したエラーハンドリング
class SecureErrorHandler:
    @staticmethod
    def handle_auth_error(error_type: str, request_context: dict) -> LocalizedError:
        # ログには詳細を記録
        logger.warning(
            f"Authentication failed: {error_type}",
            extra={
                "user_email": request_context.get("email"),
                "ip_address": request_context.get("ip"),
                "user_agent": request_context.get("user_agent")
            }
        )
        
        # ユーザーには曖昧なエラーを返す
        if error_type in ["user_not_found", "invalid_password"]:
            return LocalizedError(
                ErrorCode.INVALID_CREDENTIALS,
                request_context.get("lang", "ja")
            )
        
        # アカウントロックは具体的な情報を提供
        if error_type == "account_locked":
            return LocalizedError(
                ErrorCode.ACCOUNT_LOCKED,
                request_context.get("lang", "ja"),
                retry_after=5
            )
```

## 問題5：パフォーマンス設計

### 解答

**秒間1万リクエスト処理可能な認証システムアーキテクチャ**

```yaml
architecture:
  overview: |
    マルチレイヤーキャッシング + 非同期処理 + 水平スケーリング

  layers:
    edge:
      cdn:
        provider: "CloudFront"
        locations: 3
        cache_strategy:
          - static_assets: 1h
          - api_responses: 0s  # 認証APIはキャッシュしない
      
      waf:
        rate_limiting:
          - global: 100_000/min
          - per_ip: 1000/min
          - per_user: 100/min
    
    api_gateway:
      instances: 10
      type: "Kong Gateway"
      features:
        - jwt_validation  # ステートレス認証
        - rate_limiting
        - circuit_breaker
        - request_routing
      
    application:
      auth_service:
        instances: 20
        type: "Go microservice"
        resources:
          cpu: "4 vCPU"
          memory: "8GB"
        optimizations:
          - connection_pooling
          - prepared_statements
          - goroutine_pool: 1000
      
      session_cache:
        type: "Redis Cluster"
        nodes: 6
        memory: "64GB each"
        strategy:
          - session_data: 30min TTL
          - jwt_blacklist: 24h TTL
          - rate_limit_counters: sliding window
    
    data_layer:
      primary_db:
        type: "PostgreSQL 15"
        configuration:
          max_connections: 1000
          shared_buffers: "32GB"
          effective_cache_size: "96GB"
        
      read_replicas: 5
      
      connection_pooler:
        type: "PgBouncer"
        instances: 4
        pool_mode: "transaction"
        max_client_conn: 10000
```

**性能最適化実装**

```go
package auth

import (
    "context"
    "sync"
    "time"
)

// 認証サービスの最適化実装
type OptimizedAuthService struct {
    // コネクションプール
    dbPool      *sql.DB
    redisPool   *redis.Client
    
    // プリペアドステートメントのキャッシュ
    stmtCache   map[string]*sql.Stmt
    stmtMutex   sync.RWMutex
    
    // インメモリキャッシュ（短期）
    userCache   *lru.Cache
    
    // バッチ処理用チャネル
    auditChan   chan AuditLog
}

// 最適化された認証処理
func (s *OptimizedAuthService) Authenticate(ctx context.Context, email, password string) (*User, error) {
    // 1. レート制限チェック（Redis）
    if err := s.checkRateLimit(ctx, email); err != nil {
        return nil, err
    }
    
    // 2. キャッシュチェック（短期的な再認証対策）
    if cached := s.checkUserCache(email); cached != nil {
        if s.verifyPassword(password, cached.PasswordHash) {
            // 非同期で監査ログ記録
            s.recordAuditAsync(ctx, "login_success", email)
            return cached, nil
        }
    }
    
    // 3. DB検索（プリペアドステートメント使用）
    user, err := s.getUserByEmail(ctx, email)
    if err != nil {
        return nil, err
    }
    
    // 4. パスワード検証（CPU intensive - ワーカープールで実行）
    valid := s.verifyPasswordConcurrent(password, user.PasswordHash)
    if !valid {
        s.recordAuditAsync(ctx, "login_failure", email)
        return nil, ErrInvalidCredentials
    }
    
    // 5. セッション作成（Redis）
    session, err := s.createSession(ctx, user)
    if err != nil {
        return nil, err
    }
    
    // 6. キャッシュ更新
    s.updateUserCache(user)
    
    // 7. 非同期処理
    s.recordAuditAsync(ctx, "login_success", email)
    
    return user, nil
}

// バッチ監査ログ記録
func (s *OptimizedAuthService) auditLogger() {
    batch := make([]AuditLog, 0, 100)
    ticker := time.NewTicker(100 * time.Millisecond)
    
    for {
        select {
        case log := <-s.auditChan:
            batch = append(batch, log)
            
            if len(batch) >= 100 {
                s.flushAuditLogs(batch)
                batch = batch[:0]
            }
            
        case <-ticker.C:
            if len(batch) > 0 {
                s.flushAuditLogs(batch)
                batch = batch[:0]
            }
        }
    }
}

// 段階的なスケーリング計画
type ScalingPlan struct {
    Phases []Phase
}

type Phase struct {
    Load        int
    Duration    string
    Changes     []string
    Cost        string
}

var scalingPlan = ScalingPlan{
    Phases: []Phase{
        {
            Load:     1000,
            Duration: "現在",
            Changes:  []string{"ベースライン構成"},
            Cost:     "$500/月",
        },
        {
            Load:     5000,
            Duration: "6ヶ月後",
            Changes: []string{
                "アプリケーションサーバー 5→10台",
                "Redis クラスター導入",
                "Read Replica 追加",
            },
            Cost: "$2,000/月",
        },
        {
            Load:     10000,
            Duration: "1年後",
            Changes: []string{
                "マルチリージョン展開",
                "専用DBクラスター",
                "エッジキャッシング",
            },
            Cost: "$5,000/月",
        },
    },
}
```

**コスト最適化**

```yaml
cost_optimization:
  strategies:
    - auto_scaling:
        min_instances: 5
        max_instances: 50
        scale_up_threshold: "CPU > 70%"
        scale_down_threshold: "CPU < 30%"
    
    - spot_instances:
        percentage: 50
        fallback: on_demand
    
    - reserved_instances:
        database: 3_year_term
        redis: 1_year_term
    
    - data_lifecycle:
        audit_logs:
          hot: 7_days      # SSD
          warm: 30_days    # HDD  
          cold: 365_days   # S3
          archive: 7_years # Glacier
  
  monitoring:
    - cost_alerts:
        daily_threshold: $200
        monthly_threshold: $5000
    
    - performance_vs_cost:
        target_cost_per_request: $0.0001
        acceptable_latency: 100ms
```