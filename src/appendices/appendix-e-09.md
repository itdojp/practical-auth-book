# 第9章 演習問題解答

## 問題1：マイクロサービス認証設計

### 解答

**Eコマースシステムのマイクロサービス構成と認証アーキテクチャ**

#### サービス一覧と役割

```yaml
services:
  1_api_gateway:
    role: "外部リクエストの受付、認証、ルーティング"
    public: true
    
  2_auth_service:
    role: "認証・認可・トークン管理"
    critical: true
    
  3_user_service:
    role: "ユーザー情報管理"
    pii: true
    
  4_product_service:
    role: "商品カタログ管理"
    cacheable: true
    
  5_inventory_service:
    role: "在庫管理"
    realtime: true
    
  6_cart_service:
    role: "ショッピングカート管理"
    session_bound: true
    
  7_order_service:
    role: "注文処理"
    transactional: true
    
  8_payment_service:
    role: "決済処理"
    pci_compliant: true
    
  9_notification_service:
    role: "通知（メール、SMS、プッシュ）"
    async: true
    
  10_analytics_service:
    role: "分析・レポーティング"
    read_only: true
```

#### 認証フロー設計

```python
class EcommerceAuthFlow:
    """Eコマース認証フロー"""
    
    def user_authentication_flow(self):
        """ユーザー認証フロー"""
        return {
            'sequence': '''
            1. Client → API Gateway: Login request
            2. API Gateway → Auth Service: Validate credentials
            3. Auth Service → User Service: Get user details
            4. Auth Service → API Gateway: Issue tokens
            5. API Gateway → Client: Return tokens
            
            Token Strategy:
            - Access Token: JWT (15分)
            - Refresh Token: Opaque (7日)
            - ID Token: JWT (ユーザー情報)
            ''',
            
            'implementation': '''
            @api_gateway.post("/auth/login")
            async def login(credentials: LoginRequest):
                # 1. 基本的な検証
                if not validate_input(credentials):
                    raise ValidationError()
                
                # 2. Auth Serviceへの認証要求
                auth_result = await auth_service.authenticate(
                    email=credentials.email,
                    password=credentials.password,
                    device_id=request.headers.get("X-Device-ID")
                )
                
                if not auth_result.success:
                    # レート制限の更新
                    await rate_limiter.record_failure(credentials.email)
                    raise AuthenticationError()
                
                # 3. トークン生成
                tokens = await auth_service.create_tokens(
                    user_id=auth_result.user_id,
                    roles=auth_result.roles,
                    device_id=request.headers.get("X-Device-ID")
                )
                
                # 4. セッション情報の保存
                await session_store.create(
                    session_id=tokens.session_id,
                    user_id=auth_result.user_id,
                    tokens=tokens
                )
                
                return {
                    "access_token": tokens.access_token,
                    "refresh_token": tokens.refresh_token,
                    "expires_in": 900
                }
            '''
        }
    
    def service_to_service_flow(self):
        """サービス間認証フロー"""
        return {
            'pattern': 'Service Mesh with mTLS + Service Tokens',
            
            'implementation': '''
            class ServiceAuthenticator:
                def __init__(self):
                    self.service_registry = ServiceRegistry()
                    self.token_issuer = ServiceTokenIssuer()
                
                async def authenticate_service(self, cert: Certificate) -> ServiceIdentity:
                    # 1. mTLSによる相互認証
                    service_name = extract_service_name(cert)
                    if not self.verify_certificate(cert):
                        raise InvalidCertificateError()
                    
                    # 2. サービスの登録確認
                    service = await self.service_registry.get(service_name)
                    if not service or not service.active:
                        raise UnregisteredServiceError()
                    
                    # 3. サービストークンの発行
                    token = self.token_issuer.issue(
                        service_name=service_name,
                        permissions=service.permissions,
                        validity=timedelta(minutes=5)
                    )
                    
                    return ServiceIdentity(
                        name=service_name,
                        token=token,
                        permissions=service.permissions
                    )
            '''
        }
    
    def token_strategy(self):
        """トークン戦略"""
        return {
            'token_types': {
                'user_access_token': {
                    'format': 'JWT',
                    'claims': {
                        'sub': 'user_id',
                        'roles': ['customer', 'premium'],
                        'sid': 'session_id',
                        'did': 'device_id'
                    },
                    'ttl': '15 minutes',
                    'usage': 'API呼び出し'
                },
                
                'service_token': {
                    'format': 'JWT (内部署名)',
                    'claims': {
                        'iss': 'auth-service',
                        'sub': 'service-name',
                        'aud': 'target-service',
                        'permissions': ['read', 'write']
                    },
                    'ttl': '5 minutes',
                    'usage': 'サービス間通信'
                },
                
                'delegation_token': {
                    'format': 'JWT',
                    'claims': {
                        'act': 'acting-service',
                        'sub': 'original-user',
                        'dlg': 'delegation-chain'
                    },
                    'ttl': '2 minutes',
                    'usage': 'サービス連鎖での権限委譲'
                }
            }
        }
    
    def error_handling(self):
        """エラー処理戦略"""
        return {
            'error_responses': {
                'auth_service_down': {
                    'fallback': 'Cache-based validation',
                    'response': {
                        'status': 503,
                        'error': 'AUTH_SERVICE_UNAVAILABLE',
                        'message': 'Authentication service is temporarily unavailable',
                        'retry_after': 30
                    }
                },
                
                'token_expired': {
                    'auto_refresh': True,
                    'response': {
                        'status': 401,
                        'error': 'TOKEN_EXPIRED',
                        'message': 'Access token has expired',
                        'refresh_endpoint': '/auth/refresh'
                    }
                },
                
                'insufficient_permissions': {
                    'log_attempt': True,
                    'response': {
                        'status': 403,
                        'error': 'INSUFFICIENT_PERMISSIONS',
                        'message': 'You do not have permission to access this resource',
                        'required_roles': ['admin']
                    }
                }
            },
            
            'circuit_breaker': '''
            @circuit_breaker(
                failure_threshold=5,
                recovery_timeout=60,
                expected_exception=ServiceUnavailableError
            )
            async def call_auth_service(request):
                try:
                    return await auth_service.validate(request)
                except TimeoutError:
                    # フォールバック処理
                    return await validate_from_cache(request)
            '''
        }
```

## 問題2：API Gateway実装

### 解答

```python
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, Dict, Any
import httpx
import jwt
import redis
import time
from datetime import datetime, timedelta
import asyncio
import logging

# FastAPI アプリケーション
app = FastAPI(title="API Gateway")

# 設定
class Config:
    JWT_SECRET = "your-secret-key"
    JWT_ALGORITHM = "HS256"
    REDIS_URL = "redis://localhost:6379"
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW = 3600  # 1時間
    
    # サービスレジストリ
    SERVICES = {
        "users": "http://user-service:8080",
        "products": "http://product-service:8080",
        "orders": "http://order-service:8080"
    }

# 依存性注入
security = HTTPBearer()
redis_client = redis.from_url(Config.REDIS_URL, decode_responses=True)
logger = logging.getLogger(__name__)

# JWT検証
class JWTValidator:
    @staticmethod
    def decode_token(token: str) -> Dict[str, Any]:
        try:
            payload = jwt.decode(
                token,
                Config.JWT_SECRET,
                algorithms=[Config.JWT_ALGORITHM]
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")

# レート制限
class RateLimiter:
    def __init__(self, redis_client):
        self.redis = redis_client
        
    async def check_rate_limit(self, user_id: str) -> bool:
        key = f"rate_limit:{user_id}"
        current_time = int(time.time())
        window_start = current_time - Config.RATE_LIMIT_WINDOW
        
        # スライディングウィンドウログアルゴリズム
        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zadd(key, {str(current_time): current_time})
        pipe.zcount(key, window_start, current_time)
        pipe.expire(key, Config.RATE_LIMIT_WINDOW)
        
        results = pipe.execute()
        request_count = results[2]
        
        if request_count > Config.RATE_LIMIT_REQUESTS:
            return False
        return True

# 監査ログ
class AuditLogger:
    def __init__(self, redis_client):
        self.redis = redis_client
        
    async def log_request(self, user_id: str, request: Request, response_status: int):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "method": request.method,
            "path": str(request.url.path),
            "query_params": dict(request.query_params),
            "client_ip": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "response_status": response_status,
            "request_id": request.state.request_id
        }
        
        # Redisにログを保存（有効期限30日）
        key = f"audit_log:{datetime.utcnow().strftime('%Y%m%d')}:{user_id}"
        self.redis.rpush(key, json.dumps(log_entry))
        self.redis.expire(key, 30 * 24 * 3600)
        
        # 非同期でログファイルにも書き込み
        logger.info(f"API Request: {log_entry}")

# 依存性注入用の関数
rate_limiter = RateLimiter(redis_client)
audit_logger = AuditLogger(redis_client)
jwt_validator = JWTValidator()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    user_data = jwt_validator.decode_token(token)
    
    # レート制限チェック
    if not await rate_limiter.check_rate_limit(user_data["sub"]):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": "3600"}
        )
    
    return user_data

# プロキシ機能
class ServiceProxy:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)
        
    async def forward_request(
        self,
        service: str,
        path: str,
        method: str,
        headers: dict,
        body: bytes,
        params: dict
    ) -> httpx.Response:
        if service not in Config.SERVICES:
            raise HTTPException(status_code=404, detail="Service not found")
        
        service_url = Config.SERVICES[service]
        url = f"{service_url}/{path}"
        
        # 内部ヘッダーの追加
        internal_headers = headers.copy()
        internal_headers["X-Internal-Request"] = "true"
        internal_headers["X-Request-ID"] = headers.get("X-Request-ID", "")
        
        try:
            response = await self.client.request(
                method=method,
                url=url,
                headers=internal_headers,
                content=body,
                params=params
            )
            return response
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Service timeout")
        except httpx.HTTPError:
            raise HTTPException(status_code=502, detail="Service error")

proxy = ServiceProxy()

# ミドルウェア
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    
    return response

# エンドポイント
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway_proxy(
    service: str,
    path: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    # リクエストボディの読み取り
    body = await request.body()
    
    # ヘッダーの準備
    headers = dict(request.headers)
    headers["X-User-ID"] = current_user["sub"]
    headers["X-User-Roles"] = ",".join(current_user.get("roles", []))
    
    # サービスへのプロキシ
    response = await proxy.forward_request(
        service=service,
        path=path,
        method=request.method,
        headers=headers,
        body=body,
        params=dict(request.query_params)
    )
    
    # 監査ログ
    await audit_logger.log_request(
        user_id=current_user["sub"],
        request=request,
        response_status=response.status_code
    )
    
    # レスポンスの返却
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers)
    )

# 管理用エンドポイント
@app.get("/admin/metrics")
async def get_metrics(current_user: dict = Depends(get_current_user)):
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # メトリクスの収集
    metrics = {
        "timestamp": datetime.utcnow().isoformat(),
        "active_connections": len(proxy.client._pool._connections),
        "rate_limit_status": {}
    }
    
    # レート制限状況の取得
    for key in redis_client.scan_iter("rate_limit:*"):
        user_id = key.split(":")[-1]
        count = redis_client.zcount(key, "-inf", "+inf")
        metrics["rate_limit_status"][user_id] = {
            "current_requests": count,
            "limit": Config.RATE_LIMIT_REQUESTS
        }
    
    return metrics

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

## 問題3：Zero Trust設計

### 解答

**金融システムへのZero Trust原則適用設計**

```python
class FinancialZeroTrustDesign:
    """金融システムのZero Trust設計"""
    
    def risk_assessment_factors(self):
        """リスク評価要素（10個以上）"""
        return {
            'device_factors': {
                'device_trust_score': {
                    'weight': 15,
                    'calculation': '''
                    - 管理デバイス: 100
                    - 登録済み個人デバイス: 70
                    - 未登録デバイス: 30
                    - ルート化/Jailbreak: 0
                    '''
                },
                'device_compliance': {
                    'weight': 10,
                    'checks': [
                        'OS最新パッチ適用',
                        'アンチウイルス有効',
                        'ディスク暗号化',
                        'ファイアウォール有効'
                    ]
                }
            },
            
            'location_factors': {
                'geolocation_risk': {
                    'weight': 20,
                    'scoring': '''
                    def calculate_location_risk(ip_address, gps_coords):
                        country_risk = get_country_risk_score(ip_address)
                        
                        # 高リスク国からのアクセス
                        if country_risk > 80:
                            return 100
                        
                        # オフィスからのアクセス
                        if is_office_location(gps_coords):
                            return 10
                        
                        # VPN使用
                        if is_vpn(ip_address):
                            return 70
                        
                        return country_risk
                    '''
                },
                'impossible_travel': {
                    'weight': 25,
                    'detection': 'Previous location vs current location / time'
                }
            },
            
            'behavioral_factors': {
                'access_pattern': {
                    'weight': 10,
                    'analysis': [
                        '通常のアクセス時間帯か',
                        'アクセス頻度の異常',
                        '通常と異なるアプリケーション使用'
                    ]
                },
                'transaction_behavior': {
                    'weight': 20,
                    'checks': [
                        '取引金額の異常',
                        '送金先の異常',
                        '取引頻度の急激な変化'
                    ]
                }
            },
            
            'authentication_factors': {
                'auth_method_strength': {
                    'weight': 15,
                    'scores': {
                        'password_only': 30,
                        'password_mfa_sms': 60,
                        'password_mfa_app': 80,
                        'biometric_mfa': 95,
                        'hardware_key': 100
                    }
                },
                'session_age': {
                    'weight': 5,
                    'calculation': 'exponential_decay(session_duration)'
                }
            },
            
            'network_factors': {
                'network_reputation': {
                    'weight': 10,
                    'checks': [
                        'Known malicious IP',
                        'Tor exit node',
                        'Public WiFi',
                        'Corporate network'
                    ]
                },
                'connection_security': {
                    'weight': 5,
                    'requirements': [
                        'TLS 1.3',
                        'Certificate pinning',
                        'No weak ciphers'
                    ]
                }
            },
            
            'resource_sensitivity': {
                'data_classification': {
                    'weight': 30,
                    'levels': {
                        'public': 10,
                        'internal': 30,
                        'confidential': 60,
                        'restricted': 100
                    }
                },
                'operation_risk': {
                    'weight': 25,
                    'operations': {
                        'read_balance': 20,
                        'internal_transfer': 50,
                        'external_transfer': 80,
                        'wire_transfer': 100,
                        'account_closure': 90
                    }
                }
            }
        }
    
    def dynamic_access_control(self):
        """動的アクセス制御ルール"""
        return {
            'rule_engine': '''
            class DynamicAccessController:
                def evaluate_access(self, context: AccessContext) -> AccessDecision:
                    risk_score = self.calculate_risk_score(context)
                    
                    # リスクレベルの判定
                    if risk_score < 30:
                        risk_level = "LOW"
                    elif risk_score < 60:
                        risk_level = "MEDIUM"
                    elif risk_score < 80:
                        risk_level = "HIGH"
                    else:
                        risk_level = "CRITICAL"
                    
                    # リソース感度の取得
                    resource_sensitivity = self.get_resource_sensitivity(context.resource)
                    
                    # 動的ルールの適用
                    return self.apply_rules(risk_level, resource_sensitivity, context)
            ''',
            
            'access_rules': {
                'low_risk': {
                    'public_data': 'ALLOW',
                    'internal_data': 'ALLOW',
                    'confidential_data': 'ALLOW',
                    'restricted_data': 'ALLOW_WITH_LOGGING'
                },
                
                'medium_risk': {
                    'public_data': 'ALLOW',
                    'internal_data': 'ALLOW',
                    'confidential_data': 'REQUIRE_MFA',
                    'restricted_data': 'REQUIRE_MFA_AND_APPROVAL'
                },
                
                'high_risk': {
                    'public_data': 'ALLOW',
                    'internal_data': 'REQUIRE_MFA',
                    'confidential_data': 'REQUIRE_STEP_UP_AUTH',
                    'restricted_data': 'DENY'
                },
                
                'critical_risk': {
                    'public_data': 'ALLOW_READ_ONLY',
                    'internal_data': 'DENY',
                    'confidential_data': 'DENY',
                    'restricted_data': 'DENY_AND_ALERT'
                }
            },
            
            'step_up_authentication': '''
            async def require_step_up_auth(user: User, required_level: str):
                current_auth_level = user.current_auth_level
                
                if required_level == "MFA" and current_auth_level < 2:
                    return await prompt_mfa(user)
                
                elif required_level == "BIOMETRIC" and current_auth_level < 3:
                    return await prompt_biometric(user)
                
                elif required_level == "TRANSACTION_SIGNING":
                    return await prompt_transaction_signing(user)
            '''
        }
    
    def continuous_verification(self):
        """継続的検証の実装"""
        return {
            'verification_triggers': [
                'Periodic time-based (every 5 minutes)',
                'Resource access attempt',
                'Behavioral anomaly detected',
                'Risk score change > 20 points',
                'Network change',
                'New device detected'
            ],
            
            'implementation': '''
            class ContinuousVerificationEngine:
                def __init__(self):
                    self.verification_interval = timedelta(minutes=5)
                    self.risk_threshold_delta = 20
                
                async def monitor_session(self, session_id: str):
                    session = await self.get_session(session_id)
                    last_risk_score = session.risk_score
                    
                    while session.active:
                        # 定期的な検証
                        await asyncio.sleep(self.verification_interval.seconds)
                        
                        # リスク再評価
                        current_context = await self.build_context(session)
                        new_risk_score = await self.calculate_risk(current_context)
                        
                        # 大幅なリスク変化の検出
                        if abs(new_risk_score - last_risk_score) > self.risk_threshold_delta:
                            await self.handle_risk_change(session, new_risk_score)
                        
                        # 行動分析
                        anomalies = await self.detect_anomalies(session)
                        if anomalies:
                            await self.handle_anomalies(session, anomalies)
                        
                        last_risk_score = new_risk_score
            '''
        }
    
    def incident_response_flow(self):
        """インシデント対応フロー"""
        return {
            'detection_to_response': '''
            class IncidentResponseOrchestrator:
                async def handle_security_incident(self, incident: SecurityIncident):
                    # 1. 即座の封じ込め
                    if incident.severity >= Severity.HIGH:
                        await self.immediate_containment(incident)
                    
                    # 2. 調査
                    investigation = await self.investigate(incident)
                    
                    # 3. 影響評価
                    impact = await self.assess_impact(investigation)
                    
                    # 4. 対応実施
                    response_plan = self.create_response_plan(impact)
                    await self.execute_response(response_plan)
                    
                    # 5. 復旧
                    await self.recovery_actions(incident)
                    
                    # 6. 事後分析
                    await self.post_incident_analysis(incident)
            ''',
            
            'response_actions': {
                'immediate_containment': [
                    'セッションの即時無効化',
                    'アカウントの一時凍結',
                    '関連するAPIキーの無効化',
                    'IPアドレスのブロック'
                ],
                
                'investigation_steps': [
                    'ログの収集と分析',
                    '影響を受けたリソースの特定',
                    'アクセスパターンの分析',
                    '関連するセッションの調査'
                ],
                
                'recovery_actions': [
                    'パスワードリセット要求',
                    'MFA再登録',
                    'デバイス再認証',
                    'セキュリティ質問の更新'
                ],
                
                'notification_matrix': {
                    'low_severity': ['Security team'],
                    'medium_severity': ['Security team', 'User'],
                    'high_severity': ['Security team', 'User', 'Management'],
                    'critical_severity': ['All above', 'CISO', 'Legal', 'PR']
                }
            }
        }
```

## 問題4：サービスメッシュ設定

### 解答

**Istioを使用したセキュリティポリシー実装**

```yaml
# 1. mTLS設定 - すべてのサービス間で必須
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT

---
# 2. データベースサービスへのアクセス制限
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: database-access-policy
  namespace: production
spec:
  selector:
    matchLabels:
      app: database
  action: ALLOW
  rules:
  - from:
    - source:
        principals: 
        - "cluster.local/ns/production/sa/order-service"
        - "cluster.local/ns/production/sa/user-service"
        - "cluster.local/ns/production/sa/inventory-service"
    to:
    - operation:
        methods: ["GET", "POST", "PUT", "DELETE"]
        ports: ["5432"]

---
# 3. API Gateway経由のみ外部トラフィックを許可
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: api-gateway
  namespace: production
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      credentialName: api-cert
    hosts:
    - "api.example.com"

---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: api-routing
  namespace: production
spec:
  hosts:
  - "api.example.com"
  gateways:
  - api-gateway
  http:
  - match:
    - uri:
        prefix: "/api/v1/"
    route:
    - destination:
        host: api-gateway-service
        port:
          number: 8080

---
# 外部からの直接アクセスを拒否
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-external-access
  namespace: production
spec:
  selector:
    matchLabels:
      internal: "true"
  action: DENY
  rules:
  - from:
    - source:
        notNamespaces: ["production", "istio-system"]

---
# 4. サービスごとのレート制限
apiVersion: v1
kind: ConfigMap
metadata:
  name: ratelimit-config
  namespace: production
data:
  config.yaml: |
    domain: production-ratelimit
    descriptors:
      - key: service
        value: "user-service"
        rate_limit:
          unit: minute
          requests_per_unit: 1000
      - key: service
        value: "order-service"
        rate_limit:
          unit: minute
          requests_per_unit: 500
      - key: service
        value: "payment-service"
        rate_limit:
          unit: minute
          requests_per_unit: 100
      - key: service
        value: "analytics-service"
        rate_limit:
          unit: minute
          requests_per_unit: 2000

---
apiVersion: v1
kind: Service
metadata:
  name: ratelimit
  namespace: production
spec:
  ports:
  - port: 8081
    protocol: TCP
  selector:
    app: ratelimit

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ratelimit
  namespace: production
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ratelimit
  template:
    metadata:
      labels:
        app: ratelimit
    spec:
      containers:
      - name: ratelimit
        image: envoyproxy/ratelimit:v1.4.0
        command: ["/bin/ratelimit"]
        env:
        - name: LOG_LEVEL
          value: debug
        - name: REDIS_SOCKET_TYPE
          value: tcp
        - name: REDIS_URL
          value: redis:6379
        - name: USE_STATSD
          value: "false"
        - name: RUNTIME_ROOT
          value: /data
        - name: RUNTIME_SUBDIRECTORY
          value: ratelimit
        ports:
        - containerPort: 8080
        - containerPort: 8081
        - containerPort: 6070
        volumeMounts:
        - name: config-volume
          mountPath: /data/ratelimit/config
      volumes:
      - name: config-volume
        configMap:
          name: ratelimit-config

---
# EnvoyFilterでレート制限を適用
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: ratelimit-filter
  namespace: production
spec:
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.ratelimit
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.ratelimit.v3.RateLimit
          domain: production-ratelimit
          failure_mode_deny: false
          rate_limit_service:
            grpc_service:
              envoy_grpc:
                cluster_name: rate_limit_service
              timeout: 0.25s
            transport_api_version: V3

---
# サービスメッシュ全体の可観測性設定
apiVersion: v1
kind: ConfigMap
metadata:
  name: istio-custom-telemetry
  namespace: istio-system
data:
  custom_metrics.yaml: |
    telemetry:
    - name: security-metrics
      dimensions:
        source_service: source.workload.name | "unknown"
        destination_service: destination.service.name | "unknown"
        auth_result: connection.mtls | "none"
        response_code: response.code | 0
      metrics:
      - name: security_request_count
        dimensions:
          - source_service
          - destination_service
          - auth_result
          - response_code
        value: "1"
      - name: unauthorized_access_attempts
        dimensions:
          - source_service
          - destination_service
        value: response.code == 403 ? 1 : 0
```

## 問題5：パフォーマンス最適化

### 解答

**認証処理ボトルネック最適化計画**

```python
class AuthPerformanceOptimization:
    """認証パフォーマンス最適化"""
    
    def current_analysis(self):
        """現状分析"""
        return {
            'latency_measurements': {
                'auth_service_calls': {
                    'p50': '150ms',
                    'p95': '500ms',
                    'p99': '1200ms',
                    'breakdown': {
                        'network': '20ms',
                        'jwt_validation': '80ms',
                        'database_lookup': '200ms',
                        'permission_check': '150ms',
                        'response_serialization': '50ms'
                    }
                },
                
                'bottleneck_identification': '''
                # プロファイリング結果
                1. DB クエリ (40% of time)
                   - User lookup: 150ms avg
                   - Permission fetch: 100ms avg
                   - N+1 問題あり
                
                2. JWT 検証 (16% of time)
                   - RSA署名検証: 80ms
                   - 毎回公開鍵取得
                
                3. 権限チェック (30% of time)
                   - 複雑なRBACルール
                   - キャッシュなし
                
                4. ネットワーク (14% of time)
                   - サービス間の往復
                   - TLS handshake
                '''
            }
        }
    
    def optimization_strategies(self):
        """最適化案（5つ以上）"""
        return {
            '1_caching_strategy': {
                'description': 'マルチレベルキャッシング',
                'implementation': '''
                class MultiLevelCache:
                    def __init__(self):
                        # L1: プロセス内キャッシュ（超高速）
                        self.l1_cache = LRUCache(maxsize=10000, ttl=60)
                        
                        # L2: Redis（高速、分散）
                        self.l2_cache = RedisCache(ttl=300)
                        
                        # L3: CDN（エッジキャッシング）
                        self.l3_cache = CDNCache(ttl=600)
                    
                    async def get_user_permissions(self, user_id: str):
                        # L1チェック
                        if data := self.l1_cache.get(user_id):
                            return data
                        
                        # L2チェック
                        if data := await self.l2_cache.get(user_id):
                            self.l1_cache.set(user_id, data)
                            return data
                        
                        # DBから取得
                        data = await self.fetch_from_db(user_id)
                        
                        # 全レベルにキャッシュ
                        await self.cache_all_levels(user_id, data)
                        
                        return data
                ''',
                'expected_improvement': '60-80% reduction in DB calls'
            },
            
            '2_jwt_optimization': {
                'description': 'JWT検証の最適化',
                'implementation': '''
                class OptimizedJWTValidator:
                    def __init__(self):
                        # 公開鍵のキャッシュ
                        self.key_cache = {}
                        
                        # より高速なアルゴリズムへ移行
                        self.algorithm = 'ES256'  # ECDSAは RSAより高速
                        
                        # JWTのプリバリデーション
                        self.prevalidation_cache = TTLCache(maxsize=10000, ttl=300)
                    
                    def validate_token_fast(self, token: str):
                        # キャッシュチェック
                        if token in self.prevalidation_cache:
                            return self.prevalidation_cache[token]
                        
                        # 高速な基本チェック
                        if not self.quick_format_check(token):
                            return None
                        
                        # 署名検証（最適化済み）
                        claims = self.verify_signature_optimized(token)
                        
                        # キャッシュに保存
                        self.prevalidation_cache[token] = claims
                        
                        return claims
                ''',
                'expected_improvement': 'JWT validation from 80ms to 10ms'
            },
            
            '3_database_optimization': {
                'description': 'データベースクエリ最適化',
                'implementation': '''
                -- 複合インデックスの追加
                CREATE INDEX idx_user_permissions ON user_permissions(user_id, resource_type, permission);
                
                -- マテリアライズドビューの作成
                CREATE MATERIALIZED VIEW user_effective_permissions AS
                SELECT 
                    u.id as user_id,
                    r.name as role,
                    array_agg(DISTINCT p.permission) as permissions
                FROM users u
                JOIN user_roles ur ON u.id = ur.user_id
                JOIN roles r ON ur.role_id = r.id
                JOIN role_permissions rp ON r.id = rp.role_id
                JOIN permissions p ON rp.permission_id = p.id
                GROUP BY u.id, r.name;
                
                -- コネクションプーリングの最適化
                class OptimizedDBPool:
                    def __init__(self):
                        self.pool = asyncpg.create_pool(
                            min_size=20,
                            max_size=100,
                            max_queries=50000,
                            max_inactive_connection_lifetime=300,
                            command_timeout=10
                        )
                ''',
                'expected_improvement': 'Query time from 200ms to 20ms'
            },
            
            '4_service_mesh_optimization': {
                'description': 'サービスメッシュレベルの最適化',
                'implementation': '''
                # gRPC の使用（HTTPより効率的）
                service AuthService {
                    rpc ValidateToken(TokenRequest) returns (TokenResponse);
                    rpc GetPermissions(PermissionRequest) returns (PermissionResponse);
                }
                
                # バッチリクエスト
                service BatchAuthService {
                    rpc BatchValidate(BatchTokenRequest) returns (BatchTokenResponse);
                }
                
                # コネクション再利用
                class ServiceClient:
                    def __init__(self):
                        self.channel_pool = {
                            'auth': grpc.aio.insecure_channel(
                                'auth-service:50051',
                                options=[
                                    ('grpc.keepalive_time_ms', 10000),
                                    ('grpc.keepalive_timeout_ms', 5000),
                                    ('grpc.http2.max_pings_without_data', 0),
                                    ('grpc.http2.min_time_between_pings_ms', 10000),
                                ]
                            )
                        }
                ''',
                'expected_improvement': 'Network overhead reduced by 40%'
            },
            
            '5_edge_computing': {
                'description': 'エッジでの認証処理',
                'implementation': '''
                # CloudFlare Workers での JWT検証
                addEventListener('fetch', event => {
                    event.respondWith(handleRequest(event.request))
                })
                
                async function handleRequest(request) {
                    const token = request.headers.get('Authorization')
                    
                    // エッジでの高速JWT検証
                    const claims = await verifyJWT(token)
                    
                    if (!claims) {
                        return new Response('Unauthorized', { status: 401 })
                    }
                    
                    // 検証済みヘッダーを追加してオリジンへ
                    request.headers.set('X-Verified-User', claims.sub)
                    request.headers.set('X-Verified-Roles', claims.roles.join(','))
                    
                    return fetch(request)
                }
                ''',
                'expected_improvement': 'Reduce origin auth calls by 90%'
            }
        }
    
    def implementation_priority(self):
        """実装優先順位"""
        return {
            'priority_matrix': {
                'immediate': [
                    {
                        'task': 'L1/L2キャッシング実装',
                        'effort': '1 week',
                        'impact': 'High',
                        'risk': 'Low'
                    },
                    {
                        'task': 'データベースインデックス追加',
                        'effort': '2 days',
                        'impact': 'Medium',
                        'risk': 'Low'
                    }
                ],
                
                'short_term': [
                    {
                        'task': 'JWT アルゴリズム変更',
                        'effort': '2 weeks',
                        'impact': 'Medium',
                        'risk': 'Medium'
                    },
                    {
                        'task': 'コネクションプーリング最適化',
                        'effort': '1 week',
                        'impact': 'Medium',
                        'risk': 'Low'
                    }
                ],
                
                'long_term': [
                    {
                        'task': 'gRPC移行',
                        'effort': '1 month',
                        'impact': 'High',
                        'risk': 'Medium'
                    },
                    {
                        'task': 'エッジコンピューティング',
                        'effort': '2 months',
                        'impact': 'Very High',
                        'risk': 'Medium'
                    }
                ]
            }
        }
    
    def expected_results(self):
        """期待される改善効果"""
        return {
            'performance_targets': {
                'current': {
                    'p50': '150ms',
                    'p95': '500ms',
                    'p99': '1200ms',
                    'throughput': '1000 req/s'
                },
                
                'after_optimization': {
                    'p50': '20ms',
                    'p95': '50ms',
                    'p99': '100ms',
                    'throughput': '10000 req/s'
                }
            },
            
            'cost_benefit': {
                'implementation_cost': '$50,000',
                'infrastructure_savings': '$20,000/month',
                'roi_period': '3 months'
            },
            
            'monitoring_plan': '''
            # Prometheusメトリクス
            - auth_request_duration_seconds
            - auth_cache_hit_rate
            - auth_db_query_duration_seconds
            - auth_jwt_validation_duration_seconds
            
            # アラート設定
            - P95 latency > 100ms
            - Cache hit rate < 80%
            - Error rate > 1%
            '''
        }
```