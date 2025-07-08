# 第9章 マイクロサービスでの認証認可

## なぜこの章が重要か

マイクロサービスアーキテクチャの採用が進む中、認証認可の実装は格段に複雑になっています。モノリシックなアプリケーションでは単一のセッション管理で済んでいたものが、分散環境では各サービス間の信頼関係の確立、一貫性のある認可判断、パフォーマンスの維持など、多くの課題に直面します。この章では、マイクロサービス環境特有の認証認可の課題と、それらを解決する実践的なパターンを学びます。

## 9.1 分散システムでの課題

### 9.1.1 マイクロサービスにおける認証認可の複雑性

```python
class MicroservicesAuthChallenges:
    """マイクロサービスでの認証認可の課題"""
    
    def illustrate_complexity(self):
        """複雑性の図解"""
        
        return {
            'monolithic_vs_microservices': {
                'monolithic': {
                    'auth_points': 1,
                    'session_storage': 'Single database',
                    'authorization': 'In-process function calls',
                    'consistency': 'Guaranteed by transactions',
                    'performance': 'Memory access',
                    'security_boundary': 'Application perimeter'
                },
                
                'microservices': {
                    'auth_points': 'N services × M endpoints',
                    'session_storage': 'Distributed cache/tokens',
                    'authorization': 'Network calls',
                    'consistency': 'Eventually consistent',
                    'performance': 'Network latency',
                    'security_boundary': 'Every service'
                }
            },
            
            'key_challenges': {
                'service_proliferation': {
                    'problem': 'サービス数の増加に伴う管理複雑性',
                    'example': '''
                    10 services × 5 endpoints × 3 methods = 150 auth points
                    各ポイントで：
                    - 認証の検証
                    - 認可の判断
                    - 監査ログ
                    ''',
                    'impact': 'メンテナンスコストの指数的増加'
                },
                
                'distributed_state': {
                    'problem': 'セッション状態の分散管理',
                    'example': '''
                    User → API Gateway → Service A → Service B → Service C
                           ↓              ↓           ↓           ↓
                        Session?     Session?    Session?    Session?
                    ''',
                    'impact': 'パフォーマンス劣化、複雑性増大'
                },
                
                'service_to_service': {
                    'problem': 'サービス間の信頼関係確立',
                    'example': '''
                    Order Service が Inventory Service を呼ぶ際：
                    - Order Service の正当性をどう証明？
                    - ユーザーコンテキストをどう伝播？
                    - 権限の委譲をどう制御？
                    ''',
                    'impact': 'セキュリティリスク、実装の複雑化'
                }
            }
        }
    
    def security_implications(self):
        """セキュリティへの影響"""
        
        return {
            'attack_surface_expansion': {
                'description': '攻撃対象面の拡大',
                'factors': [
                    'すべてのサービスが潜在的な侵入点',
                    'サービス間通信の盗聴リスク',
                    'トークンの漏洩ポイント増加'
                ],
                'mitigation': 'Zero Trust原則の適用'
            },
            
            'cascading_vulnerabilities': {
                'description': '脆弱性の連鎖',
                'scenario': '''
                1. Service A の認証バイパス脆弱性
                2. Service A として Service B にアクセス
                3. Service B の権限で Service C にアクセス
                4. 権限昇格の連鎖
                ''',
                'mitigation': '最小権限原則、サービスメッシュ'
            },
            
            'token_management_complexity': {
                'description': 'トークン管理の複雑化',
                'issues': [
                    'トークンのライフサイクル管理',
                    '無効化の即時反映',
                    'トークンサイズとネットワーク負荷'
                ],
                'mitigation': '適切なトークン戦略の選択'
            }
        }
```

### 9.1.2 パフォーマンスとスケーラビリティの課題

```python
class PerformanceScalabilityChallenges:
    """パフォーマンスとスケーラビリティの課題"""
    
    def latency_accumulation(self):
        """レイテンシの蓄積問題"""
        
        return {
            'latency_breakdown': {
                'traditional_monolith': {
                    'auth_check': '< 1ms (in-memory)',
                    'total_request': '50ms'
                },
                
                'naive_microservices': {
                    'per_service_auth': '10-20ms',
                    'service_chain_5_deep': '50-100ms just for auth',
                    'total_request': '200-300ms'
                },
                
                'optimized_microservices': {
                    'edge_auth': '10ms',
                    'service_trust': '< 1ms (JWT validation)',
                    'total_request': '60-80ms'
                }
            },
            
            'optimization_strategies': {
                'caching': '''
                class TokenCache:
                    def __init__(self, ttl=300):
                        self.cache = TTLCache(maxsize=10000, ttl=ttl)
                        self.stats = CacheStats()
                    
                    def validate_token(self, token: str) -> Optional[Claims]:
                        # キャッシュチェック
                        if token in self.cache:
                            self.stats.hits += 1
                            return self.cache[token]
                        
                        # 検証とキャッシュ
                        self.stats.misses += 1
                        claims = self._validate_jwt(token)
                        if claims:
                            self.cache[token] = claims
                        return claims
                ''',
                
                'connection_pooling': '''
                # 認証サービスへの接続プール
                auth_client = AuthServiceClient(
                    pool_size=20,
                    max_overflow=10,
                    timeout=1.0,
                    retry_policy=ExponentialBackoff(max_retries=3)
                )
                ''',
                
                'circuit_breaking': '''
                @circuit_breaker(
                    failure_threshold=5,
                    recovery_timeout=60,
                    expected_exception=AuthServiceException
                )
                def check_authorization(self, token, resource, action):
                    # 認可サービスが落ちても、デフォルト動作で継続
                    return self.auth_service.authorize(token, resource, action)
                '''
            }
        }
    
    def scalability_patterns(self):
        """スケーラビリティパターン"""
        
        return {
            'horizontal_scaling': {
                'auth_service_scaling': '''
                apiVersion: autoscaling/v2
                kind: HorizontalPodAutoscaler
                metadata:
                  name: auth-service-hpa
                spec:
                  scaleTargetRef:
                    apiVersion: apps/v1
                    kind: Deployment
                    name: auth-service
                  minReplicas: 3
                  maxReplicas: 20
                  metrics:
                  - type: Resource
                    resource:
                      name: cpu
                      target:
                        type: Utilization
                        averageUtilization: 70
                  - type: Resource
                    resource:
                      name: memory
                      target:
                        type: Utilization
                        averageUtilization: 80
                ''',
                
                'cache_distribution': '''
                # Redis Clusterによる分散キャッシュ
                class DistributedSessionStore:
                    def __init__(self):
                        self.redis = RedisCluster(
                            startup_nodes=[
                                {"host": "redis-1", "port": 6379},
                                {"host": "redis-2", "port": 6379},
                                {"host": "redis-3", "port": 6379}
                            ],
                            decode_responses=True,
                            skip_full_coverage_check=True
                        )
                    
                    def get_session(self, session_id: str) -> Optional[Session]:
                        data = self.redis.get(f"session:{session_id}")
                        return Session.from_json(data) if data else None
                '''
            },
            
            'load_distribution': {
                'sticky_sessions_avoided': '''
                # JWTによるステートレス認証でスティッキーセッション不要
                @app.before_request
                def validate_request():
                    token = extract_token_from_header()
                    if not token:
                        return jsonify({"error": "No token"}), 401
                    
                    # 任意のインスタンスで検証可能
                    claims = validate_jwt(token)
                    if not claims:
                        return jsonify({"error": "Invalid token"}), 401
                    
                    g.user = claims
                ''',
                
                'regional_deployment': '''
                # マルチリージョン展開
                regions = {
                    'us-east': 'auth-us-east.example.com',
                    'eu-west': 'auth-eu-west.example.com',
                    'ap-northeast': 'auth-ap-northeast.example.com'
                }
                
                # GeoDNSによる最適なリージョンへのルーティング
                '''
            }
        }
```

### 9.1.3 一貫性と状態管理の課題

```python
class ConsistencyStateManagement:
    """一貫性と状態管理の課題"""
    
    def consistency_challenges(self):
        """一貫性の課題"""
        
        return {
            'types_of_inconsistency': {
                'permission_propagation': {
                    'scenario': 'ユーザーの権限変更が全サービスに反映されるまでのラグ',
                    'example': '''
                    T0: Admin が User の権限を revoke
                    T1: Auth Service は更新を認識
                    T2: Service A はまだ古い権限でリクエストを許可
                    T3: Service B も古い権限で動作
                    T4: 最終的に全サービスが新しい権限を認識
                    
                    問題：T1-T4 の間、不正なアクセスが可能
                    ''',
                    'solutions': [
                        'イベント駆動の権限更新',
                        '短いキャッシュTTL',
                        '権限チェックの集約'
                    ]
                },
                
                'session_invalidation': {
                    'scenario': 'ログアウトやセッション無効化の即時反映',
                    'example': '''
                    distributed_logout = {
                        'challenge': 'すべてのサービスでセッションを無効化',
                        'approaches': {
                            'blacklist': 'トークンブラックリストの共有',
                            'short_lived': '短命トークン + リフレッシュ',
                            'revocation_events': 'イベントバスでの通知'
                        }
                    }
                    '''
                }
            },
            
            'state_synchronization': {
                'event_driven_approach': '''
                class AuthEventPublisher:
                    def __init__(self, event_bus):
                        self.event_bus = event_bus
                    
                    async def publish_auth_event(self, event_type: str, data: dict):
                        event = {
                            'type': event_type,
                            'timestamp': datetime.utcnow().isoformat(),
                            'data': data,
                            'version': '1.0'
                        }
                        
                        await self.event_bus.publish('auth-events', event)
                    
                    async def user_logged_out(self, user_id: str, session_id: str):
                        await self.publish_auth_event('USER_LOGGED_OUT', {
                            'user_id': user_id,
                            'session_id': session_id
                        })
                    
                    async def permissions_changed(self, user_id: str, changes: dict):
                        await self.publish_auth_event('PERMISSIONS_CHANGED', {
                            'user_id': user_id,
                            'changes': changes
                        })
                ''',
                
                'cache_invalidation': '''
                class DistributedCacheInvalidation:
                    def __init__(self, redis_client, pubsub_channel='cache-invalidation'):
                        self.redis = redis_client
                        self.channel = pubsub_channel
                        self.local_cache = TTLCache(maxsize=1000, ttl=60)
                        
                        # 無効化イベントのサブスクライブ
                        self.start_invalidation_listener()
                    
                    def invalidate(self, key: str):
                        # ローカルキャッシュから削除
                        self.local_cache.pop(key, None)
                        
                        # 他のインスタンスに通知
                        self.redis.publish(self.channel, json.dumps({
                            'action': 'invalidate',
                            'key': key,
                            'timestamp': time.time()
                        }))
                '''
            }
        }
```

## 9.2 API Gatewayパターン

### 9.2.1 API Gatewayによる認証の集約

```python
class APIGatewayAuthentication:
    """API Gatewayでの認証実装"""
    
    def gateway_architecture(self):
        """ゲートウェイアーキテクチャ"""
        
        return {
            'pattern_overview': '''
            [Client] → [API Gateway] → [Service A]
                             ↓      → [Service B]
                      [Auth Service] → [Service C]
            
            利点:
            1. 認証の単一ポイント
            2. サービスは認証から解放
            3. 統一されたセキュリティポリシー
            ''',
            
            'implementation_example': '''
            class APIGateway:
                def __init__(self):
                    self.auth_service = AuthService()
                    self.router = ServiceRouter()
                    self.rate_limiter = RateLimiter()
                
                async def handle_request(self, request: Request) -> Response:
                    # 1. レート制限
                    if not await self.rate_limiter.check(request.client_ip):
                        return Response(status=429, body="Too Many Requests")
                    
                    # 2. 認証
                    auth_result = await self.authenticate(request)
                    if not auth_result.success:
                        return Response(status=401, body="Unauthorized")
                    
                    # 3. リクエストエンリッチメント
                    enriched_request = self.enrich_request(request, auth_result.user)
                    
                    # 4. ルーティング
                    service = self.router.get_service(request.path)
                    
                    # 5. サービス呼び出し
                    response = await service.call(enriched_request)
                    
                    # 6. レスポンス処理
                    return self.process_response(response)
                
                def enrich_request(self, request: Request, user: User) -> Request:
                    # 内部ヘッダーの追加
                    request.headers['X-User-ID'] = user.id
                    request.headers['X-User-Roles'] = ','.join(user.roles)
                    request.headers['X-Request-ID'] = generate_request_id()
                    
                    # JWTの付与（サービス間通信用）
                    internal_token = self.generate_internal_token(user)
                    request.headers['X-Internal-Token'] = internal_token
                    
                    return request
            '''
        }
    
    def token_translation(self):
        """トークン変換パターン"""
        
        return {
            'external_to_internal': '''
            class TokenTranslator:
                """外部トークンから内部トークンへの変換"""
                
                def __init__(self, signing_key: str):
                    self.signing_key = signing_key
                    self.token_cache = TTLCache(maxsize=1000, ttl=300)
                
                def translate_token(self, external_token: str) -> str:
                    # キャッシュチェック
                    if external_token in self.token_cache:
                        return self.token_cache[external_token]
                    
                    # 外部トークンの検証
                    user_info = self.validate_external_token(external_token)
                    
                    # 内部用の簡潔なトークン生成
                    internal_claims = {
                        'sub': user_info['user_id'],
                        'roles': user_info['roles'],
                        'iat': datetime.utcnow(),
                        'exp': datetime.utcnow() + timedelta(minutes=5),
                        'jti': str(uuid.uuid4())
                    }
                    
                    internal_token = jwt.encode(
                        internal_claims,
                        self.signing_key,
                        algorithm='HS256'
                    )
                    
                    # キャッシュ
                    self.token_cache[external_token] = internal_token
                    
                    return internal_token
            ''',
            
            'token_types': {
                'reference_token': {
                    'description': '外部クライアント向け',
                    'example': 'opaque_token_abc123',
                    'validation': 'Auth serviceへの問い合わせ必要',
                    'size': '小さい'
                },
                
                'self_contained_token': {
                    'description': '内部サービス向け',
                    'example': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                    'validation': '署名検証のみ',
                    'size': '大きい（クレーム含む）'
                }
            }
        }
    
    def gateway_patterns(self):
        """ゲートウェイパターンの実装"""
        
        return {
            'bff_pattern': '''
            # Backend for Frontend パターン
            class MobileBFF(APIGateway):
                """モバイルアプリ専用のゲートウェイ"""
                
                def aggregate_response(self, user_id: str) -> dict:
                    # 複数のサービスから必要なデータを収集
                    user_data = self.user_service.get_user(user_id)
                    notifications = self.notification_service.get_unread(user_id)
                    preferences = self.preference_service.get_all(user_id)
                    
                    # モバイル用に最適化された形式で返す
                    return {
                        'user': {
                            'id': user_data['id'],
                            'name': user_data['name'],
                            'avatar': user_data['avatar_url']
                        },
                        'unread_count': len(notifications),
                        'theme': preferences.get('theme', 'light')
                    }
            ''',
            
            'graphql_gateway': '''
            # GraphQL Gatewayでの認証
            class GraphQLGateway:
                def __init__(self):
                    self.schema = build_schema()
                    self.auth = AuthMiddleware()
                
                async def execute_query(self, query: str, token: str):
                    # 認証
                    user = await self.auth.validate_token(token)
                    
                    # コンテキストに認証情報を注入
                    context = {
                        'user': user,
                        'permissions': user.permissions,
                        'request_id': generate_request_id()
                    }
                    
                    # GraphQLクエリの実行
                    result = await graphql(
                        self.schema,
                        query,
                        context=context,
                        middleware=[
                            PermissionMiddleware(),
                            RateLimitMiddleware(),
                            LoggingMiddleware()
                        ]
                    )
                    
                    return result
            '''
        }
```

### 9.2.2 API Gatewayの実装パターン

```python
class APIGatewayImplementation:
    """API Gateway実装パターン"""
    
    def implementation_options(self):
        """実装オプションの比較"""
        
        return {
            'commercial_solutions': {
                'aws_api_gateway': {
                    'pros': [
                        'フルマネージド',
                        'AWS Cognitoとの統合',
                        'Lambda認証との連携'
                    ],
                    'cons': [
                        'ベンダーロックイン',
                        'カスタマイズの制限',
                        'コスト'
                    ],
                    'use_case': 'AWSエコシステム利用時'
                },
                
                'kong': {
                    'pros': [
                        'プラグイン機能豊富',
                        'オンプレミス可能',
                        'パフォーマンス'
                    ],
                    'cons': [
                        '学習曲線',
                        'エンタープライズ機能は有料'
                    ],
                    'use_case': 'フレキシブルな認証要件'
                }
            },
            
            'custom_implementation': '''
            # FastAPIによるカスタムゲートウェイ
            from fastapi import FastAPI, Request, HTTPException
            from fastapi.middleware.cors import CORSMiddleware
            import httpx
            
            app = FastAPI()
            
            # CORS設定
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://app.example.com"],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
            
            # サービスレジストリ
            services = {
                'users': 'http://user-service:8080',
                'orders': 'http://order-service:8080',
                'inventory': 'http://inventory-service:8080'
            }
            
            @app.middleware("http")
            async def auth_middleware(request: Request, call_next):
                # 認証不要のパス
                public_paths = ['/health', '/metrics', '/docs']
                if request.url.path in public_paths:
                    return await call_next(request)
                
                # トークン検証
                token = request.headers.get('Authorization', '').replace('Bearer ', '')
                if not token:
                    raise HTTPException(status_code=401, detail="Missing token")
                
                try:
                    # トークン検証とユーザー情報取得
                    user = verify_token(token)
                    request.state.user = user
                except InvalidTokenError:
                    raise HTTPException(status_code=401, detail="Invalid token")
                
                # リクエストにユーザー情報を追加
                response = await call_next(request)
                return response
            
            @app.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
            async def proxy(service: str, path: str, request: Request):
                if service not in services:
                    raise HTTPException(status_code=404, detail="Service not found")
                
                # 内部トークンの生成
                internal_token = generate_internal_token(request.state.user)
                
                # ヘッダーの準備
                headers = dict(request.headers)
                headers['X-Internal-Token'] = internal_token
                headers['X-User-ID'] = str(request.state.user.id)
                headers['X-Request-ID'] = generate_request_id()
                
                # プロキシリクエスト
                async with httpx.AsyncClient() as client:
                    response = await client.request(
                        method=request.method,
                        url=f"{services[service]}/{path}",
                        headers=headers,
                        content=await request.body(),
                        params=request.query_params
                    )
                
                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    headers=dict(response.headers)
                )
            '''
        }
    
    def security_hardening(self):
        """セキュリティ強化"""
        
        return {
            'rate_limiting': '''
            from slowapi import Limiter, _rate_limit_exceeded_handler
            from slowapi.util import get_remote_address
            
            limiter = Limiter(
                key_func=get_remote_address,
                default_limits=["1000 per hour"],
                storage_uri="redis://localhost:6379"
            )
            
            app.state.limiter = limiter
            app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
            
            @app.post("/api/auth/login")
            @limiter.limit("5 per minute")
            async def login(credentials: LoginCredentials):
                # ログイン処理
                pass
            ''',
            
            'request_validation': '''
            class SecurityMiddleware:
                def __init__(self, app):
                    self.app = app
                
                async def __call__(self, scope, receive, send):
                    if scope["type"] == "http":
                        # ヘッダーサイズチェック
                        headers = dict(scope["headers"])
                        if any(len(v) > 8192 for v in headers.values()):
                            response = Response(status_code=431)
                            await response(scope, receive, send)
                            return
                        
                        # SQLインジェクション対策
                        path = scope["path"]
                        if self.contains_sql_injection(path):
                            response = Response(status_code=400)
                            await response(scope, receive, send)
                            return
                    
                    await self.app(scope, receive, send)
                
                def contains_sql_injection(self, value: str) -> bool:
                    patterns = [
                        r"(\bUNION\b.*\bSELECT\b)",
                        r"(\bDROP\b.*\bTABLE\b)",
                        r"(\bINSERT\b.*\bINTO\b)",
                        r"(\bDELETE\b.*\bFROM\b)"
                    ]
                    return any(re.search(p, value, re.IGNORECASE) for p in patterns)
            '''
        }
```

## 9.3 サービス間認証

### 9.3.1 サービスメッシュとmTLS

```python
class ServiceMeshAuthentication:
    """サービスメッシュでの認証"""
    
    def mtls_implementation(self):
        """mTLS実装"""
        
        return {
            'istio_configuration': '''
            # Istio でのmTLS設定
            apiVersion: security.istio.io/v1beta1
            kind: PeerAuthentication
            metadata:
              name: default
              namespace: production
            spec:
              mtls:
                mode: STRICT  # すべての通信でmTLS必須
            
            ---
            apiVersion: security.istio.io/v1beta1
            kind: AuthorizationPolicy
            metadata:
              name: require-jwt
              namespace: production
            spec:
              selector:
                matchLabels:
                  app: api-gateway
              action: ALLOW
              rules:
              - from:
                - source:
                    requestPrincipals: ["*"]
                when:
                - key: request.auth.claims[iss]
                  values: ["https://auth.example.com"]
            ''',
            
            'certificate_management': '''
            class CertificateManager:
                """証明書の自動管理"""
                
                def __init__(self):
                    self.cert_authority = CertificateAuthority()
                    self.renewal_threshold = timedelta(days=30)
                
                async def rotate_certificates(self):
                    """証明書の自動ローテーション"""
                    services = await self.get_all_services()
                    
                    for service in services:
                        cert = await self.get_certificate(service.name)
                        
                        if self.needs_renewal(cert):
                            # 新しい証明書の生成
                            new_cert = await self.cert_authority.issue_certificate(
                                subject=service.name,
                                validity_days=90
                            )
                            
                            # 証明書の更新
                            await self.update_certificate(service, new_cert)
                            
                            # 古い証明書の無効化
                            await self.cert_authority.revoke_certificate(cert)
                            
                            logger.info(f"Rotated certificate for {service.name}")
                
                def needs_renewal(self, cert: Certificate) -> bool:
                    expiry = cert.not_valid_after
                    return expiry - datetime.now() < self.renewal_threshold
            '''
        }
    
    def service_identity(self):
        """サービスアイデンティティ"""
        
        return {
            'spiffe_implementation': '''
            # SPIFFE/SPIRE によるサービスID
            class SPIFFEIdentity:
                """SPIFFE準拠のサービスアイデンティティ"""
                
                def __init__(self, trust_domain: str):
                    self.trust_domain = trust_domain
                    self.workload_api = WorkloadAPI()
                
                def get_service_identity(self) -> str:
                    """サービスのSPIFFE IDを取得"""
                    # spiffe://trust-domain/path/to/service
                    return f"spiffe://{self.trust_domain}/ns/{self.namespace}/sa/{self.service_account}"
                
                async def get_svid(self) -> SVID:
                    """SPIFFE Verifiable Identity Document の取得"""
                    svid = await self.workload_api.fetch_svid()
                    return svid
                
                async def validate_peer(self, peer_cert: Certificate) -> bool:
                    """ピアサービスの検証"""
                    # SPIFFE IDの抽出
                    spiffe_id = self.extract_spiffe_id(peer_cert)
                    
                    # 信頼するサービスのリスト
                    trusted_services = await self.get_trusted_services()
                    
                    return spiffe_id in trusted_services
            ''',
            
            'service_authentication_flow': '''
            class ServiceAuthenticator:
                """サービス間認証フロー"""
                
                def __init__(self):
                    self.token_issuer = TokenIssuer()
                    self.identity_provider = ServiceIdentityProvider()
                
                async def authenticate_service(self, client_cert: Certificate) -> ServiceToken:
                    # 1. クライアント証明書の検証
                    if not self.verify_certificate(client_cert):
                        raise AuthenticationError("Invalid certificate")
                    
                    # 2. サービスIDの抽出
                    service_id = self.extract_service_id(client_cert)
                    
                    # 3. サービスの権限取得
                    permissions = await self.get_service_permissions(service_id)
                    
                    # 4. サービストークンの発行
                    token = self.token_issuer.issue_service_token(
                        service_id=service_id,
                        permissions=permissions,
                        validity=timedelta(minutes=5)  # 短命トークン
                    )
                    
                    return token
                
                def verify_certificate(self, cert: Certificate) -> bool:
                    # CA証明書での検証
                    # 有効期限チェック
                    # 失効リストチェック
                    return True  # 簡略化
            '''
        }
```

### 9.3.2 APIキーとサービストークン

```python
class ServiceTokenManagement:
    """サービストークン管理"""
    
    def api_key_patterns(self):
        """APIキーパターン"""
        
        return {
            'api_key_management': '''
            class APIKeyManager:
                """APIキーの管理"""
                
                def __init__(self, db, encryption_key):
                    self.db = db
                    self.cipher = Fernet(encryption_key)
                
                async def create_api_key(self, service_name: str, permissions: List[str]) -> APIKey:
                    # APIキーの生成
                    key_id = f"sk_{generate_random_string(8)}"
                    secret = f"{generate_random_string(32)}"
                    api_key = f"{key_id}.{secret}"
                    
                    # ハッシュ化して保存
                    hashed_secret = hashlib.sha256(secret.encode()).hexdigest()
                    
                    await self.db.api_keys.insert({
                        'key_id': key_id,
                        'secret_hash': hashed_secret,
                        'service_name': service_name,
                        'permissions': permissions,
                        'created_at': datetime.utcnow(),
                        'last_used_at': None,
                        'expires_at': datetime.utcnow() + timedelta(days=365),
                        'is_active': True
                    })
                    
                    return APIKey(
                        key=api_key,
                        key_id=key_id,
                        service_name=service_name
                    )
                
                async def validate_api_key(self, api_key: str) -> Optional[Service]:
                    try:
                        key_id, secret = api_key.split('.')
                    except ValueError:
                        return None
                    
                    # データベースから取得
                    key_record = await self.db.api_keys.find_one({'key_id': key_id})
                    if not key_record or not key_record['is_active']:
                        return None
                    
                    # 有効期限チェック
                    if key_record['expires_at'] < datetime.utcnow():
                        return None
                    
                    # シークレットの検証
                    if not self.verify_secret(secret, key_record['secret_hash']):
                        return None
                    
                    # 使用履歴の更新
                    await self.db.api_keys.update_one(
                        {'key_id': key_id},
                        {'$set': {'last_used_at': datetime.utcnow()}}
                    )
                    
                    return Service(
                        name=key_record['service_name'],
                        permissions=key_record['permissions']
                    )
            ''',
            
            'rotation_strategy': '''
            class APIKeyRotation:
                """APIキーのローテーション戦略"""
                
                def __init__(self, key_manager: APIKeyManager):
                    self.key_manager = key_manager
                    self.rotation_period = timedelta(days=90)
                    self.overlap_period = timedelta(days=7)
                
                async def rotate_keys(self):
                    """定期的なキーローテーション"""
                    
                    # ローテーション対象のキーを取得
                    keys_to_rotate = await self.get_keys_for_rotation()
                    
                    for key in keys_to_rotate:
                        # 新しいキーの生成
                        new_key = await self.key_manager.create_api_key(
                            service_name=key.service_name,
                            permissions=key.permissions
                        )
                        
                        # 通知
                        await self.notify_service(key.service_name, {
                            'action': 'key_rotation',
                            'old_key_id': key.key_id,
                            'new_key_id': new_key.key_id,
                            'overlap_end': datetime.utcnow() + self.overlap_period
                        })
                        
                        # 古いキーの有効期限設定
                        await self.schedule_key_deactivation(
                            key.key_id,
                            datetime.utcnow() + self.overlap_period
                        )
            '''
        }
    
    def service_to_service_tokens(self):
        """サービス間トークン"""
        
        return {
            'token_exchange': '''
            class TokenExchangeService:
                """トークン交換サービス（RFC 8693準拠）"""
                
                async def exchange_token(self, request: TokenExchangeRequest) -> TokenExchangeResponse:
                    # 1. 元のトークンの検証
                    subject_token_claims = self.validate_token(request.subject_token)
                    
                    # 2. アクターの検証（呼び出し元サービス）
                    actor_claims = self.validate_token(request.actor_token)
                    
                    # 3. 委任可能性のチェック
                    if not self.can_delegate(actor_claims, request.resource):
                        raise ForbiddenError("Delegation not allowed")
                    
                    # 4. 新しいトークンの生成
                    delegated_token = self.issue_delegated_token(
                        original_subject=subject_token_claims['sub'],
                        actor=actor_claims['sub'],
                        audience=request.audience,
                        scope=self.compute_delegated_scope(
                            subject_token_claims['scope'],
                            request.requested_scope
                        ),
                        validity=timedelta(minutes=5)  # 短命
                    )
                    
                    return TokenExchangeResponse(
                        access_token=delegated_token,
                        token_type="Bearer",
                        expires_in=300
                    )
            ''',
            
            'service_token_types': {
                'client_credentials': '''
                # サービス自身の権限でのアクセス
                async def get_service_token():
                    response = await auth_client.token(
                        grant_type="client_credentials",
                        client_id=SERVICE_ID,
                        client_secret=SERVICE_SECRET,
                        scope="service.read service.write"
                    )
                    return response.access_token
                ''',
                
                'delegated_token': '''
                # ユーザーの代理でのアクセス
                async def get_delegated_token(user_token: str):
                    response = await auth_client.exchange(
                        subject_token=user_token,
                        subject_token_type="access_token",
                        actor_token=await get_service_token(),
                        actor_token_type="access_token",
                        resource="https://api.example.com/orders",
                        audience="order-service"
                    )
                    return response.access_token
                '''
            }
        }
```

## 9.4 Zero Trust Architecture

### 9.4.1 Zero Trustの原則

```python
class ZeroTrustPrinciples:
    """Zero Trust原則の実装"""
    
    def core_principles(self):
        """中核となる原則"""
        
        return {
            'never_trust_always_verify': {
                'concept': '決して信頼せず、常に検証する',
                'implementation': '''
                class ZeroTrustGateway:
                    """すべてのリクエストを検証"""
                    
                    async def process_request(self, request: Request) -> Response:
                        # 1. デバイスの検証
                        device_trust = await self.verify_device(request)
                        if not device_trust.is_trusted:
                            return Response(status=403, body="Untrusted device")
                        
                        # 2. ユーザーの認証
                        user = await self.authenticate_user(request)
                        if not user:
                            return Response(status=401, body="Authentication required")
                        
                        # 3. コンテキストの評価
                        risk_score = await self.evaluate_context(request, user, device_trust)
                        
                        # 4. 動的なアクセス判断
                        if risk_score > 70:
                            # 高リスクの場合は追加認証
                            if not await self.require_mfa(user):
                                return Response(status=401, body="MFA required")
                        
                        # 5. 最小権限でのアクセス許可
                        scoped_token = self.issue_scoped_token(user, request.resource)
                        
                        # 6. 継続的な監視
                        self.monitor_session(user.id, request.session_id)
                        
                        return await self.forward_request(request, scoped_token)
                '''
            },
            
            'least_privilege_access': {
                'concept': '最小権限の原則',
                'implementation': '''
                class LeastPrivilegeEnforcer:
                    """最小権限の実施"""
                    
                    def compute_permissions(self, user: User, resource: Resource, context: Context) -> Permissions:
                        # ベース権限
                        base_permissions = self.get_role_permissions(user.role)
                        
                        # リソース固有の権限
                        resource_permissions = self.get_resource_permissions(resource)
                        
                        # コンテキストによる制限
                        if context.is_external_network:
                            base_permissions = self.restrict_for_external(base_permissions)
                        
                        if context.time_of_day not in user.allowed_hours:
                            base_permissions = self.restrict_for_time(base_permissions)
                        
                        # 交差を取る（最小権限）
                        return base_permissions.intersection(resource_permissions)
                    
                    def issue_scoped_token(self, user: User, resource: Resource) -> str:
                        permissions = self.compute_permissions(user, resource, get_context())
                        
                        claims = {
                            'sub': user.id,
                            'aud': resource.service,
                            'scope': permissions.to_scope_string(),
                            'exp': datetime.utcnow() + timedelta(minutes=5),  # 短命
                            'context': {
                                'ip': get_client_ip(),
                                'device_id': get_device_id()
                            }
                        }
                        
                        return jwt.encode(claims, self.signing_key)
                '''
            },
            
            'verify_explicitly': {
                'concept': '明示的な検証',
                'implementation': '''
                class ExplicitVerification:
                    """すべてのアクセスを明示的に検証"""
                    
                    async def verify_access(self, subject: str, action: str, resource: str) -> bool:
                        # デフォルトは拒否
                        decision = False
                        
                        # ポリシーエンジンでの評価
                        policies = await self.get_applicable_policies(subject, resource)
                        
                        for policy in policies:
                            result = self.evaluate_policy(policy, {
                                'subject': subject,
                                'action': action,
                                'resource': resource,
                                'environment': self.get_environment_attributes()
                            })
                            
                            if result == 'DENY':
                                # 明示的な拒否は最優先
                                return False
                            elif result == 'ALLOW':
                                decision = True
                        
                        # 監査ログ
                        await self.audit_access_decision(subject, action, resource, decision)
                        
                        return decision
                '''
            }
        }
    
    def microsegmentation(self):
        """マイクロセグメンテーション"""
        
        return {
            'network_policies': '''
            # Kubernetes NetworkPolicy
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata:
              name: api-gateway-policy
            spec:
              podSelector:
                matchLabels:
                  app: api-gateway
              policyTypes:
              - Ingress
              - Egress
              ingress:
              - from:
                - namespaceSelector:
                    matchLabels:
                      name: dmz
                ports:
                - protocol: TCP
                  port: 443
              egress:
              - to:
                - namespaceSelector:
                    matchLabels:
                      name: services
                ports:
                - protocol: TCP
                  port: 8080
              - to:
                - namespaceSelector:
                    matchLabels:
                      name: auth
                ports:
                - protocol: TCP
                  port: 9000
            ''',
            
            'service_mesh_policies': '''
            # Istio AuthorizationPolicy
            apiVersion: security.istio.io/v1beta1
            kind: AuthorizationPolicy
            metadata:
              name: order-service-policy
            spec:
              selector:
                matchLabels:
                  app: order-service
              action: ALLOW
              rules:
              - from:
                - source:
                    principals: ["cluster.local/ns/default/sa/api-gateway"]
                to:
                - operation:
                    methods: ["GET", "POST"]
                    paths: ["/api/orders/*"]
                when:
                - key: request.auth.claims[scope]
                  values: ["orders.read", "orders.write"]
            '''
        }
```

### 9.4.2 継続的な検証とリスク評価

```python
class ContinuousVerification:
    """継続的な検証の実装"""
    
    def risk_based_authentication(self):
        """リスクベース認証"""
        
        return {
            'risk_engine': '''
            class RiskEngine:
                """リスク評価エンジン"""
                
                def __init__(self):
                    self.ml_model = load_model('risk_assessment_model.pkl')
                    self.rules_engine = RulesEngine()
                
                async def calculate_risk_score(self, request: Request, user: User) -> RiskScore:
                    # 特徴量の抽出
                    features = {
                        # デバイス関連
                        'is_known_device': await self.is_known_device(user.id, request.device_id),
                        'device_trust_score': await self.get_device_trust_score(request.device_id),
                        
                        # 位置情報関連
                        'location_anomaly': await self.check_location_anomaly(user.id, request.ip),
                        'impossible_travel': await self.check_impossible_travel(user.id, request.ip),
                        
                        # 行動パターン
                        'unusual_time': self.is_unusual_access_time(user.id, request.timestamp),
                        'access_frequency': await self.get_access_frequency(user.id),
                        
                        # リソース関連
                        'resource_sensitivity': self.get_resource_sensitivity(request.resource),
                        'unusual_resource': await self.is_unusual_resource(user.id, request.resource)
                    }
                    
                    # MLモデルでのスコア計算
                    ml_score = self.ml_model.predict_proba([features])[0][1] * 100
                    
                    # ルールベースのスコア
                    rule_score = self.rules_engine.evaluate(features)
                    
                    # 統合スコア
                    final_score = (ml_score * 0.7 + rule_score * 0.3)
                    
                    return RiskScore(
                        score=final_score,
                        factors=features,
                        required_action=self.determine_action(final_score)
                    )
                
                def determine_action(self, score: float) -> str:
                    if score < 30:
                        return "allow"
                    elif score < 60:
                        return "challenge"  # 追加認証
                    elif score < 80:
                        return "mfa_required"
                    else:
                        return "deny"
            ''',
            
            'adaptive_policies': '''
            class AdaptivePolicyEngine:
                """適応型ポリシーエンジン"""
                
                async def enforce_policy(self, user: User, resource: Resource, risk_score: float):
                    # リスクレベルに応じたポリシー選択
                    if risk_score < 30:
                        # 低リスク：標準的なアクセス
                        return StandardPolicy(
                            session_timeout=timedelta(hours=8),
                            concurrent_sessions=5
                        )
                    
                    elif risk_score < 60:
                        # 中リスク：制限付きアクセス
                        return RestrictedPolicy(
                            session_timeout=timedelta(hours=2),
                            concurrent_sessions=2,
                            require_reauthentication_for_sensitive=True
                        )
                    
                    else:
                        # 高リスク：厳格なアクセス
                        return StrictPolicy(
                            session_timeout=timedelta(minutes=30),
                            concurrent_sessions=1,
                            require_mfa_for_all=True,
                            audit_all_actions=True
                        )
            '''
        }
    
    def continuous_monitoring(self):
        """継続的監視"""
        
        return {
            'session_monitoring': '''
            class SessionMonitor:
                """セッション監視"""
                
                def __init__(self):
                    self.anomaly_detector = AnomalyDetector()
                    self.alert_service = AlertService()
                
                async def monitor_session(self, session_id: str):
                    """セッションの継続的監視"""
                    
                    while True:
                        session = await self.get_session(session_id)
                        if not session or session.expired:
                            break
                        
                        # アクティビティの収集
                        activities = await self.collect_activities(session_id, last_5_minutes)
                        
                        # 異常検知
                        anomalies = self.anomaly_detector.detect(activities)
                        
                        if anomalies:
                            # リスクスコアの再計算
                            new_risk_score = await self.recalculate_risk(session, anomalies)
                            
                            if new_risk_score > session.risk_score + 20:
                                # 大幅なリスク上昇
                                await self.handle_risk_elevation(session, new_risk_score)
                        
                        # 定期的なヘルスチェック
                        if not await self.verify_session_health(session):
                            await self.terminate_session(session_id, "Health check failed")
                            break
                        
                        await asyncio.sleep(30)  # 30秒ごとにチェック
                
                async def handle_risk_elevation(self, session: Session, new_risk_score: float):
                    if new_risk_score > 80:
                        # 即座にセッション終了
                        await self.terminate_session(session.id, "Risk threshold exceeded")
                        await self.alert_service.send_security_alert(
                            f"High risk session terminated: {session.id}"
                        )
                    elif new_risk_score > 60:
                        # 再認証を要求
                        await self.require_reauthentication(session.id)
                        await self.notify_user(session.user_id, "Unusual activity detected")
            ''',
            
            'behavioral_analytics': '''
            class BehavioralAnalytics:
                """行動分析"""
                
                def __init__(self):
                    self.ml_pipeline = self.build_ml_pipeline()
                    self.baseline_db = BaselineDatabase()
                
                def build_ml_pipeline(self):
                    return Pipeline([
                        ('feature_extraction', FeatureExtractor()),
                        ('scaler', StandardScaler()),
                        ('anomaly_detector', IsolationForest(contamination=0.1))
                    ])
                
                async def analyze_user_behavior(self, user_id: str, activities: List[Activity]):
                    # ユーザーのベースライン取得
                    baseline = await self.baseline_db.get_baseline(user_id)
                    
                    # 特徴量の計算
                    features = self.extract_features(activities)
                    
                    # ベースラインとの比較
                    deviations = self.calculate_deviations(features, baseline)
                    
                    # 異常スコアの計算
                    anomaly_scores = self.ml_pipeline.predict(features)
                    
                    # 詳細な分析結果
                    return BehaviorAnalysis(
                        user_id=user_id,
                        anomaly_score=float(anomaly_scores.mean()),
                        deviations=deviations,
                        suspicious_patterns=self.identify_patterns(activities),
                        recommendation=self.get_recommendation(anomaly_scores.mean())
                    )
            '''
        }
```

## まとめ

この章では、マイクロサービス環境における認証認可の実装について学びました：

1. **分散システムの課題**
   - サービス増加による複雑性
   - パフォーマンスとセキュリティのトレードオフ
   - 一貫性と状態管理の難しさ

2. **API Gatewayパターン**
   - 認証の単一化
   - トークン変換戦略
   - セキュリティ強化の実装

3. **サービス間認証**
   - mTLSによる相互認証
   - APIキーとトークン管理
   - サービスアイデンティティの確立

4. **Zero Trust Architecture**
   - 常に検証する原則
   - 最小権限の徹底
   - 継続的なリスク評価

次章では、実装パターンとベストプラクティスについて、より具体的な実装例を通じて学びます。

## 演習問題

### 問題1：マイクロサービス認証設計
10個のマイクロサービスからなるEコマースシステムの認証アーキテクチャを設計しなさい。以下を含めること：
- サービス一覧と役割
- 認証フロー図
- トークン戦略
- エラー処理

### 問題2：API Gateway実装
FastAPIを使用して、以下の機能を持つAPI Gatewayを実装しなさい：
- JWT検証
- レート制限（ユーザーごと）
- サービスへのプロキシ
- 監査ログ

### 問題3：Zero Trust設計
金融システムにZero Trust原則を適用した設計を作成しなさい：
- リスク評価の要素（最低10個）
- 動的アクセス制御のルール
- 継続的検証の実装方法
- インシデント対応フロー

### 問題4：サービスメッシュ設定
Istioを使用したマイクロサービス環境で、以下のセキュリティポリシーを実装しなさい：
- すべてのサービス間でmTLS必須
- 特定のサービスのみがデータベースサービスにアクセス可能
- 外部からのトラフィックはAPI Gateway経由のみ
- サービスごとのレート制限

### 問題5：パフォーマンス最適化
認証処理がボトルネックになっているマイクロサービスシステムの最適化計画を立てなさい：
- 現状分析（レイテンシ測定）
- 最適化案（最低5つ）
- 実装優先順位
- 期待される改善効果