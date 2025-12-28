---
layout: book
order: 12
title: "第10章：実装パターン"
---

# 第10章：実装パターン

## 10.1 認証フローのパターン

### 10.1.1 基本的な認証フローパターン

```python
class AuthenticationFlowPatterns:
    """認証フローのパターン集"""
    
    def traditional_flow(self):
        """従来型の認証フロー"""
        
        return {
            'simple_password_flow': {
                'description': '最も基本的なパスワード認証',
                'use_case': '内部システム、低リスクアプリケーション',
                'implementation': '''
                class SimplePasswordAuth:
                    def __init__(self, user_repository, password_hasher):
                        self.user_repo = user_repository
                        self.hasher = password_hasher
                    
                    async def authenticate(self, username: str, password: str) -> AuthResult:
                        # 1. ユーザー検索
                        user = await self.user_repo.find_by_username(username)
                        if not user:
                            # タイミング攻撃対策：常に同じ時間かかるようにする
                            await self.hasher.dummy_verify()
                            return AuthResult(success=False, error="Invalid credentials")
                        
                        # 2. パスワード検証
                        if not await self.hasher.verify(password, user.password_hash):
                            # ログイン失敗の記録
                            await self.record_failed_attempt(user.id)
                            return AuthResult(success=False, error="Invalid credentials")
                        
                        # 3. アカウント状態確認
                        if not user.is_active:
                            return AuthResult(success=False, error="Account is disabled")
                        
                        # 4. セッション作成
                        session = await self.create_session(user)
                        
                        return AuthResult(
                            success=True,
                            user=user,
                            session=session
                        )
                ''',
                'security_considerations': [
                    'タイミング攻撃への対策',
                    'ブルートフォース対策',
                    'パスワードの安全な保存'
                ]
            },
            
            'remember_me_flow': {
                'description': '「記憶する」機能付き認証',
                'implementation': '''
                class RememberMeAuth:
                    def __init__(self, token_generator, token_store):
                        self.token_gen = token_generator
                        self.token_store = token_store
                    
                    async def create_remember_token(self, user_id: str) -> str:
                        # セキュアなトークン生成
                        token = self.token_gen.generate_secure_token()
                        
                        # トークンの保存（ハッシュ化して保存）
                        token_hash = hashlib.sha256(token.encode()).hexdigest()
                        await self.token_store.save(
                            user_id=user_id,
                            token_hash=token_hash,
                            expires_at=datetime.utcnow() + timedelta(days=30)
                        )
                        
                        return token
                    
                    async def authenticate_with_token(self, token: str) -> Optional[User]:
                        # トークンのハッシュ化
                        token_hash = hashlib.sha256(token.encode()).hexdigest()
                        
                        # トークン情報の取得
                        token_info = await self.token_store.find_by_hash(token_hash)
                        if not token_info or token_info.is_expired():
                            return None
                        
                        # トークンのローテーション（セキュリティ向上）
                        await self.token_store.delete(token_hash)
                        new_token = await self.create_remember_token(token_info.user_id)
                        
                        # ユーザー情報の取得
                        return await self.user_repo.find_by_id(token_info.user_id)
                '''
            }
        }
    
    def multi_step_authentication(self):
        """多段階認証フロー"""
        
        return {
            'progressive_authentication': {
                'description': '段階的な認証強度の上昇',
                'flow': '''
                class ProgressiveAuth:
                    def __init__(self):
                        self.auth_levels = {
                            1: 'password',
                            2: 'mfa',
                            3: 'biometric',
                            4: 'hardware_key'
                        }
                    
                    async def authenticate_progressively(self, request: AuthRequest) -> AuthResult:
                        current_level = 0
                        user = None
                        
                        # レベル1: パスワード認証
                        if request.password:
                            user = await self.verify_password(request.username, request.password)
                            if user:
                                current_level = 1
                        
                        # 要求される認証レベルの確認
                        required_level = self.get_required_level(request.resource)
                        
                        # 必要に応じて追加認証
                        while current_level < required_level:
                            next_method = self.auth_levels[current_level + 1]
                            
                            if next_method == 'mfa':
                                if not await self.verify_mfa(user, request.mfa_code):
                                    return AuthResult(
                                        success=False,
                                        error="MFA verification failed",
                                        required_level=required_level
                                    )
                                current_level = 2
                            
                            elif next_method == 'biometric':
                                if not await self.verify_biometric(user, request.biometric_data):
                                    return AuthResult(
                                        success=False,
                                        error="Biometric verification failed"
                                    )
                                current_level = 3
                        
                        return AuthResult(
                            success=True,
                            user=user,
                            auth_level=current_level
                        )
                '''
            },
            
            'step_up_authentication': {
                'description': '必要に応じた認証レベルの引き上げ',
                'implementation': '''
                class StepUpAuthMiddleware:
                    async def __call__(self, request: Request, call_next):
                        # 現在の認証レベル確認
                        current_auth = request.state.auth
                        required_level = self.get_required_auth_level(request.path)
                        
                        if current_auth.level < required_level:
                            # ステップアップが必要
                            return JSONResponse(
                                status_code=403,
                                content={
                                    "error": "step_up_required",
                                    "current_level": current_auth.level,
                                    "required_level": required_level,
                                    "step_up_url": f"/auth/step-up?level={required_level}"
                                }
                            )
                        
                        # 認証レベルが十分な場合は続行
                        response = await call_next(request)
                        return response
                '''
            }
        }
    
    def delegated_authentication(self):
        """委譲認証パターン"""
        
        return {
            'oauth_flow': {
                'description': 'OAuth 2.0による外部認証',
                'implementation': '''
                class OAuthFlowHandler:
                    def __init__(self, oauth_config):
                        self.config = oauth_config
                        self.state_store = StateStore()
                    
                    async def initiate_oauth_flow(self, provider: str) -> str:
                        # CSRF対策のstate生成
                        state = secrets.token_urlsafe(32)
                        await self.state_store.save(state, ttl=600)  # 10分有効
                        
                        # PKCE対応
                        code_verifier = secrets.token_urlsafe(32)
                        code_challenge = self.generate_code_challenge(code_verifier)
                        
                        # 認証URLの構築
                        auth_url = self.build_auth_url(
                            provider=provider,
                            state=state,
                            code_challenge=code_challenge
                        )
                        
                        return auth_url
                    
                    async def handle_callback(self, code: str, state: str) -> AuthResult:
                        # State検証
                        if not await self.state_store.verify(state):
                            raise SecurityError("Invalid state parameter")
                        
                        # トークン交換
                        tokens = await self.exchange_code_for_tokens(code)
                        
                        # ユーザー情報取得
                        user_info = await self.get_user_info(tokens.access_token)
                        
                        # ローカルユーザーとの紐付け
                        local_user = await self.link_or_create_user(user_info)
                        
                        return AuthResult(
                            success=True,
                            user=local_user,
                            external_tokens=tokens
                        )
                '''
            },
            
            'saml_flow': {
                'description': 'SAML 2.0によるエンタープライズSSO',
                'implementation': '''
                class SAMLFlowHandler:
                    def __init__(self, saml_config):
                        self.config = saml_config
                        self.saml = OneLogin_Saml2_Auth(saml_config)
                    
                    def initiate_saml_sso(self, return_url: str) -> str:
                        # SAML Request生成
                        saml_request = self.saml.login(return_to=return_url)
                        return saml_request
                    
                    async def process_saml_response(self, saml_response: str) -> AuthResult:
                        # SAML Response検証
                        self.saml.process_response()
                        
                        if not self.saml.is_authenticated():
                            errors = self.saml.get_errors()
                            raise AuthError(f"SAML authentication failed: {errors}")
                        
                        # 属性取得
                        attributes = self.saml.get_attributes()
                        
                        # ユーザー情報のマッピング
                        user_info = {
                            'email': attributes.get('email')[0],
                            'name': attributes.get('displayName')[0],
                            'groups': attributes.get('memberOf', [])
                        }
                        
                        # ローカルユーザー作成/更新
                        local_user = await self.sync_user(user_info)
                        
                        return AuthResult(
                            success=True,
                            user=local_user,
                            saml_attributes=attributes
                        )
                '''
            }
        }
```

### 10.1.2 モダンな認証フローパターン

```python
class ModernAuthenticationFlows:
    """モダンな認証フローパターン"""
    
    def passwordless_flows(self):
        """パスワードレス認証フロー"""
        
        return {
            'magic_link_flow': {
                'description': 'メールによるマジックリンク認証',
                'implementation': '''
                class MagicLinkAuth:
                    def __init__(self, token_service, email_service):
                        self.token_service = token_service
                        self.email_service = email_service
                    
                    async def send_magic_link(self, email: str) -> None:
                        # ユーザー確認
                        user = await self.user_repo.find_by_email(email)
                        
                        # トークン生成（短命: 15分）
                        token = await self.token_service.create_magic_token(
                            user_id=user.id if user else None,
                            email=email,
                            expires_in=timedelta(minutes=15)
                        )
                        
                        # マジックリンク生成
                        magic_link = f"{self.base_url}/auth/magic/{token}"
                        
                        # メール送信
                        await self.email_service.send_magic_link(
                            to=email,
                            link=magic_link,
                            user_exists=user is not None
                        )
                    
                    async def verify_magic_link(self, token: str) -> AuthResult:
                        # トークン検証
                        token_data = await self.token_service.verify_magic_token(token)
                        if not token_data:
                            return AuthResult(success=False, error="Invalid or expired link")
                        
                        # ユーザー取得または作成
                        if token_data.user_id:
                            user = await self.user_repo.find_by_id(token_data.user_id)
                        else:
                            # 新規ユーザー作成
                            user = await self.user_repo.create(email=token_data.email)
                        
                        # トークンの無効化（一度のみ使用可能）
                        await self.token_service.invalidate_token(token)
                        
                        return AuthResult(success=True, user=user)
                '''
            },
            
            'webauthn_flow': {
                'description': 'WebAuthn/FIDO2による生体認証',
                'implementation': '''
                class WebAuthnFlow:
                    def __init__(self):
                        self.rp = PublicKeyCredentialRpEntity(
                            name="My App",
                            id="example.com"
                        )
                    
                    async def registration_begin(self, user: User) -> dict:
                        # チャレンジ生成
                        challenge = secrets.token_bytes(32)
                        
                        # 登録オプション作成
                        options = generate_registration_options(
                            rp_id=self.rp.id,
                            rp_name=self.rp.name,
                            user_id=user.id.encode(),
                            user_name=user.email,
                            user_display_name=user.name,
                            challenge=challenge,
                            attestation="direct",
                            authenticator_selection=AuthenticatorSelectionCriteria(
                                authenticator_attachment="platform",
                                user_verification="required"
                            )
                        )
                        
                        # チャレンジを保存
                        await self.store_challenge(user.id, challenge)
                        
                        return options
                    
                    async def registration_complete(self, user: User, credential: dict) -> bool:
                        # チャレンジ検証
                        expected_challenge = await self.get_challenge(user.id)
                        
                        # 認証情報の検証
                        verification = verify_registration_response(
                            credential=credential,
                            expected_challenge=expected_challenge,
                            expected_origin=self.expected_origin,
                            expected_rp_id=self.rp.id
                        )
                        
                        if verification.verified:
                            # 認証情報の保存
                            await self.save_credential(
                                user_id=user.id,
                                credential_id=verification.credential_id,
                                public_key=verification.credential_public_key,
                                sign_count=verification.sign_count
                            )
                            return True
                        
                        return False
                '''
            }
        }
    
    def adaptive_authentication(self):
        """適応型認証フロー"""
        
        return {
            'risk_based_flow': {
                'description': 'リスクベースの動的認証',
                'implementation': '''
                class AdaptiveAuthFlow:
                    def __init__(self, risk_engine, auth_methods):
                        self.risk_engine = risk_engine
                        self.auth_methods = auth_methods
                    
                    async def authenticate(self, request: AuthRequest) -> AuthResult:
                        # リスク評価
                        risk_score = await self.risk_engine.evaluate(request)
                        
                        # リスクレベルに基づく認証方法の選択
                        required_methods = self.determine_auth_methods(risk_score)
                        
                        # 段階的な認証実行
                        auth_results = []
                        for method in required_methods:
                            handler = self.auth_methods[method]
                            result = await handler.authenticate(request)
                            
                            if not result.success:
                                return AuthResult(
                                    success=False,
                                    error=f"{method} authentication failed",
                                    completed_methods=auth_results
                                )
                            
                            auth_results.append(method)
                        
                        # 最終的な認証結果
                        return AuthResult(
                            success=True,
                            user=request.user,
                            auth_methods=auth_results,
                            risk_score=risk_score
                        )
                    
                    def determine_auth_methods(self, risk_score: float) -> List[str]:
                        if risk_score < 30:
                            return ['password']
                        elif risk_score < 60:
                            return ['password', 'totp']
                        elif risk_score < 80:
                            return ['password', 'totp', 'security_questions']
                        else:
                            return ['password', 'totp', 'biometric', 'admin_approval']
                '''
            }
        }
```

## 10.2 権限チェックの実装方法

### 10.2.1 権限チェックのパターン

```python
class AuthorizationPatterns:
    """権限チェックの実装パターン"""
    
    def basic_patterns(self):
        """基本的な権限チェックパターン"""
        
        return {
            'imperative_check': {
                'description': '命令的な権限チェック',
                'pros': 'シンプル、直感的',
                'cons': 'コードの重複、チェック漏れのリスク',
                'implementation': '''
                class OrderService:
                    def __init__(self, auth_service):
                        self.auth = auth_service
                    
                    async def get_order(self, user: User, order_id: str) -> Order:
                        # 命令的なチェック
                        order = await self.order_repo.find_by_id(order_id)
                        
                        if not order:
                            raise NotFoundError("Order not found")
                        
                        # 権限チェック
                        if not self.can_read_order(user, order):
                            raise ForbiddenError("Access denied")
                        
                        return order
                    
                    def can_read_order(self, user: User, order: Order) -> bool:
                        # オーナーチェック
                        if order.user_id == user.id:
                            return True
                        
                        # 管理者チェック
                        if 'admin' in user.roles:
                            return True
                        
                        # サポートスタッフチェック
                        if 'support' in user.roles and order.status != 'draft':
                            return True
                        
                        return False
                '''
            },
            
            'declarative_check': {
                'description': '宣言的な権限チェック',
                'pros': 'DRY原則、一貫性',
                'cons': '初期実装が複雑',
                'implementation': '''
                from functools import wraps
                
                class Permissions:
                    """権限デコレータ"""
                    
                    @staticmethod
                    def require(*permissions):
                        def decorator(func):
                            @wraps(func)
                            async def wrapper(self, user: User, *args, **kwargs):
                                # 権限チェック
                                if not all(perm in user.permissions for perm in permissions):
                                    raise ForbiddenError(
                                        f"Required permissions: {permissions}"
                                    )
                                return await func(self, user, *args, **kwargs)
                            return wrapper
                        return decorator
                    
                    @staticmethod
                    def require_any(*permissions):
                        def decorator(func):
                            @wraps(func)
                            async def wrapper(self, user: User, *args, **kwargs):
                                if not any(perm in user.permissions for perm in permissions):
                                    raise ForbiddenError(
                                        f"Required any of: {permissions}"
                                    )
                                return await func(self, user, *args, **kwargs)
                            return wrapper
                        return decorator
                
                class OrderService:
                    @Permissions.require('orders.read')
                    async def list_orders(self, user: User) -> List[Order]:
                        return await self.order_repo.find_by_user(user.id)
                    
                    @Permissions.require('orders.create')
                    async def create_order(self, user: User, data: OrderData) -> Order:
                        return await self.order_repo.create(user_id=user.id, **data)
                    
                    @Permissions.require_any('orders.admin', 'orders.support')
                    async def list_all_orders(self, user: User) -> List[Order]:
                        return await self.order_repo.find_all()
                '''
            }
        }
    
    def advanced_patterns(self):
        """高度な権限チェックパターン"""
        
        return {
            'policy_based_authorization': {
                'description': 'ポリシーベースの権限管理',
                'implementation': '''
                class PolicyEngine:
                    """ポリシーエンジン"""
                    
                    def __init__(self):
                        self.policies = {}
                    
                    def register_policy(self, name: str, policy: Policy):
                        self.policies[name] = policy
                    
                    async def authorize(self, user: User, action: str, resource: Any) -> bool:
                        context = AuthContext(
                            user=user,
                            action=action,
                            resource=resource,
                            environment=self.get_environment()
                        )
                        
                        # 適用可能なポリシーを取得
                        applicable_policies = self.get_applicable_policies(context)
                        
                        # ポリシー評価
                        for policy in applicable_policies:
                            result = await policy.evaluate(context)
                            
                            if result == PolicyResult.DENY:
                                return False  # 明示的な拒否は最優先
                            
                        # 少なくとも1つのポリシーが許可していれば OK
                        return any(
                            await p.evaluate(context) == PolicyResult.ALLOW 
                            for p in applicable_policies
                        )
                
                # ポリシー定義例
                class OrderOwnerPolicy(Policy):
                    async def evaluate(self, context: AuthContext) -> PolicyResult:
                        if context.action.startswith('order.'):
                            order = context.resource
                            if order.user_id == context.user.id:
                                return PolicyResult.ALLOW
                        return PolicyResult.NOT_APPLICABLE
                
                class AdminPolicy(Policy):
                    async def evaluate(self, context: AuthContext) -> PolicyResult:
                        if 'admin' in context.user.roles:
                            return PolicyResult.ALLOW
                        return PolicyResult.NOT_APPLICABLE
                
                # 使用例
                policy_engine = PolicyEngine()
                policy_engine.register_policy('order_owner', OrderOwnerPolicy())
                policy_engine.register_policy('admin', AdminPolicy())
                
                # サービスでの利用
                class OrderService:
                    def __init__(self, policy_engine):
                        self.policy_engine = policy_engine
                    
                    async def update_order(self, user: User, order_id: str, data: dict) -> Order:
                        order = await self.get_order(order_id)
                        
                        if not await self.policy_engine.authorize(user, 'order.update', order):
                            raise ForbiddenError("Access denied")
                        
                        return await self.order_repo.update(order_id, data)
                '''
            },
            
            'attribute_based_access_control': {
                'description': '属性ベースアクセス制御（ABAC）',
                'implementation': '''
                class ABACEngine:
                    """ABAC実装"""
                    
                    def __init__(self):
                        self.attribute_resolvers = {}
                        self.policy_store = PolicyStore()
                    
                    async def check_access(self, request: AccessRequest) -> bool:
                        # 属性の収集
                        attributes = await self.collect_attributes(request)
                        
                        # ポリシーの評価
                        policies = await self.policy_store.find_applicable(attributes)
                        
                        for policy in policies:
                            if not self.evaluate_policy(policy, attributes):
                                return False
                        
                        return True
                    
                    async def collect_attributes(self, request: AccessRequest) -> dict:
                        attributes = {
                            'subject': await self.get_subject_attributes(request.user),
                            'resource': await self.get_resource_attributes(request.resource),
                            'action': request.action,
                            'environment': await self.get_environment_attributes()
                        }
                        return attributes
                    
                    def evaluate_policy(self, policy: Policy, attributes: dict) -> bool:
                        # ポリシールールの評価
                        for rule in policy.rules:
                            if not self.evaluate_rule(rule, attributes):
                                return False
                        return True
                    
                    def evaluate_rule(self, rule: Rule, attributes: dict) -> bool:
                        # 属性値の取得
                        value = self.get_attribute_value(attributes, rule.attribute_path)
                        
                        # 条件評価
                        if rule.operator == 'equals':
                            return value == rule.expected_value
                        elif rule.operator == 'contains':
                            return rule.expected_value in value
                        elif rule.operator == 'greater_than':
                            return value > rule.expected_value
                        # ... 他の演算子
                
                # ポリシー例
                sensitive_data_policy = {
                    "name": "sensitive_data_access",
                    "rules": [
                        {
                            "attribute_path": "subject.clearance_level",
                            "operator": "greater_than_or_equal",
                            "expected_value": 3
                        },
                        {
                            "attribute_path": "resource.classification",
                            "operator": "equals",
                            "expected_value": "sensitive"
                        },
                        {
                            "attribute_path": "environment.time_of_day",
                            "operator": "between",
                            "expected_value": [9, 17]
                        }
                    ]
                }
                '''
            }
        }
    
    def performance_optimized_patterns(self):
        """パフォーマンス最適化パターン"""
        
        return {
            'permission_caching': {
                'description': '権限情報のキャッシング',
                'implementation': '''
                class CachedPermissionChecker:
                    def __init__(self, cache, permission_service):
                        self.cache = cache
                        self.permission_service = permission_service
                    
                    async def has_permission(self, user_id: str, permission: str) -> bool:
                        # キャッシュキー
                        cache_key = f"perm:{user_id}:{permission}"
                        
                        # キャッシュチェック
                        cached = await self.cache.get(cache_key)
                        if cached is not None:
                            return cached == "1"
                        
                        # 権限チェック
                        has_perm = await self.permission_service.check(user_id, permission)
                        
                        # キャッシュに保存（5分間）
                        await self.cache.set(
                            cache_key, 
                            "1" if has_perm else "0",
                            expire=300
                        )
                        
                        return has_perm
                    
                    async def invalidate_user_permissions(self, user_id: str):
                        """ユーザーの権限キャッシュを無効化"""
                        pattern = f"perm:{user_id}:*"
                        await self.cache.delete_pattern(pattern)
                '''
            },
            
            'batch_permission_check': {
                'description': 'バッチでの権限チェック',
                'implementation': '''
                class BatchPermissionChecker:
                    async def check_permissions_batch(
                        self, 
                        user: User, 
                        resources: List[Resource]
                    ) -> Dict[str, bool]:
                        """複数リソースの権限を一括チェック"""
                        
                        # 権限マトリクスの構築
                        permission_matrix = {}
                        
                        # ユーザーの全権限を一度に取得
                        user_permissions = await self.get_all_user_permissions(user)
                        
                        # 各リソースに対する権限チェック
                        for resource in resources:
                            # リソース固有のルール適用
                            can_access = self.evaluate_resource_access(
                                user_permissions, 
                                resource
                            )
                            permission_matrix[resource.id] = can_access
                        
                        return permission_matrix
                    
                    def evaluate_resource_access(
                        self, 
                        user_permissions: Set[str], 
                        resource: Resource
                    ) -> bool:
                        # 必要な権限の確認
                        required_permissions = resource.get_required_permissions()
                        
                        # 権限チェック
                        return all(
                            perm in user_permissions 
                            for perm in required_permissions
                        )
                '''
            }
        }
```

## 10.3 監査ログの設計

### 10.3.1 監査ログの基本設計

```python
class AuditLogDesign:
    """監査ログの設計パターン"""
    
    def audit_log_requirements(self):
        """監査ログの要件"""
        
        return {
            'essential_fields': {
                'who': 'ユーザー識別情報',
                'what': '実行されたアクション',
                'when': 'タイムスタンプ',
                'where': 'アクセス元情報',
                'why': 'アクションの文脈',
                'result': '成功/失敗'
            },
            
            'implementation': '''
            @dataclass
            class AuditLogEntry:
                # Who
                user_id: str
                user_email: str
                user_roles: List[str]
                
                # What
                action: str
                resource_type: str
                resource_id: str
                changes: Optional[Dict[str, Any]] = None
                
                # When
                timestamp: datetime
                
                # Where
                ip_address: str
                user_agent: str
                session_id: str
                
                # Why
                reason: Optional[str] = None
                request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
                
                # Result
                success: bool
                error_code: Optional[str] = None
                error_message: Optional[str] = None
                
                # Metadata
                application_version: str = None
                additional_context: Dict[str, Any] = field(default_factory=dict)
            
            class AuditLogger:
                def __init__(self, storage_backend):
                    self.storage = storage_backend
                    self.queue = asyncio.Queue(maxsize=10000)
                    self.batch_size = 100
                    self.flush_interval = 1.0
                
                async def log(self, entry: AuditLogEntry):
                    """非同期でログエントリを記録"""
                    try:
                        await self.queue.put(entry)
                    except asyncio.QueueFull:
                        # フォールバック: 同期的に書き込み
                        await self.storage.write([entry])
                
                async def start_background_writer(self):
                    """バックグラウンドでのバッチ書き込み"""
                    while True:
                        batch = []
                        deadline = time.time() + self.flush_interval
                        
                        while len(batch) < self.batch_size and time.time() < deadline:
                            try:
                                timeout = deadline - time.time()
                                entry = await asyncio.wait_for(
                                    self.queue.get(), 
                                    timeout=max(0.1, timeout)
                                )
                                batch.append(entry)
                            except asyncio.TimeoutError:
                                break
                        
                        if batch:
                            await self.storage.write(batch)
            '''
        }
    
    def sensitive_data_handling(self):
        """機密データの取り扱い"""
        
        return {
            'data_masking': '''
            class SensitiveDataMasker:
                """機密データのマスキング"""
                
                def __init__(self):
                    self.patterns = {
                        'email': (r'[^@]+@', lambda m: '***@'),
                        'credit_card': (r'\d{12}', lambda m: '****' * 3),
                        'ssn': (r'\d{3}-\d{2}-', lambda m: '***-**-'),
                        'phone': (r'\d{3}-\d{3}-', lambda m: '***-***-')
                    }
                
                def mask_dict(self, data: dict, fields_to_mask: List[str]) -> dict:
                    """辞書内の機密フィールドをマスク"""
                    masked = data.copy()
                    
                    for field in fields_to_mask:
                        if field in masked and masked[field]:
                            masked[field] = self.mask_value(field, masked[field])
                    
                    return masked
                
                def mask_value(self, field_type: str, value: str) -> str:
                    """値のマスキング"""
                    if field_type in self.patterns:
                        pattern, replacer = self.patterns[field_type]
                        return re.sub(pattern, replacer, str(value))
                    
                    # デフォルト: 最初と最後の文字以外をマスク
                    if len(str(value)) > 2:
                        return value[0] + '*' * (len(value) - 2) + value[-1]
                    return '*' * len(str(value))
            
            # 使用例
            class SecureAuditLogger(AuditLogger):
                def __init__(self, storage_backend):
                    super().__init__(storage_backend)
                    self.masker = SensitiveDataMasker()
                
                async def log_with_masking(self, entry: AuditLogEntry):
                    # 機密データのマスキング
                    if entry.changes:
                        entry.changes = self.masker.mask_dict(
                            entry.changes,
                            fields_to_mask=['password', 'credit_card', 'ssn']
                        )
                    
                    await self.log(entry)
            ''',
            
            'encryption_at_rest': '''
            class EncryptedAuditStorage:
                """保存時の暗号化"""
                
                def __init__(self, encryption_key: bytes):
                    self.cipher = Fernet(encryption_key)
                
                async def write(self, entries: List[AuditLogEntry]):
                    encrypted_entries = []
                    
                    for entry in entries:
                        # JSON形式に変換
                        json_data = json.dumps(asdict(entry), default=str)
                        
                        # 暗号化
                        encrypted = self.cipher.encrypt(json_data.encode())
                        
                        encrypted_entries.append({
                            'id': entry.request_id,
                            'timestamp': entry.timestamp,
                            'user_id': entry.user_id,  # 検索用に平文保存
                            'action': entry.action,     # 検索用に平文保存
                            'encrypted_data': encrypted.decode()
                        })
                    
                    # データベースに保存
                    await self.db.audit_logs.insert_many(encrypted_entries)
                
                async def read(self, filters: dict) -> List[AuditLogEntry]:
                    # 暗号化されたエントリを取得
                    encrypted_entries = await self.db.audit_logs.find(filters)
                    
                    entries = []
                    for enc_entry in encrypted_entries:
                        # 復号化
                        decrypted = self.cipher.decrypt(
                            enc_entry['encrypted_data'].encode()
                        )
                        
                        # AuditLogEntryに変換
                        data = json.loads(decrypted)
                        entries.append(AuditLogEntry(**data))
                    
                    return entries
            '''
        }
    
    def audit_log_analysis(self):
        """監査ログの分析"""
        
        return {
            'anomaly_detection': '''
            class AuditLogAnalyzer:
                """監査ログの異常検知"""
                
                def __init__(self):
                    self.ml_model = self.load_anomaly_model()
                    self.alert_service = AlertService()
                
                async def analyze_user_behavior(self, user_id: str):
                    """ユーザー行動の分析"""
                    # 直近の行動履歴取得
                    recent_logs = await self.get_recent_logs(user_id, hours=24)
                    
                    # 特徴量抽出
                    features = self.extract_features(recent_logs)
                    
                    # 異常スコア計算
                    anomaly_score = self.ml_model.predict([features])[0]
                    
                    if anomaly_score > 0.8:
                        await self.handle_anomaly(user_id, recent_logs, anomaly_score)
                
                def extract_features(self, logs: List[AuditLogEntry]) -> dict:
                    """行動特徴の抽出"""
                    return {
                        'action_count': len(logs),
                        'unique_ips': len(set(log.ip_address for log in logs)),
                        'failed_attempts': sum(1 for log in logs if not log.success),
                        'unusual_hours': sum(
                            1 for log in logs 
                            if log.timestamp.hour < 6 or log.timestamp.hour > 22
                        ),
                        'sensitive_actions': sum(
                            1 for log in logs 
                            if log.action in ['delete', 'export', 'admin_access']
                        )
                    }
                
                async def handle_anomaly(self, user_id: str, logs: List[AuditLogEntry], score: float):
                    """異常の処理"""
                    # アラート送信
                    await self.alert_service.send_alert(
                        level=AlertLevel.HIGH,
                        title=f"Anomalous behavior detected for user {user_id}",
                        details={
                            'anomaly_score': score,
                            'recent_actions': [
                                {
                                    'action': log.action,
                                    'timestamp': log.timestamp,
                                    'ip': log.ip_address
                                }
                                for log in logs[-10:]  # 最新10件
                            ]
                        }
                    )
                    
                    # 自動対応
                    if score > 0.95:
                        await self.security_response.lock_account(user_id)
            ''',
            
            'compliance_reporting': '''
            class ComplianceReporter:
                """コンプライアンスレポート生成"""
                
                async def generate_access_report(self, resource_id: str, date_range: DateRange):
                    """リソースへのアクセスレポート"""
                    
                    # アクセスログの取得
                    access_logs = await self.get_resource_access_logs(resource_id, date_range)
                    
                    # レポート生成
                    report = {
                        'resource_id': resource_id,
                        'period': {
                            'start': date_range.start,
                            'end': date_range.end
                        },
                        'summary': {
                            'total_accesses': len(access_logs),
                            'unique_users': len(set(log.user_id for log in access_logs)),
                            'success_rate': self.calculate_success_rate(access_logs)
                        },
                        'access_by_user': self.group_by_user(access_logs),
                        'access_by_action': self.group_by_action(access_logs),
                        'anomalies': await self.detect_anomalies(access_logs)
                    }
                    
                    return report
                
                async def generate_gdpr_report(self, user_id: str):
                    """GDPR用の個人データアクセスレポート"""
                    
                    # すべてのアクセスログ取得
                    all_logs = await self.get_user_related_logs(user_id)
                    
                    return {
                        'user_id': user_id,
                        'data_collected': self.extract_collected_data(all_logs),
                        'data_shared': self.extract_data_sharing(all_logs),
                        'data_processing': self.extract_processing_activities(all_logs),
                        'third_party_access': self.extract_third_party_access(all_logs)
                    }
            '''
        }
```

## 10.4 テスト戦略

### 10.4.1 認証認可のテスト戦略

```python
class AuthTestingStrategy:
    """認証認可のテスト戦略"""
    
    def unit_testing_patterns(self):
        """ユニットテストパターン"""
        
        return {
            'authentication_tests': '''
            import pytest
            from unittest.mock import Mock, AsyncMock
            
            class TestPasswordAuthentication:
                """パスワード認証のテスト"""
                
                @pytest.fixture
                def auth_service(self):
                    return PasswordAuthService(
                        user_repo=Mock(),
                        password_hasher=Mock()
                    )
                
                @pytest.mark.asyncio
                async def test_successful_authentication(self, auth_service):
                    # Setup
                    auth_service.user_repo.find_by_email = AsyncMock(
                        return_value=User(
                            id="123",
                            email="test@example.com",
                            password_hash="hashed",
                            is_active=True
                        )
                    )
                    auth_service.password_hasher.verify = AsyncMock(return_value=True)
                    
                    # Execute
                    result = await auth_service.authenticate(
                        "test@example.com",
                        "password123"
                    )
                    
                    # Assert
                    assert result.success is True
                    assert result.user.email == "test@example.com"
                
                @pytest.mark.asyncio
                async def test_invalid_password(self, auth_service):
                    # Setup
                    auth_service.user_repo.find_by_email = AsyncMock(
                        return_value=User(
                            id="123",
                            email="test@example.com",
                            password_hash="hashed",
                            is_active=True
                        )
                    )
                    auth_service.password_hasher.verify = AsyncMock(return_value=False)
                    
                    # Execute
                    result = await auth_service.authenticate(
                        "test@example.com",
                        "wrong_password"
                    )
                    
                    # Assert
                    assert result.success is False
                    assert result.error == "Invalid credentials"
                
                @pytest.mark.asyncio
                async def test_timing_attack_protection(self, auth_service):
                    """タイミング攻撃対策のテスト"""
                    # Setup
                    auth_service.user_repo.find_by_email = AsyncMock(return_value=None)
                    
                    # Execute - 存在しないユーザー
                    start = time.time()
                    await auth_service.authenticate("nonexistent@example.com", "password")
                    duration_nonexistent = time.time() - start
                    
                    # Execute - 存在するユーザー（パスワード違い）
                    auth_service.user_repo.find_by_email = AsyncMock(
                        return_value=User(id="123", password_hash="hash")
                    )
                    auth_service.password_hasher.verify = AsyncMock(return_value=False)
                    
                    start = time.time()
                    await auth_service.authenticate("existing@example.com", "wrong")
                    duration_existing = time.time() - start
                    
                    # Assert - 実行時間がほぼ同じ
                    assert abs(duration_nonexistent - duration_existing) < 0.05
            ''',
            
            'authorization_tests': '''
            class TestAuthorizationService:
                """認可サービスのテスト"""
                
                def test_rbac_authorization(self):
                    """RBACのテスト"""
                    # Setup
                    user = User(
                        id="123",
                        roles=["editor", "viewer"]
                    )
                    
                    rbac = RBACService()
                    rbac.define_role("editor", ["create", "update", "read"])
                    rbac.define_role("viewer", ["read"])
                    
                    # Test - エディターの権限
                    assert rbac.has_permission(user, "create") is True
                    assert rbac.has_permission(user, "update") is True
                    assert rbac.has_permission(user, "delete") is False
                
                def test_resource_based_authorization(self):
                    """リソースベース認可のテスト"""
                    # Setup
                    owner = User(id="owner123")
                    other_user = User(id="other456")
                    admin = User(id="admin789", roles=["admin"])
                    
                    resource = Document(
                        id="doc123",
                        owner_id="owner123",
                        permissions={
                            "owner123": ["read", "write", "delete"],
                            "other456": ["read"]
                        }
                    )
                    
                    authz = ResourceAuthorizationService()
                    
                    # Test - オーナーの権限
                    assert authz.can_access(owner, resource, "write") is True
                    assert authz.can_access(owner, resource, "delete") is True
                    
                    # Test - 他のユーザーの権限
                    assert authz.can_access(other_user, resource, "read") is True
                    assert authz.can_access(other_user, resource, "write") is False
                    
                    # Test - 管理者の権限
                    assert authz.can_access(admin, resource, "delete") is True
            '''
        }
    
    def integration_testing(self):
        """統合テスト"""
        
        return {
            'api_integration_tests': '''
            class TestAuthAPI:
                """認証APIの統合テスト"""
                
                @pytest.fixture
                async def client(self):
                    async with AsyncClient(app=app, base_url="http://test") as client:
                        yield client
                
                @pytest.mark.asyncio
                async def test_login_flow(self, client):
                    """完全なログインフローのテスト"""
                    
                    # 1. ログイン
                    response = await client.post("/auth/login", json={
                        "email": "test@example.com",
                        "password": "secure_password"
                    })
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert "access_token" in data
                    assert "refresh_token" in data
                    
                    access_token = data["access_token"]
                    
                    # 2. 認証が必要なエンドポイントへのアクセス
                    response = await client.get(
                        "/api/profile",
                        headers={"Authorization": f"Bearer {access_token}"}
                    )
                    
                    assert response.status_code == 200
                    profile = response.json()
                    assert profile["email"] == "test@example.com"
                    
                    # 3. トークンリフレッシュ
                    response = await client.post("/auth/refresh", json={
                        "refresh_token": data["refresh_token"]
                    })
                    
                    assert response.status_code == 200
                    new_tokens = response.json()
                    assert new_tokens["access_token"] != access_token
                
                @pytest.mark.asyncio
                async def test_mfa_flow(self, client):
                    """MFA認証フローのテスト"""
                    
                    # 1. 初回ログイン（MFAが必要）
                    response = await client.post("/auth/login", json={
                        "email": "mfa_user@example.com",
                        "password": "password"
                    })
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert data["mfa_required"] is True
                    assert "mfa_token" in data
                    
                    # 2. MFA検証
                    response = await client.post("/auth/mfa/verify", json={
                        "mfa_token": data["mfa_token"],
                        "code": "123456"  # テスト用の固定コード
                    })
                    
                    assert response.status_code == 200
                    final_tokens = response.json()
                    assert "access_token" in final_tokens
            ''',
            
            'security_testing': '''
            class TestSecurityVulnerabilities:
                """セキュリティ脆弱性のテスト"""
                
                @pytest.mark.asyncio
                async def test_sql_injection_protection(self, client):
                    """SQLインジェクション対策のテスト"""
                    
                    malicious_inputs = [
                        "admin'--",
                        "' OR '1'='1",
                        "'; DROP TABLE users; --",
                        "admin' UNION SELECT * FROM users--"
                    ]
                    
                    for payload in malicious_inputs:
                        response = await client.post("/auth/login", json={
                            "email": payload,
                            "password": "password"
                        })
                        
                        # SQLエラーが露出していないことを確認
                        assert response.status_code in [400, 401]
                        assert "SQL" not in response.text
                        assert "syntax" not in response.text.lower()
                
                @pytest.mark.asyncio
                async def test_brute_force_protection(self, client):
                    """ブルートフォース対策のテスト"""
                    
                    # 連続してログイン失敗
                    for i in range(6):
                        response = await client.post("/auth/login", json={
                            "email": "test@example.com",
                            "password": f"wrong_password_{i}"
                        })
                    
                    # レート制限が発動することを確認
                    assert response.status_code == 429
                    assert "Too many attempts" in response.json()["error"]
                
                @pytest.mark.asyncio
                async def test_jwt_tampering(self, client):
                    """JWT改ざん検知のテスト"""
                    
                    # 正規のトークン取得
                    response = await client.post("/auth/login", json={
                        "email": "test@example.com",
                        "password": "password"
                    })
                    token = response.json()["access_token"]
                    
                    # トークンを改ざん
                    parts = token.split('.')
                    payload = base64.urlsafe_b64decode(parts[1] + '==')
                    tampered_payload = payload.replace(b'"role":"user"', b'"role":"admin"')
                    tampered = parts[0] + '.' + base64.urlsafe_b64encode(tampered_payload).decode().rstrip('=') + '.' + parts[2]
                    
                    # 改ざんされたトークンでアクセス
                    response = await client.get(
                        "/api/admin/users",
                        headers={"Authorization": f"Bearer {tampered}"}
                    )
                    
                    assert response.status_code == 401
            '''
        }
    
    def e2e_testing(self):
        """E2Eテスト"""
        
        return {
            'playwright_tests': '''
            from playwright.async_api import async_playwright
            
            class TestE2EAuthentication:
                """E2E認証テスト"""
                
                @pytest.mark.asyncio
                async def test_complete_auth_flow(self):
                    async with async_playwright() as p:
                        browser = await p.chromium.launch()
                        context = await browser.new_context()
                        page = await context.new_page()
                        
                        # 1. ログインページへ移動
                        await page.goto("https://app.example.com/login")
                        
                        # 2. ログインフォームの入力
                        await page.fill('input[name="email"]', 'test@example.com')
                        await page.fill('input[name="password"]', 'password123')
                        
                        # 3. ログインボタンクリック
                        await page.click('button[type="submit"]')
                        
                        # 4. ダッシュボードへのリダイレクトを確認
                        await page.wait_for_url("https://app.example.com/dashboard")
                        
                        # 5. ユーザー情報の表示確認
                        user_name = await page.text_content('.user-name')
                        assert user_name == "Test User"
                        
                        # 6. 保護されたリソースへのアクセス
                        await page.goto("https://app.example.com/settings")
                        await page.wait_for_selector('.settings-form')
                        
                        # 7. ログアウト
                        await page.click('.logout-button')
                        await page.wait_for_url("https://app.example.com/login")
                        
                        # 8. ログアウト後のアクセス制限確認
                        await page.goto("https://app.example.com/dashboard")
                        await page.wait_for_url("https://app.example.com/login")
                        
                        await browser.close()
                
                @pytest.mark.asyncio
                async def test_mfa_e2e_flow(self):
                    """MFAのE2Eテスト"""
                    async with async_playwright() as p:
                        browser = await p.chromium.launch()
                        page = await browser.new_page()
                        
                        # 1. ログイン
                        await page.goto("https://app.example.com/login")
                        await page.fill('input[name="email"]', 'mfa_user@example.com')
                        await page.fill('input[name="password"]', 'password')
                        await page.click('button[type="submit"]')
                        
                        # 2. MFAページへのリダイレクト
                        await page.wait_for_url("https://app.example.com/mfa")
                        
                        # 3. MFAコード入力
                        # テスト環境では固定コードを使用
                        await page.fill('input[name="mfa_code"]', '123456')
                        await page.click('button[type="submit"]')
                        
                        # 4. ダッシュボードへのアクセス確認
                        await page.wait_for_url("https://app.example.com/dashboard")
                        
                        await browser.close()
            ''',
            
            'performance_testing': '''
            import asyncio
            import aiohttp
            import time
            from statistics import mean, stdev
            
            class TestAuthPerformance:
                """認証パフォーマンステスト"""
                
                async def test_login_performance(self):
                    """ログインAPIのパフォーマンステスト"""
                    
                    async def single_login():
                        async with aiohttp.ClientSession() as session:
                            start = time.time()
                            async with session.post(
                                "https://api.example.com/auth/login",
                                json={
                                    "email": "perf_test@example.com",
                                    "password": "password"
                                }
                            ) as response:
                                await response.json()
                            return time.time() - start
                    
                    # 100回の同時ログインテスト
                    tasks = [single_login() for _ in range(100)]
                    durations = await asyncio.gather(*tasks)
                    
                    # パフォーマンス指標の計算
                    avg_duration = mean(durations)
                    std_duration = stdev(durations)
                    p95_duration = sorted(durations)[int(len(durations) * 0.95)]
                    p99_duration = sorted(durations)[int(len(durations) * 0.99)]
                    
                    # アサーション
                    assert avg_duration < 0.2  # 平均200ms以下
                    assert p95_duration < 0.5  # 95パーセンタイル500ms以下
                    assert p99_duration < 1.0  # 99パーセンタイル1秒以下
                    
                    print(f"Average: {avg_duration:.3f}s")
                    print(f"Std Dev: {std_duration:.3f}s")
                    print(f"P95: {p95_duration:.3f}s")
                    print(f"P99: {p99_duration:.3f}s")
            '''
        }
```

## まとめ

この章では、認証認可システムの実装における重要なパターンとベストプラクティスを学びました：

1. **認証フローのパターン**
   - 基本的なパスワード認証からモダンなパスワードレス認証まで
   - 多段階認証と適応型認証の実装
   - 委譲認証パターンの活用

2. **権限チェックの実装方法**
   - 命令的・宣言的なアプローチの使い分け
   - ポリシーベース認可の設計
   - パフォーマンスを考慮した実装

3. **監査ログの設計**
   - 必要な情報の記録方法
   - 機密データの適切な処理
   - ログ分析と異常検知

4. **テスト戦略**
   - ユニットテストからE2Eテストまでの包括的アプローチ
   - セキュリティ脆弱性のテスト
   - パフォーマンステストの実施

次章では、セキュリティと脅威対策について、より詳細に学びます。

## 演習問題

### 問題1：認証フローの設計
B2B SaaSアプリケーションで、以下の要件を満たす認証フローを設計しなさい：
- エンタープライズSSO（SAML/OIDC）対応
- 管理者による強制的なMFA設定
- IPアドレス制限
- セッション管理の詳細設計

### 問題2：カスタム認可システム
以下の要件を満たすカスタム認可システムを実装しなさい：
- 階層的な組織構造（会社→部門→チーム）
- リソースの継承可能な権限
- 時限的な権限付与
- 権限の委譲機能

### 問題3：監査ログシステム
以下の要件を満たす監査ログシステムを設計・実装しなさい：
- GDPR準拠（個人データの適切な処理）
- 改ざん防止機能
- 効率的な検索機能
- 長期保存とアーカイブ戦略

### 問題4：E2Eテストシナリオ
以下の認証シナリオをカバーするE2Eテストを作成しなさい：
- 通常のログイン→操作→ログアウト
- パスワードリセットフロー
- MFA設定と解除
- 同時ログインセッション管理
- ブラウザを閉じた後の再アクセス

### 問題5：パフォーマンス最適化
1000万ユーザー規模のシステムで、以下の認証認可処理を最適化しなさい：
- ログイン処理（目標: p99 < 100ms）
- トークン検証（目標: p99 < 20ms）
- 複雑な権限チェック（目標: p99 < 50ms）
- 実装コードと測定結果を含めること
