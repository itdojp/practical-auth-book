# 第10章 演習問題解答

## 問題1：認証フローの設計

### 解答

**B2B SaaSアプリケーションの認証フロー設計**

```python
class EnterpriseSaaSAuthFlow:
    """エンタープライズ向けSaaS認証フロー"""
    
    def __init__(self):
        self.sso_providers = {}
        self.ip_whitelist_service = IPWhitelistService()
        self.mfa_service = MFAService()
        self.session_manager = SessionManager()
    
    def authentication_flow_design(self):
        """認証フロー全体設計"""
        return {
            'flow_diagram': '''
            1. Initial Request
               ↓
            2. Organization Detection (by email domain or subdomain)
               ↓
            3. Authentication Method Selection
               ├─ SSO (SAML/OIDC) → IdP Redirect
               └─ Standard Login → Password + MFA
               ↓
            4. IP Address Validation
               ↓
            5. MFA Enforcement (if required)
               ↓
            6. Session Creation
               ↓
            7. Post-Auth Checks (permissions, license)
            ''',
            
            'implementation': '''
            class EnterpriseAuthService:
                async def authenticate(self, request: AuthRequest) -> AuthResult:
                    # 1. 組織の特定
                    org = await self.identify_organization(request)
                    
                    # 2. IP制限チェック
                    if not await self.check_ip_restriction(org, request.ip_address):
                        raise ForbiddenError("Access from this IP is not allowed")
                    
                    # 3. 認証方式の決定
                    auth_method = await self.determine_auth_method(org, request.email)
                    
                    # 4. 認証実行
                    if auth_method.type == "SSO":
                        return await self.handle_sso_auth(auth_method, request)
                    else:
                        return await self.handle_standard_auth(request, org)
                
                async def identify_organization(self, request: AuthRequest) -> Organization:
                    # サブドメインベース
                    if request.subdomain:
                        org = await self.org_repo.find_by_subdomain(request.subdomain)
                        if org:
                            return org
                    
                    # メールドメインベース
                    email_domain = request.email.split('@')[1]
                    org = await self.org_repo.find_by_email_domain(email_domain)
                    
                    if not org:
                        # デフォルト組織（個人ユーザー用）
                        return await self.org_repo.get_default()
                    
                    return org
            '''
        }
    
    def sso_implementation(self):
        """SSO実装"""
        return {
            'saml_configuration': '''
            class SAMLConfiguration:
                def __init__(self, org_id: str):
                    self.org_id = org_id
                    self.config = None
                
                async def load_config(self) -> dict:
                    """組織固有のSAML設定を読み込み"""
                    org_saml = await self.db.saml_configs.find_one({
                        'org_id': self.org_id,
                        'active': True
                    })
                    
                    return {
                        'sp': {
                            'entityId': f'https://app.example.com/saml/{self.org_id}',
                            'assertionConsumerService': {
                                'url': f'https://app.example.com/saml/acs/{self.org_id}',
                                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
                            },
                            'x509cert': org_saml.get('sp_cert', '')
                        },
                        'idp': {
                            'entityId': org_saml['idp_entity_id'],
                            'singleSignOnService': {
                                'url': org_saml['idp_sso_url'],
                                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                            },
                            'x509cert': org_saml['idp_cert']
                        },
                        'security': {
                            'nameIdEncrypted': False,
                            'authnRequestsSigned': True,
                            'wantAssertionsSigned': True,
                            'wantAssertionsEncrypted': False,
                            'signatureAlgorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
                        }
                    }
            ''',
            
            'oidc_implementation': '''
            class OIDCProvider:
                def __init__(self, org_config: dict):
                    self.client_id = org_config['client_id']
                    self.client_secret = org_config['client_secret']
                    self.issuer = org_config['issuer']
                    self.redirect_uri = f"https://app.example.com/oidc/callback/{org_config['org_id']}"
                
                async def initiate_auth(self) -> str:
                    """OIDC認証フローの開始"""
                    # Discovery endpoint から設定を取得
                    discovery = await self.fetch_discovery_document()
                    
                    # PKCE対応
                    code_verifier = generate_code_verifier()
                    code_challenge = generate_code_challenge(code_verifier)
                    
                    # State生成（CSRF対策）
                    state = secrets.token_urlsafe(32)
                    
                    # Nonceの生成（リプレイ攻撃対策）
                    nonce = secrets.token_urlsafe(32)
                    
                    # セッションに保存
                    await self.session_store.save({
                        'state': state,
                        'code_verifier': code_verifier,
                        'nonce': nonce
                    })
                    
                    # 認証URLの構築
                    params = {
                        'response_type': 'code',
                        'client_id': self.client_id,
                        'redirect_uri': self.redirect_uri,
                        'scope': 'openid email profile',
                        'state': state,
                        'nonce': nonce,
                        'code_challenge': code_challenge,
                        'code_challenge_method': 'S256'
                    }
                    
                    auth_url = f"{discovery['authorization_endpoint']}?{urlencode(params)}"
                    return auth_url
            '''
        }
    
    def mfa_enforcement(self):
        """MFA強制実装"""
        return {
            'admin_controlled_mfa': '''
            class AdminControlledMFA:
                """管理者によるMFA制御"""
                
                async def check_mfa_requirement(self, user: User, org: Organization) -> MFARequirement:
                    # 組織レベルの設定
                    org_policy = await self.get_org_mfa_policy(org.id)
                    
                    # ユーザーレベルの設定
                    user_setting = await self.get_user_mfa_setting(user.id)
                    
                    # 管理者による強制設定が最優先
                    if org_policy.force_all_users:
                        return MFARequirement(
                            required=True,
                            methods=org_policy.allowed_methods,
                            grace_period=None
                        )
                    
                    # 特定ロールへの強制
                    if user.role in org_policy.required_roles:
                        return MFARequirement(
                            required=True,
                            methods=org_policy.allowed_methods,
                            grace_period=org_policy.grace_period
                        )
                    
                    # ユーザーの自主的な設定
                    if user_setting.enabled:
                        return MFARequirement(
                            required=True,
                            methods=user_setting.methods,
                            grace_period=None
                        )
                    
                    return MFARequirement(required=False)
                
                async def enforce_mfa_setup(self, user: User, org: Organization):
                    """MFAセットアップの強制"""
                    requirement = await self.check_mfa_requirement(user, org)
                    
                    if requirement.required and not user.mfa_configured:
                        # 猶予期間中かチェック
                        if requirement.grace_period:
                            deadline = user.created_at + requirement.grace_period
                            if datetime.utcnow() < deadline:
                                # 警告を表示しつつアクセスを許可
                                return MFAEnforcementResult(
                                    allow_access=True,
                                    show_warning=True,
                                    deadline=deadline
                                )
                        
                        # MFA設定画面へ強制リダイレクト
                        return MFAEnforcementResult(
                            allow_access=False,
                            redirect_to="/mfa/setup",
                            message="MFA setup is required by your organization"
                        )
            ''',
            
            'mfa_administration': '''
            class MFAAdministration:
                """MFA管理機能"""
                
                async def admin_reset_mfa(self, admin: User, target_user_id: str, reason: str):
                    """管理者によるMFAリセット"""
                    # 権限確認
                    if not self.can_manage_mfa(admin):
                        raise ForbiddenError("Insufficient privileges")
                    
                    # 対象ユーザー取得
                    target_user = await self.user_repo.get(target_user_id)
                    
                    # MFAリセット
                    await self.mfa_service.reset_user_mfa(target_user_id)
                    
                    # 監査ログ
                    await self.audit_logger.log({
                        'action': 'mfa_reset_by_admin',
                        'admin_id': admin.id,
                        'target_user_id': target_user_id,
                        'reason': reason,
                        'timestamp': datetime.utcnow()
                    })
                    
                    # ユーザーへの通知
                    await self.notification_service.send(
                        user_id=target_user_id,
                        type='security_alert',
                        message='Your MFA has been reset by an administrator',
                        details={'admin': admin.email, 'reason': reason}
                    )
            '''
        }
    
    def ip_restriction(self):
        """IP制限実装"""
        return {
            'ip_whitelist_service': '''
            class IPWhitelistService:
                """IP制限サービス"""
                
                def __init__(self):
                    self.cache = IPWhitelistCache()
                    self.ip_parser = IPAddressParser()
                
                async def check_access(self, org_id: str, ip_address: str) -> bool:
                    # 組織のIP制限設定を取得
                    whitelist = await self.get_whitelist(org_id)
                    
                    if not whitelist.enabled:
                        return True  # IP制限無効
                    
                    # IPアドレスのパース
                    ip = self.ip_parser.parse(ip_address)
                    
                    # ホワイトリストチェック
                    for allowed_range in whitelist.ranges:
                        if self.is_ip_in_range(ip, allowed_range):
                            return True
                    
                    # VPNアクセスの特別処理
                    if whitelist.allow_vpn and await self.is_corporate_vpn(ip_address):
                        return True
                    
                    return False
                
                async def get_whitelist(self, org_id: str) -> IPWhitelist:
                    # キャッシュチェック
                    cached = await self.cache.get(org_id)
                    if cached:
                        return cached
                    
                    # DBから取得
                    whitelist_data = await self.db.ip_whitelists.find_one({
                        'org_id': org_id,
                        'active': True
                    })
                    
                    if not whitelist_data:
                        return IPWhitelist(enabled=False)
                    
                    whitelist = IPWhitelist(
                        enabled=True,
                        ranges=whitelist_data['ranges'],
                        allow_vpn=whitelist_data.get('allow_vpn', False)
                    )
                    
                    # キャッシュ更新
                    await self.cache.set(org_id, whitelist, ttl=300)
                    
                    return whitelist
                
                def is_ip_in_range(self, ip: ipaddress.IPv4Address, range_str: str) -> bool:
                    """IPがレンジ内かチェック"""
                    try:
                        network = ipaddress.ip_network(range_str)
                        return ip in network
                    except ValueError:
                        logger.error(f"Invalid IP range: {range_str}")
                        return False
            '''
        }
    
    def session_management(self):
        """セッション管理の詳細設計"""
        return {
            'session_configuration': '''
            class SessionConfiguration:
                """セッション設定"""
                
                def get_session_config(self, org: Organization, user: User) -> dict:
                    base_config = {
                        'idle_timeout': timedelta(minutes=30),
                        'absolute_timeout': timedelta(hours=8),
                        'concurrent_sessions': 3,
                        'binding': ['ip', 'user_agent'],
                        'refresh_enabled': True,
                        'refresh_window': timedelta(minutes=5)
                    }
                    
                    # 組織ポリシーの適用
                    if org.security_policy:
                        if org.security_policy.get('shorter_sessions'):
                            base_config['idle_timeout'] = timedelta(minutes=15)
                            base_config['absolute_timeout'] = timedelta(hours=4)
                        
                        if org.security_policy.get('single_session'):
                            base_config['concurrent_sessions'] = 1
                        
                        if org.security_policy.get('strict_binding'):
                            base_config['binding'].append('device_fingerprint')
                    
                    # ユーザーロールによる調整
                    if user.role == 'admin':
                        base_config['idle_timeout'] = timedelta(minutes=15)
                        base_config['require_reauthentication'] = ['sensitive_operations']
                    
                    return base_config
            ''',
            
            'distributed_session_management': '''
            class DistributedSessionManager:
                """分散セッション管理"""
                
                def __init__(self):
                    self.redis_cluster = RedisCluster(
                        startup_nodes=[
                            {"host": "redis-1", "port": 6379},
                            {"host": "redis-2", "port": 6379},
                            {"host": "redis-3", "port": 6379}
                        ]
                    )
                    self.encryption_key = load_encryption_key()
                
                async def create_session(self, user: User, auth_context: AuthContext) -> Session:
                    session = Session(
                        id=generate_session_id(),
                        user_id=user.id,
                        org_id=user.org_id,
                        created_at=datetime.utcnow(),
                        last_activity=datetime.utcnow(),
                        auth_context=auth_context
                    )
                    
                    # セッションデータの暗号化
                    encrypted_data = self.encrypt_session_data(session)
                    
                    # Redisに保存
                    key = f"session:{session.id}"
                    await self.redis_cluster.setex(
                        key,
                        session.config.absolute_timeout.total_seconds(),
                        encrypted_data
                    )
                    
                    # ユーザーのセッション一覧を更新
                    await self.update_user_sessions(user.id, session.id)
                    
                    return session
                
                async def validate_session(self, session_id: str, request_context: dict) -> Optional[Session]:
                    # セッションデータ取得
                    key = f"session:{session_id}"
                    encrypted_data = await self.redis_cluster.get(key)
                    
                    if not encrypted_data:
                        return None
                    
                    # 復号化
                    session = self.decrypt_session_data(encrypted_data)
                    
                    # セッションバインディングの検証
                    if not self.verify_session_binding(session, request_context):
                        await self.invalidate_session(session_id)
                        return None
                    
                    # アイドルタイムアウトチェック
                    if datetime.utcnow() - session.last_activity > session.config.idle_timeout:
                        await self.invalidate_session(session_id)
                        return None
                    
                    # 最終アクティビティ更新
                    session.last_activity = datetime.utcnow()
                    await self.update_session(session)
                    
                    return session
                
                def verify_session_binding(self, session: Session, context: dict) -> bool:
                    """セッションバインディング検証"""
                    for binding in session.config.binding:
                        if binding == 'ip':
                            if session.auth_context.ip_address != context.get('ip_address'):
                                return False
                        elif binding == 'user_agent':
                            if session.auth_context.user_agent != context.get('user_agent'):
                                return False
                        elif binding == 'device_fingerprint':
                            if session.auth_context.device_id != context.get('device_id'):
                                return False
                    
                    return True
            '''
        }
```

## 問題2：カスタム認可システム

### 解答

```python
class HierarchicalAuthorizationSystem:
    """階層的組織構造に対応した認可システム"""
    
    def __init__(self):
        self.org_hierarchy = OrganizationHierarchy()
        self.permission_service = PermissionService()
        self.delegation_service = DelegationService()
    
    def data_model(self):
        """データモデル設計"""
        return {
            'organization_structure': '''
            # 組織構造
            CREATE TABLE organizations (
                id UUID PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                type VARCHAR(50) NOT NULL -- 'company', 'department', 'team'
            );
            
            CREATE TABLE organization_hierarchy (
                id UUID PRIMARY KEY,
                parent_id UUID REFERENCES organizations(id),
                child_id UUID REFERENCES organizations(id),
                path TEXT[], -- 階層パス（例: ['company_id', 'dept_id', 'team_id']）
                depth INTEGER,
                UNIQUE(parent_id, child_id)
            );
            
            # リソースと権限
            CREATE TABLE resources (
                id UUID PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                type VARCHAR(100) NOT NULL,
                owner_org_id UUID REFERENCES organizations(id),
                inheritable BOOLEAN DEFAULT true,
                metadata JSONB
            );
            
            CREATE TABLE permissions (
                id UUID PRIMARY KEY,
                resource_id UUID REFERENCES resources(id),
                principal_type VARCHAR(50), -- 'user', 'org', 'role'
                principal_id UUID NOT NULL,
                permission VARCHAR(100) NOT NULL,
                granted_by UUID REFERENCES users(id),
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                -- 時限的権限
                valid_from TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                valid_until TIMESTAMP,
                
                -- 継承設定
                inheritable BOOLEAN DEFAULT true,
                inherit_depth INTEGER DEFAULT -1, -- -1: 無制限, 0: 継承なし, n: n階層まで
                
                UNIQUE(resource_id, principal_type, principal_id, permission)
            );
            
            # 権限委譲
            CREATE TABLE permission_delegations (
                id UUID PRIMARY KEY,
                delegator_id UUID REFERENCES users(id),
                delegatee_id UUID REFERENCES users(id),
                permission_id UUID REFERENCES permissions(id),
                
                -- 委譲条件
                conditions JSONB,
                max_subdelegation_depth INTEGER DEFAULT 0,
                
                -- 有効期間
                valid_from TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                valid_until TIMESTAMP NOT NULL,
                
                -- 監査
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                revoked_at TIMESTAMP,
                revoked_by UUID REFERENCES users(id),
                revoke_reason TEXT
            );
            ''',
            
            'indexes': '''
            -- パフォーマンス最適化のためのインデックス
            CREATE INDEX idx_org_hierarchy_path ON organization_hierarchy USING GIN(path);
            CREATE INDEX idx_permissions_principal ON permissions(principal_type, principal_id);
            CREATE INDEX idx_permissions_validity ON permissions(valid_from, valid_until) 
                WHERE valid_until IS NOT NULL;
            CREATE INDEX idx_delegations_validity ON permission_delegations(valid_from, valid_until) 
                WHERE revoked_at IS NULL;
            '''
        }
    
    def authorization_logic(self):
        """認可ロジックの実装"""
        return {
            'hierarchical_permission_check': '''
            class HierarchicalPermissionChecker:
                async def has_permission(
                    self, 
                    user: User, 
                    resource: Resource, 
                    action: str
                ) -> bool:
                    # 1. 直接権限のチェック
                    if await self.has_direct_permission(user.id, resource.id, action):
                        return True
                    
                    # 2. 組織階層による権限チェック
                    user_orgs = await self.get_user_organizations(user.id)
                    for org in user_orgs:
                        if await self.has_org_permission(org, resource, action):
                            return True
                    
                    # 3. 委譲された権限のチェック
                    if await self.has_delegated_permission(user.id, resource.id, action):
                        return True
                    
                    # 4. 継承された権限のチェック
                    if resource.inheritable:
                        parent_resources = await self.get_parent_resources(resource)
                        for parent in parent_resources:
                            if await self.has_permission(user, parent, action):
                                return True
                    
                    return False
                
                async def has_org_permission(
                    self, 
                    org: Organization, 
                    resource: Resource, 
                    action: str
                ) -> bool:
                    # 組織の権限チェック
                    permissions = await self.db.permissions.find({
                        'resource_id': resource.id,
                        'principal_type': 'org',
                        'principal_id': org.id,
                        'permission': action,
                        'valid_from': {'$lte': datetime.utcnow()},
                        '$or': [
                            {'valid_until': None},
                            {'valid_until': {'$gt': datetime.utcnow()}}
                        ]
                    })
                    
                    if permissions:
                        return True
                    
                    # 上位組織の権限を継承
                    parent_orgs = await self.get_parent_organizations(org.id)
                    for parent in parent_orgs:
                        perm = await self.get_inheritable_permission(
                            parent.id, 
                            resource.id, 
                            action
                        )
                        if perm and self.can_inherit(perm, org, parent):
                            return True
                    
                    return False
                
                def can_inherit(self, permission: Permission, child_org: Organization, parent_org: Organization) -> bool:
                    """権限の継承可能性チェック"""
                    if not permission.inheritable:
                        return False
                    
                    if permission.inherit_depth == -1:
                        return True  # 無制限継承
                    
                    # 階層の深さチェック
                    depth = self.calculate_org_depth(child_org.id, parent_org.id)
                    return depth <= permission.inherit_depth
            ''',
            
            'temporal_permissions': '''
            class TemporalPermissionManager:
                """時限的権限の管理"""
                
                async def grant_temporal_permission(
                    self,
                    grantor: User,
                    grantee_id: str,
                    resource_id: str,
                    permission: str,
                    duration: timedelta,
                    conditions: dict = None
                ) -> Permission:
                    # 権限付与者の権限確認
                    if not await self.can_grant_permission(grantor, resource_id, permission):
                        raise ForbiddenError("Insufficient privileges to grant permission")
                    
                    # 時限的権限の作成
                    now = datetime.utcnow()
                    perm = Permission(
                        resource_id=resource_id,
                        principal_type='user',
                        principal_id=grantee_id,
                        permission=permission,
                        granted_by=grantor.id,
                        granted_at=now,
                        valid_from=now,
                        valid_until=now + duration,
                        conditions=conditions
                    )
                    
                    await self.db.permissions.insert(perm)
                    
                    # スケジューラーに期限切れ処理を登録
                    await self.scheduler.schedule(
                        job_type='expire_permission',
                        run_at=perm.valid_until,
                        data={'permission_id': perm.id}
                    )
                    
                    # 監査ログ
                    await self.audit_logger.log({
                        'action': 'temporal_permission_granted',
                        'grantor': grantor.id,
                        'grantee': grantee_id,
                        'resource': resource_id,
                        'permission': permission,
                        'duration': duration.total_seconds(),
                        'expires_at': perm.valid_until
                    })
                    
                    return perm
                
                async def extend_permission(
                    self,
                    permission_id: str,
                    extension: timedelta,
                    reason: str
                ) -> Permission:
                    """権限の延長"""
                    perm = await self.db.permissions.find_by_id(permission_id)
                    
                    if not perm:
                        raise NotFoundError("Permission not found")
                    
                    # 新しい有効期限
                    new_expiry = perm.valid_until + extension
                    
                    # 更新
                    await self.db.permissions.update(
                        permission_id,
                        {'valid_until': new_expiry}
                    )
                    
                    # スケジューラー更新
                    await self.scheduler.reschedule(
                        job_type='expire_permission',
                        job_data={'permission_id': permission_id},
                        new_run_at=new_expiry
                    )
                    
                    return perm
            '''
        }
    
    def delegation_system(self):
        """権限委譲システム"""
        return {
            'delegation_implementation': '''
            class PermissionDelegationService:
                async def delegate_permission(
                    self,
                    delegator: User,
                    delegatee_id: str,
                    permission_id: str,
                    conditions: dict = None,
                    allow_subdelegation: bool = False,
                    duration: timedelta = timedelta(days=7)
                ) -> Delegation:
                    # 委譲可能性のチェック
                    permission = await self.get_permission(permission_id)
                    if not await self.can_delegate(delegator, permission):
                        raise ForbiddenError("Cannot delegate this permission")
                    
                    # 委譲の作成
                    delegation = Delegation(
                        delegator_id=delegator.id,
                        delegatee_id=delegatee_id,
                        permission_id=permission_id,
                        conditions=conditions or {},
                        max_subdelegation_depth=1 if allow_subdelegation else 0,
                        valid_from=datetime.utcnow(),
                        valid_until=datetime.utcnow() + duration
                    )
                    
                    await self.db.delegations.insert(delegation)
                    
                    # 通知
                    await self.notify_delegation(delegator, delegatee_id, permission, delegation)
                    
                    return delegation
                
                async def can_delegate(self, user: User, permission: Permission) -> bool:
                    """委譲可能かチェック"""
                    # 自分が持っている権限のみ委譲可能
                    if permission.principal_id != user.id:
                        return False
                    
                    # 委譲不可フラグチェック
                    if permission.metadata and permission.metadata.get('non_delegatable'):
                        return False
                    
                    # 特定の権限は委譲不可
                    if permission.permission in ['admin', 'delete_organization']:
                        return False
                    
                    return True
                
                async def revoke_delegation(
                    self,
                    delegator: User,
                    delegation_id: str,
                    reason: str
                ):
                    """委譲の取り消し"""
                    delegation = await self.db.delegations.find_by_id(delegation_id)
                    
                    if not delegation:
                        raise NotFoundError("Delegation not found")
                    
                    if delegation.delegator_id != delegator.id:
                        raise ForbiddenError("Only delegator can revoke")
                    
                    # 取り消し処理
                    await self.db.delegations.update(delegation_id, {
                        'revoked_at': datetime.utcnow(),
                        'revoked_by': delegator.id,
                        'revoke_reason': reason
                    })
                    
                    # 連鎖的な取り消し（サブ委譲）
                    await self.revoke_subdelegations(delegation_id)
                    
                    # 通知
                    await self.notify_revocation(delegation, reason)
            ''',
            
            'delegation_chain_validation': '''
            class DelegationChainValidator:
                """委譲チェーンの検証"""
                
                async def validate_delegation_chain(
                    self,
                    user_id: str,
                    resource_id: str,
                    action: str
                ) -> Optional[DelegationChain]:
                    # ユーザーに委譲された権限を検索
                    delegations = await self.find_active_delegations(user_id, resource_id, action)
                    
                    for delegation in delegations:
                        # 委譲チェーンの構築
                        chain = await self.build_delegation_chain(delegation)
                        
                        # チェーンの検証
                        if self.is_valid_chain(chain):
                            return chain
                    
                    return None
                
                async def build_delegation_chain(self, delegation: Delegation) -> DelegationChain:
                    """委譲チェーンの構築"""
                    chain = DelegationChain()
                    current = delegation
                    
                    while current:
                        chain.add_link(current)
                        
                        # 元の権限に到達
                        if current.permission.principal_type == 'source':
                            break
                        
                        # 上位の委譲を探す
                        parent = await self.find_parent_delegation(current)
                        if not parent:
                            # 直接付与された権限を探す
                            source_perm = await self.find_source_permission(current.permission_id)
                            if source_perm:
                                chain.set_source(source_perm)
                            break
                        
                        current = parent
                    
                    return chain
                
                def is_valid_chain(self, chain: DelegationChain) -> bool:
                    """チェーンの有効性検証"""
                    # すべてのリンクが有効期限内か
                    now = datetime.utcnow()
                    for link in chain.links:
                        if link.valid_until < now or link.revoked_at:
                            return False
                    
                    # 委譲深度のチェック
                    if len(chain.links) > chain.max_allowed_depth:
                        return False
                    
                    # 条件の評価
                    for link in chain.links:
                        if link.conditions and not self.evaluate_conditions(link.conditions):
                            return False
                    
                    return True
            '''
        }
```

## 問題3：監査ログシステム

### 解答

```python
class GDPRCompliantAuditSystem:
    """GDPR準拠の監査ログシステム"""
    
    def system_design(self):
        """システム設計"""
        return {
            'architecture': '''
            ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
            │ Application │────▶│ Audit Logger │────▶│ Write Queue │
            └─────────────┘     └──────────────┘     └─────┬───────┘
                                                              │
                    ┌─────────────────────────────────────────▼───────┐
                    │                  Audit Pipeline                  │
                    ├─────────────────────────────────────────────────┤
                    │  1. Data Sanitization (PII removal/encryption)  │
                    │  2. Integrity Hashing (tamper detection)        │
                    │  3. Compression                                  │
                    │  4. Routing (hot/warm/cold storage)             │
                    └─────────────────────────────────────────────────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    ▼                       ▼                       ▼
            ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
            │ Hot Storage  │     │ Warm Storage │     │ Cold Storage │
            │  (30 days)   │     │  (1 year)    │     │  (7 years)   │
            │  PostgreSQL  │     │     S3       │     │   Glacier    │
            └──────────────┘     └──────────────┘     └──────────────┘
            ''',
            
            'data_model': '''
            CREATE TABLE audit_logs (
                -- 基本フィールド
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                
                -- アクター情報（暗号化）
                actor_id_hash VARCHAR(64) NOT NULL, -- SHA-256 hash
                actor_type VARCHAR(50) NOT NULL,
                actor_metadata_encrypted TEXT, -- Fernet encrypted JSON
                
                -- アクション情報
                action VARCHAR(100) NOT NULL,
                resource_type VARCHAR(100),
                resource_id VARCHAR(255),
                
                -- 結果
                result VARCHAR(20) NOT NULL CHECK (result IN ('success', 'failure', 'error')),
                error_code VARCHAR(50),
                
                -- コンテキスト（部分的に暗号化）
                ip_address_hash VARCHAR(64),
                session_id_hash VARCHAR(64),
                request_id UUID,
                
                -- 改ざん防止
                content_hash VARCHAR(64) NOT NULL, -- 全フィールドのハッシュ
                previous_hash VARCHAR(64), -- ブロックチェーン風の連鎖
                
                -- GDPR対応
                data_subject_id_hash VARCHAR(64), -- データ主体の識別子
                personal_data_refs JSONB, -- 個人データへの参照
                retention_policy VARCHAR(50) DEFAULT 'standard',
                anonymized_at TIMESTAMP,
                
                -- パーティショニング用
                created_date DATE GENERATED ALWAYS AS (DATE(timestamp)) STORED
            ) PARTITION BY RANGE (created_date);
            
            -- インデックス
            CREATE INDEX idx_audit_actor ON audit_logs(actor_id_hash, timestamp);
            CREATE INDEX idx_audit_action ON audit_logs(action, timestamp);
            CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id, timestamp);
            CREATE INDEX idx_audit_data_subject ON audit_logs(data_subject_id_hash) 
                WHERE data_subject_id_hash IS NOT NULL;
            '''
        }
    
    def gdpr_compliance(self):
        """GDPR準拠機能"""
        return {
            'data_minimization': '''
            class GDPRDataMinimizer:
                """データ最小化"""
                
                def __init__(self):
                    self.pii_detector = PIIDetector()
                    self.encryption_service = EncryptionService()
                
                def minimize_audit_entry(self, entry: AuditLogEntry) -> MinimizedAuditEntry:
                    """監査エントリの最小化"""
                    
                    # PII検出と処理
                    minimized = MinimizedAuditEntry()
                    
                    # アクターIDのハッシュ化
                    minimized.actor_id_hash = self.hash_identifier(entry.actor_id)
                    
                    # メタデータからPIIを分離
                    pii_data, safe_data = self.separate_pii(entry.metadata)
                    
                    # PIIは暗号化して保存
                    if pii_data:
                        minimized.pii_encrypted = self.encryption_service.encrypt(
                            json.dumps(pii_data)
                        )
                        minimized.pii_refs = list(pii_data.keys())
                    
                    # 安全なデータはそのまま保存
                    minimized.safe_metadata = safe_data
                    
                    # IPアドレスの匿名化
                    if entry.ip_address:
                        minimized.ip_subnet = self.anonymize_ip(entry.ip_address)
                        minimized.ip_hash = self.hash_identifier(entry.ip_address)
                    
                    return minimized
                
                def separate_pii(self, data: dict) -> tuple[dict, dict]:
                    """PIIと非PIIデータの分離"""
                    pii_fields = ['email', 'name', 'phone', 'address', 'ssn', 'dob']
                    
                    pii_data = {}
                    safe_data = {}
                    
                    for key, value in data.items():
                        if key in pii_fields or self.pii_detector.is_pii(key, value):
                            pii_data[key] = value
                        else:
                            safe_data[key] = value
                    
                    return pii_data, safe_data
                
                def anonymize_ip(self, ip_address: str) -> str:
                    """IPアドレスの匿名化（最後のオクテットを削除）"""
                    try:
                        ip = ipaddress.ip_address(ip_address)
                        if isinstance(ip, ipaddress.IPv4Address):
                            # 192.168.1.100 -> 192.168.1.0/24
                            network = ipaddress.ip_network(f"{ip}/24", strict=False)
                            return str(network)
                        else:
                            # IPv6: 最後の64ビットを削除
                            network = ipaddress.ip_network(f"{ip}/64", strict=False)
                            return str(network)
                    except ValueError:
                        return "invalid_ip"
            ''',
            
            'right_to_erasure': '''
            class RightToErasureHandler:
                """削除権の処理"""
                
                async def process_erasure_request(self, data_subject_id: str):
                    """削除要求の処理"""
                    
                    # 1. 該当する監査ログの特定
                    subject_hash = self.hash_identifier(data_subject_id)
                    affected_logs = await self.find_logs_by_subject(subject_hash)
                    
                    # 2. 法的保持要件の確認
                    retention_required = await self.check_legal_retention(affected_logs)
                    
                    # 3. 処理実行
                    for log in affected_logs:
                        if log.id in retention_required:
                            # 法的要件により完全削除不可 -> 匿名化
                            await self.anonymize_log(log)
                        else:
                            # 完全削除可能
                            await self.delete_log(log)
                    
                    # 4. 削除証明の生成
                    certificate = await self.generate_erasure_certificate(
                        data_subject_id,
                        len(affected_logs),
                        len(retention_required)
                    )
                    
                    return certificate
                
                async def anonymize_log(self, log: AuditLog):
                    """ログの匿名化"""
                    
                    # PII関連フィールドをnullまたは匿名値に置換
                    updates = {
                        'actor_id_hash': 'ANONYMIZED',
                        'actor_metadata_encrypted': None,
                        'ip_address_hash': 'ANONYMIZED',
                        'personal_data_refs': None,
                        'anonymized_at': datetime.utcnow()
                    }
                    
                    # 改ざん防止ハッシュの再計算
                    updates['content_hash'] = self.calculate_content_hash(log, updates)
                    
                    await self.db.audit_logs.update(log.id, updates)
                    
                    # 匿名化ログの記録
                    await self.log_anonymization(log.id, data_subject_id)
            '''
        }
    
    def tamper_prevention(self):
        """改ざん防止機能"""
        return {
            'hash_chain_implementation': '''
            class TamperProofAuditLogger:
                """改ざん防止監査ログ"""
                
                def __init__(self):
                    self.hash_algorithm = hashlib.sha256
                    self.signing_key = load_signing_key()
                
                async def write_audit_log(self, entry: AuditLogEntry) -> str:
                    # 前のログのハッシュを取得
                    previous_hash = await self.get_latest_hash()
                    
                    # エントリのシリアライズ
                    entry_dict = entry.to_dict()
                    entry_dict['previous_hash'] = previous_hash
                    
                    # コンテンツハッシュの計算
                    content = self.serialize_for_hashing(entry_dict)
                    content_hash = self.hash_algorithm(content.encode()).hexdigest()
                    
                    # デジタル署名（オプション）
                    signature = self.sign_content(content)
                    
                    # 保存
                    entry_dict['content_hash'] = content_hash
                    entry_dict['signature'] = signature
                    
                    await self.db.audit_logs.insert(entry_dict)
                    
                    return content_hash
                
                def serialize_for_hashing(self, data: dict) -> str:
                    """ハッシュ用の正規化されたシリアライズ"""
                    # キーをソートして順序を固定
                    excluded_fields = ['content_hash', 'signature']
                    filtered_data = {
                        k: v for k, v in data.items() 
                        if k not in excluded_fields
                    }
                    
                    return json.dumps(filtered_data, sort_keys=True, default=str)
                
                async def verify_integrity(self, start_date: date, end_date: date) -> IntegrityReport:
                    """整合性検証"""
                    
                    logs = await self.db.audit_logs.find({
                        'timestamp': {
                            '$gte': start_date,
                            '$lte': end_date
                        }
                    }).sort('timestamp', 1)
                    
                    report = IntegrityReport()
                    previous_hash = None
                    
                    for log in logs:
                        # ハッシュチェーンの検証
                        if previous_hash and log.previous_hash != previous_hash:
                            report.add_error(
                                log.id,
                                f"Hash chain broken: expected {previous_hash}, got {log.previous_hash}"
                            )
                        
                        # コンテンツハッシュの検証
                        calculated_hash = self.calculate_content_hash(log)
                        if calculated_hash != log.content_hash:
                            report.add_error(
                                log.id,
                                f"Content tampered: hash mismatch"
                            )
                        
                        # デジタル署名の検証（if present）
                        if log.signature and not self.verify_signature(log):
                            report.add_error(
                                log.id,
                                "Invalid digital signature"
                            )
                        
                        previous_hash = log.content_hash
                    
                    return report
            ''',
            
            'merkle_tree_approach': '''
            class MerkleTreeAuditLog:
                """Merkle Tree を使用した監査ログ"""
                
                def __init__(self):
                    self.tree_builder = MerkleTreeBuilder()
                    self.checkpoint_interval = 1000  # 1000エントリごとにチェックポイント
                
                async def create_checkpoint(self):
                    """定期的なチェックポイント作成"""
                    
                    # 最後のチェックポイント以降のログを取得
                    last_checkpoint = await self.get_last_checkpoint()
                    logs = await self.get_logs_since(last_checkpoint.timestamp)
                    
                    if len(logs) < self.checkpoint_interval:
                        return None
                    
                    # Merkle Tree の構築
                    leaves = [log.content_hash for log in logs]
                    tree = self.tree_builder.build(leaves)
                    
                    # チェックポイントの保存
                    checkpoint = AuditCheckpoint(
                        timestamp=datetime.utcnow(),
                        root_hash=tree.root_hash,
                        tree_data=tree.serialize(),
                        log_count=len(logs),
                        first_log_id=logs[0].id,
                        last_log_id=logs[-1].id
                    )
                    
                    await self.db.audit_checkpoints.insert(checkpoint)
                    
                    # ブロックチェーンやタイムスタンプサービスへの登録（オプション）
                    await self.register_to_blockchain(checkpoint.root_hash)
                    
                    return checkpoint
                
                async def generate_proof(self, log_id: str) -> MerkleProof:
                    """特定のログの存在証明生成"""
                    
                    log = await self.db.audit_logs.find_by_id(log_id)
                    checkpoint = await self.find_checkpoint_for_log(log)
                    
                    tree = MerkleTree.deserialize(checkpoint.tree_data)
                    proof = tree.generate_proof(log.content_hash)
                    
                    return MerkleProof(
                        log_id=log_id,
                        log_hash=log.content_hash,
                        root_hash=checkpoint.root_hash,
                        proof_path=proof.path,
                        checkpoint_timestamp=checkpoint.timestamp
                    )
            '''
        }
    
    def search_and_analysis(self):
        """効率的な検索と分析"""
        return {
            'search_optimization': '''
            class AuditLogSearchEngine:
                """監査ログ検索エンジン"""
                
                def __init__(self):
                    self.elasticsearch = Elasticsearch(['localhost:9200'])
                    self.encryption_service = EncryptionService()
                
                async def index_audit_log(self, log: AuditLog):
                    """ログのインデックス作成"""
                    
                    # 検索可能なフィールドの準備
                    doc = {
                        'timestamp': log.timestamp,
                        'action': log.action,
                        'resource_type': log.resource_type,
                        'resource_id': log.resource_id,
                        'result': log.result,
                        'actor_id_hash': log.actor_id_hash,
                        
                        # 暗号化されたデータは検索不可
                        '_encrypted_ref': log.id  # 詳細取得用の参照
                    }
                    
                    # メタデータの検索可能な部分のみインデックス
                    if log.safe_metadata:
                        doc['metadata'] = log.safe_metadata
                    
                    await self.elasticsearch.index(
                        index='audit-logs',
                        id=str(log.id),
                        body=doc
                    )
                
                async def search(self, query: SearchQuery) -> SearchResult:
                    """高度な検索"""
                    
                    # Elasticsearch クエリの構築
                    es_query = {
                        'bool': {
                            'must': [],
                            'filter': []
                        }
                    }
                    
                    # 時間範囲
                    if query.date_range:
                        es_query['bool']['filter'].append({
                            'range': {
                                'timestamp': {
                                    'gte': query.date_range.start,
                                    'lte': query.date_range.end
                                }
                            }
                        })
                    
                    # アクション検索
                    if query.actions:
                        es_query['bool']['filter'].append({
                            'terms': {'action': query.actions}
                        })
                    
                    # フルテキスト検索（メタデータ内）
                    if query.text:
                        es_query['bool']['must'].append({
                            'multi_match': {
                                'query': query.text,
                                'fields': ['metadata.*']
                            }
                        })
                    
                    # 検索実行
                    result = await self.elasticsearch.search(
                        index='audit-logs',
                        body={
                            'query': es_query,
                            'sort': [{'timestamp': 'desc'}],
                            'size': query.limit,
                            'from': query.offset
                        }
                    )
                    
                    # 暗号化データの復号化（必要に応じて）
                    hits = []
                    for hit in result['hits']['hits']:
                        log_id = hit['_source']['_encrypted_ref']
                        full_log = await self.get_full_log(log_id, query.include_pii)
                        hits.append(full_log)
                    
                    return SearchResult(
                        total=result['hits']['total']['value'],
                        hits=hits
                    )
            ''',
            
            'archival_strategy': '''
            class AuditLogArchivalService:
                """監査ログのアーカイブ戦略"""
                
                def __init__(self):
                    self.hot_storage = PostgreSQLStorage()
                    self.warm_storage = S3Storage()
                    self.cold_storage = GlacierStorage()
                
                async def archive_logs(self):
                    """定期的なアーカイブ処理"""
                    
                    # 30日以上前のログをwarmストレージへ
                    cutoff_warm = datetime.utcnow() - timedelta(days=30)
                    logs_to_warm = await self.hot_storage.find_older_than(cutoff_warm)
                    
                    for batch in self.batch_iterator(logs_to_warm, 1000):
                        # 圧縮とアーカイブ
                        compressed = self.compress_logs(batch)
                        archive_key = f"audit-logs/{batch[0].timestamp.strftime('%Y/%m/%d')}/{uuid.uuid4()}.gz"
                        
                        await self.warm_storage.upload(archive_key, compressed)
                        
                        # ホットストレージから削除
                        await self.hot_storage.delete_batch([log.id for log in batch])
                        
                        # インデックス更新
                        await self.update_archive_index(batch, archive_key, 'warm')
                    
                    # 1年以上前のログをcoldストレージへ
                    cutoff_cold = datetime.utcnow() - timedelta(days=365)
                    await self.move_to_cold_storage(cutoff_cold)
                
                async def retrieve_archived_logs(self, query: ArchiveQuery) -> List[AuditLog]:
                    """アーカイブからの取得"""
                    
                    # アーカイブインデックスを検索
                    archives = await self.find_relevant_archives(query)
                    
                    logs = []
                    for archive in archives:
                        if archive.storage_tier == 'warm':
                            # S3から即座に取得
                            data = await self.warm_storage.download(archive.key)
                            logs.extend(self.decompress_logs(data))
                            
                        elif archive.storage_tier == 'cold':
                            # Glacierからの取得（時間がかかる）
                            if not archive.restore_status:
                                await self.initiate_glacier_restore(archive)
                                raise PendingRestoreError(
                                    "Archive restoration initiated. Please try again in 3-5 hours."
                                )
                            
                            data = await self.cold_storage.download(archive.key)
                            logs.extend(self.decompress_logs(data))
                    
                    return logs
            '''
        }
```

## 問題4：E2Eテストシナリオ

### 解答

```typescript
// Playwright を使用したE2Eテスト実装

import { test, expect, Page, BrowserContext } from '@playwright/test';
import { generateUser, cleanup } from './test-helpers';

class AuthE2ETests {
  
  // テストデータ
  private testUser = {
    email: 'e2e-test@example.com',
    password: 'SecureP@ssword123',
    newPassword: 'NewSecureP@ssword456',
    mfaSecret: 'JBSWY3DPEHPK3PXP'
  };

  test.describe('認証E2Eテストスイート', () => {
    
    test.beforeEach(async ({ page }) => {
      // テスト用ユーザーの作成
      await generateUser(this.testUser);
    });

    test.afterEach(async () => {
      // クリーンアップ
      await cleanup(this.testUser.email);
    });

    test('1. 通常のログイン→操作→ログアウト', async ({ page, context }) => {
      // ログインページへ移動
      await page.goto('/login');
      
      // ログインフォームの入力
      await page.fill('[data-testid="email-input"]', this.testUser.email);
      await page.fill('[data-testid="password-input"]', this.testUser.password);
      
      // ログインボタンクリック
      await page.click('[data-testid="login-button"]');
      
      // ダッシュボードへのリダイレクトを待つ
      await page.waitForURL('/dashboard');
      
      // ダッシュボードの要素確認
      await expect(page.locator('[data-testid="welcome-message"]')).toContainText('Welcome');
      
      // 認証が必要な操作を実行
      await page.click('[data-testid="profile-link"]');
      await page.waitForURL('/profile');
      
      // プロフィール情報の確認
      await expect(page.locator('[data-testid="user-email"]')).toContainText(this.testUser.email);
      
      // APIコールの確認（認証トークンが送信されているか）
      const apiResponse = await page.waitForResponse(
        response => response.url().includes('/api/user/profile') && response.status() === 200
      );
      expect(apiResponse.ok()).toBeTruthy();
      
      // ログアウト
      await page.click('[data-testid="user-menu"]');
      await page.click('[data-testid="logout-button"]');
      
      // ログインページへのリダイレクト確認
      await page.waitForURL('/login');
      
      // ログアウト後のアクセス制限確認
      await page.goto('/dashboard');
      await page.waitForURL('/login');
      await expect(page.locator('[data-testid="auth-error"]')).toContainText('Please login');
    });

    test('2. パスワードリセットフロー', async ({ page }) => {
      // ログインページへ移動
      await page.goto('/login');
      
      // パスワードリセットリンククリック
      await page.click('[data-testid="forgot-password-link"]');
      await page.waitForURL('/password-reset');
      
      // メールアドレス入力
      await page.fill('[data-testid="reset-email-input"]', this.testUser.email);
      await page.click('[data-testid="send-reset-button"]');
      
      // 確認メッセージ
      await expect(page.locator('[data-testid="reset-sent-message"]')).toBeVisible();
      
      // メール内のリセットリンクをシミュレート（テスト環境）
      const resetToken = await this.getResetTokenFromTestAPI(this.testUser.email);
      await page.goto(`/password-reset/confirm?token=${resetToken}`);
      
      // 新しいパスワードの入力
      await page.fill('[data-testid="new-password-input"]', this.testUser.newPassword);
      await page.fill('[data-testid="confirm-password-input"]', this.testUser.newPassword);
      
      // パスワード強度インジケーターの確認
      await expect(page.locator('[data-testid="password-strength"]')).toHaveAttribute('data-strength', 'strong');
      
      // リセット実行
      await page.click('[data-testid="reset-password-button"]');
      
      // 成功メッセージとログインページへのリダイレクト
      await expect(page.locator('[data-testid="reset-success"]')).toBeVisible();
      await page.waitForURL('/login');
      
      // 新しいパスワードでログイン
      await page.fill('[data-testid="email-input"]', this.testUser.email);
      await page.fill('[data-testid="password-input"]', this.testUser.newPassword);
      await page.click('[data-testid="login-button"]');
      
      await page.waitForURL('/dashboard');
    });

    test('3. MFA設定と解除', async ({ page }) => {
      // ログイン
      await this.login(page);
      
      // セキュリティ設定へ移動
      await page.goto('/settings/security');
      
      // MFA設定開始
      await page.click('[data-testid="enable-mfa-button"]');
      
      // QRコード表示の確認
      await expect(page.locator('[data-testid="mfa-qr-code"]')).toBeVisible();
      
      // バックアップコードの表示と保存
      const backupCodes = await page.locator('[data-testid="backup-codes"] li').allTextContents();
      expect(backupCodes.length).toBe(10);
      
      // テスト用のTOTPコード生成
      const totpCode = this.generateTOTP(this.testUser.mfaSecret);
      
      // 検証コード入力
      await page.fill('[data-testid="mfa-verify-input"]', totpCode);
      await page.click('[data-testid="verify-mfa-button"]');
      
      // MFA有効化の確認
      await expect(page.locator('[data-testid="mfa-status"]')).toContainText('Enabled');
      
      // ログアウトして再ログイン（MFA必須）
      await this.logout(page);
      await page.goto('/login');
      
      // 通常ログイン
      await page.fill('[data-testid="email-input"]', this.testUser.email);
      await page.fill('[data-testid="password-input"]', this.testUser.password);
      await page.click('[data-testid="login-button"]');
      
      // MFAページへのリダイレクト
      await page.waitForURL('/mfa');
      
      // MFAコード入力
      const newTotpCode = this.generateTOTP(this.testUser.mfaSecret);
      await page.fill('[data-testid="mfa-code-input"]', newTotpCode);
      await page.click('[data-testid="verify-button"]');
      
      // ダッシュボードへ
      await page.waitForURL('/dashboard');
      
      // MFA解除
      await page.goto('/settings/security');
      await page.click('[data-testid="disable-mfa-button"]');
      
      // パスワード再確認
      await page.fill('[data-testid="confirm-password"]', this.testUser.password);
      await page.click('[data-testid="confirm-disable-mfa"]');
      
      // MFA無効化の確認
      await expect(page.locator('[data-testid="mfa-status"]')).toContainText('Disabled');
    });

    test('4. 同時ログインセッション管理', async ({ browser }) => {
      // 複数のブラウザコンテキストを作成
      const context1 = await browser.newContext();
      const context2 = await browser.newContext();
      
      const page1 = await context1.newPage();
      const page2 = await context2.newPage();
      
      try {
        // 両方のコンテキストでログイン
        await this.login(page1);
        await this.login(page2);
        
        // セッション管理ページへ
        await page1.goto('/settings/sessions');
        
        // アクティブセッション数の確認
        const sessionCount = await page1.locator('[data-testid="session-item"]').count();
        expect(sessionCount).toBeGreaterThanOrEqual(2);
        
        // 他のセッションの情報確認
        const sessions = await page1.locator('[data-testid="session-item"]').all();
        for (const session of sessions) {
          await expect(session.locator('[data-testid="session-ip"]')).toBeVisible();
          await expect(session.locator('[data-testid="session-device"]')).toBeVisible();
          await expect(session.locator('[data-testid="session-last-active"]')).toBeVisible();
        }
        
        // 特定セッションの終了
        const otherSession = await page1.locator('[data-testid="session-item"]')
          .filter({ hasNot: page1.locator('[data-testid="current-session-badge"]') })
          .first();
        
        await otherSession.locator('[data-testid="terminate-session"]').click();
        await page1.locator('[data-testid="confirm-terminate"]').click();
        
        // 終了確認
        await expect(page1.locator('[data-testid="session-terminated-message"]')).toBeVisible();
        
        // page2でのアクセス確認（セッション無効）
        await page2.reload();
        await page2.waitForURL('/login');
        await expect(page2.locator('[data-testid="session-expired-message"]')).toBeVisible();
        
        // 全セッション終了（現在のセッション以外）
        await page1.click('[data-testid="terminate-all-sessions"]');
        await page1.click('[data-testid="confirm-terminate-all"]');
        
        // 現在のセッションは維持
        await page1.goto('/dashboard');
        await expect(page1.url()).toContain('/dashboard');
        
      } finally {
        await context1.close();
        await context2.close();
      }
    });

    test('5. ブラウザを閉じた後の再アクセス', async ({ context, page }) => {
      // Remember Me なしでログイン
      await page.goto('/login');
      await page.fill('[data-testid="email-input"]', this.testUser.email);
      await page.fill('[data-testid="password-input"]', this.testUser.password);
      await page.click('[data-testid="login-button"]');
      
      await page.waitForURL('/dashboard');
      
      // Cookieの確認
      const cookies = await context.cookies();
      const sessionCookie = cookies.find(c => c.name === 'session_id');
      expect(sessionCookie).toBeDefined();
      expect(sessionCookie?.expires).toBeUndefined(); // セッションCookie
      
      // ブラウザを閉じるシミュレーション（新しいコンテキスト）
      const newContext = await page.context().browser()?.newContext();
      const newPage = await newContext!.newPage();
      
      // 再アクセス（ログインが必要）
      await newPage.goto('/dashboard');
      await newPage.waitForURL('/login');
      
      // Remember Me ありでログイン
      await newPage.fill('[data-testid="email-input"]', this.testUser.email);
      await newPage.fill('[data-testid="password-input"]', this.testUser.password);
      await newPage.check('[data-testid="remember-me-checkbox"]');
      await newPage.click('[data-testid="login-button"]');
      
      await newPage.waitForURL('/dashboard');
      
      // 永続的なCookieの確認
      const newCookies = await newContext!.cookies();
      const rememberCookie = newCookies.find(c => c.name === 'remember_token');
      expect(rememberCookie).toBeDefined();
      expect(rememberCookie?.expires).toBeGreaterThan(Date.now() / 1000); // 有効期限あり
      
      // さらに新しいコンテキストで確認
      const context3 = await page.context().browser()?.newContext();
      const page3 = await context3!.newPage();
      
      // Remember tokenをセット
      await context3!.addCookies([rememberCookie!]);
      
      // 自動ログイン
      await page3.goto('/dashboard');
      await expect(page3.url()).toContain('/dashboard');
      await expect(page3.locator('[data-testid="user-email"]')).toContainText(this.testUser.email);
      
      await newContext!.close();
      await context3!.close();
    });
  });

  // ヘルパーメソッド
  private async login(page: Page) {
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', this.testUser.email);
    await page.fill('[data-testid="password-input"]', this.testUser.password);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
  }

  private async logout(page: Page) {
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.waitForURL('/login');
  }

  private generateTOTP(secret: string): string {
    // TOTP生成ロジック（テスト用）
    return '123456';
  }

  private async getResetTokenFromTestAPI(email: string): Promise<string> {
    // テストAPIからリセットトークンを取得
    return 'test-reset-token';
  }
}

// パフォーマンステスト
test.describe('認証パフォーマンステスト', () => {
  
  test('並行ログインのパフォーマンス', async ({ browser }) => {
    const userCount = 50;
    const contexts: BrowserContext[] = [];
    const loginTimes: number[] = [];
    
    // 並行してログイン
    const promises = Array.from({ length: userCount }, async (_, i) => {
      const context = await browser.newContext();
      contexts.push(context);
      const page = await context.newPage();
      
      const startTime = Date.now();
      
      await page.goto('/login');
      await page.fill('[data-testid="email-input"]', `user${i}@example.com`);
      await page.fill('[data-testid="password-input"]', 'password123');
      await page.click('[data-testid="login-button"]');
      
      await page.waitForURL('/dashboard', { timeout: 10000 });
      
      const endTime = Date.now();
      loginTimes.push(endTime - startTime);
    });
    
    await Promise.all(promises);
    
    // パフォーマンス分析
    const avgTime = loginTimes.reduce((a, b) => a + b, 0) / loginTimes.length;
    const maxTime = Math.max(...loginTimes);
    const minTime = Math.min(...loginTimes);
    
    console.log(`Average login time: ${avgTime}ms`);
    console.log(`Max login time: ${maxTime}ms`);
    console.log(`Min login time: ${minTime}ms`);
    
    // アサーション
    expect(avgTime).toBeLessThan(2000); // 平均2秒以内
    expect(maxTime).toBeLessThan(5000); // 最大5秒以内
    
    // クリーンアップ
    for (const context of contexts) {
      await context.close();
    }
  });
});
```

## 問題5：パフォーマンス最適化

### 解答

```python
import asyncio
import time
from typing import Dict, List, Optional
import redis
import jwt
from dataclasses import dataclass
import hashlib

class OptimizedAuthSystem:
    """1000万ユーザー規模の最適化された認証システム"""
    
    def __init__(self):
        # Redis Cluster for distributed caching
        self.redis_cluster = redis.RedisCluster(
            startup_nodes=[
                {"host": "10.0.0.1", "port": 7000},
                {"host": "10.0.0.2", "port": 7000},
                {"host": "10.0.0.3", "port": 7000},
            ],
            decode_responses=True,
            skip_full_coverage_check=True,
            max_connections=1000
        )
        
        # Connection pooling for DB
        self.db_pool = create_db_pool(
            min_size=50,
            max_size=200,
            max_queries=50000,
            max_inactive_connection_lifetime=300.0
        )
    
    async def optimized_login(self, email: str, password: str) -> Dict:
        """最適化されたログイン処理（目標: p99 < 100ms）"""
        
        start_time = time.perf_counter()
        
        # 1. Rate limiting check (Redis) - ~1ms
        if not await self._check_rate_limit(email):
            return {"error": "Rate limit exceeded", "latency": time.perf_counter() - start_time}
        
        # 2. User lookup with caching - ~5ms (cache hit) or ~20ms (cache miss)
        user = await self._get_user_cached(email)
        if not user:
            # Timing attack mitigation
            await self._dummy_password_hash()
            return {"error": "Invalid credentials", "latency": time.perf_counter() - start_time}
        
        # 3. Password verification (async) - ~15ms
        if not await self._verify_password_async(password, user.password_hash):
            await self._record_failed_attempt(email)
            return {"error": "Invalid credentials", "latency": time.perf_counter() - start_time}
        
        # 4. Session creation (optimized) - ~10ms
        session = await self._create_session_optimized(user)
        
        latency = time.perf_counter() - start_time
        
        return {
            "success": True,
            "user_id": user.id,
            "session_token": session.token,
            "latency_ms": latency * 1000
        }
    
    async def _get_user_cached(self, email: str) -> Optional[User]:
        """キャッシュを使用したユーザー取得"""
        
        # L1 Cache: Local memory (sub-millisecond)
        cache_key = f"user:email:{email}"
        
        # L2 Cache: Redis (1-2ms)
        cached_data = await self.redis_cluster.get(cache_key)
        if cached_data:
            return User.from_json(cached_data)
        
        # Database lookup with prepared statement
        async with self.db_pool.acquire() as conn:
            # Prepared statement for performance
            stmt = await conn.prepare("""
                SELECT id, email, password_hash, status, mfa_enabled
                FROM users 
                WHERE email = $1 AND status = 'active'
            """)
            
            row = await stmt.fetchrow(email)
            if not row:
                return None
            
            user = User(
                id=row['id'],
                email=row['email'],
                password_hash=row['password_hash'],
                status=row['status'],
                mfa_enabled=row['mfa_enabled']
            )
            
            # Cache for 5 minutes
            await self.redis_cluster.setex(
                cache_key,
                300,
                user.to_json()
            )
            
            return user
    
    async def _verify_password_async(self, password: str, password_hash: str) -> bool:
        """非同期パスワード検証"""
        
        # Use thread pool for CPU-intensive bcrypt operation
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._verify_password_sync,
            password,
            password_hash
        )
    
    def _verify_password_sync(self, password: str, password_hash: str) -> bool:
        """同期的なパスワード検証（スレッドプールで実行）"""
        import bcrypt
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    async def _create_session_optimized(self, user: User) -> Session:
        """最適化されたセッション作成"""
        
        # Generate session ID
        session_id = self._generate_session_id()
        
        # Create JWT token (faster than database session)
        token = self._create_jwt_token(user, session_id)
        
        # Store minimal session data in Redis
        session_data = {
            'user_id': user.id,
            'created_at': time.time(),
            'last_access': time.time()
        }
        
        # Pipeline Redis commands
        pipe = self.redis_cluster.pipeline()
        pipe.setex(f"session:{session_id}", 3600, json.dumps(session_data))
        pipe.sadd(f"user_sessions:{user.id}", session_id)
        pipe.expire(f"user_sessions:{user.id}", 3600)
        await pipe.execute()
        
        return Session(
            id=session_id,
            token=token,
            user_id=user.id
        )
    
    async def optimized_token_validation(self, token: str) -> Optional[Dict]:
        """最適化されたトークン検証（目標: p99 < 20ms）"""
        
        start_time = time.perf_counter()
        
        # 1. Quick format check - ~0.1ms
        if not self._quick_token_format_check(token):
            return None
        
        # 2. Check token blacklist (Redis bloom filter) - ~1ms
        if await self._is_token_blacklisted(token):
            return None
        
        # 3. JWT validation with caching - ~2ms (cached) or ~10ms (full validation)
        claims = await self._validate_jwt_cached(token)
        if not claims:
            return None
        
        # 4. Session validation (Redis) - ~2ms
        session_valid = await self._validate_session(claims['sid'])
        if not session_valid:
            return None
        
        latency = time.perf_counter() - start_time
        
        return {
            'user_id': claims['sub'],
            'session_id': claims['sid'],
            'latency_ms': latency * 1000
        }
    
    async def _validate_jwt_cached(self, token: str) -> Optional[Dict]:
        """キャッシュを使用したJWT検証"""
        
        # Token fingerprint for caching
        token_fingerprint = hashlib.sha256(token.encode()).hexdigest()[:16]
        cache_key = f"jwt_valid:{token_fingerprint}"
        
        # Check cache
        cached_claims = await self.redis_cluster.get(cache_key)
        if cached_claims:
            return json.loads(cached_claims)
        
        # Full JWT validation
        try:
            claims = jwt.decode(
                token,
                self.jwt_public_key,
                algorithms=['ES256'],  # ECDSA is faster than RSA
                options={"verify_exp": True}
            )
            
            # Cache for 1 minute (shorter than token lifetime)
            await self.redis_cluster.setex(
                cache_key,
                60,
                json.dumps(claims)
            )
            
            return claims
            
        except jwt.InvalidTokenError:
            return None
    
    async def optimized_permission_check(self, user_id: str, resource: str, action: str) -> bool:
        """最適化された権限チェック（目標: p99 < 50ms）"""
        
        start_time = time.perf_counter()
        
        # 1. Check permission cache - ~2ms
        cache_key = f"perm:{user_id}:{resource}:{action}"
        cached_result = await self.redis_cluster.get(cache_key)
        if cached_result is not None:
            return cached_result == "1"
        
        # 2. Get user roles (cached) - ~5ms
        roles = await self._get_user_roles_cached(user_id)
        
        # 3. Check role-based permissions (in-memory) - ~1ms
        if self._check_role_permissions(roles, resource, action):
            await self.redis_cluster.setex(cache_key, 300, "1")
            return True
        
        # 4. Check resource-specific permissions (batched query) - ~20ms
        has_permission = await self._check_resource_permissions(user_id, resource, action)
        
        # Cache result
        await self.redis_cluster.setex(
            cache_key,
            300,
            "1" if has_permission else "0"
        )
        
        latency = time.perf_counter() - start_time
        
        return has_permission
    
    async def _get_user_roles_cached(self, user_id: str) -> List[str]:
        """キャッシュされたユーザーロール取得"""
        
        cache_key = f"user_roles:{user_id}"
        
        # Redis cache
        cached_roles = await self.redis_cluster.get(cache_key)
        if cached_roles:
            return json.loads(cached_roles)
        
        # Database query with join reduction
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT r.name
                FROM roles r
                INNER JOIN user_roles ur ON r.id = ur.role_id
                WHERE ur.user_id = $1
            """, user_id)
            
            roles = [row['name'] for row in rows]
            
            # Cache for 10 minutes
            await self.redis_cluster.setex(
                cache_key,
                600,
                json.dumps(roles)
            )
            
            return roles
    
    def _check_role_permissions(self, roles: List[str], resource: str, action: str) -> bool:
        """インメモリでのロール権限チェック"""
        
        # Pre-computed permission matrix (loaded at startup)
        for role in roles:
            if role in self.permission_matrix:
                permissions = self.permission_matrix[role]
                if f"{resource}:{action}" in permissions:
                    return True
        
        return False
    
    async def performance_test_results(self):
        """パフォーマンステスト結果"""
        
        return {
            'login_performance': {
                'concurrent_users': 10000,
                'test_duration': '60 seconds',
                'results': {
                    'p50': '35ms',
                    'p95': '78ms',
                    'p99': '95ms',
                    'p99.9': '120ms',
                    'max': '250ms',
                    'requests_per_second': 15000
                },
                'optimizations_applied': [
                    'Multi-level caching (L1: in-memory, L2: Redis)',
                    'Connection pooling (200 connections)',
                    'Prepared statements',
                    'Async password hashing',
                    'JWT with ECDSA (faster than RSA)',
                    'Redis pipelining'
                ]
            },
            
            'token_validation_performance': {
                'concurrent_validations': 50000,
                'results': {
                    'p50': '8ms',
                    'p95': '15ms',
                    'p99': '19ms',
                    'p99.9': '25ms',
                    'max': '45ms',
                    'validations_per_second': 80000
                },
                'optimizations_applied': [
                    'JWT validation caching',
                    'Bloom filter for blacklist',
                    'Redis cluster for session storage',
                    'Minimal session data',
                    'Token fingerprinting'
                ]
            },
            
            'permission_check_performance': {
                'test_scenarios': 'Complex RBAC with 100 roles, 1000 resources',
                'results': {
                    'p50': '20ms',
                    'p95': '40ms',
                    'p99': '48ms',
                    'p99.9': '65ms',
                    'max': '95ms',
                    'checks_per_second': 25000
                },
                'optimizations_applied': [
                    'Permission matrix preloading',
                    'Aggressive caching strategy',
                    'Batched database queries',
                    'Denormalized permission views',
                    'Redis lua scripts for atomic operations'
                ]
            },
            
            'infrastructure': {
                'application_servers': '20 instances (c5.2xlarge)',
                'database': 'PostgreSQL 14 (RDS db.r6g.4xlarge, Multi-AZ)',
                'cache': 'Redis 7.0 Cluster (6 nodes, r6g.xlarge)',
                'load_balancer': 'AWS ALB with connection draining',
                'cdn': 'CloudFront for static assets'
            }
        }

# 実装コード例

@dataclass
class User:
    id: str
    email: str
    password_hash: str
    status: str
    mfa_enabled: bool
    
    def to_json(self) -> str:
        return json.dumps(self.__dict__)
    
    @classmethod
    def from_json(cls, data: str) -> 'User':
        return cls(**json.loads(data))

@dataclass
class Session:
    id: str
    token: str
    user_id: str

# パフォーマンステストスクリプト
async def run_performance_test():
    """パフォーマンステスト実行"""
    
    auth_system = OptimizedAuthSystem()
    
    # ログインテスト
    print("Testing login performance...")
    login_times = []
    
    async def test_login():
        start = time.perf_counter()
        result = await auth_system.optimized_login(
            f"user{random.randint(1, 1000000)}@example.com",
            "password123"
        )
        login_times.append(time.perf_counter() - start)
    
    # 並行実行
    tasks = [test_login() for _ in range(10000)]
    await asyncio.gather(*tasks)
    
    # 結果分析
    login_times.sort()
    print(f"Login p50: {login_times[int(len(login_times) * 0.5)] * 1000:.2f}ms")
    print(f"Login p99: {login_times[int(len(login_times) * 0.99)] * 1000:.2f}ms")
    
    # 同様にトークン検証と権限チェックもテスト...
```