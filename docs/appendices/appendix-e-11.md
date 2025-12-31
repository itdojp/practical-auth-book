---
layout: book
title: "第11章 演習問題解答"
---

# 第11章 演習問題解答

## 問題1：脅威モデリング

### 解答

**銀行オンラインバンキングシステムの脅威モデル**

```python
class BankingSystemThreatModel:
    """銀行システムの脅威モデル"""
    
    def system_overview(self):
        """システム概要"""
        return {
            'components': {
                'frontend': ['Web Application', 'Mobile App (iOS/Android)'],
                'api_layer': ['API Gateway', 'Authentication Service', 'Transaction Service'],
                'backend': ['Core Banking System', 'Database Cluster', 'HSM (Hardware Security Module)'],
                'external': ['SMS Gateway', 'Email Service', 'Credit Bureau API']
            },
            'data_flow': '''
            User → CDN → WAF → Load Balancer → API Gateway → Backend Services → Database
                     ↓                                ↓
                  Mobile App                 External Services
            ''',
            'security_boundaries': [
                'Internet → DMZ',
                'DMZ → Internal Network',
                'Internal Network → Core Banking',
                'Core Banking → HSM'
            ]
        }
    
    def threat_identification(self):
        """脅威の識別（STRIDE）"""
        return {
            'spoofing': [
                {
                    'threat': 'フィッシングによる認証情報窃取',
                    'target': 'ユーザー認証',
                    'likelihood': 'HIGH',
                    'impact': 'CRITICAL',
                    'mitigation': [
                        'フィッシング対策の教育',
                        'ドメイン監視とテイクダウン',
                        'ブラウザでの警告表示',
                        'トランザクション署名の実装'
                    ]
                },
                {
                    'threat': 'セッショントークンの偽造',
                    'target': 'API認証',
                    'likelihood': 'MEDIUM',
                    'impact': 'CRITICAL',
                    'mitigation': [
                        '暗号学的に安全なトークン生成',
                        'トークンの短期有効期限（5分）',
                        'デバイスバインディング'
                    ]
                }
            ],
            
            'tampering': [
                {
                    'threat': '送金額の改ざん',
                    'target': 'トランザクションデータ',
                    'likelihood': 'MEDIUM',
                    'impact': 'CRITICAL',
                    'mitigation': [
                        'エンドツーエンドの暗号化',
                        'トランザクション署名（HSM使用）',
                        'チェックサムによる整合性確認'
                    ]
                },
                {
                    'threat': 'モバイルアプリの改造',
                    'target': 'モバイルアプリケーション',
                    'likelihood': 'HIGH',
                    'impact': 'HIGH',
                    'mitigation': [
                        'アプリの難読化',
                        'ルート/Jailbreak検知',
                        'アプリ証明書のピンニング',
                        'リモートアテステーション'
                    ]
                }
            ],
            
            'repudiation': [
                {
                    'threat': '不正送金の否認',
                    'target': '取引記録',
                    'likelihood': 'MEDIUM',
                    'impact': 'HIGH',
                    'mitigation': [
                        '全操作の監査ログ記録',
                        'タイムスタンプ付きデジタル署名',
                        '取引確認の多要素認証',
                        'ブロックチェーンによる記録'
                    ]
                }
            ],
            
            'information_disclosure': [
                {
                    'threat': 'データベースからの大量情報漏洩',
                    'target': '顧客データベース',
                    'likelihood': 'LOW',
                    'impact': 'CRITICAL',
                    'mitigation': [
                        'データベース暗号化（TDE）',
                        'アクセス制御の厳格化',
                        'データマスキング',
                        'DLPソリューションの導入'
                    ]
                },
                {
                    'threat': 'APIレスポンスからの情報漏洩',
                    'target': 'API通信',
                    'likelihood': 'MEDIUM',
                    'impact': 'HIGH',
                    'mitigation': [
                        '最小限の情報開示原則',
                        'フィールドレベルの暗号化',
                        'エラーメッセージの汎用化'
                    ]
                }
            ],
            
            'denial_of_service': [
                {
                    'threat': 'DDoS攻撃',
                    'target': 'Webサービス全体',
                    'likelihood': 'HIGH',
                    'impact': 'HIGH',
                    'mitigation': [
                        'CDN/DDoS防御サービス',
                        'レート制限',
                        '自動スケーリング',
                        'フェイルオーバー機構'
                    ]
                },
                {
                    'threat': 'リソース枯渇攻撃',
                    'target': '認証サービス',
                    'likelihood': 'MEDIUM',
                    'impact': 'HIGH',
                    'mitigation': [
                        'リソースクォータ設定',
                        'サーキットブレーカー',
                        'バックプレッシャー制御'
                    ]
                }
            ],
            
            'elevation_of_privilege': [
                {
                    'threat': '一般ユーザーから管理者権限への昇格',
                    'target': '権限管理システム',
                    'likelihood': 'LOW',
                    'impact': 'CRITICAL',
                    'mitigation': [
                        '最小権限の原則',
                        '権限の定期的レビュー',
                        'Just-In-Time権限付与',
                        '特権アクセス管理（PAM）'
                    ]
                }
            ]
        }
    
    def attack_scenarios(self):
        """具体的な攻撃シナリオ"""
        return {
            'account_takeover_scenario': {
                'description': 'アカウント乗っ取りシナリオ',
                'steps': [
                    '1. フィッシングメールでユーザーを偽サイトに誘導',
                    '2. 認証情報を窃取',
                    '3. 正規サイトにログイン',
                    '4. 送金限度額を確認',
                    '5. 複数の少額送金で検知を回避',
                    '6. 最終的に口座を空にする'
                ],
                'countermeasures': [
                    'ログイン時の異常検知（新しいデバイス、場所）',
                    '送金パターンの異常検知',
                    'ステップアップ認証（高額送金時）',
                    'クーリングオフ期間（24時間）',
                    '送金先のリスクスコアリング'
                ]
            },
            
            'insider_threat_scenario': {
                'description': '内部犯行シナリオ',
                'steps': [
                    '1. 銀行職員が顧客データにアクセス',
                    '2. VIP顧客の取引パターンを分析',
                    '3. 情報を外部に売却',
                    '4. または、システムに細工を仕掛ける'
                ],
                'countermeasures': [
                    '職務分離（Segregation of Duties）',
                    'アクセスログの完全記録と分析',
                    '異常アクセスパターンの検知',
                    'データアクセスの承認ワークフロー',
                    '定期的な権限棚卸し'
                ]
            },
            
            'supply_chain_attack_scenario': {
                'description': 'サプライチェーン攻撃シナリオ',
                'steps': [
                    '1. 第三者ライブラリに悪意のあるコードを混入',
                    '2. 定期的な依存関係更新で混入',
                    '3. 本番環境でバックドアが動作',
                    '4. 顧客データを外部に送信'
                ],
                'countermeasures': [
                    '依存関係の脆弱性スキャン',
                    'SBOMの管理',
                    'コンテナイメージの署名検証',
                    'ランタイムセキュリティ監視',
                    'ネットワークの出口制御'
                ]
            }
        }
    
    def risk_assessment_matrix(self):
        """リスク評価マトリクス"""
        return {
            'calculation': 'Risk = Likelihood × Impact',
            'matrix': '''
            Impact
              ↑
            Critical │ Medium  │  High   │Critical │Critical │
            High     │  Low    │ Medium  │  High   │Critical │
            Medium   │  Low    │  Low    │ Medium  │  High   │
            Low      │  Low    │  Low    │  Low    │ Medium  │
                     └─────────┴─────────┴─────────┴─────────┘
                        Low     Medium    High    Critical
                                    Likelihood →
            ''',
            'risk_treatment': {
                'CRITICAL': 'Immediate action required, executive escalation',
                'HIGH': 'Action within 30 days, management approval',
                'MEDIUM': 'Action within 90 days, standard process',
                'LOW': 'Accept or monitor, periodic review'
            }
        }
```

## 問題2：攻撃シミュレーション

### 解答

```python
import time
import hmac
import hashlib
import secrets
import bcrypt
from typing import Optional, Tuple
import re

class SecureAuthenticationSystem:
    """セキュアな認証システムの実装"""
    
    def __init__(self):
        self.pepper = secrets.token_bytes(32)  # アプリケーション固有のペッパー
        
    # 1. タイミング攻撃を考慮したユーザー認証
    async def authenticate_user_timing_safe(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """タイミング攻撃に対して安全な認証"""
        
        # 一定時間を確保（最小実行時間）
        min_time = 0.1  # 100ms
        start_time = time.perf_counter()
        
        try:
            # ユーザー取得
            user = await self.get_user_by_username(username)
            
            # ダミーハッシュ（ユーザーが存在しない場合用）
            dummy_hash = b'$2b$12$dummy.hash.for.timing.attack.protection.against.user.enum'
            
            if user:
                stored_hash = user.password_hash.encode('utf-8')
                is_valid = bcrypt.checkpw(
                    self._prepare_password(password).encode('utf-8'),
                    stored_hash
                )
            else:
                # ユーザーが存在しない場合でも同じ処理時間
                bcrypt.checkpw(b'dummy_password', dummy_hash)
                is_valid = False
            
            # 処理時間の調整
            elapsed = time.perf_counter() - start_time
            if elapsed < min_time:
                await asyncio.sleep(min_time - elapsed)
            
            if is_valid and user:
                # 成功時の追加チェック
                if not user.is_active:
                    return False, "Account is disabled"
                if user.requires_password_change:
                    return False, "Password change required"
                
                return True, None
            
            return False, "Invalid credentials"
            
        except Exception as e:
            # エラー時も一定時間を確保
            elapsed = time.perf_counter() - start_time
            if elapsed < min_time:
                await asyncio.sleep(min_time - elapsed)
            
            # エラー情報を漏らさない
            return False, "Authentication failed"
    
    # 2. レインボーテーブル攻撃に強いパスワード保存
    def hash_password_secure(self, password: str) -> str:
        """レインボーテーブル攻撃に強いパスワードハッシュ化"""
        
        # パスワード強度チェック
        if not self._validate_password_strength(password):
            raise ValueError("Password does not meet security requirements")
        
        # ペッパーを追加（データベース外で管理）
        peppered_password = self._prepare_password(password)
        
        # bcryptでハッシュ化（自動的にソルトを生成）
        # ワークファクター12（2^12回の反復）
        hashed = bcrypt.hashpw(
            peppered_password.encode('utf-8'),
            bcrypt.gensalt(rounds=12)
        )
        
        return hashed.decode('utf-8')
    
    def _prepare_password(self, password: str) -> str:
        """パスワードにペッパーを追加"""
        return hmac.new(
            self.pepper,
            password.encode('utf-8'),
            hashlib.sha256
        ).hexdigest() + password
    
    def _validate_password_strength(self, password: str) -> bool:
        """パスワード強度の検証"""
        if len(password) < 12:
            return False
        
        # NIST SP 800-63B準拠
        # - 一般的な脆弱なパスワードのチェック
        # - 複雑性要件は強制しない（長さを重視）
        
        # 既知の脆弱なパスワードリストとの照合
        if self._is_common_password(password):
            return False
        
        # 連続する文字の確認
        if self._has_sequential_chars(password):
            return False
        
        return True
    
    # 3. セッション固定攻撃の防御
    class SessionManager:
        """セッション固定攻撃に対する防御を実装"""
        
        def __init__(self):
            self.sessions = {}
            self.session_config = {
                'secure': True,
                'httponly': True,
                'samesite': 'Strict',
                'max_age': 3600
            }
        
        async def create_session(self, user_id: str, request: Request) -> Session:
            """セキュアなセッション作成"""
            
            # 既存のセッションIDは信頼しない
            old_session_id = request.cookies.get('session_id')
            if old_session_id:
                await self.invalidate_session(old_session_id)
            
            # 新しいセッションIDを生成（予測不可能）
            session_id = self._generate_secure_session_id()
            
            # セッションデータの作成
            session = Session(
                id=session_id,
                user_id=user_id,
                created_at=time.time(),
                last_activity=time.time(),
                ip_address=request.client.host,
                user_agent=request.headers.get('User-Agent'),
                fingerprint=self._calculate_fingerprint(request)
            )
            
            # セッションの保存
            await self._store_session(session)
            
            return session
        
        def _generate_secure_session_id(self) -> str:
            """暗号学的に安全なセッションID生成"""
            # 256ビットのランダムな値
            random_bytes = secrets.token_bytes(32)
            
            # タイムスタンプを含める（リプレイ攻撃対策）
            timestamp = struct.pack('>Q', int(time.time() * 1000000))
            
            # HMACで署名
            session_data = random_bytes + timestamp
            signature = hmac.new(
                self.signing_key,
                session_data,
                hashlib.sha256
            ).digest()
            
            # Base64エンコード
            session_id = base64.urlsafe_b64encode(
                session_data + signature
            ).decode('utf-8').rstrip('=')
            
            return session_id
        
        async def validate_session(self, session_id: str, request: Request) -> Optional[Session]:
            """セッション検証（固定攻撃対策込み）"""
            
            session = await self._get_session(session_id)
            if not session:
                return None
            
            # セッション固定攻撃の検知
            if await self._detect_session_fixation(session, request):
                await self.invalidate_session(session_id)
                raise SecurityException("Session fixation attack detected")
            
            # フィンガープリントの検証
            current_fingerprint = self._calculate_fingerprint(request)
            if not self._verify_fingerprint(session.fingerprint, current_fingerprint):
                await self.invalidate_session(session_id)
                return None
            
            # IPアドレスの変更チェック（オプション）
            if self.config.get('bind_session_to_ip'):
                if session.ip_address != request.client.host:
                    # 詳細なリスク評価
                    risk_score = await self._assess_ip_change_risk(session, request)
                    if risk_score > 0.7:
                        return None
            
            # ログイン後のセッションID再生成（重要）
            if session.needs_regeneration:
                new_session = await self._regenerate_session(session, request)
                return new_session
            
            # セッションの更新
            session.last_activity = time.time()
            await self._update_session(session)
            
            return session
        
        async def _detect_session_fixation(self, session: Session, request: Request) -> bool:
            """セッション固定攻撃の検知"""
            
            # 同一セッションIDの使用履歴
            history = await self._get_session_history(session.id)
            
            # 複数のユーザーで使用されていないか
            unique_users = set(h.user_id for h in history if h.user_id)
            if len(unique_users) > 1:
                return True
            
            # 認証前後での使用
            pre_auth_use = any(not h.authenticated for h in history)
            post_auth_use = any(h.authenticated for h in history)
            
            if pre_auth_use and post_auth_use and not session.regenerated:
                return True
            
            return False
    
    # 4. CSRFトークンの実装
    class CSRFProtection:
        """CSRF保護の実装"""
        
        def __init__(self):
            self.token_lifetime = 3600  # 1時間
            self.signing_key = secrets.token_bytes(32)
        
        def generate_csrf_token(self, session_id: str) -> Tuple[str, str]:
            """CSRFトークンの生成"""
            
            # トークンの生成
            token_value = secrets.token_urlsafe(32)
            timestamp = int(time.time())
            
            # トークンデータの作成
            token_data = f"{token_value}:{timestamp}:{session_id}"
            
            # 署名の作成
            signature = hmac.new(
                self.signing_key,
                token_data.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            # 最終的なトークン
            csrf_token = f"{token_data}:{signature}"
            
            # ダブルサブミットクッキー用の値
            cookie_token = hmac.new(
                self.signing_key,
                f"{token_value}:{session_id}".encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            return csrf_token, cookie_token
        
        def validate_csrf_token(
            self,
            token: str,
            cookie_token: str,
            session_id: str,
            request_method: str
        ) -> bool:
            """CSRFトークンの検証"""
            
            # 安全なメソッドはスキップ
            if request_method in ['GET', 'HEAD', 'OPTIONS']:
                return True
            
            if not token or not cookie_token:
                return False
            
            try:
                # トークンの分解
                parts = token.split(':')
                if len(parts) != 4:
                    return False
                
                token_value, timestamp, token_session_id, signature = parts
                
                # セッションIDの確認
                if token_session_id != session_id:
                    return False
                
                # 有効期限の確認
                token_age = int(time.time()) - int(timestamp)
                if token_age > self.token_lifetime:
                    return False
                
                # 署名の検証
                expected_signature = hmac.new(
                    self.signing_key,
                    f"{token_value}:{timestamp}:{session_id}".encode('utf-8'),
                    hashlib.sha256
                ).hexdigest()
                
                if not hmac.compare_digest(signature, expected_signature):
                    return False
                
                # ダブルサブミットクッキーの検証
                expected_cookie = hmac.new(
                    self.signing_key,
                    f"{token_value}:{session_id}".encode('utf-8'),
                    hashlib.sha256
                ).hexdigest()
                
                if not hmac.compare_digest(cookie_token, expected_cookie):
                    return False
                
                return True
                
            except Exception:
                return False
        
        def get_csrf_cookie_settings(self) -> dict:
            """CSRFクッキーの設定"""
            return {
                'key': 'csrf_token',
                'httponly': False,  # JavaScriptからアクセス可能にする
                'secure': True,
                'samesite': 'Strict',
                'path': '/',
                'max_age': self.token_lifetime
            }

# 使用例とテスト
async def test_secure_authentication():
    auth_system = SecureAuthenticationSystem()
    
    # パスワードのハッシュ化
    password = "MySecureP@ssw0rd123!"
    hashed = auth_system.hash_password_secure(password)
    print(f"Hashed password: {hashed}")
    
    # 認証のテスト（タイミング攻撃対策付き）
    success, error = await auth_system.authenticate_user_timing_safe(
        "user@example.com",
        password
    )
    
    # セッション管理
    session_manager = auth_system.SessionManager()
    if success:
        session = await session_manager.create_session("user123", request)
        print(f"Session created: {session.id}")
    
    # CSRF保護
    csrf = auth_system.CSRFProtection()
    csrf_token, cookie_token = csrf.generate_csrf_token(session.id)
    print(f"CSRF token: {csrf_token}")
```

## 問題3：インシデント対応計画

### 解答

```python
class EcommerceIncidentResponsePlan:
    """Eコマースサイトのインシデント対応計画"""
    
    def __init__(self):
        self.incident_id = "INC-2024-0315-001"
        self.incident_start = "2024-03-15 14:30:00 UTC"
        self.detection_time = "2024-03-15 16:15:00 UTC"
        
    def immediate_response(self):
        """即時対応（0〜2時間）"""
        return {
            'phase': 'IMMEDIATE_CONTAINMENT',
            'timeline': '0-2 hours',
            'actions': [
                {
                    'action': '影響を受けた管理者アカウントの即時無効化',
                    'command': '''
                    UPDATE admin_users 
                    SET status = 'SUSPENDED', 
                        suspended_at = NOW(),
                        suspended_reason = 'Security incident INC-2024-0315-001'
                    WHERE id IN (SELECT admin_id FROM suspicious_admin_logins);
                    ''',
                    'responsible': 'Security Team',
                    'eta': '5 minutes'
                },
                {
                    'action': '全管理者セッションの無効化',
                    'command': '''
                    DELETE FROM admin_sessions;
                    FLUSHDB on Redis admin_session_cache;
                    ''',
                    'responsible': 'DevOps Team',
                    'eta': '10 minutes'
                },
                {
                    'action': '管理者パネルへのアクセス制限',
                    'implementation': '''
                    # Nginxでの一時的なIP制限
                    location /admin {
                        allow 10.0.0.0/8;  # 社内ネットワークのみ
                        deny all;
                    }
                    ''',
                    'responsible': 'Infrastructure Team',
                    'eta': '15 minutes'
                },
                {
                    'action': '影響範囲の初期評価',
                    'queries': [
                        '''
                        -- 不正アクセスのあった時間帯の管理者操作
                        SELECT * FROM admin_audit_logs
                        WHERE timestamp BETWEEN '2024-03-13 16:00:00' AND NOW()
                        AND admin_id IN (SELECT admin_id FROM suspicious_admin_logins)
                        ORDER BY timestamp;
                        ''',
                        '''
                        -- アクセスされた顧客データ
                        SELECT DISTINCT customer_id, action, timestamp
                        FROM data_access_logs
                        WHERE accessed_by IN (SELECT admin_id FROM suspicious_admin_logins)
                        AND timestamp > '2024-03-13 16:00:00';
                        '''
                    ],
                    'responsible': 'Security Analyst',
                    'eta': '30 minutes'
                }
            ],
            'communication': {
                'internal': [
                    {
                        'to': 'Executive Team',
                        'message': 'Critical security incident detected. Admin compromise confirmed.',
                        'channel': 'Secure phone call',
                        'time': '+15 minutes'
                    },
                    {
                        'to': 'All IT Staff',
                        'message': 'All hands on deck. Join incident response channel.',
                        'channel': 'Slack #incident-response',
                        'time': '+5 minutes'
                    }
                ],
                'external': {
                    'customers': 'Not yet - pending impact assessment',
                    'authorities': 'Prepare notification, send if PII confirmed compromised'
                }
            }
        }
    
    def investigation_phase(self):
        """調査フェーズ（2〜6時間）"""
        return {
            'phase': 'INVESTIGATION',
            'timeline': '2-6 hours',
            'forensics': {
                'log_preservation': [
                    'Create snapshots of all relevant databases',
                    'Export and secure all logs from past 7 days',
                    'Capture network traffic for analysis',
                    'Preserve WAF logs'
                ],
                'timeline_reconstruction': '''
                -- 攻撃者の行動タイムライン
                WITH attacker_timeline AS (
                    SELECT 
                        timestamp,
                        source_ip,
                        user_agent,
                        action,
                        target_resource,
                        response_code
                    FROM combined_logs
                    WHERE session_id IN (
                        SELECT DISTINCT session_id 
                        FROM admin_sessions 
                        WHERE admin_id = 'compromised_admin_123'
                    )
                    ORDER BY timestamp
                )
                SELECT * FROM attacker_timeline;
                ''',
                'ioc_extraction': {
                    'ip_addresses': [],
                    'user_agents': [],
                    'accessed_endpoints': [],
                    'modified_data': [],
                    'exfiltrated_data': []
                }
            },
            'impact_assessment': {
                'data_accessed': {
                    'customer_records': 'Run query to count affected customers',
                    'payment_info': 'Check if payment tables were accessed',
                    'personal_info': 'Verify PII access scope'
                },
                'systems_compromised': [
                    'Admin panel',
                    'Customer database (read-only)',
                    'Order management system'
                ],
                'business_impact': {
                    'revenue_at_risk': 'Calculate based on affected customers',
                    'regulatory_exposure': 'GDPR, PCI-DSS compliance',
                    'reputation_damage': 'High - customer trust'
                }
            }
        }
    
    def containment_strategy(self):
        """封じ込め戦略（6〜12時間）"""
        return {
            'phase': 'CONTAINMENT',
            'timeline': '6-12 hours',
            'technical_measures': [
                {
                    'measure': '全管理者パスワードの強制リセット',
                    'implementation': '''
                    UPDATE admin_users 
                    SET password_reset_required = TRUE,
                        password_reset_token = generate_secure_token(),
                        password_reset_expires = NOW() + INTERVAL '24 hours';
                    ''',
                    'notification': 'Email all admins with secure reset link'
                },
                {
                    'measure': 'MFA必須化',
                    'implementation': '''
                    UPDATE system_settings 
                    SET admin_mfa_required = TRUE,
                        admin_mfa_grace_period = 0;
                    '''
                },
                {
                    'measure': '監査ログの強化',
                    'implementation': '''
                    -- 詳細ログの有効化
                    SET GLOBAL general_log = 'ON';
                    SET GLOBAL log_output = 'TABLE';
                    
                    -- 全クエリの記録
                    SET GLOBAL audit_log_policy = 'ALL';
                    '''
                },
                {
                    'measure': 'ネットワークセグメンテーション',
                    'implementation': 'Isolate admin network from production'
                }
            ],
            'customer_protection': [
                {
                    'action': '影響を受けた顧客アカウントの保護',
                    'steps': [
                        'Flag affected accounts for monitoring',
                        'Enable additional fraud detection rules',
                        'Prepare password reset for affected users'
                    ]
                },
                {
                    'action': '不正な注文の検出',
                    'query': '''
                    SELECT * FROM orders
                    WHERE created_at > '2024-03-13 16:00:00'
                    AND customer_id IN (
                        SELECT customer_id FROM potentially_affected_customers
                    )
                    AND (
                        shipping_address_changed = TRUE OR
                        payment_method_changed = TRUE OR
                        order_amount > historical_average * 2
                    );
                    '''
                }
            ]
        }
    
    def recovery_plan(self):
        """復旧計画（12〜48時間）"""
        return {
            'phase': 'RECOVERY',
            'timeline': '12-48 hours',
            'system_hardening': [
                {
                    'component': 'Admin Authentication',
                    'improvements': [
                        'Implement hardware key requirement for admins',
                        'Add IP allowlisting for admin access',
                        'Implement session recording for admin actions',
                        'Deploy privileged access management (PAM) solution'
                    ]
                },
                {
                    'component': 'Monitoring',
                    'improvements': [
                        'Deploy SIEM with custom rules',
                        'Implement behavioral analytics',
                        'Set up real-time alerting for anomalies',
                        'Create security dashboard'
                    ]
                }
            ],
            'gradual_restoration': {
                'phase_1': {
                    'time': '+12 hours',
                    'action': 'Restore read-only admin access',
                    'validation': 'Verify all logging working'
                },
                'phase_2': {
                    'time': '+24 hours',
                    'action': 'Enable write operations with approval workflow',
                    'validation': 'Test approval mechanism'
                },
                'phase_3': {
                    'time': '+48 hours',
                    'action': 'Full functionality with enhanced monitoring',
                    'validation': 'Complete security audit'
                }
            }
        }
    
    def communication_plan(self):
        """コミュニケーション計画"""
        return {
            'stakeholder_matrix': {
                'customers': {
                    'affected': {
                        'when': 'Within 24 hours of confirmation',
                        'how': 'Direct email + in-app notification',
                        'message': 'Security notice with specific actions'
                    },
                    'general': {
                        'when': 'Within 48 hours',
                        'how': 'Blog post + email',
                        'message': 'Transparency report'
                    }
                },
                'regulators': {
                    'gdpr': {
                        'when': 'Within 72 hours',
                        'how': 'Official notification form',
                        'content': 'Full breach report'
                    },
                    'pci': {
                        'when': 'Immediately',
                        'how': 'Phone + written follow-up',
                        'content': 'Initial assessment'
                    }
                },
                'media': {
                    'strategy': 'Proactive disclosure',
                    'spokesperson': 'CISO',
                    'key_messages': [
                        'Swift detection and response',
                        'Customer data protection measures',
                        'Ongoing improvements'
                    ]
                }
            }
        }
    
    def post_incident_review(self):
        """事後レビュー"""
        return {
            'timeline': '1 week post-incident',
            'participants': [
                'CISO', 'CTO', 'Security Team',
                'DevOps', 'Customer Service Lead'
            ],
            'agenda': [
                'Timeline review',
                'Decision effectiveness',
                'Communication assessment',
                'Technical gaps identified',
                'Process improvements'
            ],
            'deliverables': [
                'Incident report',
                'Lessons learned document',
                'Action items with owners',
                'Updated incident response playbook'
            ],
            'metrics': {
                'detection_time': 'Time from breach to detection',
                'containment_time': 'Time from detection to containment',
                'recovery_time': 'Time to full restoration',
                'customer_impact': 'Number of affected users',
                'financial_impact': 'Total cost of incident'
            }
        }
```

## 問題4：セキュリティ監査

### 解答

```python
class SaaSSecurityAuditPlan:
    """中規模SaaS企業のセキュリティ監査計画"""
    
    def __init__(self):
        self.company_profile = {
            'employees': 200,
            'customers': 5000,
            'annual_revenue': '$20M',
            'data_sensitivity': 'HIGH',
            'compliance_requirements': ['SOC2', 'ISO27001', 'GDPR']
        }
    
    def audit_scope_and_objectives(self):
        """監査スコープと目標"""
        return {
            'scope': {
                'included': [
                    'Authentication and authorization systems',
                    'User identity management',
                    'Access control mechanisms',
                    'Session management',
                    'API security',
                    'Privileged access management',
                    'Third-party integrations',
                    'Audit logging and monitoring'
                ],
                'excluded': [
                    'Physical security',
                    'Non-production environments',
                    'Third-party vendor assessments'
                ],
                'systems': [
                    'Production authentication service',
                    'Identity provider (IdP)',
                    'Customer portal',
                    'Admin console',
                    'API gateway',
                    'Database access layer'
                ]
            },
            'objectives': [
                'Verify compliance with security standards',
                'Identify vulnerabilities in auth systems',
                'Assess access control effectiveness',
                'Evaluate incident response readiness',
                'Review security configurations',
                'Test detection capabilities'
            ],
            'success_criteria': {
                'no_critical_findings': True,
                'high_findings_threshold': 5,
                'compliance_score': 0.90,
                'remediation_timeline': '90 days'
            }
        }
    
    def audit_methodology(self):
        """監査手法とツール"""
        return {
            'framework': 'NIST Cybersecurity Framework + CIS Controls',
            'approach': {
                'phase_1': {
                    'name': 'Discovery and Planning',
                    'activities': [
                        'Documentation review',
                        'Architecture analysis',
                        'Stakeholder interviews',
                        'Risk assessment'
                    ],
                    'tools': [
                        'Document management system',
                        'Visio/Draw.io for diagrams',
                        'Risk assessment templates'
                    ]
                },
                'phase_2': {
                    'name': 'Technical Assessment',
                    'activities': [
                        'Configuration review',
                        'Vulnerability scanning',
                        'Penetration testing',
                        'Code review'
                    ],
                    'tools': [
                        'Burp Suite Pro',
                        'OWASP ZAP',
                        'Nessus',
                        'SonarQube',
                        'Git security scanning'
                    ]
                },
                'phase_3': {
                    'name': 'Process and Compliance Review',
                    'activities': [
                        'Policy review',
                        'Procedure validation',
                        'Compliance mapping',
                        'Training assessment'
                    ],
                    'tools': [
                        'GRC platform',
                        'Compliance matrices',
                        'Interview guides'
                    ]
                }
            },
            'testing_methodology': {
                'black_box': {
                    'percentage': 40,
                    'focus': 'External attacker perspective'
                },
                'gray_box': {
                    'percentage': 40,
                    'focus': 'Authenticated user perspective'
                },
                'white_box': {
                    'percentage': 20,
                    'focus': 'Code and configuration review'
                }
            }
        }
    
    def timeline_3_months(self):
        """3ヶ月間のタイムライン"""
        return {
            'month_1': {
                'week_1_2': {
                    'phase': 'Planning and Discovery',
                    'activities': [
                        'Kick-off meeting',
                        'Scope finalization',
                        'Documentation collection',
                        'Initial interviews',
                        'Environment access setup'
                    ],
                    'deliverables': [
                        'Audit charter',
                        'Detailed project plan',
                        'Risk assessment matrix'
                    ]
                },
                'week_3_4': {
                    'phase': 'Architecture and Design Review',
                    'activities': [
                        'System architecture review',
                        'Data flow analysis',
                        'Integration mapping',
                        'Security control assessment'
                    ],
                    'deliverables': [
                        'Architecture assessment report',
                        'Initial findings document'
                    ]
                }
            },
            'month_2': {
                'week_5_6': {
                    'phase': 'Technical Testing - Part 1',
                    'activities': [
                        'Authentication mechanism testing',
                        'Session management review',
                        'Password policy validation',
                        'MFA implementation check'
                    ],
                    'deliverables': [
                        'Authentication test results',
                        'Vulnerability report v1'
                    ]
                },
                'week_7_8': {
                    'phase': 'Technical Testing - Part 2',
                    'activities': [
                        'Authorization testing',
                        'API security assessment',
                        'Privilege escalation testing',
                        'Integration security review'
                    ],
                    'deliverables': [
                        'Authorization test results',
                        'API security report'
                    ]
                }
            },
            'month_3': {
                'week_9_10': {
                    'phase': 'Process and Compliance',
                    'activities': [
                        'Policy compliance check',
                        'Operational procedure review',
                        'Incident response testing',
                        'Training effectiveness'
                    ],
                    'deliverables': [
                        'Compliance assessment',
                        'Process maturity report'
                    ]
                },
                'week_11_12': {
                    'phase': 'Reporting and Remediation Planning',
                    'activities': [
                        'Finding consolidation',
                        'Risk rating assignment',
                        'Remediation planning',
                        'Executive presentation',
                        'Knowledge transfer'
                    ],
                    'deliverables': [
                        'Final audit report',
                        'Executive summary',
                        'Remediation roadmap',
                        'Presentation materials'
                    ]
                }
            }
        }
    
    def deliverables_and_reports(self):
        """成果物とレポート形式"""
        return {
            'report_structure': {
                'executive_summary': {
                    'length': '2-3 pages',
                    'content': [
                        'Overall security posture',
                        'Critical findings summary',
                        'Risk assessment',
                        'Compliance status',
                        'Key recommendations'
                    ],
                    'audience': 'C-suite, Board'
                },
                'technical_report': {
                    'length': '50-75 pages',
                    'sections': [
                        'Methodology',
                        'Detailed findings',
                        'Evidence and screenshots',
                        'Attack scenarios',
                        'Technical recommendations',
                        'Configuration guides'
                    ],
                    'audience': 'Security team, DevOps'
                },
                'compliance_report': {
                    'length': '30-40 pages',
                    'content': [
                        'Compliance framework mapping',
                        'Gap analysis',
                        'Control effectiveness',
                        'Evidence documentation',
                        'Certification readiness'
                    ],
                    'audience': 'Compliance team, Auditors'
                }
            },
            'finding_format': {
                'structure': {
                    'title': 'Clear, descriptive title',
                    'severity': 'Critical/High/Medium/Low',
                    'category': 'Authentication/Authorization/Configuration',
                    'description': 'Detailed explanation',
                    'evidence': 'Screenshots, logs, code snippets',
                    'impact': 'Business and technical impact',
                    'likelihood': 'Probability assessment',
                    'recommendations': 'Step-by-step remediation',
                    'references': 'Standards, best practices'
                },
                'risk_rating_matrix': '''
                Risk = Likelihood × Impact
                
                Critical: Immediate action required
                High: Fix within 30 days
                Medium: Fix within 90 days
                Low: Fix within 180 days
                '''
            },
            'additional_deliverables': [
                {
                    'name': 'Security Metrics Dashboard',
                    'format': 'Interactive dashboard',
                    'content': 'KPIs, trends, benchmarks'
                },
                {
                    'name': 'Remediation Tracker',
                    'format': 'Spreadsheet/JIRA',
                    'content': 'Finding tracking, assignments, progress'
                },
                {
                    'name': 'Security Awareness Materials',
                    'format': 'Presentations, guides',
                    'content': 'Training materials based on findings'
                }
            ]
        }
    
    def audit_checklist_sample(self):
        """監査チェックリストサンプル"""
        return {
            'authentication_checklist': [
                {
                    'item': 'Password Policy Compliance',
                    'checks': [
                        'Minimum length ≥ 12 characters',
                        'Complexity requirements aligned with NIST',
                        'Password history enforcement',
                        'Breach password detection',
                        'Account lockout policy'
                    ],
                    'evidence': 'Configuration files, test results'
                },
                {
                    'item': 'Multi-Factor Authentication',
                    'checks': [
                        'MFA available for all users',
                        'MFA required for admins',
                        'Backup authentication methods',
                        'MFA bypass controls',
                        'Recovery procedures'
                    ],
                    'evidence': 'User statistics, configuration'
                }
            ],
            'authorization_checklist': [
                {
                    'item': 'Access Control Model',
                    'checks': [
                        'RBAC/ABAC implementation',
                        'Principle of least privilege',
                        'Segregation of duties',
                        'Regular access reviews',
                        'Orphaned account detection'
                    ],
                    'evidence': 'Role matrices, review records'
                }
            ]
        }
```

## 問題5：ゼロトラスト移行

### 解答

```python
class ZeroTrustMigrationPlan:
    """ゼロトラストアーキテクチャへの移行計画"""
    
    def current_state_analysis(self):
        """現状分析（As-Is）"""
        return {
            'architecture_type': 'Perimeter-based (Castle-and-Moat)',
            'current_components': {
                'network_security': {
                    'perimeter_firewall': 'Fortinet FortiGate',
                    'vpn': 'Traditional SSL VPN for remote access',
                    'network_segmentation': 'VLAN-based, limited microsegmentation',
                    'internal_trust': 'Implicit trust within network perimeter'
                },
                'identity_management': {
                    'directory': 'Active Directory on-premises',
                    'authentication': 'Username/password, limited MFA',
                    'sso': 'ADFS for some applications',
                    'privileged_access': 'Shared admin accounts'
                },
                'application_security': {
                    'access_control': 'Network-based (IP restrictions)',
                    'api_security': 'Basic API keys',
                    'encryption': 'TLS for external, limited internal'
                },
                'device_management': {
                    'corporate_devices': 'Domain-joined, GPO managed',
                    'byod': 'Limited support via VPN',
                    'compliance': 'Manual checks'
                },
                'monitoring': {
                    'logging': 'Decentralized, limited retention',
                    'siem': 'Basic implementation',
                    'visibility': 'Network-focused, limited application insight'
                }
            },
            'current_challenges': [
                'VPN bottlenecks for remote workers',
                'Lateral movement risk after breach',
                'Limited visibility into encrypted traffic',
                'Complex firewall rules',
                'Shadow IT proliferation',
                'Inconsistent security policies'
            ],
            'risk_assessment': {
                'high_risks': [
                    'Compromised credentials = network access',
                    'Limited cloud security',
                    'Insufficient endpoint protection',
                    'Weak third-party access controls'
                ]
            }
        }
    
    def target_architecture(self):
        """目標アーキテクチャ（To-Be）"""
        return {
            'architecture_type': 'Zero Trust Network Architecture (ZTNA)',
            'core_principles': {
                'never_trust_always_verify': 'Every access request verified',
                'least_privilege': 'Minimal access by default',
                'assume_breach': 'Design for compromised environment',
                'verify_explicitly': 'Multi-factor verification',
                'continuous_verification': 'Not just at login'
            },
            'target_components': {
                'identity_and_access': {
                    'identity_provider': 'Cloud-based IdP (Okta/Azure AD)',
                    'authentication': 'Passwordless + MFA everywhere',
                    'authorization': 'Dynamic, context-aware policies',
                    'privileged_access': 'Just-in-time, zero standing privileges'
                },
                'device_trust': {
                    'device_registry': 'All devices registered and managed',
                    'compliance_checking': 'Continuous compliance validation',
                    'trust_scoring': 'Risk-based device trust levels',
                    'byod_support': 'Full support with isolation'
                },
                'network_architecture': {
                    'microsegmentation': 'Identity-based, not network-based',
                    'software_defined_perimeter': 'Dynamic, encrypted tunnels',
                    'direct_to_cloud': 'No backhauling through datacenter',
                    'zero_trust_proxy': 'All access through proxy'
                },
                'application_security': {
                    'api_gateway': 'Centralized API management',
                    'service_mesh': 'mTLS between all services',
                    'policy_engine': 'Centralized policy decision point',
                    'encryption': 'End-to-end encryption everywhere'
                },
                'data_protection': {
                    'classification': 'Automated data classification',
                    'dlp': 'Context-aware DLP',
                    'encryption': 'Data-centric security',
                    'rights_management': 'Persistent data protection'
                },
                'monitoring_and_analytics': {
                    'siem_soar': 'Advanced threat detection',
                    'ueba': 'User behavior analytics',
                    'continuous_monitoring': 'Real-time risk assessment',
                    'automated_response': 'Policy-driven remediation'
                }
            }
        }
    
    def migration_steps_6_months(self):
        """6ヶ月の移行ステップ"""
        return {
            'month_1': {
                'phase': 'Foundation and Planning',
                'objectives': [
                    'Establish Zero Trust program',
                    'Complete detailed assessment',
                    'Define success metrics'
                ],
                'activities': [
                    {
                        'task': 'Form Zero Trust team',
                        'deliverable': 'RACI matrix, project charter',
                        'stakeholders': ['CISO', 'CIO', 'Network', 'Security', 'Apps']
                    },
                    {
                        'task': 'Asset and data discovery',
                        'deliverable': 'Complete asset inventory',
                        'tools': ['ServiceNow', 'Lansweeper']
                    },
                    {
                        'task': 'Risk assessment',
                        'deliverable': 'Risk heat map, priority matrix',
                        'focus': 'Critical assets first'
                    },
                    {
                        'task': 'Vendor selection',
                        'deliverable': 'Vendor shortlist, POC plan',
                        'evaluate': ['ZTNA platforms', 'CASB', 'IdP']
                    }
                ],
                'quick_wins': [
                    'Enable MFA for all admin accounts',
                    'Implement password policy improvements',
                    'Begin logging centralization'
                ]
            },
            'month_2_3': {
                'phase': 'Identity-Centric Security',
                'objectives': [
                    'Modernize identity infrastructure',
                    'Implement strong authentication',
                    'Begin policy development'
                ],
                'activities': [
                    {
                        'task': 'Deploy cloud IdP',
                        'steps': [
                            'Set up Okta/Azure AD tenant',
                            'Integrate with AD',
                            'Migrate first application batch',
                            'Configure MFA policies'
                        ],
                        'milestone': '30% apps integrated'
                    },
                    {
                        'task': 'Implement privileged access management',
                        'solution': 'CyberArk or similar',
                        'scope': 'All admin accounts'
                    },
                    {
                        'task': 'Device trust framework',
                        'components': [
                            'Device inventory',
                            'Certificate deployment',
                            'Compliance policies',
                            'MDM integration'
                        ]
                    },
                    {
                        'task': 'Policy engine setup',
                        'deliverable': 'Initial policy set',
                        'approach': 'Start with monitor mode'
                    }
                ],
                'metrics': {
                    'mfa_adoption': '100% admins, 50% users',
                    'passwordless': '20% pilot users',
                    'device_registration': '60% corporate devices'
                }
            },
            'month_4_5': {
                'phase': 'Network and Application Transformation',
                'objectives': [
                    'Deploy ZTNA infrastructure',
                    'Implement microsegmentation',
                    'Secure application access'
                ],
                'activities': [
                    {
                        'task': 'Deploy Zero Trust Network Access',
                        'components': [
                            'Install ZT proxy/gateway',
                            'Configure identity integration',
                            'Create access policies',
                            'Migrate VPN users'
                        ],
                        'target': '50% remote users migrated'
                    },
                    {
                        'task': 'Implement microsegmentation',
                        'approach': [
                            'Deploy Illumio/Guardicore',
                            'Map application dependencies',
                            'Create segmentation policies',
                            'Enable enforcement gradually'
                        ]
                    },
                    {
                        'task': 'API security enhancement',
                        'implementation': [
                            'Deploy API gateway',
                            'Implement OAuth 2.0/OIDC',
                            'Enable mutual TLS',
                            'API inventory and classification'
                        ]
                    },
                    {
                        'task': 'CASB deployment',
                        'scope': 'Critical SaaS applications',
                        'features': ['Visibility', 'DLP', 'Threat protection']
                    }
                ],
                'decommission': [
                    'Legacy VPN (partial)',
                    'Network-based access rules',
                    'Shared service accounts'
                ]
            },
            'month_6': {
                'phase': 'Optimization and Maturation',
                'objectives': [
                    'Complete migration',
                    'Optimize policies',
                    'Establish operations'
                ],
                'activities': [
                    {
                        'task': 'Complete application migration',
                        'target': '100% critical apps',
                        'validation': 'User acceptance testing'
                    },
                    {
                        'task': 'Advanced threat protection',
                        'components': [
                            'UEBA implementation',
                            'Automated response playbooks',
                            'Threat intelligence integration'
                        ]
                    },
                    {
                        'task': 'Policy optimization',
                        'approach': [
                            'Analyze policy violations',
                            'Refine access rules',
                            'Implement dynamic policies',
                            'Remove legacy rules'
                        ]
                    },
                    {
                        'task': 'Operational handover',
                        'deliverables': [
                            'Runbooks',
                            'Training completion',
                            'Support model',
                            'Success metrics'
                        ]
                    }
                ],
                'final_state': {
                    'vpn_usage': '<10% (exception only)',
                    'zero_trust_coverage': '95% resources',
                    'policy_decisions': '>1M daily',
                    'mean_time_to_detect': '<5 minutes'
                }
            }
        }
    
    def risks_and_mitigations(self):
        """リスクと対策"""
        return {
            'technical_risks': [
                {
                    'risk': 'Service disruption during migration',
                    'probability': 'MEDIUM',
                    'impact': 'HIGH',
                    'mitigation': [
                        'Phased rollout approach',
                        'Extensive testing in staging',
                        'Rollback plans for each phase',
                        'Parallel run period'
                    ]
                },
                {
                    'risk': 'Performance degradation',
                    'probability': 'MEDIUM',
                    'impact': 'MEDIUM',
                    'mitigation': [
                        'Capacity planning',
                        'Performance baselines',
                        'Edge proxy deployment',
                        'Caching strategies'
                    ]
                },
                {
                    'risk': 'Integration complexity',
                    'probability': 'HIGH',
                    'impact': 'MEDIUM',
                    'mitigation': [
                        'Detailed integration planning',
                        'Vendor professional services',
                        'POC for each integration',
                        'Standardized APIs'
                    ]
                }
            ],
            'organizational_risks': [
                {
                    'risk': 'User resistance',
                    'probability': 'HIGH',
                    'impact': 'MEDIUM',
                    'mitigation': [
                        'Early stakeholder engagement',
                        'Clear communication plan',
                        'Training programs',
                        'Champion network'
                    ]
                },
                {
                    'risk': 'Skills gap',
                    'probability': 'HIGH',
                    'impact': 'HIGH',
                    'mitigation': [
                        'Training investment',
                        'Hire ZT expertise',
                        'Vendor support contracts',
                        'Knowledge transfer plans'
                    ]
                }
            ],
            'budget_risks': [
                {
                    'risk': 'Cost overrun',
                    'probability': 'MEDIUM',
                    'impact': 'MEDIUM',
                    'mitigation': [
                        'Detailed cost modeling',
                        'Phased investment',
                        'ROI tracking',
                        'Executive sponsorship'
                    ]
                }
            ],
            'success_factors': [
                'Strong executive sponsorship',
                'Clear communication',
                'Incremental approach',
                'Continuous measurement',
                'User-centric design'
            ]
        }
```