---
layout: book
order: 10
title: "第8章：認証システム設計"
---

## 8.1 要件定義と設計の進め方

### 8.1.1 なぜ要件定義から始めるのか

```python
class AuthSystemRequirementsAnalysis:
    """認証システムの要件分析"""
    
    def explain_importance(self):
        """要件定義の重要性"""
        
        return {
            'common_mistakes': {
                'feature_creep': {
                    'problem': '機能の追加し過ぎ',
                    'example': '''
                    初期要件：メールとパスワードでログイン
                    ↓
                    追加1：ソーシャルログイン（5種類）
                    追加2：生体認証
                    追加3：パスワードレス
                    追加4：ブロックチェーン認証（？）
                    
                    結果：複雑で保守困難なシステム
                    ''',
                    'consequence': '開発期間の延長、バグの増加、UXの悪化'
                },
                
                'security_theater': {
                    'problem': '見かけだけのセキュリティ',
                    'example': '''
                    # 複雑なパスワードルール
                    - 大文字小文字数字記号必須
                    - 12文字以上
                    - 辞書に載っている単語禁止
                    - 30日ごとに変更必須
                    
                    結果：付箋にパスワードを書く
                    ''',
                    'consequence': 'ユーザビリティ低下、実質的なセキュリティ低下'
                },
                
                'over_engineering': {
                    'problem': '過度な設計',
                    'example': '''
                    想定ユーザー数：1000人
                    設計：
                    - マイクロサービス（10個）
                    - 分散データベース
                    - グローバル展開前提
                    - 毎秒100万リクエスト対応
                    ''',
                    'consequence': '不要な複雑性、高コスト、開発遅延'
                }
            },
            
            'requirements_driven_design': {
                'principle': '要件が設計を決定する',
                'process': '''
                1. ビジネス要件の理解
                   └─ 何を守るのか？誰が使うのか？
                
                2. セキュリティ要件の定義
                   └─ 脅威モデル、コンプライアンス
                
                3. 技術要件の導出
                   └─ パフォーマンス、可用性、拡張性
                
                4. 制約条件の整理
                   └─ 予算、期間、既存システム
                
                5. 優先順位付け
                   └─ MVP、Phase1、将来拡張
                '''
            }
        }
```

### 8.1.2 要件定義のフレームワーク

```python
class RequirementsFramework:
    """要件定義のフレームワーク"""
    
    def define_business_requirements(self):
        """ビジネス要件の定義"""
        
        return {
            'user_stories': {
                'template': 'As a [role], I want [feature] so that [benefit]',
                'examples': [
                    {
                        'story': 'As a customer, I want to login with my email so that I can access my account',
                        'acceptance_criteria': [
                            'Email and password fields are displayed',
                            'Invalid credentials show error message',
                            'Successful login redirects to dashboard',
                            'Session persists across page refreshes'
                        ]
                    },
                    {
                        'story': 'As an admin, I want to disable user accounts so that I can prevent unauthorized access',
                        'acceptance_criteria': [
                            'Admin can search and find users',
                            'Disable action is logged',
                            'Disabled users cannot login',
                            'Users receive notification'
                        ]
                    }
                ]
            },
            
            'business_metrics': {
                'user_experience': [
                    'Login success rate > 95%',
                    'Average login time < 5 seconds',
                    'Password reset completion rate > 80%'
                ],
                'security': [
                    'Account takeover rate < 0.01%',
                    'Brute force attacks blocked 100%',
                    'Security incidents < 1 per month'
                ],
                'operational': [
                    'Support tickets for login issues < 5%',
                    'System uptime > 99.9%',
                    'User onboarding time < 2 minutes'
                ]
            }
        }
    
    def define_security_requirements(self):
        """セキュリティ要件の定義"""
        
        return {
            'authentication_requirements': {
                'password_policy': {
                    'minimum_length': 12,
                    'complexity': 'NIST guidelines (no forced complexity)',
                    'history': 'Last 5 passwords cannot be reused',
                    'expiry': 'No forced expiry, risk-based prompts'
                },
                
                'mfa_requirements': {
                    'mandatory_for': ['admin_users', 'high_value_transactions'],
                    'optional_for': ['regular_users'],
                    'methods': ['totp', 'sms', 'push_notification'],
                    'backup_codes': True
                },
                
                'session_management': {
                    'idle_timeout': '30 minutes',
                    'absolute_timeout': '8 hours',
                    'concurrent_sessions': 'Limited to 5',
                    'device_tracking': True
                }
            },
            
            'threat_model': {
                'external_threats': [
                    {
                        'threat': 'Brute force attacks',
                        'mitigation': 'Rate limiting, account lockout, CAPTCHA'
                    },
                    {
                        'threat': 'Credential stuffing',
                        'mitigation': 'Breach detection, unusual activity monitoring'
                    },
                    {
                        'threat': 'Phishing',
                        'mitigation': 'Security keys, user education'
                    }
                ],
                
                'internal_threats': [
                    {
                        'threat': 'Insider access',
                        'mitigation': 'Audit logging, least privilege'
                    },
                    {
                        'threat': 'Developer mistakes',
                        'mitigation': 'Security testing, code review'
                    }
                ]
            },
            
            'compliance_requirements': {
                'gdpr': {
                    'data_minimization': True,
                    'right_to_deletion': True,
                    'consent_management': True,
                    'breach_notification': '72 hours'
                },
                'pci_dss': {
                    'applicable': 'If handling payment cards',
                    'requirements': ['Strong cryptography', 'Access control', 'Monitoring']
                }
            }
        }
    
    def define_technical_requirements(self):
        """技術要件の定義"""
        
        return {
            'performance_requirements': {
                'response_time': {
                    'login_api': 'p95 < 200ms',
                    'token_validation': 'p95 < 50ms',
                    'user_lookup': 'p95 < 100ms'
                },
                
                'throughput': {
                    'peak_load': '1000 requests/second',
                    'sustained_load': '100 requests/second',
                    'concurrent_users': '10,000'
                },
                
                'scalability': {
                    'horizontal_scaling': True,
                    'auto_scaling': True,
                    'global_distribution': False  # Phase 2
                }
            },
            
            'availability_requirements': {
                'uptime_sla': '99.9%',
                'maintenance_window': 'Sunday 2-4 AM',
                'disaster_recovery': {
                    'rto': '1 hour',  # Recovery Time Objective
                    'rpo': '15 minutes'  # Recovery Point Objective
                },
                'degraded_mode': 'Read-only authentication if DB is down'
            },
            
            'integration_requirements': {
                'existing_systems': [
                    {
                        'system': 'User database',
                        'integration_type': 'Direct DB access',
                        'constraints': 'Read-only access'
                    },
                    {
                        'system': 'Email service',
                        'integration_type': 'API',
                        'use_cases': ['Password reset', 'MFA codes']
                    }
                ],
                
                'future_integrations': [
                    'LDAP/Active Directory',
                    'SAML IdP',
                    'OAuth providers'
                ]
            }
        }
    
    def prioritize_requirements(self):
        """要件の優先順位付け"""
        
        return {
            'moscow_method': {
                'must_have': [
                    'Email/password authentication',
                    'Secure password storage',
                    'Session management',
                    'Password reset',
                    'Basic rate limiting'
                ],
                
                'should_have': [
                    'MFA for admins',
                    'Account lockout',
                    'Audit logging',
                    'Remember me',
                    'CAPTCHA'
                ],
                
                'could_have': [
                    'Social login',
                    'Biometric authentication',
                    'Advanced threat detection',
                    'Self-service MFA'
                ],
                
                'wont_have': [
                    'Blockchain authentication',
                    'Quantum-resistant crypto',
                    'AI-based authentication'
                ]
            },
            
            'phased_approach': {
                'mvp': {
                    'timeline': '2 months',
                    'features': ['Basic auth', 'Password reset', 'Session management'],
                    'users': 'Internal beta'
                },
                
                'phase_1': {
                    'timeline': '3 months',
                    'features': ['MFA', 'Audit logging', 'Admin panel'],
                    'users': 'Limited release'
                },
                
                'phase_2': {
                    'timeline': '6 months',
                    'features': ['SSO', 'Advanced security', 'API expansion'],
                    'users': 'General availability'
                }
            }
        }
```

### 8.1.3 設計プロセスの実践

```python
class DesignProcess:
    """設計プロセスの実践"""
    
    def iterative_design_approach(self):
        """反復的な設計アプローチ"""
        
        return {
            'design_thinking_process': {
                'empathize': {
                    'activities': [
                        'User interviews',
                        'Support ticket analysis',
                        'Competitor analysis'
                    ],
                    'outputs': [
                        'User personas',
                        'Pain points',
                        'User journey maps'
                    ]
                },
                
                'define': {
                    'activities': [
                        'Problem statement creation',
                        'Requirements prioritization',
                        'Success metrics definition'
                    ],
                    'outputs': [
                        'Problem statement',
                        'Requirements document',
                        'KPIs'
                    ]
                },
                
                'ideate': {
                    'activities': [
                        'Brainstorming sessions',
                        'Architecture sketching',
                        'Technology evaluation'
                    ],
                    'outputs': [
                        'Solution options',
                        'Architecture diagrams',
                        'Tech stack recommendations'
                    ]
                },
                
                'prototype': {
                    'activities': [
                        'Proof of concept',
                        'API design',
                        'UI mockups'
                    ],
                    'outputs': [
                        'Working prototype',
                        'API specification',
                        'UI designs'
                    ]
                },
                
                'test': {
                    'activities': [
                        'Security testing',
                        'Performance testing',
                        'User testing'
                    ],
                    'outputs': [
                        'Test results',
                        'Feedback',
                        'Improvement recommendations'
                    ]
                }
            }
        }
    
    def architectural_decisions(self):
        """アーキテクチャ決定"""
        
        return {
            'decision_record_template': {
                'title': 'ADR-001: Authentication Service Architecture',
                'status': 'Accepted',
                'context': '''
                We need to decide on the overall architecture for the authentication service.
                Current system has 10k users, expected to grow to 100k in 2 years.
                ''',
                
                'decision': '''
                We will use a monolithic architecture with modular design.
                Authentication logic will be in a separate service.
                Session storage will use Redis.
                ''',
                
                'consequences': '''
                Positive:
                - Simpler deployment and monitoring
                - Lower operational complexity
                - Faster time to market
                
                Negative:
                - Scaling requires scaling entire service
                - Technology choices affect entire service
                
                Mitigation:
                - Design with future microservices split in mind
                - Use clean architecture principles
                '''
            },
            
            'key_decisions': [
                {
                    'decision': 'Stateless vs Stateful sessions',
                    'choice': 'Stateful with Redis',
                    'rationale': 'Better control over sessions, easier revocation'
                },
                {
                    'decision': 'Sync vs Async processing',
                    'choice': 'Sync for auth, async for audit/analytics',
                    'rationale': 'User experience vs system efficiency'
                },
                {
                    'decision': 'SQL vs NoSQL for user data',
                    'choice': 'PostgreSQL for users, Redis for sessions',
                    'rationale': 'ACID compliance for user data, speed for sessions'
                }
            ]
        }
```

## 8.2 データベース設計

### 8.2.1 認証システムのデータモデル

```python
class AuthenticationDataModel:
    """認証システムのデータモデル"""
    
    def core_entities(self):
        """中核となるエンティティ"""
        
        return {
            'users_table': '''
            CREATE TABLE users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                email VARCHAR(255) UNIQUE NOT NULL,
                email_verified BOOLEAN DEFAULT FALSE,
                email_verified_at TIMESTAMP,
                
                -- パスワード関連
                password_hash VARCHAR(255),
                password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                password_reset_token VARCHAR(255),
                password_reset_expires_at TIMESTAMP,
                
                -- プロフィール
                username VARCHAR(50) UNIQUE,
                display_name VARCHAR(100),
                profile_picture_url VARCHAR(500),
                
                -- ステータス
                status VARCHAR(20) DEFAULT 'active' 
                    CHECK (status IN ('active', 'inactive', 'suspended', 'deleted')),
                suspended_at TIMESTAMP,
                suspended_reason TEXT,
                deleted_at TIMESTAMP,
                
                -- メタデータ
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login_at TIMESTAMP,
                login_count INTEGER DEFAULT 0,
                
                -- セキュリティ
                mfa_enabled BOOLEAN DEFAULT FALSE,
                mfa_secret VARCHAR(255),
                backup_codes TEXT[], -- 暗号化して保存
                
                -- インデックス用
                created_at_date DATE GENERATED ALWAYS AS (DATE(created_at)) STORED
            );
            
            -- インデックス
            CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
            CREATE INDEX idx_users_status ON users(status) WHERE status != 'deleted';
            CREATE INDEX idx_users_created_at ON users(created_at_date);
            CREATE INDEX idx_users_last_login ON users(last_login_at) WHERE last_login_at IS NOT NULL;
            ''',
            
            'user_credentials_table': '''
            -- 複数の認証方式をサポート
            CREATE TABLE user_credentials (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                credential_type VARCHAR(50) NOT NULL,
                credential_id VARCHAR(255) NOT NULL,
                credential_public_key TEXT,
                credential_data JSONB,
                
                -- 使用状況
                last_used_at TIMESTAMP,
                use_count INTEGER DEFAULT 0,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                UNIQUE(user_id, credential_type, credential_id)
            );
            
            CREATE INDEX idx_credentials_user ON user_credentials(user_id);
            CREATE INDEX idx_credentials_type ON user_credentials(credential_type);
            ''',
            
            'sessions_table': '''
            -- アクティブセッション管理
            CREATE TABLE sessions (
                id VARCHAR(128) PRIMARY KEY,
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                
                -- セッション情報
                ip_address INET,
                user_agent TEXT,
                device_fingerprint VARCHAR(64),
                
                -- 時間管理
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                
                -- セッションデータ
                data JSONB DEFAULT '{}',
                
                -- セキュリティ
                is_mfa_verified BOOLEAN DEFAULT FALSE,
                mfa_verified_at TIMESTAMP
            );
            
            CREATE INDEX idx_sessions_user ON sessions(user_id);
            CREATE INDEX idx_sessions_expires ON sessions(expires_at);
            CREATE INDEX idx_sessions_device ON sessions(user_id, device_fingerprint);
            ''',
            
            'audit_logs_table': '''
            -- 監査ログ（パーティショニング推奨）
            CREATE TABLE audit_logs (
                id BIGSERIAL,
                user_id UUID,
                event_type VARCHAR(50) NOT NULL,
                event_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                -- コンテキスト情報
                ip_address INET,
                user_agent TEXT,
                session_id VARCHAR(128),
                
                -- イベント詳細
                event_data JSONB,
                
                -- 結果
                success BOOLEAN NOT NULL,
                error_code VARCHAR(50),
                error_message TEXT,
                
                PRIMARY KEY (event_timestamp, id)
            ) PARTITION BY RANGE (event_timestamp);
            
            -- 月次パーティション
            CREATE TABLE audit_logs_2024_01 PARTITION OF audit_logs
                FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
            
            CREATE INDEX idx_audit_user_time ON audit_logs(user_id, event_timestamp);
            CREATE INDEX idx_audit_type_time ON audit_logs(event_type, event_timestamp);
            '''
        }
    
    def supporting_entities(self):
        """サポート用エンティティ"""
        
        return {
            'login_attempts': '''
            -- ログイン試行の追跡
            CREATE TABLE login_attempts (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                email VARCHAR(255) NOT NULL,
                ip_address INET NOT NULL,
                
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN NOT NULL,
                failure_reason VARCHAR(50),
                
                -- レート制限用
                attempt_count INTEGER DEFAULT 1,
                locked_until TIMESTAMP
            );
            
            CREATE INDEX idx_attempts_email_ip ON login_attempts(email, ip_address);
            CREATE INDEX idx_attempts_time ON login_attempts(attempt_time);
            
            -- 古いレコードの自動削除
            CREATE OR REPLACE FUNCTION cleanup_old_attempts() RETURNS void AS $$
            BEGIN
                DELETE FROM login_attempts 
                WHERE attempt_time < CURRENT_TIMESTAMP - INTERVAL '7 days';
            END;
            $$ LANGUAGE plpgsql;
            ''',
            
            'device_tracking': '''
            -- デバイストラッキング
            CREATE TABLE user_devices (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                
                device_fingerprint VARCHAR(64) NOT NULL,
                device_name VARCHAR(100),
                device_type VARCHAR(50),
                
                -- 識別情報
                user_agent TEXT,
                platform VARCHAR(50),
                browser VARCHAR(50),
                
                -- 信頼状態
                is_trusted BOOLEAN DEFAULT FALSE,
                trusted_at TIMESTAMP,
                
                -- 使用状況
                first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                login_count INTEGER DEFAULT 1,
                
                UNIQUE(user_id, device_fingerprint)
            );
            
            CREATE INDEX idx_devices_user ON user_devices(user_id);
            CREATE INDEX idx_devices_trusted ON user_devices(user_id) WHERE is_trusted = TRUE;
            ''',
            
            'oauth_tokens': '''
            -- OAuth/JWT トークン管理
            CREATE TABLE oauth_tokens (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                
                token_type VARCHAR(20) NOT NULL, -- 'access', 'refresh'
                token_hash VARCHAR(64) NOT NULL, -- SHA-256 hash
                
                client_id VARCHAR(100),
                scope TEXT,
                
                issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                revoked_at TIMESTAMP,
                
                -- リフレッシュトークン用
                refresh_token_hash VARCHAR(64),
                refresh_count INTEGER DEFAULT 0,
                
                UNIQUE(token_hash)
            );
            
            CREATE INDEX idx_tokens_user ON oauth_tokens(user_id);
            CREATE INDEX idx_tokens_expires ON oauth_tokens(expires_at) WHERE revoked_at IS NULL;
            '''
        }
    
    def data_integrity_patterns(self):
        """データ整合性パターン"""
        
        return {
            'soft_delete_pattern': '''
            -- ソフトデリートの実装
            CREATE OR REPLACE FUNCTION soft_delete_user(user_id UUID) 
            RETURNS void AS $$
            BEGIN
                -- トランザクション内で実行
                UPDATE users 
                SET 
                    status = 'deleted',
                    deleted_at = CURRENT_TIMESTAMP,
                    email = email || ':deleted:' || extract(epoch from CURRENT_TIMESTAMP),
                    username = username || ':deleted:' || extract(epoch from CURRENT_TIMESTAMP)
                WHERE id = user_id;
                
                -- 関連セッションの削除
                DELETE FROM sessions WHERE user_id = user_id;
                
                -- 監査ログ
                INSERT INTO audit_logs (user_id, event_type, success, event_data)
                VALUES (user_id, 'user_deleted', true, '{"deleted_by": "system"}');
            END;
            $$ LANGUAGE plpgsql;
            ''',
            
            'password_history': '''
            -- パスワード履歴管理
            CREATE TABLE password_history (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX idx_password_history_user ON password_history(user_id, created_at DESC);
            
            -- パスワード変更時のチェック
            CREATE OR REPLACE FUNCTION check_password_history(
                p_user_id UUID, 
                p_new_password_hash VARCHAR
            ) RETURNS BOOLEAN AS $$
            DECLARE
                history_count INTEGER := 5; -- 最近5つのパスワードをチェック
            BEGIN
                RETURN NOT EXISTS (
                    SELECT 1 
                    FROM password_history 
                    WHERE user_id = p_user_id 
                        AND password_hash = p_new_password_hash
                    ORDER BY created_at DESC 
                    LIMIT history_count
                );
            END;
            $$ LANGUAGE plpgsql;
            ''',
            
            'data_encryption': '''
            -- 機密データの暗号化
            
            -- PII暗号化用の拡張
            CREATE EXTENSION IF NOT EXISTS pgcrypto;
            
            -- 暗号化ヘルパー関数
            CREATE OR REPLACE FUNCTION encrypt_pii(plain_text TEXT, key_id TEXT)
            RETURNS TEXT AS $$
            DECLARE
                encryption_key BYTEA;
            BEGIN
                -- キー管理サービスから鍵を取得（実装は省略）
                encryption_key := get_encryption_key(key_id);
                
                RETURN encode(
                    pgp_sym_encrypt(plain_text, encryption_key::TEXT),
                    'base64'
                );
            END;
            $$ LANGUAGE plpgsql;
            
            CREATE OR REPLACE FUNCTION decrypt_pii(encrypted_text TEXT, key_id TEXT)
            RETURNS TEXT AS $$
            DECLARE
                encryption_key BYTEA;
            BEGIN
                encryption_key := get_encryption_key(key_id);
                
                RETURN pgp_sym_decrypt(
                    decode(encrypted_text, 'base64'),
                    encryption_key::TEXT
                );
            END;
            $$ LANGUAGE plpgsql;
            '''
        }
```

### 8.2.2 パフォーマンス最適化

```python
class DatabasePerformanceOptimization:
    """データベースパフォーマンス最適化"""
    
    def indexing_strategy(self):
        """インデックス戦略"""
        
        return {
            'critical_indexes': {
                'authentication_queries': '''
                -- ログイン用の複合インデックス
                CREATE INDEX idx_users_login ON users(email, status) 
                WHERE deleted_at IS NULL AND status = 'active';
                
                -- セッション検証用
                CREATE INDEX idx_sessions_validation ON sessions(id, user_id, expires_at)
                WHERE expires_at > CURRENT_TIMESTAMP;
                
                -- デバイス認証用
                CREATE INDEX idx_devices_auth ON user_devices(user_id, device_fingerprint, is_trusted);
                ''',
                
                'analytics_queries': '''
                -- 日次アクティブユーザー
                CREATE INDEX idx_audit_daily_active ON audit_logs(event_timestamp, user_id)
                WHERE event_type IN ('login_success', 'session_refresh');
                
                -- ログイン失敗分析
                CREATE INDEX idx_audit_failures ON audit_logs(event_timestamp, ip_address)
                WHERE event_type = 'login_failure' AND success = false;
                '''
            },
            
            'partial_indexes': '''
            -- アクティブユーザーのみのインデックス
            CREATE INDEX idx_active_users_email ON users(email) 
            WHERE status = 'active' AND deleted_at IS NULL;
            
            -- MFA有効ユーザー
            CREATE INDEX idx_mfa_users ON users(id) 
            WHERE mfa_enabled = true AND status = 'active';
            
            -- 最近ログインしたユーザー
            CREATE INDEX idx_recent_login ON users(last_login_at) 
            WHERE last_login_at > CURRENT_TIMESTAMP - INTERVAL '30 days';
            ''',
            
            'covering_indexes': '''
            -- セッション情報を含むインデックス
            CREATE INDEX idx_sessions_full ON sessions(id) 
            INCLUDE (user_id, expires_at, is_mfa_verified);
            
            -- ユーザー認証情報を含むインデックス
            CREATE INDEX idx_users_auth ON users(email) 
            INCLUDE (id, password_hash, status, mfa_enabled);
            '''
        }
    
    def query_optimization(self):
        """クエリ最適化"""
        
        return {
            'common_query_patterns': {
                'user_authentication': '''
                -- 最適化されたユーザー認証クエリ
                WITH user_auth AS (
                    SELECT 
                        id, 
                        password_hash, 
                        status,
                        mfa_enabled,
                        (CURRENT_TIMESTAMP - last_login_at) as time_since_login
                    FROM users
                    WHERE email = $1 
                        AND deleted_at IS NULL
                        AND status IN ('active', 'inactive')
                    LIMIT 1
                )
                SELECT * FROM user_auth;
                
                -- EXPLAINプラン
                -- Index Scan using idx_users_login (cost=0.42..8.44)
                ''',
                
                'session_validation': '''
                -- 効率的なセッション検証
                SELECT 
                    s.id,
                    s.user_id,
                    s.expires_at,
                    s.is_mfa_verified,
                    u.status as user_status,
                    u.mfa_enabled
                FROM sessions s
                INNER JOIN users u ON s.user_id = u.id
                WHERE s.id = $1
                    AND s.expires_at > CURRENT_TIMESTAMP
                    AND u.status = 'active'
                    AND u.deleted_at IS NULL;
                ''',
                
                'concurrent_sessions': '''
                -- ユーザーの同時セッション取得
                SELECT 
                    id,
                    ip_address,
                    user_agent,
                    created_at,
                    last_accessed_at,
                    CASE 
                        WHEN device_fingerprint = $2 THEN true 
                        ELSE false 
                    END as is_current_device
                FROM sessions
                WHERE user_id = $1
                    AND expires_at > CURRENT_TIMESTAMP
                ORDER BY last_accessed_at DESC
                LIMIT 10;
                '''
            },
            
            'batch_operations': '''
            -- バッチセッションクリーンアップ
            DELETE FROM sessions
            WHERE expires_at < CURRENT_TIMESTAMP
                AND id = ANY(
                    SELECT id 
                    FROM sessions 
                    WHERE expires_at < CURRENT_TIMESTAMP
                    LIMIT 1000
                );
            
            -- バッチ監査ログアーカイブ
            WITH moved_rows AS (
                DELETE FROM audit_logs
                WHERE event_timestamp < CURRENT_TIMESTAMP - INTERVAL '90 days'
                RETURNING *
            )
            INSERT INTO audit_logs_archive 
            SELECT * FROM moved_rows;
            '''
        }
    
    def scaling_patterns(self):
        """スケーリングパターン"""
        
        return {
            'read_replica_strategy': {
                'setup': '''
                -- マスター/レプリカ構成
                -- マスター: 書き込み専用
                -- レプリカ: 読み込み専用
                
                -- アプリケーションレベルでの振り分け
                class DatabaseRouter:
                    def __init__(self):
                        self.master = psycopg2.connect(master_dsn)
                        self.replica = psycopg2.connect(replica_dsn)
                    
                    def execute_write(self, query, params):
                        with self.master.cursor() as cur:
                            cur.execute(query, params)
                            self.master.commit()
                    
                    def execute_read(self, query, params):
                        with self.replica.cursor() as cur:
                            cur.execute(query, params)
                            return cur.fetchall()
                ''',
                
                'consistency_handling': '''
                -- レプリケーションラグの対処
                
                -- 書き込み直後の読み込みはマスターから
                def authenticate_user(email, password):
                    # マスターから読み込み（一貫性保証）
                    user = db.master.query("SELECT * FROM users WHERE email = %s", [email])
                    
                    if verify_password(password, user.password_hash):
                        # セッション作成（マスターに書き込み）
                        session = create_session(user.id)
                        return session
                    
                def get_user_profile(user_id):
                    # レプリカから読み込み（少しの遅延は許容）
                    return db.replica.query("SELECT * FROM users WHERE id = %s", [user_id])
                '''
            },
            
            'sharding_strategy': {
                'user_sharding': '''
                -- ユーザーIDベースのシャーディング
                
                CREATE OR REPLACE FUNCTION get_shard_for_user(user_id UUID) 
                RETURNS INTEGER AS $$
                BEGIN
                    -- UUIDの最初の8文字をハッシュ
                    RETURN abs(hashtext(user_id::text)) % 4; -- 4シャード
                END;
                $$ LANGUAGE plpgsql;
                
                -- シャードごとのテーブル
                CREATE TABLE users_shard_0 () INHERITS (users);
                CREATE TABLE users_shard_1 () INHERITS (users);
                CREATE TABLE users_shard_2 () INHERITS (users);
                CREATE TABLE users_shard_3 () INHERITS (users);
                
                -- ルーティング関数
                CREATE OR REPLACE FUNCTION route_user_insert() 
                RETURNS TRIGGER AS $$
                DECLARE
                    shard_num INTEGER;
                BEGIN
                    shard_num := get_shard_for_user(NEW.id);
                    
                    EXECUTE format('INSERT INTO users_shard_%s VALUES ($1.*)', shard_num)
                    USING NEW;
                    
                    RETURN NULL;
                END;
                $$ LANGUAGE plpgsql;
                ''',
                
                'session_sharding': '''
                -- セッションは別のデータストア（Redis）を推奨
                
                class SessionStore:
                    def __init__(self):
                        self.redis_cluster = RedisCluster(
                            startup_nodes=[
                                {"host": "redis-1", "port": 6379},
                                {"host": "redis-2", "port": 6379},
                                {"host": "redis-3", "port": 6379}
                            ]
                        )
                    
                    def save_session(self, session_id, data, ttl=1800):
                        key = f"session:{session_id}"
                        self.redis_cluster.setex(key, ttl, json.dumps(data))
                    
                    def get_session(self, session_id):
                        key = f"session:{session_id}"
                        data = self.redis_cluster.get(key)
                        return json.loads(data) if data else None
                '''
            }
        }
```

## 8.3 API設計とエンドポイント

### 8.3.1 RESTful API設計

```python
class AuthenticationAPIDesign:
    """認証API設計"""
    
    def api_principles(self):
        """API設計原則"""
        
        return {
            'design_principles': {
                'consistency': '一貫性のある命名とレスポンス形式',
                'statelessness': 'RESTfulの原則に従う',
                'versioning': '後方互換性を考慮したバージョニング',
                'security': 'セキュリティファースト',
                'documentation': 'OpenAPI仕様での文書化'
            },
            
            'naming_conventions': {
                'resources': {
                    'pattern': '/api/v1/{resource}/{id}/{sub-resource}',
                    'examples': [
                        '/api/v1/auth/login',
                        '/api/v1/users/{id}',
                        '/api/v1/users/{id}/sessions',
                        '/api/v1/users/{id}/mfa'
                    ]
                },
                
                'http_methods': {
                    'GET': '取得',
                    'POST': '作成',
                    'PUT': '完全な更新',
                    'PATCH': '部分的な更新',
                    'DELETE': '削除'
                }
            },
            
            'response_format': {
                'success_response': {
                    'status': 'success',
                    'data': {},
                    'meta': {
                        'timestamp': '2024-01-15T10:30:00Z',
                        'version': 'v1'
                    }
                },
                
                'error_response': {
                    'status': 'error',
                    'error': {
                        'code': 'AUTH_001',
                        'message': 'Invalid credentials',
                        'details': 'The email or password is incorrect',
                        'timestamp': '2024-01-15T10:30:00Z'
                    }
                },
                
                'pagination_response': {
                    'status': 'success',
                    'data': [],
                    'pagination': {
                        'page': 1,
                        'per_page': 20,
                        'total': 100,
                        'total_pages': 5
                    }
                }
            }
        }
    
    def authentication_endpoints(self):
        """認証エンドポイント"""
        
        return {
            'login': {
                'endpoint': 'POST /api/v1/auth/login',
                'description': 'ユーザーログイン',
                'request': {
                    'headers': {
                        'Content-Type': 'application/json',
                        'X-Device-Fingerprint': 'optional-device-id'
                    },
                    'body': {
                        'email': 'user@example.com',
                        'password': 'secure_password',
                        'remember_me': False
                    }
                },
                'response': {
                    'success': {
                        'status': 'success',
                        'data': {
                            'user': {
                                'id': 'uuid',
                                'email': 'user@example.com',
                                'name': 'John Doe'
                            },
                            'session': {
                                'token': 'session_token',
                                'expires_at': '2024-01-15T18:30:00Z'
                            },
                            'requires_mfa': False
                        }
                    },
                    'mfa_required': {
                        'status': 'success',
                        'data': {
                            'mfa_token': 'temporary_token',
                            'mfa_methods': ['totp', 'sms'],
                            'expires_at': '2024-01-15T10:35:00Z'
                        }
                    },
                    'errors': {
                        '401': {
                            'code': 'INVALID_CREDENTIALS',
                            'message': 'Invalid email or password'
                        },
                        '423': {
                            'code': 'ACCOUNT_LOCKED',
                            'message': 'Account is temporarily locked',
                            'retry_after': 300
                        }
                    }
                },
                'implementation': '''
                @app.route('/api/v1/auth/login', methods=['POST'])
                @rate_limit(calls=5, period=300)  # 5 attempts per 5 minutes
                def login():
                    data = request.get_json()
                    
                    # 入力検証
                    errors = validate_login_input(data)
                    if errors:
                        return jsonify({
                            'status': 'error',
                            'error': {
                                'code': 'VALIDATION_ERROR',
                                'details': errors
                            }
                        }), 400
                    
                    # レート制限チェック
                    if is_rate_limited(data['email'], request.remote_addr):
                        return jsonify({
                            'status': 'error',
                            'error': {
                                'code': 'RATE_LIMITED',
                                'message': 'Too many attempts',
                                'retry_after': 300
                            }
                        }), 429
                    
                    # 認証処理
                    user = authenticate_user(data['email'], data['password'])
                    if not user:
                        record_failed_attempt(data['email'], request.remote_addr)
                        return jsonify({
                            'status': 'error',
                            'error': {
                                'code': 'INVALID_CREDENTIALS',
                                'message': 'Invalid email or password'
                            }
                        }), 401
                    
                    # MFAチェック
                    if user.mfa_enabled:
                        mfa_token = generate_mfa_token(user.id)
                        return jsonify({
                            'status': 'success',
                            'data': {
                                'mfa_token': mfa_token,
                                'mfa_methods': get_user_mfa_methods(user.id),
                                'expires_at': get_expiry_time(minutes=5)
                            }
                        })
                    
                    # セッション作成
                    session = create_session(user, request)
                    
                    return jsonify({
                        'status': 'success',
                        'data': {
                            'user': serialize_user(user),
                            'session': {
                                'token': session.token,
                                'expires_at': session.expires_at
                            }
                        }
                    })
                '''
            },
            
            'logout': {
                'endpoint': 'POST /api/v1/auth/logout',
                'description': 'ユーザーログアウト',
                'request': {
                    'headers': {
                        'Authorization': 'Bearer {session_token}'
                    },
                    'body': {
                        'everywhere': False  # 全デバイスからログアウト
                    }
                },
                'response': {
                    'success': {
                        'status': 'success',
                        'data': {
                            'message': 'Successfully logged out'
                        }
                    }
                }
            },
            
            'refresh': {
                'endpoint': 'POST /api/v1/auth/refresh',
                'description': 'セッションリフレッシュ',
                'request': {
                    'headers': {
                        'Authorization': 'Bearer {refresh_token}'
                    }
                },
                'response': {
                    'success': {
                        'status': 'success',
                        'data': {
                            'session': {
                                'token': 'new_session_token',
                                'expires_at': '2024-01-15T19:30:00Z'
                            }
                        }
                    }
                }
            }
        }
    
    def user_management_endpoints(self):
        """ユーザー管理エンドポイント"""
        
        return {
            'register': {
                'endpoint': 'POST /api/v1/auth/register',
                'description': '新規ユーザー登録',
                'request': {
                    'body': {
                        'email': 'user@example.com',
                        'password': 'secure_password',
                        'name': 'John Doe',
                        'accept_terms': True
                    }
                },
                'validation': '''
                def validate_registration(data):
                    errors = {}
                    
                    # Email検証
                    if not is_valid_email(data.get('email')):
                        errors['email'] = 'Invalid email format'
                    elif email_exists(data.get('email')):
                        errors['email'] = 'Email already registered'
                    
                    # パスワード検証
                    password_errors = validate_password(data.get('password'))
                    if password_errors:
                        errors['password'] = password_errors
                    
                    # 利用規約
                    if not data.get('accept_terms'):
                        errors['accept_terms'] = 'You must accept the terms'
                    
                    return errors
                '''
            },
            
            'profile': {
                'get': {
                    'endpoint': 'GET /api/v1/users/me',
                    'description': '現在のユーザー情報取得',
                    'response': {
                        'id': 'uuid',
                        'email': 'user@example.com',
                        'name': 'John Doe',
                        'created_at': '2024-01-01T00:00:00Z',
                        'mfa_enabled': False
                    }
                },
                
                'update': {
                    'endpoint': 'PATCH /api/v1/users/me',
                    'description': 'プロフィール更新',
                    'request': {
                        'body': {
                            'name': 'Jane Doe',
                            'timezone': 'Asia/Tokyo'
                        }
                    }
                }
            },
            
            'password_reset': {
                'request': {
                    'endpoint': 'POST /api/v1/auth/password-reset',
                    'description': 'パスワードリセット要求',
                    'request': {
                        'body': {
                            'email': 'user@example.com'
                        }
                    },
                    'implementation': '''
                    @app.route('/api/v1/auth/password-reset', methods=['POST'])
                    @rate_limit(calls=3, period=3600)  # 3 requests per hour
                    def request_password_reset():
                        email = request.json.get('email')
                        
                        # 常に同じレスポンスを返す（情報漏洩防止）
                        response = {
                            'status': 'success',
                            'data': {
                                'message': 'If the email exists, a reset link has been sent'
                            }
                        }
                        
                        # 非同期でメール送信
                        if is_valid_email(email):
                            user = get_user_by_email(email)
                            if user:
                                token = generate_reset_token(user.id)
                                send_reset_email.delay(user.email, token)
                        
                        return jsonify(response)
                    '''
                },
                
                'confirm': {
                    'endpoint': 'POST /api/v1/auth/password-reset/confirm',
                    'description': 'パスワードリセット実行',
                    'request': {
                        'body': {
                            'token': 'reset_token',
                            'password': 'new_secure_password'
                        }
                    }
                }
            }
        }
    
    def security_endpoints(self):
        """セキュリティ関連エンドポイント"""
        
        return {
            'mfa_endpoints': {
                'setup': {
                    'endpoint': 'POST /api/v1/users/me/mfa/setup',
                    'description': 'MFA設定開始',
                    'request': {
                        'body': {
                            'method': 'totp'
                        }
                    },
                    'response': {
                        'status': 'success',
                        'data': {
                            'secret': 'base32_secret',
                            'qr_code': 'data:image/png;base64,...',
                            'backup_codes': [
                                'XXXX-XXXX',
                                'YYYY-YYYY'
                            ]
                        }
                    }
                },
                
                'verify': {
                    'endpoint': 'POST /api/v1/auth/mfa/verify',
                    'description': 'MFA検証',
                    'request': {
                        'headers': {
                            'X-MFA-Token': 'temporary_token'
                        },
                        'body': {
                            'code': '123456'
                        }
                    }
                },
                
                'disable': {
                    'endpoint': 'DELETE /api/v1/users/me/mfa',
                    'description': 'MFA無効化',
                    'request': {
                        'body': {
                            'password': 'current_password'
                        }
                    }
                }
            },
            
            'sessions_management': {
                'list': {
                    'endpoint': 'GET /api/v1/users/me/sessions',
                    'description': 'アクティブセッション一覧',
                    'response': {
                        'sessions': [{
                            'id': 'session_id',
                            'device': 'Chrome on Windows',
                            'ip_address': '192.168.1.1',
                            'location': 'Tokyo, Japan',
                            'created_at': '2024-01-15T10:00:00Z',
                            'last_activity': '2024-01-15T10:30:00Z',
                            'is_current': True
                        }]
                    }
                },
                
                'revoke': {
                    'endpoint': 'DELETE /api/v1/users/me/sessions/{session_id}',
                    'description': '特定セッションの無効化'
                },
                
                'revoke_all': {
                    'endpoint': 'DELETE /api/v1/users/me/sessions',
                    'description': '全セッションの無効化',
                    'request': {
                        'body': {
                            'except_current': True
                        }
                    }
                }
            }
        }
```

### 8.3.2 API セキュリティ実装

```python
class APISecurityImplementation:
    """APIセキュリティ実装"""
    
    def authentication_middleware(self):
        """認証ミドルウェア"""
        
        return {
            'bearer_token_auth': '''
            from functools import wraps
            from flask import request, jsonify, g
            
            def require_auth(f):
                @wraps(f)
                def decorated_function(*args, **kwargs):
                    # Authorization ヘッダーの確認
                    auth_header = request.headers.get('Authorization')
                    if not auth_header:
                        return jsonify({
                            'status': 'error',
                            'error': {
                                'code': 'MISSING_AUTH',
                                'message': 'Authorization header required'
                            }
                        }), 401
                    
                    # Bearer トークンの抽出
                    try:
                        scheme, token = auth_header.split(' ')
                        if scheme.lower() != 'bearer':
                            raise ValueError('Invalid scheme')
                    except ValueError:
                        return jsonify({
                            'status': 'error',
                            'error': {
                                'code': 'INVALID_AUTH_FORMAT',
                                'message': 'Authorization header must be Bearer token'
                            }
                        }), 401
                    
                    # セッション検証
                    session = validate_session(token)
                    if not session:
                        return jsonify({
                            'status': 'error',
                            'error': {
                                'code': 'INVALID_TOKEN',
                                'message': 'Invalid or expired token'
                            }
                        }), 401
                    
                    # ユーザー情報をコンテキストに追加
                    g.current_user = session.user
                    g.current_session = session
                    
                    return f(*args, **kwargs)
                
                return decorated_function
            ''',
            
            'rate_limiting': '''
            from flask_limiter import Limiter
            from flask_limiter.util import get_remote_address
            
            limiter = Limiter(
                app,
                key_func=get_remote_address,
                default_limits=["1000 per hour"],
                storage_uri="redis://localhost:6379"
            )
            
            # エンドポイント別のレート制限
            @app.route('/api/v1/auth/login', methods=['POST'])
            @limiter.limit("5 per 5 minutes")
            def login():
                pass
            
            @app.route('/api/v1/auth/register', methods=['POST'])
            @limiter.limit("3 per hour")
            def register():
                pass
            
            # 動的レート制限
            def get_rate_limit():
                if g.current_user and g.current_user.is_premium:
                    return "10000 per hour"
                return "1000 per hour"
            
            @app.route('/api/v1/data')
            @limiter.limit(get_rate_limit)
            def get_data():
                pass
            ''',
            
            'input_validation': '''
            from marshmallow import Schema, fields, validate, ValidationError
            
            class LoginSchema(Schema):
                email = fields.Email(required=True)
                password = fields.Str(
                    required=True,
                    validate=validate.Length(min=8, max=128)
                )
                remember_me = fields.Bool(missing=False)
                device_fingerprint = fields.Str(
                    validate=validate.Length(equal=64)
                )
            
            def validate_input(schema_class):
                def decorator(f):
                    @wraps(f)
                    def decorated_function(*args, **kwargs):
                        schema = schema_class()
                        try:
                            data = schema.load(request.get_json())
                            request.validated_data = data
                        except ValidationError as err:
                            return jsonify({
                                'status': 'error',
                                'error': {
                                    'code': 'VALIDATION_ERROR',
                                    'details': err.messages
                                }
                            }), 400
                        
                        return f(*args, **kwargs)
                    
                    return decorated_function
                return decorator
            
            @app.route('/api/v1/auth/login', methods=['POST'])
            @validate_input(LoginSchema)
            def login():
                data = request.validated_data
                # 検証済みデータを使用
            '''
        }
    
    def security_headers(self):
        """セキュリティヘッダー"""
        
        return {
            'implementation': '''
            @app.after_request
            def set_security_headers(response):
                # 基本的なセキュリティヘッダー
                response.headers['X-Content-Type-Options'] = 'nosniff'
                response.headers['X-Frame-Options'] = 'DENY'
                response.headers['X-XSS-Protection'] = '1; mode=block'
                response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
                
                # Content Security Policy
                response.headers['Content-Security-Policy'] = "; ".join([
                    "default-src 'self'",
                    "script-src 'self' 'unsafe-inline'",
                    "style-src 'self' 'unsafe-inline'",
                    "img-src 'self' data: https:",
                    "font-src 'self'",
                    "connect-src 'self'",
                    "frame-ancestors 'none'"
                ])
                
                # CORS設定（必要に応じて）
                if request.origin in app.config['ALLOWED_ORIGINS']:
                    response.headers['Access-Control-Allow-Origin'] = request.origin
                    response.headers['Access-Control-Allow-Credentials'] = 'true'
                
                return response
            ''',
            
            'api_versioning': '''
            # URLパスでのバージョニング
            @app.route('/api/v1/users/<user_id>')
            def get_user_v1(user_id):
                # v1 実装
                pass
            
            @app.route('/api/v2/users/<user_id>')
            def get_user_v2(user_id):
                # v2 実装（拡張フィールド付き）
                pass
            
            # ヘッダーでのバージョニング
            @app.route('/api/users/<user_id>')
            def get_user(user_id):
                api_version = request.headers.get('API-Version', 'v1')
                
                if api_version == 'v2':
                    return get_user_v2_logic(user_id)
                else:
                    return get_user_v1_logic(user_id)
            '''
        }
```

## 8.4 エラーハンドリングとユーザビリティ

### 8.4.1 エラー設計の原則

```python
class ErrorHandlingDesign:
    """エラーハンドリング設計"""
    
    def error_design_principles(self):
        """エラー設計の原則"""
        
        return {
            'user_friendly_errors': {
                'principle': 'ユーザーが理解し、行動できるエラーメッセージ',
                'bad_example': {
                    'message': 'Error 0x80070005',
                    'problem': '意味不明、対処法が不明'
                },
                'good_example': {
                    'message': 'パスワードが間違っています。大文字小文字を確認してください。',
                    'reason': '具体的で行動可能'
                }
            },
            
            'security_conscious_errors': {
                'principle': 'セキュリティ情報を漏らさない',
                'bad_example': {
                    'message': 'ユーザー user@example.com は存在しません',
                    'problem': 'アカウントの存在確認に使える'
                },
                'good_example': {
                    'message': 'メールアドレスまたはパスワードが正しくありません',
                    'reason': '情報を特定できない'
                }
            },
            
            'actionable_errors': {
                'principle': 'ユーザーが次に何をすべきか明確',
                'example': {
                    'error': 'アカウントがロックされています',
                    'action': '5分後に再度お試しください',
                    'help_link': '/support/account-locked'
                }
            }
        }
    
    def error_taxonomy(self):
        """エラーの分類"""
        
        return {
            'client_errors': {
                'validation_errors': {
                    'code': 'VALIDATION_ERROR',
                    'http_status': 400,
                    'examples': [
                        'メールアドレスの形式が正しくありません',
                        'パスワードは8文字以上必要です',
                        '利用規約への同意が必要です'
                    ]
                },
                
                'authentication_errors': {
                    'code': 'AUTH_ERROR',
                    'http_status': 401,
                    'examples': [
                        'ログインが必要です',
                        'セッションの有効期限が切れました',
                        '認証情報が正しくありません'
                    ]
                },
                
                'authorization_errors': {
                    'code': 'FORBIDDEN',
                    'http_status': 403,
                    'examples': [
                        'この操作を行う権限がありません',
                        'アカウントが一時的に制限されています'
                    ]
                },
                
                'rate_limit_errors': {
                    'code': 'RATE_LIMITED',
                    'http_status': 429,
                    'examples': [
                        'リクエストが多すぎます。しばらくお待ちください',
                        '1時間に5回までしか試行できません'
                    ]
                }
            },
            
            'server_errors': {
                'internal_errors': {
                    'code': 'INTERNAL_ERROR',
                    'http_status': 500,
                    'user_message': 'システムエラーが発生しました。しばらく経ってから再度お試しください。',
                    'log_detail': True
                },
                
                'service_unavailable': {
                    'code': 'SERVICE_UNAVAILABLE',
                    'http_status': 503,
                    'user_message': 'メンテナンス中です。10分後に再度アクセスしてください。'
                }
            }
        }
    
    def error_response_format(self):
        """エラーレスポンス形式"""
        
        return {
            'standard_format': {
                'status': 'error',
                'error': {
                    'code': 'ERROR_CODE',
                    'message': 'ユーザー向けメッセージ',
                    'field': 'エラーが発生したフィールド（任意）',
                    'details': '追加情報（任意）',
                    'request_id': 'リクエストID（サポート用）'
                }
            },
            
            'validation_error_format': {
                'status': 'error',
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': '入力内容に誤りがあります',
                    'details': {
                        'email': ['メールアドレスの形式が正しくありません'],
                        'password': [
                            'パスワードは8文字以上必要です',
                            '少なくとも1つの数字を含めてください'
                        ]
                    }
                }
            },
            
            'implementation': '''
            class APIError(Exception):
                """API エラーの基底クラス"""
                
                def __init__(self, code, message, status_code=400, details=None):
                    self.code = code
                    self.message = message
                    self.status_code = status_code
                    self.details = details
                    super().__init__(self.message)
                
                def to_dict(self):
                    response = {
                        'status': 'error',
                        'error': {
                            'code': self.code,
                            'message': self.message,
                            'request_id': g.request_id
                        }
                    }
                    
                    if self.details:
                        response['error']['details'] = self.details
                    
                    return response
            
            class ValidationError(APIError):
                def __init__(self, errors):
                    super().__init__(
                        code='VALIDATION_ERROR',
                        message='入力内容に誤りがあります',
                        status_code=400,
                        details=errors
                    )
            
            class AuthenticationError(APIError):
                def __init__(self, message='認証が必要です'):
                    super().__init__(
                        code='AUTHENTICATION_REQUIRED',
                        message=message,
                        status_code=401
                    )
            
            @app.errorhandler(APIError)
            def handle_api_error(error):
                response = jsonify(error.to_dict())
                response.status_code = error.status_code
                
                # エラーログ
                if error.status_code >= 500:
                    app.logger.error(
                        f"API Error: {error.code}",
                        extra={
                            'request_id': g.request_id,
                            'user_id': g.get('current_user', {}).get('id'),
                            'error_details': error.details
                        }
                    )
                
                return response
            '''
        }
```

### 8.4.2 ユーザビリティの向上

```python
class UsabilityEnhancements:
    """ユーザビリティの向上"""
    
    def user_experience_patterns(self):
        """UXパターン"""
        
        return {
            'progressive_disclosure': {
                'concept': '段階的な情報開示',
                'login_flow': {
                    'step1': {
                        'show': ['email'],
                        'hide': ['password', 'mfa']
                    },
                    'step2': {
                        'show': ['password'],
                        'context': 'ユーザー名確認後'
                    },
                    'step3': {
                        'show': ['mfa'],
                        'context': 'MFA有効時のみ'
                    }
                },
                'benefits': [
                    '認知負荷の軽減',
                    'エラーの段階的な処理',
                    'よりスムーズな体験'
                ]
            },
            
            'helpful_feedback': {
                'password_strength': '''
                function checkPasswordStrength(password) {
                    const feedback = {
                        score: 0,
                        suggestions: []
                    };
                    
                    // 長さチェック
                    if (password.length < 8) {
                        feedback.suggestions.push('8文字以上にしてください');
                    } else if (password.length < 12) {
                        feedback.score += 1;
                        feedback.suggestions.push('12文字以上だとより安全です');
                    } else {
                        feedback.score += 2;
                    }
                    
                    // 文字種チェック
                    const patterns = {
                        lowercase: /[a-z]/,
                        uppercase: /[A-Z]/,
                        numbers: /[0-9]/,
                        special: /[^A-Za-z0-9]/
                    };
                    
                    let types = 0;
                    for (const [type, pattern] of Object.entries(patterns)) {
                        if (pattern.test(password)) {
                            types++;
                        }
                    }
                    
                    feedback.score += types;
                    
                    // 強度表示
                    if (feedback.score <= 2) {
                        feedback.strength = 'weak';
                        feedback.color = '#dc3545';
                        feedback.text = '弱い';
                    } else if (feedback.score <= 4) {
                        feedback.strength = 'medium';
                        feedback.color = '#ffc107';
                        feedback.text = '普通';
                    } else {
                        feedback.strength = 'strong';
                        feedback.color = '#28a745';
                        feedback.text = '強い';
                    }
                    
                    return feedback;
                }
                ''',
                
                'real_time_validation': '''
                // リアルタイム検証
                const emailInput = document.getElementById('email');
                let validationTimer;
                
                emailInput.addEventListener('input', (e) => {
                    clearTimeout(validationTimer);
                    
                    // デバウンス
                    validationTimer = setTimeout(() => {
                        validateEmail(e.target.value);
                    }, 500);
                });
                
                async function validateEmail(email) {
                    // 基本的な形式チェック
                    if (!isValidEmailFormat(email)) {
                        showError('email', 'メールアドレスの形式が正しくありません');
                        return;
                    }
                    
                    // 既存チェック（オプション）
                    if (checkingEnabled) {
                        const response = await fetch('/api/v1/auth/check-email', {
                            method: 'POST',
                            body: JSON.stringify({ email })
                        });
                        
                        if (response.ok) {
                            showSuccess('email', '利用可能です');
                        }
                    }
                }
                '''
            },
            
            'accessibility': {
                'aria_labels': '''
                <form role="form" aria-label="ログインフォーム">
                    <div class="form-group">
                        <label for="email">メールアドレス</label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            required
                            aria-required="true"
                            aria-describedby="email-error"
                            aria-invalid="false"
                        />
                        <span id="email-error" class="error" role="alert"></span>
                    </div>
                    
                    <button type="submit" aria-busy="false">
                        ログイン
                    </button>
                </form>
                ''',
                
                'keyboard_navigation': '''
                // キーボードナビゲーション
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        const activeElement = document.activeElement;
                        
                        if (activeElement.tagName === 'INPUT') {
                            const form = activeElement.closest('form');
                            const inputs = form.querySelectorAll('input');
                            const index = Array.from(inputs).indexOf(activeElement);
                            
                            if (index < inputs.length - 1) {
                                // 次の入力フィールドへ
                                inputs[index + 1].focus();
                                e.preventDefault();
                            } else {
                                // 送信
                                form.submit();
                            }
                        }
                    }
                });
                '''
            }
        }
    
    def performance_optimization(self):
        """パフォーマンス最適化"""
        
        return {
            'api_performance': {
                'caching_strategy': '''
                from functools import lru_cache
                import redis
                
                redis_client = redis.Redis()
                
                @lru_cache(maxsize=1000)
                def get_user_permissions(user_id):
                    """ユーザー権限のキャッシュ"""
                    # Redisから取得
                    cache_key = f"permissions:{user_id}"
                    cached = redis_client.get(cache_key)
                    
                    if cached:
                        return json.loads(cached)
                    
                    # DBから取得
                    permissions = fetch_user_permissions_from_db(user_id)
                    
                    # Redisにキャッシュ（5分）
                    redis_client.setex(
                        cache_key,
                        300,
                        json.dumps(permissions)
                    )
                    
                    return permissions
                ''',
                
                'response_compression': '''
                from flask_compress import Compress
                
                app = Flask(__name__)
                Compress(app)
                
                # 特定のレスポンスのみ圧縮
                @app.route('/api/v1/users')
                def get_users():
                    users = fetch_users()
                    response = jsonify(users)
                    
                    # 大きなレスポンスのみ圧縮
                    if len(response.data) > 1024:  # 1KB以上
                        response.headers['Content-Encoding'] = 'gzip'
                    
                    return response
                ''',
                
                'pagination': '''
                def paginate_query(query, page=1, per_page=20, max_per_page=100):
                    """効率的なページネーション"""
                    
                    # per_pageの制限
                    per_page = min(per_page, max_per_page)
                    
                    # カーソルベースのページネーション（大規模データ用）
                    if page > 100:  # 深いページの場合
                        return cursor_paginate(query, cursor, per_page)
                    
                    # オフセットベース（通常のケース）
                    paginated = query.paginate(
                        page=page,
                        per_page=per_page,
                        error_out=False
                    )
                    
                    return {
                        'items': [item.to_dict() for item in paginated.items],
                        'pagination': {
                            'page': page,
                            'per_page': per_page,
                            'total': paginated.total,
                            'pages': paginated.pages,
                            'has_next': paginated.has_next,
                            'has_prev': paginated.has_prev
                        }
                    }
                '''
            },
            
            'frontend_optimization': {
                'lazy_loading': '''
                // 遅延読み込み
                const loadMFASettings = () => {
                    import('./mfa-settings.js').then(module => {
                        module.initializeMFA();
                    });
                };
                
                // IntersectionObserverで可視時に読み込み
                const observer = new IntersectionObserver((entries) => {
                    entries.forEach(entry => {
                        if (entry.isIntersecting) {
                            loadMFASettings();
                            observer.unobserve(entry.target);
                        }
                    });
                });
                
                observer.observe(document.getElementById('mfa-section'));
                ''',
                
                'optimistic_updates': '''
                // 楽観的更新
                async function updateProfile(data) {
                    // UIを即座に更新
                    updateUIOptimistically(data);
                    
                    try {
                        const response = await api.updateProfile(data);
                        // 成功
                        showSuccess('プロフィールを更新しました');
                    } catch (error) {
                        // 失敗時は元に戻す
                        revertUIUpdate();
                        showError('更新に失敗しました');
                    }
                }
                '''
            }
        }
```

## まとめ

この章では、実践的な認証システムの設計について学びました：

1. **要件定義と設計の進め方**
   - ビジネス要件から技術要件への落とし込み
   - セキュリティ要件の明確化
   - 段階的な実装アプローチ

2. **データベース設計**
   - 認証システムに必要なエンティティ
   - パフォーマンスを考慮したインデックス戦略
   - スケーラビリティのための設計パターン

3. **API設計とエンドポイント**
   - RESTfulな認証API設計
   - セキュリティを考慮した実装
   - エラーハンドリングのベストプラクティス

4. **エラーハンドリングとユーザビリティ**
   - ユーザーフレンドリーなエラー設計
   - アクセシビリティの考慮
   - パフォーマンス最適化

次章では、マイクロサービス環境での認証認可について学びます。

## 演習問題

### 問題1：要件定義
スタートアップのSaaSプロダクト（B2B、想定ユーザー1万社）の認証システムの要件定義を作成しなさい。ビジネス要件、セキュリティ要件、技術要件を含めること。

### 問題2：データベース設計
以下の要件を満たすデータベーススキーマを設計しなさい：
- マルチテナント対応
- 監査ログの長期保存
- GDPR準拠（データ削除要求対応）
- 月間10億リクエスト対応

### 問題3：API設計
企業向けSSOをサポートする認証APIを設計しなさい。SAML、OIDC、独自認証の3つをサポートし、統一されたAPIインターフェースを提供すること。

### 問題4：エラー設計
多言語対応（日英中）の認証システムのエラーメッセージ体系を設計しなさい。セキュリティとユーザビリティのバランスを考慮すること。

### 問題5：パフォーマンス設計
秒間1万リクエストを処理できる認証システムのアーキテクチャを設計しなさい。コスト効率も考慮し、段階的なスケーリング計画を含めること。