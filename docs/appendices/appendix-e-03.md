---
layout: book
title: "第3章 演習問題解答"
---

# 第3章 演習問題解答

## 問題1：RBACシステムの設計

### 中規模IT企業のRBAC設計

```python
class CompanyRBACDesign:
    """中規模IT企業（300名）のRBAC設計"""
    
    def __init__(self):
        self.departments = self._define_departments()
        self.roles = self._define_roles()
        self.permissions = self._define_permissions()
        self.separation_of_duties = self._define_sod_rules()
    
    def _define_departments(self):
        """部門構造の定義"""
        return {
            'engineering': {
                'name': '開発部門',
                'size': 120,
                'sub_departments': ['frontend', 'backend', 'qa', 'devops']
            },
            'sales': {
                'name': '営業部門', 
                'size': 80,
                'sub_departments': ['direct_sales', 'partner_sales', 'customer_success']
            },
            'management': {
                'name': '管理部門',
                'size': 50,
                'sub_departments': ['finance', 'legal', 'facilities']
            },
            'hr': {
                'name': '人事部門',
                'size': 50,
                'sub_departments': ['recruitment', 'training', 'compensation']
            }
        }
    
    def _define_roles(self):
        """役割の階層構造"""
        return {
            # 全社共通役割
            'employee': {
                'name': '一般社員',
                'parent': None,
                'permissions': [
                    'read_public_info',
                    'update_own_profile',
                    'submit_expense',
                    'view_org_chart'
                ]
            },
            
            # 開発部門の役割
            'developer': {
                'name': '開発者',
                'parent': 'employee',
                'permissions': [
                    'read_source_code',
                    'write_source_code',
                    'create_branch',
                    'view_ci_results'
                ]
            },
            'senior_developer': {
                'name': 'シニア開発者',
                'parent': 'developer',
                'permissions': [
                    'merge_to_main',
                    'create_release_tag',
                    'modify_ci_config'
                ]
            },
            'tech_lead': {
                'name': 'テックリード',
                'parent': 'senior_developer',
                'permissions': [
                    'approve_architecture',
                    'manage_team_resources',
                    'production_deployment'
                ]
            },
            'qa_engineer': {
                'name': 'QAエンジニア',
                'parent': 'employee',
                'permissions': [
                    'read_source_code',
                    'create_test_cases',
                    'execute_tests',
                    'file_bugs',
                    'access_staging_env'
                ]
            },
            'devops_engineer': {
                'name': 'DevOpsエンジニア',
                'parent': 'employee',
                'permissions': [
                    'manage_infrastructure',
                    'view_system_logs',
                    'modify_deployment_config',
                    'access_production_readonly'
                ]
            },
            'devops_lead': {
                'name': 'DevOpsリード',
                'parent': 'devops_engineer',
                'permissions': [
                    'access_production_write',
                    'modify_security_groups',
                    'manage_ssl_certificates',
                    'emergency_shutdown'
                ]
            },
            
            # 営業部門の役割
            'sales_rep': {
                'name': '営業担当',
                'parent': 'employee',
                'permissions': [
                    'read_customer_data',
                    'create_opportunity',
                    'update_opportunity',
                    'view_sales_reports'
                ]
            },
            'sales_manager': {
                'name': '営業マネージャー',
                'parent': 'sales_rep',
                'permissions': [
                    'approve_discount',
                    'view_team_pipeline',
                    'modify_territory',
                    'access_competitor_analysis'
                ]
            },
            'customer_success': {
                'name': 'カスタマーサクセス',
                'parent': 'employee',
                'permissions': [
                    'read_customer_data',
                    'create_support_ticket',
                    'view_usage_analytics',
                    'schedule_customer_meeting'
                ]
            },
            
            # 管理部門の役割
            'accountant': {
                'name': '経理担当',
                'parent': 'employee',
                'permissions': [
                    'view_financial_reports',
                    'process_invoices',
                    'manage_ar_ap',
                    'run_financial_queries'
                ]
            },
            'finance_manager': {
                'name': '財務マネージャー',
                'parent': 'accountant',
                'permissions': [
                    'approve_payments',
                    'modify_budgets',
                    'access_bank_accounts',
                    'sign_contracts'
                ]
            },
            
            # 人事部門の役割
            'hr_specialist': {
                'name': 'HR担当',
                'parent': 'employee',
                'permissions': [
                    'read_employee_data',
                    'manage_benefits',
                    'process_leave_requests',
                    'view_org_metrics'
                ]
            },
            'hr_manager': {
                'name': 'HRマネージャー',
                'parent': 'hr_specialist',
                'permissions': [
                    'modify_employee_data',
                    'view_compensation_data',
                    'approve_promotions',
                    'access_performance_reviews'
                ]
            },
            
            # 管理職共通
            'manager': {
                'name': 'マネージャー',
                'parent': 'employee',
                'permissions': [
                    'approve_team_expense',
                    'view_team_performance',
                    'manage_team_schedule',
                    'conduct_reviews'
                ]
            },
            
            # システム管理役割
            'system_admin': {
                'name': 'システム管理者',
                'parent': 'employee',
                'permissions': [
                    'manage_user_accounts',
                    'reset_passwords',
                    'view_audit_logs',
                    'manage_system_config'
                ]
            },
            'security_admin': {
                'name': 'セキュリティ管理者',
                'parent': 'employee',
                'permissions': [
                    'manage_security_policies',
                    'review_access_logs',
                    'investigate_incidents',
                    'manage_certificates'
                ]
            }
        }
    
    def _define_sod_rules(self):
        """職務分離ルールの定義"""
        return [
            {
                'name': '開発と本番デプロイの分離',
                'conflicting_roles': ['developer', 'devops_lead'],
                'exception_process': 'CTO承認が必要'
            },
            {
                'name': '財務承認の分離',
                'conflicting_roles': ['accountant', 'finance_manager'],
                'description': '請求書作成者と承認者は別人物である必要'
            },
            {
                'name': 'セキュリティ監査の独立性',
                'conflicting_roles': ['system_admin', 'security_admin'],
                'description': 'システム管理者は自身の行動を監査できない'
            },
            {
                'name': '人事データアクセスの制限',
                'conflicting_permissions': [
                    ['view_compensation_data', 'approve_payments'],
                    ['modify_employee_data', 'process_invoices']
                ],
                'description': '給与情報と支払い処理の分離'
            }
        ]
    
    def implement_role_assignment_workflow(self):
        """役割割り当てワークフロー"""
        
        class RoleAssignmentWorkflow:
            def __init__(self):
                self.approval_matrix = {
                    # role: [required_approvers]
                    'developer': ['tech_lead', 'hr_specialist'],
                    'senior_developer': ['tech_lead', 'manager'],
                    'tech_lead': ['cto', 'hr_manager'],
                    'devops_engineer': ['devops_lead', 'security_admin'],
                    'devops_lead': ['cto', 'security_admin'],
                    'finance_manager': ['cfo', 'ceo'],
                    'system_admin': ['cto', 'security_admin'],
                    'security_admin': ['ciso', 'ceo']
                }
            
            def request_role(self, user_id: str, requested_role: str, 
                           justification: str):
                """役割リクエストの作成"""
                
                request = {
                    'id': f'req_{int(time.time())}',
                    'user_id': user_id,
                    'requested_role': requested_role,
                    'justification': justification,
                    'status': 'pending',
                    'required_approvals': self.approval_matrix.get(
                        requested_role, ['manager']
                    ),
                    'approvals': [],
                    'created_at': time.time()
                }
                
                # SODチェック
                sod_violations = self.check_sod_violations(user_id, requested_role)
                if sod_violations:
                    request['sod_violations'] = sod_violations
                    request['required_approvals'].append('compliance_officer')
                
                return request
            
            def check_sod_violations(self, user_id: str, new_role: str):
                """職務分離違反のチェック"""
                current_roles = self.get_user_roles(user_id)
                violations = []
                
                for sod_rule in self.sod_rules:
                    if new_role in sod_rule['conflicting_roles']:
                        conflicts = set(current_roles) & set(sod_rule['conflicting_roles'])
                        if conflicts:
                            violations.append({
                                'rule': sod_rule['name'],
                                'conflicting_roles': list(conflicts)
                            })
                
                return violations
        
        return RoleAssignmentWorkflow()
    
    def generate_access_matrix_report(self):
        """アクセスマトリックスレポートの生成"""
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_users': 300,
            'total_roles': len(self.roles),
            'total_permissions': len(self._get_all_permissions()),
            'role_distribution': {},
            'critical_permissions': {},
            'sod_compliance': []
        }
        
        # 役割分布の分析
        for dept, info in self.departments.items():
            dept_roles = self._analyze_department_roles(dept)
            report['role_distribution'][dept] = {
                'employee_count': info['size'],
                'roles': dept_roles,
                'avg_permissions_per_user': self._calculate_avg_permissions(dept)
            }
        
        # 重要権限の保持者
        critical_perms = [
            'access_production_write',
            'approve_payments', 
            'modify_employee_data',
            'access_bank_accounts'
        ]
        
        for perm in critical_perms:
            holders = self._find_permission_holders(perm)
            report['critical_permissions'][perm] = {
                'holder_count': len(holders),
                'roles': holders,
                'last_review': '2024-03-01'
            }
        
        return report
```

### 実装のポイント

1. **階層的な役割設計**
   - 基本役割（employee）から継承
   - 部門特有の役割を定義
   - 権限の積み上げ方式

2. **職務分離の実装**
   - 相反する役割の定義
   - 例外承認プロセス
   - 自動違反検出

3. **承認ワークフロー**
   - 役割に応じた承認者
   - SOD違反時の追加承認
   - 監査証跡の保持

## 問題2：ABACポリシーの作成

### 医療記録システムのABACポリシー

```python
class MedicalRecordABACPolicies:
    """医療記録システムのABACポリシー実装"""
    
    def __init__(self):
        self.policies = []
        self._create_policies()
    
    def _create_policies(self):
        """ポリシーの作成"""
        
        # ポリシー1: 患者の自己記録アクセス
        self.policies.append({
            'id': 'patient_own_record',
            'description': '患者は自分の医療記録のみ閲覧可能',
            'priority': 10,
            'condition': """
                user['role'] == 'patient' and 
                user['patient_id'] == resource['patient_id'] and
                action in ['read', 'download']
            """,
            'effect': 'ALLOW'
        })
        
        # ポリシー2: 担当医のアクセス
        self.policies.append({
            'id': 'assigned_doctor_access',
            'description': '担当医は担当患者の記録を閲覧・編集可能',
            'priority': 20,
            'condition': """
                user['role'] == 'doctor' and
                resource['patient_id'] in user['assigned_patients'] and
                action in ['read', 'write', 'update'] and
                not resource.get('locked', False)
            """,
            'effect': 'ALLOW'
        })
        
        # ポリシー3: 診療時間外の制限
        self.policies.append({
            'id': 'after_hours_readonly',
            'description': '診療時間外は読み取りのみ',
            'priority': 30,
            'condition': """
                user['role'] in ['doctor', 'nurse'] and
                not in_time_range('08:00', '18:00') and
                action in ['write', 'update', 'delete']
            """,
            'effect': 'DENY'
        })
        
        # ポリシー4: 緊急時アクセス
        self.policies.append({
            'id': 'emergency_access',
            'description': '緊急時は任意の医師が閲覧可能',
            'priority': 40,
            'condition': """
                user['role'] == 'doctor' and
                env.get('emergency_mode', False) and
                action == 'read' and
                user['license_status'] == 'active'
            """,
            'effect': 'ALLOW',
            'obligations': ['log_emergency_access', 'notify_patient']
        })
        
        # ポリシー5: 看護師のアクセス
        self.policies.append({
            'id': 'nurse_access',
            'description': '看護師は担当病棟の患者記録を閲覧可能',
            'priority': 25,
            'condition': """
                user['role'] == 'nurse' and
                resource['ward'] == user['assigned_ward'] and
                action == 'read' and
                resource['record_type'] in ['vitals', 'medication', 'nursing_notes']
            """,
            'effect': 'ALLOW'
        })
        
        # ポリシー6: 機密記録の保護
        self.policies.append({
            'id': 'sensitive_record_protection',
            'description': '精神科・HIV等の機密記録は特別な権限が必要',
            'priority': 50,
            'condition': """
                resource.get('sensitivity_level', 'normal') == 'high' and
                not user.get('special_access_granted', False)
            """,
            'effect': 'DENY'
        })
        
        # ポリシー7: 記録の変更履歴
        self.policies.append({
            'id': 'audit_trail_requirement',
            'description': 'すべての変更操作は監査ログ必須',
            'priority': 5,
            'condition': """
                action in ['write', 'update', 'delete']
            """,
            'effect': 'ALLOW',
            'obligations': ['create_audit_log', 'capture_change_reason']
        })
        
        # ポリシー8: 部門間アクセス
        self.policies.append({
            'id': 'department_access',
            'description': '他科の医師も必要に応じてアクセス可能',
            'priority': 35,
            'condition': """
                user['role'] == 'doctor' and
                resource['patient_id'] in user.get('consultation_requests', []) and
                action == 'read' and
                in_time_range('08:00', '20:00')
            """,
            'effect': 'ALLOW',
            'obligations': ['notify_primary_doctor']
        })
    
    def create_policy_engine(self):
        """ポリシーエンジンの実装"""
        
        class MedicalPolicyEngine:
            def __init__(self, policies):
                self.policies = sorted(policies, key=lambda p: p['priority'], reverse=True)
                self.obligation_handlers = {
                    'log_emergency_access': self._log_emergency_access,
                    'notify_patient': self._notify_patient,
                    'create_audit_log': self._create_audit_log,
                    'capture_change_reason': self._capture_change_reason,
                    'notify_primary_doctor': self._notify_primary_doctor
                }
            
            def evaluate(self, context):
                """ポリシー評価"""
                
                applicable_policies = []
                obligations = []
                
                for policy in self.policies:
                    try:
                        # 安全な評価環境
                        eval_env = {
                            'user': context['user'],
                            'resource': context['resource'],
                            'action': context['action'],
                            'env': context.get('environment', {}),
                            'in_time_range': self._in_time_range,
                            'datetime': datetime
                        }
                        
                        # 条件評価
                        if eval(policy['condition'], {"__builtins__": {}}, eval_env):
                            applicable_policies.append(policy)
                            
                            # DENY が優先
                            if policy['effect'] == 'DENY':
                                return {
                                    'decision': 'DENY',
                                    'reason': policy['description'],
                                    'applicable_policies': [policy['id']]
                                }
                            
                            # 義務の収集
                            if 'obligations' in policy:
                                obligations.extend(policy['obligations'])
                    
                    except Exception as e:
                        # ポリシーエラーは安全側に倒す（DENY）
                        print(f"Policy evaluation error: {policy['id']} - {e}")
                        continue
                
                # ALLOW ポリシーがあるか
                allow_policies = [p for p in applicable_policies if p['effect'] == 'ALLOW']
                
                if allow_policies:
                    # 義務の実行
                    for obligation in set(obligations):
                        self._execute_obligation(obligation, context)
                    
                    return {
                        'decision': 'ALLOW',
                        'reason': allow_policies[0]['description'],
                        'applicable_policies': [p['id'] for p in allow_policies],
                        'obligations_executed': list(set(obligations))
                    }
                
                # デフォルトは拒否
                return {
                    'decision': 'DENY',
                    'reason': 'No applicable ALLOW policy',
                    'applicable_policies': []
                }
            
            def _in_time_range(self, start: str, end: str) -> bool:
                """時間範囲チェック"""
                current = datetime.now().time()
                start_time = datetime.strptime(start, '%H:%M').time()
                end_time = datetime.strptime(end, '%H:%M').time()
                return start_time <= current <= end_time
            
            def _execute_obligation(self, obligation: str, context: dict):
                """義務の実行"""
                if obligation in self.obligation_handlers:
                    self.obligation_handlers[obligation](context)
            
            def _log_emergency_access(self, context):
                """緊急アクセスのログ"""
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'access_type': 'EMERGENCY',
                    'user': context['user']['id'],
                    'patient': context['resource']['patient_id'],
                    'reason': context.get('emergency_reason', 'Not specified'),
                    'action': context['action']
                }
                # 特別な監査ログに記録
                self._write_to_emergency_log(log_entry)
            
            def _notify_patient(self, context):
                """患者への通知"""
                notification = {
                    'patient_id': context['resource']['patient_id'],
                    'message': f"緊急時アクセス: Dr. {context['user']['name']}が記録を参照しました",
                    'timestamp': datetime.now(),
                    'access_details': {
                        'doctor': context['user']['id'],
                        'accessed_sections': context.get('accessed_sections', ['全般'])
                    }
                }
                # 通知システムに送信
                self._send_notification(notification)
            
            def _create_audit_log(self, context):
                """監査ログの作成"""
                audit_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'user_id': context['user']['id'],
                    'user_role': context['user']['role'],
                    'action': context['action'],
                    'resource_type': 'medical_record',
                    'resource_id': context['resource']['id'],
                    'patient_id': context['resource']['patient_id'],
                    'ip_address': context.get('ip_address'),
                    'user_agent': context.get('user_agent')
                }
                # 改ざん防止のためのハッシュ
                audit_entry['hash'] = self._calculate_audit_hash(audit_entry)
                self._store_audit_log(audit_entry)
        
        return MedicalPolicyEngine(self.policies)
```

### テストケース

```python
def test_medical_abac_policies():
    """医療記録ABACポリシーのテスト"""
    
    engine = MedicalRecordABACPolicies().create_policy_engine()
    
    # テストケース1: 患者の自己記録アクセス
    context1 = {
        'user': {'role': 'patient', 'patient_id': 'P12345'},
        'resource': {'patient_id': 'P12345', 'type': 'medical_record'},
        'action': 'read'
    }
    result1 = engine.evaluate(context1)
    assert result1['decision'] == 'ALLOW'
    
    # テストケース2: 診療時間外の書き込み拒否
    context2 = {
        'user': {'role': 'doctor', 'assigned_patients': ['P12345']},
        'resource': {'patient_id': 'P12345'},
        'action': 'write',
        'environment': {'current_time': '21:00'}
    }
    result2 = engine.evaluate(context2)
    assert result2['decision'] == 'DENY'
    
    # テストケース3: 緊急時アクセス
    context3 = {
        'user': {'role': 'doctor', 'license_status': 'active'},
        'resource': {'patient_id': 'P99999'},
        'action': 'read',
        'environment': {'emergency_mode': True}
    }
    result3 = engine.evaluate(context3)
    assert result3['decision'] == 'ALLOW'
    assert 'log_emergency_access' in result3['obligations_executed']
```

## 問題3：最小権限の実装

### 既存システムへの最小権限適用計画

```python
class LeastPrivilegeMigrationPlan:
    """最小権限原則の段階的導入計画"""
    
    def __init__(self):
        self.phases = []
        self.metrics = {}
        self.risk_mitigation = {}
    
    def phase1_current_state_analysis(self):
        """フェーズ1: 現状分析"""
        
        analysis_plan = {
            'duration': '4 weeks',
            'activities': {
                'week1': {
                    'name': '権限インベントリ作成',
                    'tasks': [
                        'すべてのシステム権限の洗い出し',
                        'ユーザー/グループの権限マッピング',
                        '特権アカウントの特定',
                        'サービスアカウントの棚卸し'
                    ],
                    'deliverable': 'permission_inventory.xlsx'
                },
                'week2': {
                    'name': '利用状況分析',
                    'tasks': [
                        'アクセスログの収集（90日分）',
                        '実際に使用された権限の特定',
                        '未使用権限の識別',
                        'アクセスパターンの分析'
                    ],
                    'deliverable': 'usage_analysis_report.pdf'
                },
                'week3': {
                    'name': 'リスク評価',
                    'tasks': [
                        '過剰権限によるリスクの定量化',
                        '権限削減による業務影響の評価',
                        'クリティカルな権限の特定',
                        'コンプライアンス要件の確認'
                    ],
                    'deliverable': 'risk_assessment_matrix.xlsx'
                },
                'week4': {
                    'name': '削減計画策定',
                    'tasks': [
                        '権限削減の優先順位付け',
                        'ユーザーグループ別の影響分析',
                        '段階的削減スケジュール作成',
                        'ロールバック計画の準備'
                    ],
                    'deliverable': 'reduction_roadmap.pdf'
                }
            }
        }
        
        # 分析ツールの実装
        class PermissionAnalyzer:
            def analyze_current_permissions(self):
                """現在の権限を分析"""
                analysis = {
                    'total_users': 0,
                    'total_permissions': 0,
                    'overprivileged_users': [],
                    'unused_permissions': [],
                    'high_risk_combinations': []
                }
                
                # 実装例
                users = self.get_all_users()
                for user in users:
                    permissions = self.get_user_permissions(user)
                    used_permissions = self.get_used_permissions(user, days=90)
                    
                    unused = set(permissions) - set(used_permissions)
                    if len(unused) > len(permissions) * 0.5:  # 50%以上未使用
                        analysis['overprivileged_users'].append({
                            'user': user,
                            'total_permissions': len(permissions),
                            'unused_count': len(unused),
                            'risk_score': self.calculate_risk_score(unused)
                        })
                
                return analysis
        
        return analysis_plan
    
    def phase2_gradual_reduction(self):
        """フェーズ2: 段階的な権限削減"""
        
        reduction_waves = [
            {
                'wave': 1,
                'name': '低リスク権限の削減',
                'duration': '2 weeks',
                'target': 'unused_readonly_permissions',
                'approach': {
                    'identification': '90日間未使用の読み取り専用権限',
                    'notification': 'ユーザーへ2週間前に通知',
                    'reduction': '一括削除',
                    'rollback': '要求に応じて48時間以内に復元'
                },
                'expected_reduction': '30%'
            },
            {
                'wave': 2,
                'name': '中リスク権限の削減',
                'duration': '4 weeks',
                'target': 'unused_write_permissions',
                'approach': {
                    'identification': '60日間未使用の書き込み権限',
                    'notification': 'マネージャー承認を含む通知',
                    'reduction': '部門単位で段階実施',
                    'monitoring': '削除後2週間の集中監視'
                },
                'expected_reduction': '25%'
            },
            {
                'wave': 3,
                'name': '高リスク権限の再設計',
                'duration': '6 weeks',
                'target': 'admin_and_privileged_access',
                'approach': {
                    'identification': '管理者権限の細分化',
                    'design': 'Just-In-Time access導入',
                    'implementation': 'MFA必須化と時限的権限',
                    'training': '新プロセスのトレーニング実施'
                },
                'expected_reduction': '40%'
            }
        ]
        
        # 削減実行ツール
        class PermissionReducer:
            def __init__(self):
                self.reduction_log = []
                self.rollback_queue = []
            
            def execute_reduction(self, wave_config):
                """権限削減の実行"""
                affected_users = self.identify_affected_users(wave_config)
                
                for user in affected_users:
                    # 削減前のスナップショット
                    snapshot = self.create_permission_snapshot(user)
                    
                    # 権限削減
                    removed_permissions = self.remove_permissions(
                        user, 
                        wave_config['target']
                    )
                    
                    # ロールバック情報の保存
                    self.rollback_queue.append({
                        'user': user,
                        'snapshot': snapshot,
                        'removed': removed_permissions,
                        'timestamp': time.time(),
                        'expires': time.time() + (30 * 24 * 3600)  # 30日間保持
                    })
                    
                    # ログ記録
                    self.reduction_log.append({
                        'user': user,
                        'wave': wave_config['wave'],
                        'removed_count': len(removed_permissions),
                        'timestamp': time.time()
                    })
            
            def handle_permission_request(self, user, requested_permission):
                """権限リクエストの処理"""
                # 以前持っていた権限かチェック
                previous_permission = self.check_previous_permission(
                    user, 
                    requested_permission
                )
                
                if previous_permission:
                    # 迅速な復元プロセス
                    return self.quick_restore(user, requested_permission)
                else:
                    # 新規権限申請プロセス
                    return self.new_permission_request(user, requested_permission)
        
        return reduction_waves
    
    def phase3_continuous_optimization(self):
        """フェーズ3: 継続的な最適化"""
        
        optimization_framework = {
            'automated_reviews': {
                'frequency': 'monthly',
                'criteria': [
                    'Unused permissions > 30 days',
                    'Anomalous access patterns',
                    'Role membership changes',
                    'Departed user cleanup'
                ],
                'actions': [
                    'Automatic notification',
                    'Manager approval required',
                    'Grace period: 14 days',
                    'Automatic removal if no response'
                ]
            },
            
            'just_in_time_expansion': {
                'implementation': [
                    'Break glass procedures for emergencies',
                    'Time-limited elevations (default: 8 hours)',
                    'Approval workflows based on risk',
                    'Automatic de-provisioning'
                ]
            },
            
            'metrics_and_monitoring': {
                'kpis': [
                    'Average permissions per user',
                    'Unused permission ratio',
                    'Time to provision/deprovision',
                    'Security incidents related to excess privileges'
                ],
                'dashboards': [
                    'Real-time privilege usage',
                    'Compliance status',
                    'Risk heat map',
                    'Trend analysis'
                ]
            }
        }
        
        return optimization_framework
    
    def create_communication_plan(self):
        """コミュニケーション計画"""
        
        return {
            'stakeholders': {
                'executives': {
                    'message': 'リスク削減とコンプライアンス向上',
                    'frequency': 'Monthly progress reports',
                    'format': 'Executive dashboard'
                },
                'managers': {
                    'message': 'チーム影響と承認プロセス',
                    'frequency': 'Bi-weekly updates',
                    'format': 'Department meetings'
                },
                'end_users': {
                    'message': '変更内容と利用可能なサポート',
                    'frequency': 'As needed + 2 weeks notice',
                    'format': 'Email + Portal notifications'
                },
                'it_team': {
                    'message': '技術的実装とサポート手順',
                    'frequency': 'Weekly sync',
                    'format': 'Technical documentation + Training'
                }
            },
            
            'channels': [
                'Email campaigns',
                'Intranet announcements',
                'Team meetings',
                'Help desk notices',
                'Training sessions'
            ],
            
            'feedback_mechanism': {
                'collection': [
                    'Dedicated email address',
                    'Feedback form',
                    'Office hours',
                    'Anonymous suggestions'
                ],
                'response_sla': '48 hours',
                'escalation_path': 'Manager -> IT Security -> CISO'
            }
        }
```

## 問題4：認可パフォーマンスの最適化

### 高性能認可システムの設計

```python
import asyncio
from typing import Dict, Set, Optional, Tuple
import hashlib
import pickle
from collections import OrderedDict
import aioredis

class HighPerformanceAuthorizationSystem:
    """1000 req/s, 10ms以下のレスポンスタイムを実現する認可システム"""
    
    def __init__(self):
        self.static_cache = StaticPermissionCache()
        self.dynamic_evaluator = DynamicPolicyEvaluator()
        self.request_router = AuthorizationRouter()
        self.monitoring = PerformanceMonitor()
    
    async def initialize(self):
        """システムの初期化"""
        # Redis接続プール
        self.redis_pool = await aioredis.create_redis_pool(
            'redis://localhost',
            minsize=10,
            maxsize=50
        )
        
        # 静的権限のプリロード
        await self.static_cache.preload_permissions()
        
        # ウォームアップ
        await self._warmup_caches()
    
    class StaticPermissionCache:
        """静的権限の高速キャッシュ"""
        
        def __init__(self):
            # 多層キャッシュ構造
            self.l1_cache = {}  # プロセスメモリ（最速）
            self.l2_cache = None  # Redis（共有）
            self.bloom_filters = {}  # 否定的キャッシュ
            
        async def check_permission(self, user_id: str, permission: str) -> Optional[bool]:
            """静的権限チェック（目標: <1ms）"""
            
            # L1キャッシュ（~0.01ms）
            cache_key = f"{user_id}:{permission}"
            if cache_key in self.l1_cache:
                self.metrics.l1_hits += 1
                return self.l1_cache[cache_key]
            
            # Bloom filterで明らかなNOを高速判定（~0.05ms）
            if not self._bloom_filter_check(user_id, permission):
                self.metrics.bloom_filter_hits += 1
                return False
            
            # L2キャッシュ（~1ms）
            result = await self._check_l2_cache(cache_key)
            if result is not None:
                self.metrics.l2_hits += 1
                self._update_l1_cache(cache_key, result)
                return result
            
            # キャッシュミス
            return None
        
        def _bloom_filter_check(self, user_id: str, permission: str) -> bool:
            """Bloom filterによる事前フィルタリング"""
            if user_id not in self.bloom_filters:
                return True  # フィルタがない場合は通す
            
            bf = self.bloom_filters[user_id]
            return bf.might_contain(permission)
        
        async def preload_permissions(self):
            """権限の事前ロード"""
            # バッチでユーザー権限を取得
            batch_size = 1000
            
            for user_batch in self._get_user_batches(batch_size):
                permissions_map = await self._load_user_permissions_batch(user_batch)
                
                for user_id, permissions in permissions_map.items():
                    # Bloom filter作成
                    bf = BloomFilter(capacity=len(permissions) * 2, error_rate=0.01)
                    for perm in permissions:
                        bf.add(perm)
                        # L1キャッシュに追加
                        self.l1_cache[f"{user_id}:{perm}"] = True
                    
                    self.bloom_filters[user_id] = bf
    
    class DynamicPolicyEvaluator:
        """動的ポリシー評価器"""
        
        def __init__(self):
            self.policy_cache = LRUCache(maxsize=10000)
            self.compiled_policies = {}
            self.context_cache = TTLCache(maxsize=5000, ttl=300)  # 5分
            
        async def evaluate(self, request: Dict) -> Tuple[bool, str]:
            """動的ポリシー評価（目標: <10ms for 20% of requests）"""
            
            # キャッシュキー生成
            cache_key = self._generate_cache_key(request)
            
            # キャッシュチェック（~0.1ms）
            cached = self.policy_cache.get(cache_key)
            if cached and not self._is_expired(cached):
                return cached['result'], cached['reason']
            
            # コンテキスト収集（並列化）
            context = await self._gather_context_parallel(request)
            
            # ポリシー評価（最適化済み）
            result, reason = await self._evaluate_policies_optimized(context)
            
            # 結果をキャッシュ
            self.policy_cache[cache_key] = {
                'result': result,
                'reason': reason,
                'timestamp': time.time(),
                'ttl': self._determine_cache_ttl(context)
            }
            
            return result, reason
        
        async def _gather_context_parallel(self, request: Dict) -> Dict:
            """並列コンテキスト収集"""
            
            # 必要なコンテキストを並列で取得
            tasks = [
                self._get_user_attributes(request['user_id']),
                self._get_resource_attributes(request['resource_id']),
                self._get_environment_context(),
                self._get_risk_score(request)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            return {
                'user': results[0] if not isinstance(results[0], Exception) else {},
                'resource': results[1] if not isinstance(results[1], Exception) else {},
                'environment': results[2] if not isinstance(results[2], Exception) else {},
                'risk': results[3] if not isinstance(results[3], Exception) else {'score': 0}
            }
        
        async def _evaluate_policies_optimized(self, context: Dict) -> Tuple[bool, str]:
            """最適化されたポリシー評価"""
            
            # ポリシーを優先度でソート済み
            for policy in self.compiled_policies.values():
                try:
                    # JITコンパイルされた条件を評価
                    if policy['compiled_condition'](context):
                        if policy['effect'] == 'DENY':
                            return False, policy['reason']
                        elif policy['effect'] == 'ALLOW':
                            return True, policy['reason']
                except Exception as e:
                    # エラーは安全側に倒す
                    self.logger.error(f"Policy evaluation error: {e}")
                    continue
            
            return False, "No matching policy"
    
    class AuthorizationRouter:
        """リクエストルーティングと負荷分散"""
        
        def __init__(self):
            self.static_threshold = 0.8  # 80%は静的で処理
            self.circuit_breaker = CircuitBreaker()
            
        async def route_request(self, request: Dict) -> Tuple[bool, str, Dict]:
            """リクエストのルーティング"""
            
            start_time = time.time()
            metrics = {'path': None, 'latency': 0}
            
            # 静的チェックで解決可能か判定
            if self._is_static_checkable(request):
                # 静的パス（高速）
                result = await self.static_cache.check_permission(
                    request['user_id'],
                    request['permission']
                )
                
                if result is not None:
                    metrics['path'] = 'static'
                    metrics['latency'] = (time.time() - start_time) * 1000
                    return result, "Static permission", metrics
            
            # 動的評価が必要
            if self.circuit_breaker.is_open():
                # サーキットブレーカーが開いている場合は失敗
                return False, "System overloaded", {'path': 'circuit_breaker'}
            
            try:
                result, reason = await asyncio.wait_for(
                    self.dynamic_evaluator.evaluate(request),
                    timeout=0.01  # 10msタイムアウト
                )
                
                metrics['path'] = 'dynamic'
                metrics['latency'] = (time.time() - start_time) * 1000
                
                return result, reason, metrics
                
            except asyncio.TimeoutError:
                self.circuit_breaker.record_failure()
                return False, "Evaluation timeout", {'path': 'timeout'}
    
    def create_benchmarking_suite(self):
        """ベンチマーキングスイート"""
        
        class AuthorizationBenchmark:
            def __init__(self, system):
                self.system = system
                self.results = {}
            
            async def run_benchmark(self):
                """包括的なベンチマークを実行"""
                
                print("Starting authorization system benchmark...")
                
                # ウォームアップ
                await self._warmup(1000)
                
                # テストシナリオ
                scenarios = [
                    {
                        'name': 'Static Only',
                        'static_ratio': 1.0,
                        'target_rps': 1000,
                        'duration': 60
                    },
                    {
                        'name': 'Mixed Load (80/20)',
                        'static_ratio': 0.8,
                        'target_rps': 1000,
                        'duration': 60
                    },
                    {
                        'name': 'Heavy Dynamic',
                        'static_ratio': 0.5,
                        'target_rps': 1000,
                        'duration': 60
                    }
                ]
                
                for scenario in scenarios:
                    result = await self._run_scenario(scenario)
                    self.results[scenario['name']] = result
                    self._print_results(scenario['name'], result)
            
            async def _run_scenario(self, scenario):
                """シナリオの実行"""
                
                start_time = time.time()
                request_count = 0
                latencies = []
                errors = 0
                
                # 並行リクエスト生成
                tasks = []
                for _ in range(scenario['target_rps']):
                    task = asyncio.create_task(
                        self._send_request(scenario['static_ratio'])
                    )
                    tasks.append(task)
                    
                    # レート制御
                    await asyncio.sleep(1.0 / scenario['target_rps'])
                    
                    if time.time() - start_time > scenario['duration']:
                        break
                
                # 結果収集
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, Exception):
                        errors += 1
                    else:
                        latencies.append(result['latency'])
                        request_count += 1
                
                return {
                    'request_count': request_count,
                    'errors': errors,
                    'avg_latency': np.mean(latencies),
                    'p50_latency': np.percentile(latencies, 50),
                    'p95_latency': np.percentile(latencies, 95),
                    'p99_latency': np.percentile(latencies, 99),
                    'throughput': request_count / scenario['duration']
                }
        
        return AuthorizationBenchmark(self)
```

### 最適化テクニックまとめ

1. **多層キャッシング**
   - L1: プロセスメモリ（<0.01ms）
   - L2: Redis（<1ms）
   - Bloom Filter: 否定的キャッシュ

2. **並列処理**
   - コンテキスト収集の並列化
   - 非同期I/O活用

3. **回路ブレーカー**
   - 過負荷時の高速失敗
   - システム保護

4. **JITコンパイル**
   - ポリシー条件の事前コンパイル
   - 評価の高速化

## 問題5：認可モデルの移行

### ACLからRBACへの移行計画

```python
class ACLToRBACMigration:
    """ACLベースシステムからRBACへの安全な移行"""
    
    def __init__(self):
        self.migration_phases = []
        self.rollback_points = []
        self.validation_rules = []
    
    def phase1_analysis_and_role_extraction(self):
        """フェーズ1: ACL分析と役割抽出"""
        
        class ACLAnalyzer:
            def __init__(self):
                self.acl_patterns = {}
                self.suggested_roles = []
                
            def analyze_acl_patterns(self, acl_data):
                """ACLパターンの分析"""
                
                # ユーザーグループの類似性分析
                user_permission_matrix = self._build_permission_matrix(acl_data)
                
                # クラスタリングによる役割候補の抽出
                from sklearn.cluster import DBSCAN
                
                clustering = DBSCAN(eps=0.3, min_samples=5)
                clusters = clustering.fit_predict(user_permission_matrix)
                
                # 各クラスターを役割候補として分析
                for cluster_id in set(clusters):
                    if cluster_id == -1:  # ノイズ
                        continue
                    
                    cluster_users = [
                        user for user, cluster in zip(users, clusters) 
                        if cluster == cluster_id
                    ]
                    
                    # 共通権限の抽出
                    common_permissions = self._extract_common_permissions(
                        cluster_users, 
                        threshold=0.8  # 80%以上が持つ権限
                    )
                    
                    suggested_role = {
                        'name': f'role_cluster_{cluster_id}',
                        'permissions': common_permissions,
                        'users': cluster_users,
                        'confidence': self._calculate_confidence(cluster_users, common_permissions)
                    }
                    
                    self.suggested_roles.append(suggested_role)
                
                return self.suggested_roles
            
            def generate_role_mapping_report(self):
                """役割マッピングレポートの生成"""
                
                report = {
                    'analysis_date': datetime.now(),
                    'total_users': len(self.all_users),
                    'total_permissions': len(self.all_permissions),
                    'suggested_roles': []
                }
                
                for role in self.suggested_roles:
                    role_analysis = {
                        'suggested_name': role['name'],
                        'permission_count': len(role['permissions']),
                        'user_count': len(role['users']),
                        'coverage': len(role['users']) / len(self.all_users),
                        'permission_reduction': 1 - (len(role['permissions']) / 
                                                   self._avg_user_permissions()),
                        'sample_users': role['users'][:5],
                        'key_permissions': role['permissions'][:10]
                    }
                    
                    report['suggested_roles'].append(role_analysis)
                
                return report
        
        return ACLAnalyzer()
    
    def phase2_role_design_and_validation(self):
        """フェーズ2: 役割設計と検証"""
        
        validation_framework = {
            'coverage_test': {
                'description': '既存の全権限がRBACでカバーされるか',
                'implementation': self._validate_permission_coverage,
                'threshold': 1.0  # 100%カバレッジ必須
            },
            
            'granularity_test': {
                'description': '役割が適切な粒度か',
                'implementation': self._validate_role_granularity,
                'criteria': {
                    'min_users_per_role': 5,
                    'max_permissions_per_role': 50,
                    'max_role_overlap': 0.3
                }
            },
            
            'security_test': {
                'description': 'セキュリティが低下していないか',
                'implementation': self._validate_security_posture,
                'checks': [
                    'No privilege escalation',
                    'Maintains separation of duties',
                    'No unauthorized access expansion'
                ]
            }
        }
        
        def _validate_permission_coverage(self, old_acl, new_rbac):
            """権限カバレッジの検証"""
            
            uncovered_permissions = []
            
            for user in old_acl.users:
                old_permissions = set(old_acl.get_user_permissions(user))
                new_permissions = set(new_rbac.get_user_permissions(user))
                
                missing = old_permissions - new_permissions
                extra = new_permissions - old_permissions
                
                if missing:
                    uncovered_permissions.append({
                        'user': user,
                        'missing': list(missing),
                        'severity': self._assess_permission_criticality(missing)
                    })
                
                if extra:
                    # 追加権限は要注意
                    self.warnings.append({
                        'user': user,
                        'extra_permissions': list(extra),
                        'risk': 'Potential over-provisioning'
                    })
            
            return len(uncovered_permissions) == 0, uncovered_permissions
        
        return validation_framework
    
    def phase3_parallel_implementation(self):
        """フェーズ3: 並行実装"""
        
        class ParallelAuthSystem:
            """ACLとRBACを並行実行する認可システム"""
            
            def __init__(self, acl_system, rbac_system):
                self.acl = acl_system
                self.rbac = rbac_system
                self.mode = 'shadow'  # shadow, dual, rbac_primary, rbac_only
                self.discrepancy_log = []
                
            async def check_authorization(self, request):
                """並行認可チェック"""
                
                if self.mode == 'shadow':
                    # ACLが主、RBACは影で実行
                    acl_result = await self.acl.check(request)
                    rbac_result = await self.rbac.check(request)
                    
                    if acl_result != rbac_result:
                        self._log_discrepancy(request, acl_result, rbac_result)
                    
                    return acl_result
                
                elif self.mode == 'dual':
                    # 両方実行して安全な方を選択
                    acl_result = await self.acl.check(request)
                    rbac_result = await self.rbac.check(request)
                    
                    if acl_result != rbac_result:
                        self._log_discrepancy(request, acl_result, rbac_result)
                        # 移行期間中は許可的に（どちらかがOKならOK）
                        return acl_result or rbac_result
                    
                    return acl_result
                
                elif self.mode == 'rbac_primary':
                    # RBACが主、ACLは監査のみ
                    rbac_result = await self.rbac.check(request)
                    
                    # 非同期で差分チェック
                    asyncio.create_task(self._audit_check(request, rbac_result))
                    
                    return rbac_result
                
                else:  # rbac_only
                    return await self.rbac.check(request)
            
            def analyze_discrepancies(self):
                """差異分析レポート"""
                
                analysis = {
                    'total_requests': len(self.all_requests),
                    'discrepancy_count': len(self.discrepancy_log),
                    'discrepancy_rate': len(self.discrepancy_log) / len(self.all_requests),
                    'patterns': {}
                }
                
                # パターン分析
                for disc in self.discrepancy_log:
                    pattern = self._identify_pattern(disc)
                    if pattern not in analysis['patterns']:
                        analysis['patterns'][pattern] = {
                            'count': 0,
                            'examples': []
                        }
                    
                    analysis['patterns'][pattern]['count'] += 1
                    if len(analysis['patterns'][pattern]['examples']) < 5:
                        analysis['patterns'][pattern]['examples'].append(disc)
                
                return analysis
        
        return ParallelAuthSystem
    
    def phase4_cutover_and_validation(self):
        """フェーズ4: 切り替えと検証"""
        
        cutover_plan = {
            'pre_cutover_checklist': [
                {
                    'item': 'Discrepancy rate < 0.1%',
                    'verification': 'analyze_last_7_days_logs()',
                    'required': True
                },
                {
                    'item': 'Performance metrics stable',
                    'verification': 'check_latency_p99() < baseline * 1.1',
                    'required': True
                },
                {
                    'item': 'All critical users migrated',
                    'verification': 'verify_vip_users_rbac_ready()',
                    'required': True
                },
                {
                    'item': 'Rollback procedure tested',
                    'verification': 'rollback_test_successful()',
                    'required': True
                }
            ],
            
            'cutover_sequence': [
                {
                    'step': 1,
                    'action': 'Enable RBAC primary mode',
                    'rollback': 'Switch back to dual mode',
                    'validation': 'Monitor error rate for 1 hour',
                    'success_criteria': 'Error rate < 0.01%'
                },
                {
                    'step': 2,
                    'action': 'Disable ACL writes',
                    'rollback': 'Re-enable ACL writes',
                    'validation': 'Verify all permission changes via RBAC',
                    'success_criteria': 'No failed permission updates'
                },
                {
                    'step': 3,
                    'action': 'Switch to RBAC only mode',
                    'rollback': 'Re-enable parallel mode',
                    'validation': 'Full system test',
                    'success_criteria': 'All integration tests pass'
                },
                {
                    'step': 4,
                    'action': 'Decommission ACL system',
                    'rollback': 'Keep ACL data for 90 days',
                    'validation': 'Final audit comparison',
                    'success_criteria': 'No access issues reported'
                }
            ],
            
            'post_cutover_monitoring': {
                'duration': '30 days',
                'metrics': [
                    'Authorization latency',
                    'Permission denied rate',
                    'User complaints',
                    'System errors'
                ],
                'alerts': {
                    'latency_spike': 'p99 > baseline * 1.5',
                    'error_spike': 'error_rate > 0.1%',
                    'user_complaints': 'tickets > normal * 2'
                }
            }
        }
        
        return cutover_plan
```

## チャレンジ問題：Zero Trust認可の設計

### Zero Trustアーキテクチャに基づく認可システム

```python
class ZeroTrustAuthorizationSystem:
    """Zero Trust原則に基づく次世代認可システム"""
    
    def __init__(self):
        self.trust_engine = ContinuousTrustEngine()
        self.policy_engine = DynamicPolicyEngine()
        self.micro_segmentation = MicroSegmentationController()
        self.audit_system = ComprehensiveAuditSystem()
    
    class ContinuousTrustEngine:
        """継続的な信頼性評価エンジン"""
        
        def __init__(self):
            self.trust_factors = {
                'device_health': 0.2,
                'user_behavior': 0.3,
                'network_security': 0.2,
                'authentication_strength': 0.2,
                'time_and_location': 0.1
            }
            self.ml_model = self._load_anomaly_detection_model()
        
        async def calculate_trust_score(self, context):
            """リアルタイムの信頼スコア計算"""
            
            scores = {}
            
            # デバイスヘルス
            scores['device_health'] = await self._assess_device_health(
                context['device_id']
            )
            
            # ユーザー行動分析
            scores['user_behavior'] = await self._analyze_user_behavior(
                context['user_id'],
                context['recent_actions']
            )
            
            # ネットワークセキュリティ
            scores['network_security'] = await self._evaluate_network_security(
                context['source_ip'],
                context['network_path']
            )
            
            # 認証強度
            scores['authentication_strength'] = self._calculate_auth_strength(
                context['auth_methods'],
                context['session_age']
            )
            
            # 時間と場所
            scores['time_and_location'] = self._assess_spatiotemporal_risk(
                context['timestamp'],
                context['geolocation']
            )
            
            # 重み付き平均
            trust_score = sum(
                scores[factor] * weight 
                for factor, weight in self.trust_factors.items()
            )
            
            # 異常検知
            anomaly_score = self.ml_model.predict_anomaly(context)
            
            # 最終スコア（異常があれば大幅減点）
            final_score = trust_score * (1 - anomaly_score)
            
            return {
                'trust_score': final_score,
                'factors': scores,
                'anomaly_detected': anomaly_score > 0.7,
                'timestamp': time.time()
            }
        
        async def _assess_device_health(self, device_id):
            """デバイスの健全性評価"""
            
            checks = {
                'os_updated': await self._check_os_version(device_id),
                'antivirus_active': await self._check_antivirus(device_id),
                'firewall_enabled': await self._check_firewall(device_id),
                'disk_encrypted': await self._check_encryption(device_id),
                'patches_current': await self._check_patches(device_id),
                'no_malware': await self._scan_for_threats(device_id)
            }
            
            # コンプライアンススコア計算
            compliance_score = sum(checks.values()) / len(checks)
            
            # デバイスの信頼性履歴
            history_score = await self._get_device_trust_history(device_id)
            
            return compliance_score * 0.7 + history_score * 0.3
    
    class DynamicPolicyEngine:
        """動的ポリシーエンジン"""
        
        def __init__(self):
            self.policies = self._load_zero_trust_policies()
            self.context_enrichers = []
            
        def create_zero_trust_policies(self):
            """Zero Trust ポリシーの定義"""
            
            policies = [
                {
                    'id': 'continuous_verification',
                    'name': '継続的検証の要求',
                    'condition': """
                    # 信頼スコアが閾値を下回ったら再認証
                    if context['trust_score'] < 0.6:
                        require_reauthentication()
                    
                    # 高リスク操作には追加検証
                    if context['action_risk_level'] == 'high' and context['trust_score'] < 0.8:
                        require_mfa()
                    """,
                    'effect': 'CONDITIONAL_ALLOW'
                },
                
                {
                    'id': 'least_privilege_enforcement',
                    'name': '最小権限の動的適用',
                    'condition': """
                    # 信頼レベルに応じて権限を制限
                    allowed_permissions = calculate_allowed_permissions(
                        base_permissions=user['role_permissions'],
                        trust_score=context['trust_score'],
                        resource_sensitivity=resource['classification']
                    )
                    
                    return requested_permission in allowed_permissions
                    """,
                    'effect': 'DYNAMIC_ALLOW'
                },
                
                {
                    'id': 'micro_segmentation',
                    'name': 'マイクロセグメンテーション',
                    'condition': """
                    # ネットワークセグメント間のアクセス制御
                    source_segment = get_network_segment(context['source_ip'])
                    target_segment = get_network_segment(resource['location'])
                    
                    if not is_allowed_segment_access(source_segment, target_segment):
                        return False
                    
                    # East-West トラフィックの検査
                    return inspect_lateral_movement(context)
                    """,
                    'effect': 'ALLOW'
                },
                
                {
                    'id': 'data_centric_security',
                    'name': 'データ中心のセキュリティ',
                    'condition': """
                    # データの分類に基づくアクセス制御
                    data_classification = resource['data_classification']
                    user_clearance = user['clearance_level']
                    
                    if not has_clearance(user_clearance, data_classification):
                        return False
                    
                    # データの利用目的チェック
                    if not validate_purpose(context['stated_purpose'], resource['allowed_purposes']):
                        return False
                    
                    # データの移動制限
                    if is_data_export(context['action']) and not user['export_authorized']:
                        return False
                    
                    return True
                    """,
                    'effect': 'ALLOW'
                }
            ]
            
            return policies
    
    class MicroSegmentationController:
        """マイクロセグメンテーション制御"""
        
        def __init__(self):
            self.segments = {}
            self.policies = {}
            self.sdn_controller = SDNController()
        
        def define_segments(self):
            """セグメントの定義"""
            
            segments = {
                'user_workstations': {
                    'cidr': '10.1.0.0/16',
                    'trust_level': 'low',
                    'allowed_services': ['web', 'email'],
                    'inspection_level': 'full'
                },
                
                'application_tier': {
                    'cidr': '10.2.0.0/16',
                    'trust_level': 'medium',
                    'allowed_services': ['api', 'database_client'],
                    'inspection_level': 'moderate'
                },
                
                'database_tier': {
                    'cidr': '10.3.0.0/16',
                    'trust_level': 'high',
                    'allowed_services': ['database'],
                    'inspection_level': 'minimal',
                    'access_requirements': ['mfa', 'privileged_account']
                },
                
                'dmz': {
                    'cidr': '10.4.0.0/16',
                    'trust_level': 'untrusted',
                    'allowed_services': ['public_web'],
                    'inspection_level': 'paranoid'
                }
            }
            
            return segments
        
        async def enforce_segmentation(self, source, destination, context):
            """セグメンテーションの実施"""
            
            source_segment = self._identify_segment(source)
            dest_segment = self._identify_segment(destination)
            
            # セグメント間ポリシーチェック
            policy = self._get_segment_policy(source_segment, dest_segment)
            
            if not policy:
                # デフォルト拒否
                return {
                    'allowed': False,
                    'reason': 'No policy defined for segment pair'
                }
            
            # 追加の検証
            validations = []
            
            # 時間ベースアクセス
            if 'time_restrictions' in policy:
                validations.append(
                    self._check_time_restrictions(policy['time_restrictions'])
                )
            
            # プロトコル検査
            if 'allowed_protocols' in policy:
                validations.append(
                    context['protocol'] in policy['allowed_protocols']
                )
            
            # ペイロード検査
            if policy.get('deep_packet_inspection', False):
                validations.append(
                    await self._inspect_payload(context['payload'])
                )
            
            # すべての検証に合格した場合のみ許可
            return {
                'allowed': all(validations),
                'applied_policy': policy['id'],
                'validations': validations
            }
    
    class ComprehensiveAuditSystem:
        """包括的な監査システム"""
        
        def __init__(self):
            self.audit_pipeline = self._create_audit_pipeline()
            self.compliance_frameworks = ['SOC2', 'ISO27001', 'NIST']
            
        def _create_audit_pipeline(self):
            """監査パイプラインの構築"""
            
            return {
                'collection': {
                    'sources': [
                        'authorization_decisions',
                        'trust_score_changes',
                        'policy_evaluations',
                        'network_flows',
                        'data_access_logs'
                    ],
                    'enrichment': [
                        'user_context',
                        'asset_information',
                        'threat_intelligence'
                    ]
                },
                
                'processing': {
                    'real_time_analysis': [
                        'anomaly_detection',
                        'threat_correlation',
                        'compliance_violations'
                    ],
                    'storage': {
                        'hot_storage': '7_days',
                        'warm_storage': '90_days',
                        'cold_storage': '7_years'
                    }
                },
                
                'reporting': {
                    'dashboards': [
                        'executive_overview',
                        'security_operations',
                        'compliance_status'
                    ],
                    'alerts': {
                        'high_priority': ['unauthorized_access', 'data_exfiltration'],
                        'medium_priority': ['policy_violations', 'trust_degradation'],
                        'low_priority': ['configuration_drift', 'maintenance_required']
                    }
                }
            }
        
        async def generate_compliance_report(self, framework='SOC2'):
            """コンプライアンスレポートの生成"""
            
            report = {
                'framework': framework,
                'period': 'last_quarter',
                'executive_summary': {},
                'detailed_findings': {},
                'recommendations': []
            }
            
            # 各コントロールの評価
            controls = self._get_framework_controls(framework)
            
            for control in controls:
                evaluation = await self._evaluate_control(control)
                
                report['detailed_findings'][control['id']] = {
                    'description': control['description'],
                    'status': evaluation['status'],
                    'evidence': evaluation['evidence'],
                    'gaps': evaluation['gaps'],
                    'remediation': evaluation['remediation']
                }
            
            # サマリー生成
            report['executive_summary'] = {
                'overall_compliance': self._calculate_compliance_score(report),
                'critical_findings': self._extract_critical_findings(report),
                'improvement_areas': self._identify_improvements(report)
            }
            
            return report
    
    def implement_zero_trust_flow(self):
        """Zero Trust フローの実装"""
        
        async def authorize_request(self, request):
            """Zero Trust 認可フロー"""
            
            # ステップ1: 継続的な信頼性評価
            trust_result = await self.trust_engine.calculate_trust_score(request)
            
            if trust_result['trust_score'] < 0.3:
                # 信頼スコアが低すぎる場合は即座に拒否
                await self.audit_system.log_high_risk_denial(request, trust_result)
                return {
                    'decision': 'DENY',
                    'reason': 'Insufficient trust score',
                    'required_action': 'reauthenticate'
                }
            
            # ステップ2: コンテキストの強化
            enriched_context = await self._enrich_context(request, trust_result)
            
            # ステップ3: 動的ポリシー評価
            policy_result = await self.policy_engine.evaluate(enriched_context)
            
            # ステップ4: マイクロセグメンテーションチェック
            if policy_result['decision'] == 'ALLOW':
                segment_result = await self.micro_segmentation.enforce_segmentation(
                    request['source'],
                    request['destination'],
                    enriched_context
                )
                
                if not segment_result['allowed']:
                    policy_result['decision'] = 'DENY'
                    policy_result['reason'] = segment_result['reason']
            
            # ステップ5: 条件付き許可の処理
            if policy_result['decision'] == 'CONDITIONAL_ALLOW':
                conditions_met = await self._verify_conditions(
                    policy_result['conditions'],
                    enriched_context
                )
                
                if not conditions_met:
                    policy_result['decision'] = 'DENY'
                    policy_result['reason'] = 'Conditions not met'
            
            # ステップ6: 包括的な監査
            await self.audit_system.log_authorization_decision(
                request,
                trust_result,
                policy_result,
                enriched_context
            )
            
            # ステップ7: 継続的なモニタリングの設定
            if policy_result['decision'] == 'ALLOW':
                await self._setup_continuous_monitoring(
                    request['session_id'],
                    trust_result['trust_score']
                )
            
            return policy_result
```

### Zero Trust実装のまとめ

1. **継続的検証**
   - リアルタイムの信頼性評価
   - 動的な権限調整
   - セッション中の再認証

2. **最小権限の徹底**
   - Just-In-Time アクセス
   - 条件付き権限付与
   - 自動権限失効

3. **マイクロセグメンテーション**
   - ネットワークレベルの分離
   - East-Westトラフィックの検査
   - セグメント間ポリシー

4. **包括的な可視性**
   - 全アクセスの記録
   - リアルタイム分析
   - コンプライアンス自動化