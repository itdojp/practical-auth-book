---
layout: book
title: "第3章 認可の基礎"
---

# 第3章 認可の基礎

## なぜこの章が重要か

「ログインできた」ことと「何でもできる」ことは全く別の問題です。適切な認可設計により、システムの柔軟性とセキュリティを両立できます。この章では、認可モデルの本質を理解し、組織の成長に対応できる権限管理システムの構築方法を学びます。実装を通じて、セキュアで保守性の高い認可システムを設計する力を身につけましょう。

## 3.1 アクセス制御の基本原則 - なぜ最小権限が重要なのか

### 3.1.1 認可の本質的な役割

認証が「誰であるか」を確認するのに対し、認可は「何ができるか」を決定します。この区別が曖昧だと、深刻なセキュリティホールが生まれます。

**実例：ある金融システムの事故**

2022年、ある証券会社で発生した内部不正事件を見てみましょう：

```
事件の概要：
- 一般職員が顧客の投資情報に不正アクセス
- 6ヶ月間にわたり、5000件以上の顧客データを閲覧
- 情報を外部に売却し、1億円以上の被害

根本原因：
- 「ログインできる = すべてのデータが見られる」という設計
- 職務に関係ないデータへのアクセス制限なし
- アクセスログの監視不足
```

この事件は、認証だけでは不十分であることを明確に示しています。

### 3.1.2 最小権限の原則（Principle of Least Privilege）

#### なぜ最小権限が必要なのか

```python
class SecurityIncidentSimulation:
    """最小権限の重要性をシミュレーション"""
    
    def simulate_without_least_privilege(self):
        """最小権限なしの場合の被害想定"""
        compromised_account = {
            'type': 'regular_employee',
            'default_permissions': ['read_all', 'write_all', 'delete_all']
        }
        
        potential_damage = {
            'data_breach': 'ALL customer records accessible',
            'data_manipulation': 'Financial records can be altered',
            'service_disruption': 'Critical services can be stopped',
            'lateral_movement': 'Access to other systems possible'
        }
        
        return {
            'impact_scope': 'ENTIRE ORGANIZATION',
            'recovery_time': 'WEEKS to MONTHS',
            'financial_loss': 'MILLIONS'
        }
    
    def simulate_with_least_privilege(self):
        """最小権限ありの場合の被害限定"""
        compromised_account = {
            'type': 'regular_employee',
            'actual_permissions': ['read_own_data', 'write_own_tasks']
        }
        
        limited_damage = {
            'data_breach': 'Only assigned customer records',
            'data_manipulation': 'Only own task data',
            'service_disruption': 'None',
            'lateral_movement': 'Blocked by permission boundaries'
        }
        
        return {
            'impact_scope': 'LIMITED to user\'s scope',
            'recovery_time': 'HOURS',
            'financial_loss': 'MINIMAL'
        }
```

#### 最小権限の実装パターン

```python
from enum import Enum
from typing import Set, Dict, List
import time

class Permission(Enum):
    """権限の定義"""
    # リソースに対する操作
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    
    # 管理操作
    GRANT = "grant"  # 権限の付与
    REVOKE = "revoke"  # 権限の剥奪

class Resource:
    """保護されるリソース"""
    def __init__(self, resource_id: str, resource_type: str, owner: str):
        self.id = resource_id
        self.type = resource_type
        self.owner = owner
        self.created_at = time.time()

class LeastPrivilegeSystem:
    """最小権限の原則を実装したシステム"""
    
    def __init__(self):
        self.permissions = {}  # {user_id: {resource_id: Set[Permission]}}
        self.audit_log = []
        
    def grant_permission(self, granter_id: str, user_id: str, 
                        resource: Resource, permission: Permission) -> bool:
        """権限の付与（最小権限の原則に基づく）"""
        
        # 1. 付与者が付与権限を持っているか確認
        if not self._can_grant(granter_id, resource):
            self._log_denied_action(granter_id, "grant", resource.id, 
                                  "Insufficient privileges")
            return False
        
        # 2. 最小権限の原則に基づく検証
        if not self._is_permission_necessary(user_id, resource, permission):
            self._log_denied_action(granter_id, "grant", resource.id, 
                                  "Violates least privilege principle")
            return False
        
        # 3. 権限を付与
        if user_id not in self.permissions:
            self.permissions[user_id] = {}
        if resource.id not in self.permissions[user_id]:
            self.permissions[user_id][resource.id] = set()
        
        self.permissions[user_id][resource.id].add(permission)
        
        # 4. 監査ログに記録
        self._log_action(granter_id, "granted", permission, user_id, resource.id)
        
        return True
    
    def _is_permission_necessary(self, user_id: str, resource: Resource, 
                                permission: Permission) -> bool:
        """権限が本当に必要かを判定"""
        # ここでは職務分離や役割に基づいた判定を行う
        
        # 例：自分が所有していないリソースへの削除権限は原則不可
        if permission == Permission.DELETE and resource.owner != user_id:
            return False
        
        # 例：読み取り権限なしに書き込み権限は付与しない
        if permission == Permission.WRITE:
            current_perms = self.permissions.get(user_id, {}).get(resource.id, set())
            if Permission.READ not in current_perms:
                return False
        
        return True
    
    def check_permission(self, user_id: str, resource: Resource, 
                        permission: Permission) -> bool:
        """権限チェック"""
        result = (user_id in self.permissions and 
                 resource.id in self.permissions[user_id] and 
                 permission in self.permissions[user_id][resource.id])
        
        # すべてのアクセス試行を記録（セキュリティ監査のため）
        self._log_access_attempt(user_id, resource.id, permission, result)
        
        return result
    
    def revoke_expired_permissions(self):
        """期限切れ権限の自動剥奪"""
        current_time = time.time()
        revoked_count = 0
        
        for user_id in list(self.permissions.keys()):
            for resource_id in list(self.permissions[user_id].keys()):
                # 時限的権限のチェック（実装例）
                if self._is_permission_expired(user_id, resource_id, current_time):
                    del self.permissions[user_id][resource_id]
                    revoked_count += 1
                    self._log_action("system", "auto-revoked", "all", 
                                   user_id, resource_id)
        
        return revoked_count
    
    def _log_action(self, actor: str, action: str, permission, 
                   target_user: str, resource_id: str):
        """監査ログへの記録"""
        log_entry = {
            'timestamp': time.time(),
            'actor': actor,
            'action': action,
            'permission': str(permission),
            'target_user': target_user,
            'resource_id': resource_id
        }
        self.audit_log.append(log_entry)
```

### 3.1.3 職務分離（Separation of Duties）

#### なぜ職務分離が必要か

職務分離は、不正や誤りを防ぐための重要な原則です。一人の人間が取引の開始から完了まですべてを制御できないようにします。

```python
class SeparationOfDuties:
    """職務分離の実装"""
    
    def __init__(self):
        self.conflicting_roles = {
            'payment_initiator': ['payment_approver', 'payment_auditor'],
            'payment_approver': ['payment_initiator', 'payment_auditor'],
            'payment_auditor': ['payment_initiator', 'payment_approver'],
            
            'code_developer': ['code_deployer', 'production_admin'],
            'code_reviewer': ['code_developer'],  # 同じコードの開発者とレビュアーは分離
            
            'user_creator': ['user_approver'],
            'permission_granter': ['permission_auditor']
        }
        
        self.user_roles = {}  # {user_id: Set[role]}
        self.pending_operations = {}  # 承認待ちオペレーション
    
    def assign_role(self, user_id: str, role: str) -> tuple[bool, str]:
        """役割の割り当て（職務分離チェック付き）"""
        
        # 既存の役割を取得
        current_roles = self.user_roles.get(user_id, set())
        
        # 職務分離違反をチェック
        for current_role in current_roles:
            if role in self.conflicting_roles.get(current_role, []):
                return False, f"Role '{role}' conflicts with existing role '{current_role}'"
        
        # 役割を割り当て
        if user_id not in self.user_roles:
            self.user_roles[user_id] = set()
        self.user_roles[user_id].add(role)
        
        return True, f"Role '{role}' assigned successfully"
    
    def initiate_sensitive_operation(self, initiator_id: str, 
                                   operation_type: str, 
                                   operation_data: dict) -> str:
        """センシティブな操作の開始（承認が必要）"""
        
        operation_id = f"op_{int(time.time() * 1000)}"
        
        self.pending_operations[operation_id] = {
            'type': operation_type,
            'initiator': initiator_id,
            'data': operation_data,
            'status': 'pending',
            'created_at': time.time(),
            'required_approvals': self._get_required_approvals(operation_type),
            'approvals': []
        }
        
        return operation_id
    
    def approve_operation(self, approver_id: str, operation_id: str) -> tuple[bool, str]:
        """操作の承認"""
        
        if operation_id not in self.pending_operations:
            return False, "Operation not found"
        
        operation = self.pending_operations[operation_id]
        
        # 自己承認の禁止
        if approver_id == operation['initiator']:
            return False, "Self-approval is not allowed"
        
        # 承認者の役割チェック
        approver_roles = self.user_roles.get(approver_id, set())
        required_roles = operation['required_approvals']
        
        valid_role = None
        for role in approver_roles:
            if role in required_roles:
                valid_role = role
                break
        
        if not valid_role:
            return False, "Approver does not have required role"
        
        # 承認を記録
        operation['approvals'].append({
            'approver': approver_id,
            'role': valid_role,
            'timestamp': time.time()
        })
        
        # すべての必要な承認が揃ったかチェック
        approved_roles = {approval['role'] for approval in operation['approvals']}
        if approved_roles >= set(required_roles):
            operation['status'] = 'approved'
            return True, "Operation fully approved and ready for execution"
        
        return True, f"Approval recorded. Still waiting for: {set(required_roles) - approved_roles}"
    
    def _get_required_approvals(self, operation_type: str) -> List[str]:
        """操作タイプに基づいて必要な承認者の役割を返す"""
        approval_requirements = {
            'high_value_payment': ['payment_approver', 'finance_manager'],
            'user_deletion': ['user_admin', 'security_officer'],
            'permission_elevation': ['security_admin', 'compliance_officer'],
            'system_configuration': ['system_admin', 'change_manager']
        }
        
        return approval_requirements.get(operation_type, ['supervisor'])
```

### 3.1.4 Defense in Depth（多層防御）

認可は単独で機能するのではなく、セキュリティの複数の層の一つとして機能します。

```python
class DefenseInDepth:
    """多層防御の実装例"""
    
    def __init__(self):
        self.security_layers = {
            'network': NetworkSecurity(),
            'authentication': AuthenticationLayer(),
            'authorization': AuthorizationLayer(),
            'application': ApplicationSecurity(),
            'data': DataProtection()
        }
    
    def process_request(self, request):
        """リクエストを多層防御で処理"""
        
        # 各層でセキュリティチェック
        for layer_name, layer in self.security_layers.items():
            result = layer.check(request)
            
            if not result.passed:
                return {
                    'allowed': False,
                    'blocked_at': layer_name,
                    'reason': result.reason,
                    'timestamp': time.time()
                }
            
            # 各層でコンテキストを追加
            request.security_context[layer_name] = result.context
        
        return {
            'allowed': True,
            'security_context': request.security_context,
            'timestamp': time.time()
        }

class AuthorizationLayer:
    """認可層の実装"""
    
    def __init__(self):
        self.policies = []
        self.decision_log = []
    
    def check(self, request):
        """認可チェック"""
        
        # 1. コンテキスト情報の収集
        context = self._build_context(request)
        
        # 2. 適用可能なポリシーの特定
        applicable_policies = self._find_applicable_policies(context)
        
        # 3. ポリシー評価
        decisions = []
        for policy in applicable_policies:
            decision = self._evaluate_policy(policy, context)
            decisions.append(decision)
            
            # 即座に拒否するポリシーがあれば終了
            if decision.effect == 'DENY' and policy.priority == 'OVERRIDE':
                return AuthzResult(
                    passed=False,
                    reason=f"Denied by policy: {policy.name}",
                    context={'denied_by': policy.id}
                )
        
        # 4. 決定の集約
        final_decision = self._combine_decisions(decisions)
        
        # 5. 監査ログ
        self._log_decision(request, decisions, final_decision)
        
        return AuthzResult(
            passed=(final_decision == 'ALLOW'),
            reason=self._format_reason(decisions),
            context={'evaluated_policies': len(applicable_policies)}
        )
    
    def _build_context(self, request):
        """認可判断のためのコンテキスト構築"""
        return {
            'user': {
                'id': request.user_id,
                'roles': request.user_roles,
                'attributes': request.user_attributes,
                'authentication_level': request.auth_context.get('level', 'basic')
            },
            'resource': {
                'type': request.resource_type,
                'id': request.resource_id,
                'owner': request.resource_owner,
                'classification': request.resource_classification
            },
            'action': request.action,
            'environment': {
                'time': time.time(),
                'ip_address': request.ip_address,
                'user_agent': request.user_agent,
                'location': request.geo_location
            }
        }
```

## 3.2 認可モデルの比較（ACL, RBAC, ABAC）- 各モデルの適用場面

### 3.2.1 Access Control List (ACL) - シンプルだが限界がある

#### ACLの仕組みと実装

ACLは最も基本的な認可モデルで、各リソースに対して「誰が何をできるか」を直接指定します。

```python
class ACLSystem:
    """ACL（Access Control List）の実装"""
    
    def __init__(self):
        self.acls = {}  # {resource_id: {user_id: Set[permission]}}
        self.groups = {}  # {group_id: Set[user_id]}
        self.resource_metadata = {}
    
    def create_resource(self, resource_id: str, owner_id: str, 
                       resource_type: str = "file"):
        """リソース作成時のデフォルトACL設定"""
        
        # オーナーにはフルアクセス権限
        self.acls[resource_id] = {
            owner_id: {
                Permission.READ, 
                Permission.WRITE, 
                Permission.DELETE,
                Permission.GRANT  # ACL変更権限
            }
        }
        
        self.resource_metadata[resource_id] = {
            'owner': owner_id,
            'type': resource_type,
            'created_at': time.time(),
            'inherit_from': None
        }
    
    def grant_permission(self, resource_id: str, granter_id: str,
                        target: str, permissions: Set[Permission],
                        target_type: str = "user") -> bool:
        """権限の付与"""
        
        # 付与者がGRANT権限を持っているか確認
        if not self._has_permission(granter_id, resource_id, Permission.GRANT):
            raise PermissionError(f"User {granter_id} cannot grant permissions")
        
        if resource_id not in self.acls:
            self.acls[resource_id] = {}
        
        if target_type == "user":
            # ユーザーへの直接付与
            if target not in self.acls[resource_id]:
                self.acls[resource_id][target] = set()
            self.acls[resource_id][target].update(permissions)
            
        elif target_type == "group":
            # グループへの付与（グループメンバー全員に適用）
            if target not in self.groups:
                raise ValueError(f"Group {target} does not exist")
            
            for user_id in self.groups[target]:
                if user_id not in self.acls[resource_id]:
                    self.acls[resource_id][user_id] = set()
                self.acls[resource_id][user_id].update(permissions)
        
        return True
    
    def check_permission(self, user_id: str, resource_id: str, 
                        permission: Permission) -> bool:
        """権限チェック"""
        
        # 直接の権限チェック
        if self._has_permission(user_id, resource_id, permission):
            return True
        
        # 継承された権限のチェック（ディレクトリ構造など）
        parent_id = self.resource_metadata.get(resource_id, {}).get('inherit_from')
        if parent_id:
            return self.check_permission(user_id, parent_id, permission)
        
        return False
    
    def _has_permission(self, user_id: str, resource_id: str, 
                       permission: Permission) -> bool:
        """直接の権限を持っているかチェック"""
        return (resource_id in self.acls and
                user_id in self.acls[resource_id] and
                permission in self.acls[resource_id][user_id])
    
    def get_effective_permissions(self, user_id: str, resource_id: str) -> Set[Permission]:
        """ユーザーの実効権限を取得"""
        permissions = set()
        
        # 直接付与された権限
        if resource_id in self.acls and user_id in self.acls[resource_id]:
            permissions.update(self.acls[resource_id][user_id])
        
        # グループ経由の権限
        for group_id, members in self.groups.items():
            if user_id in members and resource_id in self.acls:
                group_perms = self.acls[resource_id].get(f"group:{group_id}", set())
                permissions.update(group_perms)
        
        return permissions

# ACLの限界を示す例
def demonstrate_acl_limitations():
    """ACLのスケーラビリティ問題を実証"""
    
    acl_system = ACLSystem()
    
    # 1000人のユーザーと1000個のリソースがある場合
    users = [f"user_{i}" for i in range(1000)]
    resources = [f"resource_{i}" for i in range(1000)]
    
    # 各リソースに対して個別に権限を設定する必要がある
    permission_entries = 0
    for resource in resources:
        acl_system.create_resource(resource, "admin", "file")
        # 各ユーザーに読み取り権限を付与
        for user in users[:100]:  # 100人のユーザーのみでも
            acl_system.grant_permission(resource, "admin", user, {Permission.READ})
            permission_entries += 1
    
    print(f"ACLエントリ数: {permission_entries}")  # 100,000エントリ！
    print("問題点:")
    print("1. 管理が複雑 - 誰がどのリソースにアクセスできるか把握困難")
    print("2. 一括変更が困難 - 部署異動時などに大量の更新が必要")
    print("3. パフォーマンス - 大量のACLエントリの評価")
```

### 3.2.2 Role-Based Access Control (RBAC) - 企業で最も使われるモデル

#### RBACの設計思想

RBACは「役割」という概念を導入することで、権限管理を大幅に簡素化します。

```python
from typing import Dict, Set, List, Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod

@dataclass
class Role:
    """役割の定義"""
    id: str
    name: str
    description: str
    permissions: Set[str]
    parent_roles: Set[str] = None  # 役割の階層化
    
    def __post_init__(self):
        if self.parent_roles is None:
            self.parent_roles = set()

class RBACSystem:
    """階層型RBACの実装"""
    
    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self.user_roles: Dict[str, Set[str]] = {}  # user_id -> Set[role_id]
        self.permissions: Dict[str, Dict] = {}  # permission定義
        self.role_hierarchy = {}  # 役割の階層関係
        self.constraints = []  # 制約条件
        
    def create_role(self, role_id: str, name: str, description: str,
                   permissions: Set[str], parent_roles: Set[str] = None) -> Role:
        """役割の作成"""
        
        # 循環参照のチェック
        if parent_roles:
            for parent_id in parent_roles:
                if self._would_create_cycle(role_id, parent_id):
                    raise ValueError(f"Role hierarchy would create a cycle")
        
        role = Role(role_id, name, description, permissions, parent_roles)
        self.roles[role_id] = role
        
        # 階層の更新
        if parent_roles:
            for parent_id in parent_roles:
                if parent_id not in self.role_hierarchy:
                    self.role_hierarchy[parent_id] = set()
                self.role_hierarchy[parent_id].add(role_id)
        
        return role
    
    def assign_role(self, user_id: str, role_id: str) -> bool:
        """ユーザーへの役割割り当て"""
        
        if role_id not in self.roles:
            raise ValueError(f"Role {role_id} does not exist")
        
        # 制約チェック（相互排他的役割など）
        if not self._check_constraints(user_id, role_id):
            return False
        
        if user_id not in self.user_roles:
            self.user_roles[user_id] = set()
        
        self.user_roles[user_id].add(role_id)
        
        # 監査ログ（実装は省略）
        self._log_role_assignment(user_id, role_id)
        
        return True
    
    def check_permission(self, user_id: str, permission: str, 
                        context: Dict = None) -> bool:
        """権限チェック"""
        
        # ユーザーの全ての権限を取得（階層も考慮）
        user_permissions = self.get_all_permissions(user_id)
        
        # コンテキストベースの動的チェック
        if context and permission in user_permissions:
            return self._evaluate_contextual_permission(
                user_id, permission, context
            )
        
        return permission in user_permissions
    
    def get_all_permissions(self, user_id: str) -> Set[str]:
        """ユーザーの全権限を取得（役割階層を考慮）"""
        
        if user_id not in self.user_roles:
            return set()
        
        all_permissions = set()
        visited_roles = set()
        
        # DFSで役割階層を辿る
        def collect_permissions(role_id: str):
            if role_id in visited_roles:
                return
            
            visited_roles.add(role_id)
            role = self.roles.get(role_id)
            
            if role:
                all_permissions.update(role.permissions)
                
                # 親役割の権限も収集
                for parent_id in role.parent_roles:
                    collect_permissions(parent_id)
        
        # ユーザーの全役割から権限を収集
        for role_id in self.user_roles[user_id]:
            collect_permissions(role_id)
        
        return all_permissions
    
    def add_constraint(self, constraint_type: str, roles: Set[str]):
        """制約の追加（例：相互排他的役割）"""
        
        constraint = {
            'type': constraint_type,
            'roles': roles,
            'created_at': time.time()
        }
        
        self.constraints.append(constraint)
    
    def _check_constraints(self, user_id: str, new_role_id: str) -> bool:
        """制約条件のチェック"""
        
        current_roles = self.user_roles.get(user_id, set())
        
        for constraint in self.constraints:
            if constraint['type'] == 'mutually_exclusive':
                if new_role_id in constraint['roles']:
                    # 既存の役割と相互排他的でないかチェック
                    conflicting = current_roles.intersection(constraint['roles'])
                    if conflicting:
                        print(f"Role {new_role_id} conflicts with {conflicting}")
                        return False
            
            elif constraint['type'] == 'prerequisite':
                # 前提条件の役割を持っているかチェック
                if new_role_id in constraint['roles']:
                    required = constraint.get('requires', set())
                    if not required.issubset(current_roles):
                        print(f"Missing prerequisite roles: {required - current_roles}")
                        return False
        
        return True
    
    def _would_create_cycle(self, child_id: str, parent_id: str) -> bool:
        """役割階層に循環が生じるかチェック"""
        
        # 親から子への経路が既に存在するかチェック
        visited = set()
        
        def has_path(from_role: str, to_role: str) -> bool:
            if from_role == to_role:
                return True
            
            if from_role in visited:
                return False
            
            visited.add(from_role)
            
            for child in self.role_hierarchy.get(from_role, []):
                if has_path(child, to_role):
                    return True
            
            return False
        
        return has_path(parent_id, child_id)

# RBACの実用例
def create_enterprise_rbac():
    """企業向けRBACの構築例"""
    
    rbac = RBACSystem()
    
    # 基本権限の定義
    permissions = {
        # データアクセス
        'read_public_data': 'Public data read access',
        'read_internal_data': 'Internal data read access',
        'read_confidential_data': 'Confidential data read access',
        
        # 操作権限
        'create_report': 'Create reports',
        'approve_report': 'Approve reports',
        'publish_report': 'Publish reports',
        
        # 管理権限
        'manage_users': 'User management',
        'manage_roles': 'Role management',
        'view_audit_logs': 'View audit logs'
    }
    
    # 役割の階層的な定義
    
    # 基本役割
    rbac.create_role(
        'employee', 
        'Employee', 
        'Basic employee role',
        {'read_public_data'}
    )
    
    # 部門別役割（employeeを継承）
    rbac.create_role(
        'analyst',
        'Data Analyst',
        'Can create reports',
        {'read_internal_data', 'create_report'},
        {'employee'}
    )
    
    rbac.create_role(
        'senior_analyst',
        'Senior Analyst',
        'Can approve reports',
        {'approve_report'},
        {'analyst'}
    )
    
    # 管理役割
    rbac.create_role(
        'manager',
        'Department Manager',
        'Department management',
        {'read_confidential_data', 'publish_report'},
        {'senior_analyst'}
    )
    
    rbac.create_role(
        'admin',
        'System Administrator',
        'Full system access',
        {'manage_users', 'manage_roles', 'view_audit_logs'},
        {'employee'}
    )
    
    # 制約の追加
    rbac.add_constraint('mutually_exclusive', {'analyst', 'admin'})
    rbac.add_constraint('mutually_exclusive', {'manager', 'admin'})
    
    return rbac
```

### 3.2.3 Attribute-Based Access Control (ABAC) - 最も柔軟なモデル

#### ABACの力と複雑さ

ABACは属性（ユーザー属性、リソース属性、環境属性）に基づいて動的に権限を決定します。

```python
from typing import Any, Dict, List, Callable
import json
from datetime import datetime, time

class Attribute:
    """属性の定義"""
    def __init__(self, name: str, value: Any, category: str):
        self.name = name
        self.value = value
        self.category = category  # 'user', 'resource', 'environment'

class PolicyRule:
    """ABACポリシールール"""
    def __init__(self, rule_id: str, description: str, 
                 condition: str, effect: str = 'ALLOW'):
        self.id = rule_id
        self.description = description
        self.condition = condition  # Python式として評価される
        self.effect = effect  # 'ALLOW' or 'DENY'
        self.priority = 0  # 高い値が優先

class ABACSystem:
    """Attribute-Based Access Control システム"""
    
    def __init__(self):
        self.policies: List[PolicyRule] = []
        self.attribute_definitions = {}
        self.policy_information_point = PolicyInformationPoint()
        
    def add_policy(self, policy: PolicyRule):
        """ポリシーの追加"""
        # ポリシーの構文チェック
        try:
            compile(policy.condition, '<policy>', 'eval')
        except SyntaxError as e:
            raise ValueError(f"Invalid policy condition: {e}")
        
        self.policies.append(policy)
        # 優先度順にソート
        self.policies.sort(key=lambda p: p.priority, reverse=True)
    
    def evaluate_access(self, subject_attrs: Dict, resource_attrs: Dict, 
                       action: str, environment_attrs: Dict = None) -> tuple[bool, str]:
        """アクセス要求の評価"""
        
        # 評価コンテキストの構築
        context = {
            'user': subject_attrs,
            'resource': resource_attrs,
            'action': action,
            'env': environment_attrs or self._get_environment_attributes()
        }
        
        # 追加の属性情報を取得
        context = self.policy_information_point.enrich_context(context)
        
        # ポリシーを順番に評価
        applicable_policies = []
        
        for policy in self.policies:
            try:
                # ポリシー条件を安全に評価
                if self._evaluate_condition(policy.condition, context):
                    applicable_policies.append(policy)
                    
                    # DENY優先（最初のDENYで即座に拒否）
                    if policy.effect == 'DENY':
                        return False, f"Denied by policy: {policy.description}"
                        
            except Exception as e:
                # ポリシー評価エラーは拒否として扱う
                print(f"Policy evaluation error: {e}")
                continue
        
        # 適用可能なALLOWポリシーがあるか
        allow_policies = [p for p in applicable_policies if p.effect == 'ALLOW']
        if allow_policies:
            return True, f"Allowed by: {allow_policies[0].description}"
        
        # デフォルトは拒否
        return False, "No applicable ALLOW policy found"
    
    def _evaluate_condition(self, condition: str, context: Dict) -> bool:
        """条件式の安全な評価"""
        # 利用可能な関数を制限
        safe_functions = {
            'len': len,
            'int': int,
            'str': str,
            'bool': bool,
            'any': any,
            'all': all,
            'min': min,
            'max': max,
            'datetime': datetime,
            'time': time,
            'in_time_range': self._in_time_range,
            'has_clearance': self._has_clearance
        }
        
        # 評価環境を構築
        eval_env = {**context, **safe_functions}
        
        # 条件を評価
        return eval(condition, {"__builtins__": {}}, eval_env)
    
    def _get_environment_attributes(self) -> Dict:
        """環境属性の取得"""
        now = datetime.now()
        return {
            'current_time': now.time(),
            'current_date': now.date(),
            'day_of_week': now.strftime('%A'),
            'is_business_hours': self._is_business_hours(now),
            'threat_level': self._get_current_threat_level(),
            'system_load': self._get_system_load()
        }
    
    def _in_time_range(self, start: str, end: str) -> bool:
        """時間範囲内かチェック"""
        current = datetime.now().time()
        start_time = datetime.strptime(start, '%H:%M').time()
        end_time = datetime.strptime(end, '%H:%M').time()
        
        if start_time <= end_time:
            return start_time <= current <= end_time
        else:  # 日をまたぐ場合
            return current >= start_time or current <= end_time
    
    def _has_clearance(self, user_clearance: str, required_clearance: str) -> bool:
        """セキュリティクリアランスのチェック"""
        clearance_levels = {
            'PUBLIC': 0,
            'INTERNAL': 1,
            'CONFIDENTIAL': 2,
            'SECRET': 3,
            'TOP_SECRET': 4
        }
        
        user_level = clearance_levels.get(user_clearance, 0)
        required_level = clearance_levels.get(required_clearance, 999)
        
        return user_level >= required_level
    
    def _is_business_hours(self, dt: datetime) -> bool:
        """営業時間内かチェック"""
        if dt.weekday() >= 5:  # 土日
            return False
        return time(9, 0) <= dt.time() <= time(18, 0)
    
    def _get_current_threat_level(self) -> str:
        """現在の脅威レベルを取得（実装例）"""
        # 実際にはSIEMシステムなどから取得
        return "NORMAL"
    
    def _get_system_load(self) -> float:
        """システム負荷を取得（実装例）"""
        # 実際にはモニタリングシステムから取得
        return 0.3

class PolicyInformationPoint:
    """追加の属性情報を提供するコンポーネント"""
    
    def __init__(self):
        self.data_sources = {}
    
    def enrich_context(self, context: Dict) -> Dict:
        """コンテキストに追加情報を付加"""
        enriched = context.copy()
        
        # ユーザーの追加属性を取得
        if 'user' in context and 'id' in context['user']:
            user_id = context['user']['id']
            enriched['user'].update(self._get_user_attributes(user_id))
        
        # リソースの追加属性を取得
        if 'resource' in context and 'id' in context['resource']:
            resource_id = context['resource']['id']
            enriched['resource'].update(self._get_resource_attributes(resource_id))
        
        return enriched
    
    def _get_user_attributes(self, user_id: str) -> Dict:
        """ユーザーの追加属性を取得"""
        # 実際にはLDAPやHRシステムから取得
        return {
            'department': 'Engineering',
            'clearance_level': 'SECRET',
            'employment_type': 'FULL_TIME',
            'years_of_service': 5,
            'training_completed': ['security_awareness', 'data_handling'],
            'current_projects': ['ProjectA', 'ProjectB']
        }
    
    def _get_resource_attributes(self, resource_id: str) -> Dict:
        """リソースの追加属性を取得"""
        # 実際にはCMDBやメタデータストアから取得
        return {
            'classification': 'CONFIDENTIAL',
            'owner': 'user123',
            'created_date': '2024-01-15',
            'last_modified': '2024-03-20',
            'tags': ['financial', 'quarterly_report'],
            'retention_period': 7  # years
        }

# ABACポリシーの実用例
def create_abac_policies():
    """実用的なABACポリシーの作成"""
    
    abac = ABACSystem()
    
    # ポリシー1: 営業時間内のみアクセス可能
    policy1 = PolicyRule(
        'business_hours_only',
        'Access allowed only during business hours',
        "env['is_business_hours'] == True",
        'ALLOW'
    )
    policy1.priority = 10
    abac.add_policy(policy1)
    
    # ポリシー2: 機密データへのアクセスは適切なクリアランスが必要
    policy2 = PolicyRule(
        'clearance_required',
        'Confidential data requires appropriate clearance',
        "has_clearance(user['clearance_level'], resource['classification'])",
        'ALLOW'
    )
    policy2.priority = 20
    abac.add_policy(policy2)
    
    # ポリシー3: 部門間のデータアクセス制限
    policy3 = PolicyRule(
        'department_isolation',
        'Cross-department access denied',
        "user['department'] == resource['owner_department'] or user['role'] == 'admin'",
        'ALLOW'
    )
    policy3.priority = 15
    abac.add_policy(policy3)
    
    # ポリシー4: 高負荷時の読み取り専用
    policy4 = PolicyRule(
        'high_load_readonly',
        'Only read access during high system load',
        "env['system_load'] > 0.8 and action != 'read'",
        'DENY'
    )
    policy4.priority = 30
    
    # ポリシー5: 地理的制限
    policy5 = PolicyRule(
        'geo_restriction',
        'Access from approved locations only',
        "env['client_country'] in ['JP', 'US', 'EU'] or user['role'] == 'remote_worker'",
        'ALLOW'
    )
    policy5.priority = 25
    
    # ポリシー6: 時限的アクセス
    policy6 = PolicyRule(
        'project_timeline',
        'Project data accessible only during project period',
        """
        resource['project'] in user['current_projects'] and 
        datetime.now() <= datetime.strptime(resource['project_end_date'], '%Y-%m-%d')
        """,
        'ALLOW'
    )
    
    return abac
```

### 3.2.4 認可モデルの選択基準

```python
class AuthorizationModelSelector:
    """組織に適した認可モデルを選択するためのフレームワーク"""
    
    def analyze_requirements(self, organization_profile: Dict) -> Dict:
        """要件分析に基づく推奨"""
        
        scores = {
            'ACL': 0,
            'RBAC': 0,
            'ABAC': 0,
            'Hybrid': 0
        }
        
        # 組織規模
        user_count = organization_profile.get('user_count', 0)
        if user_count < 50:
            scores['ACL'] += 3
        elif user_count < 500:
            scores['RBAC'] += 3
        else:
            scores['RBAC'] += 2
            scores['ABAC'] += 2
        
        # 組織構造の複雑さ
        if organization_profile.get('hierarchical_structure', False):
            scores['RBAC'] += 3
        
        if organization_profile.get('matrix_organization', False):
            scores['ABAC'] += 3
            scores['Hybrid'] += 2
        
        # セキュリティ要件
        security_level = organization_profile.get('security_requirements', 'medium')
        if security_level == 'high':
            scores['ABAC'] += 3
            scores['Hybrid'] += 2
        elif security_level == 'critical':
            scores['ABAC'] += 4
            scores['Hybrid'] += 3
        
        # 動的な要件
        if organization_profile.get('dynamic_permissions', False):
            scores['ABAC'] += 4
        
        if organization_profile.get('time_based_access', False):
            scores['ABAC'] += 2
            scores['Hybrid'] += 2
        
        # コンプライアンス要件
        if organization_profile.get('regulatory_compliance', []):
            scores['RBAC'] += 2  # 監査が容易
            scores['ABAC'] += 1  # 細かい制御が可能
        
        # 運用の複雑さとのトレードオフ
        if organization_profile.get('limited_it_resources', False):
            scores['ACL'] += 1
            scores['RBAC'] += 2
            scores['ABAC'] -= 2  # 複雑すぎる
        
        # 推奨モデルの決定
        recommended_model = max(scores, key=scores.get)
        
        return {
            'scores': scores,
            'recommendation': recommended_model,
            'reasoning': self._generate_reasoning(recommended_model, organization_profile),
            'implementation_guidance': self._get_implementation_guidance(recommended_model)
        }
    
    def _generate_reasoning(self, model: str, profile: Dict) -> str:
        """推奨理由の生成"""
        
        reasoning_templates = {
            'ACL': "小規模で単純な権限管理には、ACLのシンプルさが適しています。",
            'RBAC': "明確な組織構造と役割分担がある環境では、RBACが最適です。",
            'ABAC': "複雑で動的な権限要件には、ABACの柔軟性が必要です。",
            'Hybrid': "複雑な要件に対しては、複数のモデルを組み合わせることが効果的です。"
        }
        
        return reasoning_templates.get(model, "要件に基づいて選択されました。")
    
    def _get_implementation_guidance(self, model: str) -> List[str]:
        """実装ガイダンス"""
        
        guidance = {
            'ACL': [
                "リソースごとの権限マトリックスを作成",
                "グループ機能を活用して管理を簡素化",
                "定期的な権限レビュープロセスを確立"
            ],
            'RBAC': [
                "組織の役割を明確に定義",
                "役割の階層構造を設計",
                "職務分離の原則を実装",
                "役割の定期的な見直しプロセスを確立"
            ],
            'ABAC': [
                "属性のカタログを作成",
                "ポリシー言語を選定（XACML、OPAなど）",
                "ポリシーのテストフレームワークを構築",
                "属性の信頼できるソースを確立"
            ],
            'Hybrid': [
                "基本的な構造にはRBACを使用",
                "例外的なケースにABACを適用",
                "統合されたポリシー管理システムを構築"
            ]
        }
        
        return guidance.get(model, [])
```

## 3.3 最小権限の原則 - セキュリティインシデントの最小化

### 3.3.1 最小権限の実装パターン

```python
class LeastPrivilegeImplementation:
    """最小権限の原則の実装パターン"""
    
    def __init__(self):
        self.permission_lifecycle = PermissionLifecycle()
        self.just_in_time_access = JustInTimeAccess()
        self.privilege_elevation = PrivilegeElevation()
    
    def implement_permission_lifecycle(self):
        """権限のライフサイクル管理"""
        
        class PermissionLifecycle:
            def __init__(self):
                self.permissions = {}
                self.expiration_times = {}
                self.usage_tracking = {}
            
            def grant_temporary_permission(self, user_id: str, permission: str,
                                         duration_hours: int, justification: str):
                """一時的な権限の付与"""
                
                expiration = time.time() + (duration_hours * 3600)
                
                grant_record = {
                    'user_id': user_id,
                    'permission': permission,
                    'granted_at': time.time(),
                    'expires_at': expiration,
                    'justification': justification,
                    'approved_by': self._get_approver(permission),
                    'usage_count': 0
                }
                
                # 権限を付与
                if user_id not in self.permissions:
                    self.permissions[user_id] = {}
                
                self.permissions[user_id][permission] = grant_record
                
                # 自動失効をスケジュール
                self._schedule_revocation(user_id, permission, expiration)
                
                return grant_record
            
            def track_permission_usage(self, user_id: str, permission: str):
                """権限の使用を追跡"""
                
                if (user_id in self.permissions and 
                    permission in self.permissions[user_id]):
                    
                    self.permissions[user_id][permission]['usage_count'] += 1
                    self.permissions[user_id][permission]['last_used'] = time.time()
                    
                    # 使用パターンの分析
                    self._analyze_usage_pattern(user_id, permission)
            
            def review_unused_permissions(self, days_threshold: int = 30):
                """使用されていない権限の検出"""
                
                current_time = time.time()
                unused_permissions = []
                
                for user_id, user_perms in self.permissions.items():
                    for permission, details in user_perms.items():
                        last_used = details.get('last_used', details['granted_at'])
                        days_unused = (current_time - last_used) / 86400
                        
                        if days_unused > days_threshold:
                            unused_permissions.append({
                                'user_id': user_id,
                                'permission': permission,
                                'days_unused': int(days_unused),
                                'usage_count': details['usage_count']
                            })
                
                return unused_permissions
            
            def auto_revoke_unused(self, permissions_to_revoke: List[Dict]):
                """未使用権限の自動取り消し"""
                
                revoked = []
                for perm in permissions_to_revoke:
                    if self._should_auto_revoke(perm):
                        self._revoke_permission(
                            perm['user_id'], 
                            perm['permission'],
                            reason='Unused for extended period'
                        )
                        revoked.append(perm)
                
                return revoked
    
    def implement_just_in_time_access(self):
        """Just-In-Time (JIT) アクセスの実装"""
        
        class JustInTimeAccess:
            def __init__(self):
                self.elevation_requests = {}
                self.approval_workflows = {}
                self.active_elevations = {}
            
            def request_elevation(self, user_id: str, requested_role: str,
                                reason: str, duration_minutes: int = 60):
                """権限昇格のリクエスト"""
                
                request_id = f"req_{int(time.time() * 1000)}"
                
                request = {
                    'id': request_id,
                    'user_id': user_id,
                    'current_roles': self._get_current_roles(user_id),
                    'requested_role': requested_role,
                    'reason': reason,
                    'duration': duration_minutes,
                    'status': 'pending',
                    'created_at': time.time(),
                    'risk_score': self._calculate_risk_score(user_id, requested_role)
                }
                
                self.elevation_requests[request_id] = request
                
                # リスクに基づいて承認フローを決定
                if request['risk_score'] < 30:
                    # 低リスク：自動承認
                    self._auto_approve(request_id)
                elif request['risk_score'] < 70:
                    # 中リスク：マネージャー承認
                    self._route_to_manager(request_id)
                else:
                    # 高リスク：複数承認者
                    self._route_to_security_team(request_id)
                
                return request_id
            
            def _calculate_risk_score(self, user_id: str, requested_role: str) -> int:
                """リスクスコアの計算"""
                
                score = 0
                
                # 要求された権限の危険度
                high_risk_roles = ['admin', 'security_admin', 'database_admin']
                if requested_role in high_risk_roles:
                    score += 50
                
                # ユーザーの信頼度
                user_trust = self._get_user_trust_score(user_id)
                score -= user_trust
                
                # 時間帯
                current_hour = datetime.now().hour
                if current_hour < 6 or current_hour > 22:
                    score += 20  # 深夜早朝はリスク高
                
                # 過去の昇格履歴
                elevation_history = self._get_elevation_history(user_id)
                if elevation_history['violations'] > 0:
                    score += 30
                
                return max(0, min(100, score))
            
            def activate_elevation(self, request_id: str):
                """承認された権限昇格を有効化"""
                
                request = self.elevation_requests.get(request_id)
                if not request or request['status'] != 'approved':
                    return False
                
                # セッションベースの権限昇格
                elevation_token = secrets.token_urlsafe(32)
                
                self.active_elevations[elevation_token] = {
                    'user_id': request['user_id'],
                    'elevated_role': request['requested_role'],
                    'original_roles': request['current_roles'],
                    'started_at': time.time(),
                    'expires_at': time.time() + (request['duration'] * 60),
                    'request_id': request_id
                }
                
                # 監査ログとモニタリング
                self._start_elevation_monitoring(elevation_token)
                
                return elevation_token
            
            def check_elevation(self, elevation_token: str) -> Optional[Dict]:
                """昇格状態の確認"""
                
                if elevation_token not in self.active_elevations:
                    return None
                
                elevation = self.active_elevations[elevation_token]
                
                # 期限切れチェック
                if time.time() > elevation['expires_at']:
                    self._end_elevation(elevation_token, reason='expired')
                    return None
                
                # 異常な使用パターンの検出
                if self._detect_anomalous_usage(elevation_token):
                    self._end_elevation(elevation_token, reason='anomaly_detected')
                    return None
                
                return elevation
            
            def _start_elevation_monitoring(self, elevation_token: str):
                """昇格中の行動を監視"""
                
                elevation = self.active_elevations[elevation_token]
                
                # リアルタイムモニタリングの設定
                monitoring_config = {
                    'user_id': elevation['user_id'],
                    'session_id': elevation_token,
                    'alerts': {
                        'high_volume_access': 100,  # 100回以上のアクセス
                        'sensitive_data_access': True,
                        'configuration_changes': True,
                        'bulk_operations': True
                    },
                    'recording': True  # セッション記録
                }
                
                # モニタリングシステムに登録（実装は省略）
                self._register_monitoring(monitoring_config)
```

### 3.3.2 権限の定期的な見直し

```python
class PermissionReviewProcess:
    """権限の定期的なレビュープロセス"""
    
    def __init__(self):
        self.review_cycles = {
            'high_privilege': 30,  # 日
            'normal': 90,
            'low_risk': 180
        }
        self.certification_records = {}
    
    def initiate_access_review(self, review_type: str = 'quarterly'):
        """アクセスレビューの開始"""
        
        review_id = f"review_{datetime.now().strftime('%Y%m%d')}"
        
        review = {
            'id': review_id,
            'type': review_type,
            'started_at': time.time(),
            'status': 'in_progress',
            'scope': self._determine_review_scope(review_type),
            'reviewers': {},
            'findings': []
        }
        
        # レビュー対象の特定
        review_items = self._identify_review_items(review['scope'])
        
        # レビュアーへの割り当て
        for item in review_items:
            reviewer = self._assign_reviewer(item)
            if reviewer not in review['reviewers']:
                review['reviewers'][reviewer] = []
            review['reviewers'][reviewer].append(item)
        
        # 通知の送信
        self._send_review_notifications(review)
        
        return review_id
    
    def _identify_review_items(self, scope: Dict) -> List[Dict]:
        """レビュー対象の特定"""
        
        items = []
        
        # 高権限ユーザー
        if scope.get('high_privilege_users', True):
            high_priv_users = self._get_high_privilege_users()
            for user in high_priv_users:
                items.append({
                    'type': 'user_permissions',
                    'user_id': user['id'],
                    'risk_level': 'high',
                    'permissions': user['permissions'],
                    'last_review': user.get('last_review_date')
                })
        
        # 長期未使用の権限
        if scope.get('unused_permissions', True):
            unused = self._find_unused_permissions(days=60)
            for perm in unused:
                items.append({
                    'type': 'unused_permission',
                    'user_id': perm['user_id'],
                    'permission': perm['permission'],
                    'last_used': perm['last_used'],
                    'recommendation': 'revoke'
                })
        
        # 異常なアクセスパターン
        if scope.get('anomalous_access', True):
            anomalies = self._detect_access_anomalies()
            for anomaly in anomalies:
                items.append({
                    'type': 'anomalous_pattern',
                    'user_id': anomaly['user_id'],
                    'pattern': anomaly['pattern'],
                    'risk_score': anomaly['risk_score'],
                    'recommendation': 'investigate'
                })
        
        return items
    
    def process_review_decision(self, review_id: str, item_id: str, 
                              decision: str, justification: str):
        """レビュー決定の処理"""
        
        decisions_map = {
            'approve': self._approve_access,
            'revoke': self._revoke_access,
            'modify': self._modify_access,
            'investigate': self._flag_for_investigation
        }
        
        if decision in decisions_map:
            result = decisions_map[decision](item_id, justification)
            
            # 証跡の記録
            self._record_certification(review_id, item_id, decision, justification)
            
            return result
        
        return False
    
    def generate_review_report(self, review_id: str) -> Dict:
        """レビュー結果のレポート生成"""
        
        review = self._get_review(review_id)
        
        report = {
            'review_id': review_id,
            'period': f"{review['started_at']} - {time.time()}",
            'summary': {
                'total_items_reviewed': 0,
                'approvals': 0,
                'revocations': 0,
                'modifications': 0,
                'investigations': 0
            },
            'risk_findings': [],
            'compliance_status': 'compliant',
            'recommendations': []
        }
        
        # 統計情報の集計
        for decision in self.certification_records.get(review_id, {}).values():
            report['summary']['total_items_reviewed'] += 1
            report['summary'][f"{decision['decision']}s"] += 1
        
        # リスク所見
        report['risk_findings'] = self._analyze_risk_findings(review_id)
        
        # 推奨事項
        report['recommendations'] = self._generate_recommendations(report)
        
        return report
```

## 3.4 動的認可と静的認可 - パフォーマンスとセキュリティのバランス

### 3.4.1 静的認可の実装

```python
class StaticAuthorization:
    """コンパイル時に決定される静的認可"""
    
    def __init__(self):
        self.permission_cache = {}
        self.role_permission_matrix = {}
        self.compiled_policies = {}
    
    def precompile_permissions(self):
        """権限の事前計算"""
        
        # 役割と権限のマトリックスを事前計算
        for role_id, role in self.get_all_roles().items():
            permissions = set()
            
            # 直接の権限
            permissions.update(role.permissions)
            
            # 継承された権限
            for parent_role in role.parent_roles:
                permissions.update(self._get_role_permissions(parent_role))
            
            self.role_permission_matrix[role_id] = permissions
        
        # ユーザーごとの実効権限を計算
        for user_id, user_roles in self.get_user_roles().items():
            effective_permissions = set()
            
            for role_id in user_roles:
                effective_permissions.update(
                    self.role_permission_matrix.get(role_id, set())
                )
            
            self.permission_cache[user_id] = effective_permissions
        
        return len(self.permission_cache)
    
    def check_permission_static(self, user_id: str, permission: str) -> bool:
        """静的な権限チェック（高速）"""
        
        # O(1)のルックアップ
        user_permissions = self.permission_cache.get(user_id, set())
        return permission in user_permissions
    
    def optimize_for_performance(self):
        """パフォーマンス最適化"""
        
        # ビットマスクによる権限表現
        class BitMaskPermissions:
            def __init__(self):
                self.permission_bits = {}
                self.next_bit = 0
            
            def register_permission(self, permission: str) -> int:
                """権限にビットを割り当て"""
                if permission not in self.permission_bits:
                    self.permission_bits[permission] = 1 << self.next_bit
                    self.next_bit += 1
                return self.permission_bits[permission]
            
            def create_permission_mask(self, permissions: Set[str]) -> int:
                """権限セットからビットマスクを作成"""
                mask = 0
                for perm in permissions:
                    mask |= self.permission_bits.get(perm, 0)
                return mask
            
            def check_permission(self, user_mask: int, permission: str) -> bool:
                """ビット演算による高速チェック"""
                perm_bit = self.permission_bits.get(permission, 0)
                return (user_mask & perm_bit) != 0
        
        return BitMaskPermissions()
```

### 3.4.2 動的認可の実装

```python
class DynamicAuthorization:
    """実行時に評価される動的認可"""
    
    def __init__(self):
        self.policy_engine = PolicyEngine()
        self.context_providers = []
        self.decision_cache = LRUCache(maxsize=10000)
    
    def evaluate_dynamic_permission(self, request: Dict) -> tuple[bool, str]:
        """動的な権限評価"""
        
        # キャッシュチェック
        cache_key = self._generate_cache_key(request)
        cached_decision = self.decision_cache.get(cache_key)
        
        if cached_decision and not self._is_cache_expired(cached_decision):
            return cached_decision['result'], cached_decision['reason']
        
        # コンテキストの収集
        context = self._gather_context(request)
        
        # ポリシーの評価
        decision = self.policy_engine.evaluate(context)
        
        # 結果をキャッシュ（適切な場合のみ）
        if self._is_cacheable(context, decision):
            self.decision_cache.put(cache_key, {
                'result': decision.permit,
                'reason': decision.reason,
                'timestamp': time.time(),
                'ttl': self._determine_ttl(context)
            })
        
        return decision.permit, decision.reason
    
    def _gather_context(self, request: Dict) -> Dict:
        """動的コンテキストの収集"""
        
        context = {
            'request': request,
            'timestamp': time.time(),
            'dynamic_attributes': {}
        }
        
        # 各コンテキストプロバイダーから情報を収集
        for provider in self.context_providers:
            try:
                provider_data = provider.get_context(request)
                context['dynamic_attributes'].update(provider_data)
            except Exception as e:
                # プロバイダーの失敗は認可拒否につながらない
                print(f"Context provider error: {e}")
        
        return context
    
    def add_context_provider(self, provider):
        """コンテキストプロバイダーの追加"""
        self.context_providers.append(provider)

class LocationContextProvider:
    """位置情報コンテキストプロバイダー"""
    
    def get_context(self, request: Dict) -> Dict:
        ip_address = request.get('ip_address')
        
        # GeoIP検索（実装は省略）
        location_info = self._lookup_geoip(ip_address)
        
        return {
            'client_country': location_info.get('country', 'unknown'),
            'client_city': location_info.get('city', 'unknown'),
            'is_corporate_network': self._is_corporate_ip(ip_address),
            'is_vpn': self._detect_vpn(ip_address)
        }

class RiskContextProvider:
    """リスク評価コンテキストプロバイダー"""
    
    def get_context(self, request: Dict) -> Dict:
        user_id = request.get('user_id')
        
        # ユーザーの行動分析
        risk_indicators = {
            'failed_login_attempts': self._get_recent_failures(user_id),
            'unusual_access_time': self._is_unusual_time(user_id),
            'new_device': self._is_new_device(request),
            'concurrent_sessions': self._count_active_sessions(user_id)
        }
        
        # リスクスコアの計算
        risk_score = self._calculate_risk_score(risk_indicators)
        
        return {
            'risk_score': risk_score,
            'risk_level': self._categorize_risk(risk_score),
            'risk_indicators': risk_indicators
        }
```

### 3.4.3 ハイブリッドアプローチ

```python
class HybridAuthorization:
    """静的と動的を組み合わせたハイブリッド認可"""
    
    def __init__(self):
        self.static_auth = StaticAuthorization()
        self.dynamic_auth = DynamicAuthorization()
        self.performance_monitor = PerformanceMonitor()
    
    def authorize(self, request: Dict) -> tuple[bool, str, Dict]:
        """ハイブリッド認可の実行"""
        
        start_time = time.time()
        metrics = {'static_time': 0, 'dynamic_time': 0, 'total_time': 0}
        
        # フェーズ1: 静的チェック（高速）
        static_start = time.time()
        static_result = self.static_auth.check_permission_static(
            request['user_id'], 
            request['permission']
        )
        metrics['static_time'] = time.time() - static_start
        
        # 静的に拒否された場合は即座に終了
        if not static_result:
            metrics['total_time'] = time.time() - start_time
            return False, "Statically denied", metrics
        
        # フェーズ2: 動的チェックが必要か判定
        if self._requires_dynamic_check(request):
            dynamic_start = time.time()
            dynamic_result, reason = self.dynamic_auth.evaluate_dynamic_permission(request)
            metrics['dynamic_time'] = time.time() - dynamic_start
            
            if not dynamic_result:
                metrics['total_time'] = time.time() - start_time
                return False, f"Dynamically denied: {reason}", metrics
        
        metrics['total_time'] = time.time() - start_time
        
        # パフォーマンスモニタリング
        self.performance_monitor.record(request['permission'], metrics)
        
        return True, "Authorized", metrics
    
    def _requires_dynamic_check(self, request: Dict) -> bool:
        """動的チェックが必要か判定"""
        
        # 高リスクリソース
        if request.get('resource_classification') in ['SECRET', 'TOP_SECRET']:
            return True
        
        # 特定の操作
        if request.get('action') in ['delete', 'modify_permissions', 'export_data']:
            return True
        
        # 特定の条件
        if request.get('amount', 0) > 10000:  # 高額取引
            return True
        
        # コンテキストベースのフラグ
        if request.get('require_dynamic_check', False):
            return True
        
        return False
    
    def optimize_authorization_strategy(self):
        """認可戦略の最適化"""
        
        # パフォーマンスデータの分析
        stats = self.performance_monitor.get_statistics()
        
        recommendations = []
        
        # 静的チェックで十分な権限の特定
        for permission, metrics in stats.items():
            if metrics['dynamic_check_rate'] < 0.1:  # 10%未満
                recommendations.append({
                    'permission': permission,
                    'recommendation': 'move_to_static_only',
                    'expected_improvement': f"{metrics['avg_dynamic_time']}ms"
                })
        
        # 頻繁に評価される動的ポリシーのキャッシュ推奨
        for permission, metrics in stats.items():
            if metrics['request_rate'] > 100:  # 100 req/s以上
                recommendations.append({
                    'permission': permission,
                    'recommendation': 'increase_cache_ttl',
                    'current_ttl': metrics.get('cache_ttl', 0),
                    'suggested_ttl': min(300, metrics.get('cache_ttl', 0) * 2)
                })
        
        return recommendations

class PerformanceMonitor:
    """認可パフォーマンスのモニタリング"""
    
    def __init__(self):
        self.metrics = {}
        self.thresholds = {
            'static_latency_ms': 1,
            'dynamic_latency_ms': 50,
            'total_latency_ms': 100
        }
    
    def record(self, permission: str, timing: Dict):
        """メトリクスの記録"""
        
        if permission not in self.metrics:
            self.metrics[permission] = {
                'count': 0,
                'static_time_sum': 0,
                'dynamic_time_sum': 0,
                'dynamic_checks': 0,
                'cache_hits': 0
            }
        
        m = self.metrics[permission]
        m['count'] += 1
        m['static_time_sum'] += timing['static_time'] * 1000  # ms
        
        if timing['dynamic_time'] > 0:
            m['dynamic_checks'] += 1
            m['dynamic_time_sum'] += timing['dynamic_time'] * 1000
        
        # 閾値チェック
        self._check_thresholds(permission, timing)
    
    def get_statistics(self) -> Dict:
        """統計情報の取得"""
        
        stats = {}
        
        for perm, metrics in self.metrics.items():
            count = metrics['count']
            if count == 0:
                continue
            
            stats[perm] = {
                'request_rate': count,  # 実際は時間窓で計算
                'avg_static_time': metrics['static_time_sum'] / count,
                'avg_dynamic_time': (metrics['dynamic_time_sum'] / 
                                   metrics['dynamic_checks'] 
                                   if metrics['dynamic_checks'] > 0 else 0),
                'dynamic_check_rate': metrics['dynamic_checks'] / count,
                'cache_hit_rate': metrics['cache_hits'] / count
            }
        
        return stats
```

## まとめ

この章では、認可の基礎として以下を学びました：

1. **アクセス制御の基本原則**
   - 最小権限の原則の重要性と実装
   - 職務分離による不正防止
   - 多層防御の考え方

2. **認可モデルの比較**
   - ACL：シンプルだが管理が困難
   - RBAC：組織構造に適合し、最も普及
   - ABAC：柔軟だが複雑

3. **最小権限の実装**
   - Just-In-Time アクセス
   - 権限の定期的な見直し
   - 自動化による管理負荷の軽減

4. **静的・動的認可のバランス**
   - パフォーマンスとセキュリティのトレードオフ
   - ハイブリッドアプローチの利点
   - 継続的な最適化

次章では、これらの認証・認可の仕組みを実際のWebアプリケーションで実装する方法として、セッション管理について詳しく学んでいきます。

## 演習問題

### 問題1：RBACシステムの設計
中規模IT企業（従業員300名）のRBACシステムを設計しなさい。以下を含むこと：
- 部門構造（開発、営業、管理、人事）
- 各部門の典型的な役割
- 権限の階層構造
- 職務分離の実装

### 問題2：ABACポリシーの作成
以下のシナリオに対するABACポリシーを作成しなさい：
- 医療記録システム
- 患者は自分の記録のみ閲覧可能
- 担当医は担当患者の記録を閲覧・編集可能
- 緊急時は任意の医師が閲覧可能
- 診療時間外は読み取りのみ

### 問題3：最小権限の実装
既存システムに最小権限の原則を適用する計画を立てなさい：
- 現状分析の方法
- 段階的な権限削減計画
- 影響を受けるユーザーへの対応
- 効果測定の方法

### 問題4：認可パフォーマンスの最適化
1秒間に1000件の認可リクエストを処理する必要があるシステムで、以下の要件を満たす設計を行いなさい：
- 平均レスポンスタイム：10ms以下
- 動的ポリシー評価が20%のリクエストで必要
- 99.9%の可用性

### 問題5：認可モデルの移行
ACLベースの既存システムをRBACに移行する計画を作成しなさい：
- 現状のACL分析
- 役割の抽出方法
- 移行期間中の並行運用
- 検証とロールバック計画

### チャレンジ問題：Zero Trust認可の設計
Zero Trustアーキテクチャに基づく認可システムを設計しなさい：
- 継続的な検証の仕組み
- コンテキストベースの動的認可
- マイクロセグメンテーション
- 監査とコンプライアンス