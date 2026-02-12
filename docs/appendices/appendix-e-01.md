---
layout: book
title: "第1章 演習問題解答"
---

# 第1章 演習問題解答

## 問題1：認証と認可の区別

### 解答

1. **認証** - メールアドレスとパスワードによる本人確認
2. **認可** - アクセス権限の判定
3. **認証** - 生体情報による本人確認
4. **認可** - リソースへのアクセス制御
5. **認証** - 追加の本人確認手段（多要素認証の一部）

### 解説

認証と認可の見分け方
- 「誰であるか」を確認 → **認証**
- 「何ができるか」を判定 → **認可**

覚え方のコツ
- Authen**N** = ideNtity（身元確認）
- Authori**Z**ation = 権限（permiZZion）

## 問題2：セキュリティインシデントの分析

### 解答

**根本原因：**

1. **アカウント管理プロセスの不備**
   - 退職時のアカウント無効化が実施されていない
   - 定期的なアカウント棚卸しの欠如

2. **認証方式の脆弱性**
   - パスワードのみの単一要素認証
   - パスワード変更ポリシーの不在

3. **監査・監視の不足**
   - 異常なアクセスパターンの検知機能なし
   - アクセスログの定期レビュー未実施

**対策：**

1. **即時対応**
   ```text
   - 該当アカウントの即時無効化
   - 全従業員のパスワード強制変更
   - アクセスログの詳細調査
   ```

2. **プロセス改善**
   ```text
   退職時チェックリスト：
   □ ADアカウントの無効化
   □ メールアカウントの停止
   □ VPNアクセスの削除
   □ 物理的なアクセスカードの回収
   □ 各システムの権限削除
   ```

3. **技術的対策**
   ```python
   # アカウント自動無効化の実装例
   def check_employee_status():
       for user in get_all_users():
           if user.employment_status == "terminated":
               if days_since_termination(user) >= 0:
                   disable_account(user)
                   log_action(f"Account disabled: {user.id}")
   ```

4. **継続的な改善**
   - 四半期ごとのアカウント棚卸し
   - 多要素認証の導入
   - SIEM（Security Information and Event Management）の導入

## 問題3：技術選択の判断

### シナリオA：社内業務システム

**推奨する認証方式：**
- **基本認証**：Active Directory連携によるSSO
- **追加認証**：スマートフォンアプリによるMFA（TOTP）

**理由：**
1. **利便性**：1日複数回アクセスするため、SSOで認証回数を削減
2. **セキュリティ**：人事・給与情報は機密性が高いため、MFA必須
3. **コスト効率**：既存のAD基盤を活用、TOTPは無料で実装可能
4. **管理性**：500名規模なら、AD中心の管理が最適

**実装例：**
```yaml
# 認証フロー設定
authentication:
  primary:
    type: "active_directory"
    server: "ldap://ad.company.local"
  mfa:
    type: "totp"
    required_for:
      - "/hr/*"
      - "/payroll/*"
    grace_period: "8_hours"
```

### シナリオB：一般消費者向けECサイト

**推奨する認証方式：**
- **基本認証**：メールアドレス + パスワード
- **オプション**：ソーシャルログイン（Google、Facebook）
- **リスクベース認証**：異常検知時のみ追加認証

**理由：**
1. **利便性最優先**：月1-2回の利用では、複雑な認証は離脱要因
2. **段階的セキュリティ**：通常は簡単に、決済時は厳格に
3. **コスト配慮**：100万ユーザーでのMFA必須はコスト高
4. **転換率**：ソーシャルログインで新規登録のハードルを下げる

**実装例：**
```javascript
// リスクベース認証の実装
async function assessRisk(request, user) {
    const riskFactors = {
        newDevice: await isNewDevice(request, user),
        unusualLocation: await isUnusualLocation(request, user),
        highValueTransaction: request.amount > 50000,
        rapidRequests: await checkVelocity(user)
    };
    
    const riskScore = calculateScore(riskFactors);
    
    if (riskScore > 70) {
        return { action: "require_2fa" };
    } else if (riskScore > 40) {
        return { action: "require_captcha" };
    }
    return { action: "allow" };
}
```

## 問題4：実装計画の作成

### 実装計画

#### Phase 1：基本認証（2週間）
```text
Week 1-2:
- ユーザー登録機能
- パスワードハッシュ化（bcrypt）
- ログイン/ログアウト
- セッション管理
```

#### Phase 2：セキュリティ強化（2週間）
```text
Week 3-4:
- パスワードポリシー実装
- アカウントロックアウト機能
- HTTPS必須化
- CSRF対策
```

#### Phase 3：利便性向上（1週間）
```text
Week 5:
- パスワードリセット機能
- Remember Me機能
- ログイン履歴表示
```

#### Phase 4：高度な機能（2週間）
```text
Week 6-7:
- MFA導入（TOTP）
- OAuth2.0連携準備
- 管理者向け機能
```

### セキュリティ考慮事項

```python
# セキュリティ設定の例
SECURITY_CONFIG = {
    # パスワードポリシー
    "password": {
        "min_length": 12,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_special": True,
        "history_count": 5,  # 過去5回のパスワードは再利用不可
        "max_age_days": 90
    },
    
    # セッション設定
    "session": {
        "timeout_minutes": 30,
        "absolute_timeout_hours": 8,
        "secure_cookie": True,
        "http_only": True,
        "same_site": "Strict"
    },
    
    # ロックアウト設定
    "lockout": {
        "max_attempts": 5,
        "lockout_duration_minutes": 30,
        "reset_window_minutes": 15
    }
}
```

### 将来の拡張性

1. **データベース設計**
```sql
-- 拡張可能な認証情報テーブル
CREATE TABLE auth_methods (
    user_id INT,
    method_type VARCHAR(50),  -- 'password', 'totp', 'webauthn'
    method_data JSON,
    created_at TIMESTAMP,
    PRIMARY KEY (user_id, method_type)
);
```

2. **APIの設計**
```text
POST   /api/auth/register
POST   /api/auth/login
POST   /api/auth/logout
POST   /api/auth/refresh
GET    /api/auth/methods     # 利用可能な認証方式
POST   /api/auth/mfa/setup   # MFA設定
DELETE /api/auth/mfa         # MFA解除
```

## 問題5：用語の説明

### シングルサインオン（SSO）

**経営層向け説明：**
「SSOは、会社の建物に入る際の『統合IDカード』のようなものです。1枚のカードで、正門、各フロア、会議室、すべてにアクセスできるように、1回のログインで複数のシステムが使えるようになります。従業員の生産性が向上し、パスワード忘れによるヘルプデスク対応も削減できます。」

### 多要素認証（MFA）

**経営層向け説明：**
「銀行のATMをイメージしてください。キャッシュカード（持ち物）と暗証番号（知識）の2つが必要ですね。MFAも同じで、パスワードに加えて、スマートフォンに送られるコードなど、複数の要素で本人確認をします。これにより、パスワードが漏れても、不正アクセスを防げます。」

### セッション管理

**経営層向け説明：**
「ホテルのチェックインに例えられます。一度フロントで本人確認をしたら、滞在中は部屋の鍵だけで出入りできますね。Webシステムも同じで、最初にログインしたら、その『滞在期間』中は再度パスワードを入力せずに作業できます。ただし、安全のため一定時間で『チェックアウト』させる仕組みも必要です。」

### トークンベース認証

**経営層向け説明：**
「遊園地の『1日パスポート』のようなものです。入場時に本人確認をして発行されたパスポートを見せれば、各アトラクションで再度身分証明する必要はありません。デジタルの世界でも、最初の認証後に発行される『デジタルパスポート』（トークン）を使って、効率的にサービスを利用できます。」

## チャレンジ問題：脅威モデリング

### 想定される脅威

1. **内部不正アクセス**
   - **脅威**：医療従事者による権限外の患者情報閲覧
   - **影響度**：高（プライバシー侵害、信頼失墜）
   - **発生可能性**：中
   - **対策**
     ```
     - 職種別の厳格なRBAC実装
     - アクセスログの全件記録
     - 異常アクセスのリアルタイム検知
     ```

2. **認証情報の窃取**
   - **脅威**：フィッシングによるID/パスワード詐取
   - **影響度**：高（なりすましによる情報漏洩）
   - **発生可能性**：高
   - **対策**
     ```
     - 医療従事者向けMFA必須化
     - フィッシング対策訓練
     - 異常ログインの検知とアラート
     ```

3. **患者による他患者情報へのアクセス**
   - **脅威**：URLパラメータ改ざん等による他者情報閲覧
   - **影響度**：高（個人情報漏洩）
   - **発生可能性**：中
   - **対策**
     ```python
     # オブジェクトレベルの認可チェック
     def get_patient_record(user, patient_id):
         if user.role == "patient" and user.patient_id != patient_id:
             raise AuthorizationError("Access denied")
         return fetch_record(patient_id)
     ```

4. **外部連携における情報漏洩**
   - **脅威**：薬局システムとの通信経路での情報窃取
   - **影響度**：高（処方箋情報の漏洩）
   - **発生可能性**：低
   - **対策**
     ```
     - API間のmTLS実装
     - JWTによる情報の最小化
     - 監査ログの相互保存
     ```

5. **長期間の不正アクセス**
   - **脅威**：退職者アカウントの放置による継続的アクセス
   - **影響度**：高（長期的な情報収集）
   - **発生可能性**：中
   - **対策**
     ```
     - HRシステムとの自動連携
     - 定期的なアクセス権限の棚卸し
     - 最終ログイン日時によるアカウント自動無効化
     ```

### リスク評価マトリクス

```text
影響度
  高│ [1,2,3] │ [4,5]  │        │
  中│         │        │        │
  低│         │        │   [4]  │
    └─────────┴────────┴────────┘
      低        中        高
                発生可能性
```

### 残存リスクの評価

すべての対策を実施しても、以下のリスクが残存します。

1. **ソーシャルエンジニアリング**：技術的対策では完全に防げない
2. **ゼロデイ攻撃**：未知の脆弱性は対策不可能
3. **内部共謀**：複数人による組織的な不正

これらに対しては、継続的な教育、監視強化、インシデント対応体制の整備が必要。
