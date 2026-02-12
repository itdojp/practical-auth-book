---
layout: book
order: 4
title: "第2章：認証システムの基礎"
---

# 第2章：認証システムの基礎

## 2.1 認証の3要素 - 各要素の特性と使い分け

### 2.1.1 なぜ3要素に分類されるのか

人類は長い歴史の中で、「本人であることを証明する」ための様々な方法を編み出してきました。これらは最終的に3つの本質的なカテゴリーに集約されます。

**歴史的な例：**
```text
古代ローマ：印章（所有物）
中世の城：合言葉（知識）
現代：指紋認証（生体）
```

この3要素への分類は、それぞれが持つ**独立した特性**と**攻撃への耐性**の違いに基づいています。

### 2.1.2 知識要素（Something You Know）

#### 特性と仕組み

知識要素は、本人の記憶に依存する認証方式です。

**利点：**
- 実装が簡単
- コストが低い
- ユーザーにとって馴染みがある

**欠点：**
- 忘れやすい
- 推測可能
- 共有されやすい

**実装例：**
```python
# パスワードの複雑性チェック
import re

def validate_password_strength(password):
    """パスワードの強度を検証する"""
    checks = {
        'length': len(password) >= 12,
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'lowercase': bool(re.search(r'[a-z]', password)),
        'numbers': bool(re.search(r'\d', password)),
        'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
        'no_common_patterns': not any(pattern in password.lower() 
                                     for pattern in ['password', '123456', 'qwerty'])
    }
    
    score = sum(checks.values())
    strength = {
        6: "強",
        5: "中",
        4: "弱",
    }.get(score, "非常に弱")
    
    return {
        'score': score,
        'strength': strength,
        'checks': checks,
        'suggestions': [k for k, v in checks.items() if not v]
    }
```

#### なぜパスワードだけでは不十分なのか

**統計データが示す現実：**
```text
2024年の調査結果：
- 80%のセキュリティ侵害がパスワード関連
- 平均的なユーザーは100個のアカウントを保有
- 65%のユーザーがパスワードを使い回し
- パスワードマネージャーの利用率は30%未満
```

**技術的な脅威：**
1. **ブルートフォース攻撃の高速化**
   ```python
   # GPUを使った攻撃速度の例
   # RTX 4090での推定解析速度
   hash_rates = {
       'MD5': '164.1 GH/s',        # 1641億回/秒
       'SHA1': '58.3 GH/s',         # 583億回/秒
       'bcrypt(cost=12)': '32.5 KH/s',  # 3.25万回/秒
   }
   
   # 8文字の英数字パスワードの解析時間
   def calculate_crack_time(charset_size, length, hash_rate):
       total_combinations = charset_size ** length
       seconds = total_combinations / hash_rate
       return seconds
   ```

2. **データベース漏洩のリスク**
   ```sql
   -- 過去の大規模漏洩事例
   -- Yahoo (2013): 30億アカウント
   -- LinkedIn (2012): 1.17億アカウント
   -- Adobe (2013): 1.53億アカウント
   ```

### 2.1.3 所有物要素（Something You Have）

#### 特性と仕組み

物理的またはデジタル的な「もの」を所有していることで認証します。

**種類と特徴：**
```python
authentication_factors = {
    'hardware_token': {
        'security': 'high',
        'cost': 'high',
        'usability': 'medium',
        'example': 'YubiKey, RSA SecurID'
    },
    'software_token': {
        'security': 'medium',
        'cost': 'low',
        'usability': 'high',
        'example': 'Google Authenticator, Authy'
    },
    'sms_otp': {
        'security': 'low',  # SIMスワッピング攻撃
        'cost': 'medium',
        'usability': 'high',
        'example': 'SMS経由のワンタイムパスワード'
    }
}
```

#### TOTP/HOTPの仕組み

**TOTP (Time-based One-Time Password) の実装：**
```python
import hmac
import time
import struct
import base64

def generate_totp(secret, time_step=30, digits=6):
    """TOTP トークンを生成する"""
    # 現在時刻をtime_stepで割った値をカウンターとする
    counter = int(time.time()) // time_step
    
    # カウンターを8バイトのバイト列に変換
    counter_bytes = struct.pack('>Q', counter)
    
    # HMAC-SHA1でハッシュ値を計算
    hmac_digest = hmac.new(
        base64.b32decode(secret), 
        counter_bytes, 
        'sha1'
    ).digest()
    
    # Dynamic Truncation
    offset = hmac_digest[-1] & 0x0f
    truncated = hmac_digest[offset:offset+4]
    code = struct.unpack('>I', truncated)[0]
    code &= 0x7fffffff
    code %= 10**digits
    
    return str(code).zfill(digits)

# 使用例
secret = "JBSWY3DPEHPK3PXP"  # Base32エンコードされた共有秘密
print(f"現在のTOTPコード: {generate_totp(secret)}")
```

#### なぜ所有物要素が重要なのか

**攻撃シナリオの変化：**
```text
従来：パスワードを盗む → ログイン成功
現在：パスワードを盗む → 所有物がない → ログイン失敗
```

**実際の効果：**
- Google: 従業員へのフィッシング攻撃成功率が0%に
- Microsoft: アカウント侵害が99.9%減少

### 2.1.4 生体要素（Something You Are）

#### 特性と仕組み

個人の身体的または行動的特徴を使用した認証です。

**生体認証の分類：**
```python
biometric_types = {
    '生理的生体認証': {
        '指紋': {
            'FAR': '0.001%',  # 他人受入率
            'FRR': '0.1%',    # 本人拒否率
            'spoofing_risk': 'medium',
            'privacy_concern': 'medium'
        },
        '顔認証': {
            'FAR': '0.01%',
            'FRR': '1%',
            'spoofing_risk': 'high',  # 写真での偽装
            'privacy_concern': 'high'
        },
        '虹彩認証': {
            'FAR': '0.0001%',
            'FRR': '0.01%',
            'spoofing_risk': 'low',
            'privacy_concern': 'medium'
        }
    },
    '行動的生体認証': {
        'キーストローク': {
            'accuracy': '80〜95%',
            'continuous_auth': True,
            'user_training': 'required'
        },
        '歩行認証': {
            'accuracy': '90〜95%',
            'passive': True,
            'device_dependent': True
        }
    }
}
```

#### 生体認証の技術的実装

**特徴抽出と照合の流れ：**
```python
class BiometricAuthenticator:
    def __init__(self):
        self.enrolled_templates = {}
    
    def enroll(self, user_id, biometric_data):
        """生体情報を登録する"""
        # 特徴抽出
        features = self.extract_features(biometric_data)
        
        # テンプレート生成（可逆変換不可能な形式）
        template = self.generate_template(features)
        
        # 保存（暗号化推奨）
        self.enrolled_templates[user_id] = self.encrypt_template(template)
        
    def authenticate(self, user_id, biometric_data):
        """生体認証を実行する"""
        # 登録テンプレートの取得
        stored_template = self.decrypt_template(
            self.enrolled_templates.get(user_id)
        )
        
        if not stored_template:
            return False
        
        # 入力データから特徴抽出
        input_features = self.extract_features(biometric_data)
        input_template = self.generate_template(input_features)
        
        # 類似度計算
        similarity = self.calculate_similarity(stored_template, input_template)
        
        # 閾値判定
        threshold = self.get_threshold()
        return similarity >= threshold
    
    def extract_features(self, biometric_data):
        """生体データから特徴を抽出する"""
        # 実装は生体認証の種類による
        pass
```

### 2.1.5 要素の組み合わせ戦略

#### なぜ複数要素が必要なのか

**単一要素の限界：**
```text
知識要素のみ：
├─ 攻撃：フィッシング、キーロガー
└─ 影響：即座に全権限を奪われる

所有物要素のみ：
├─ 攻撃：デバイスの盗難、複製
└─ 影響：物理的アクセスで突破

生体要素のみ：
├─ 攻撃：偽造、強要
└─ 影響：変更不可能な認証情報の漏洩
```

**多要素認証の防御力：**
```python
# 各要素の突破確率（仮定値）
breach_probability = {
    'password': 0.1,      # 10%
    'totp': 0.01,         # 1%
    'biometric': 0.001,   # 0.1%
}

# 単一要素 vs 多要素
single_factor = breach_probability['password']  # 10%
two_factor = breach_probability['password'] * breach_probability['totp']  # 0.1%
three_factor = single_factor * breach_probability['totp'] * breach_probability['biometric']  # 0.001%

print(f"突破確率の比較:")
print(f"単一要素: {single_factor * 100}%")
print(f"二要素: {two_factor * 100}%")
print(f"三要素: {three_factor * 100}%")
```

## 2.2 パスワード認証の仕組みと限界 - なぜパスワードだけでは不十分なのか

### 2.2.1 パスワード認証の歴史と進化

#### 平文保存時代の教訓

**1960〜1970年代の実装：**
```python
# 絶対にやってはいけない実装例
class InsecurePasswordAuth:
    def __init__(self):
        self.users = {}  # {username: password}
    
    def register(self, username, password):
        self.users[username] = password  # 平文保存！
    
    def authenticate(self, username, password):
        return self.users.get(username) == password

# なぜ危険なのか
"""
1. データベース漏洩時、全パスワードが即座に利用可能
2. 内部者による不正閲覧が可能
3. バックアップやログにパスワードが残る
"""
```

#### ハッシュ化の導入と課題

**単純なハッシュ化の問題：**
```python
import hashlib

# 改善されたが、まだ不十分な実装
class SimpleHashPasswordAuth:
    def __init__(self):
        self.users = {}  # {username: password_hash}
    
    def register(self, username, password):
        # MD5ハッシュ（現在は非推奨）
        password_hash = hashlib.md5(password.encode()).hexdigest()
        self.users[username] = password_hash
    
    def authenticate(self, username, password):
        password_hash = hashlib.md5(password.encode()).hexdigest()
        return self.users.get(username) == password_hash

# この実装の問題点
"""
1. レインボーテーブル攻撃に脆弱
2. 同じパスワードは同じハッシュ値
3. 高速なハッシュ関数は総当たり攻撃に弱い
"""

# レインボーテーブルの例
rainbow_table = {
    '5f4dcc3b5aa765d61d8327deb882cf99': 'password',
    'e10adc3949ba59abbe56e057f20f883e': '123456',
    'd8578edf8458ce06fbc5bb76a58c5ca4': 'qwerty',
    # ... 数百万のエントリ
}
```

### 2.2.2 現代的なパスワード保存の実装

#### ソルトの導入

**なぜソルトが必要なのか：**
```python
import secrets
import hashlib

class SaltedPasswordAuth:
    def __init__(self):
        self.users = {}  # {username: {'salt': salt, 'hash': hash}}
    
    def register(self, username, password):
        # ランダムなソルトを生成
        salt = secrets.token_hex(16)
        
        # パスワードとソルトを結合してハッシュ化
        password_hash = hashlib.sha256(
            (password + salt).encode()
        ).hexdigest()
        
        self.users[username] = {
            'salt': salt,
            'hash': password_hash
        }
    
    def authenticate(self, username, password):
        user_data = self.users.get(username)
        if not user_data:
            return False
        
        # 保存されたソルトを使用して検証
        password_hash = hashlib.sha256(
            (password + user_data['salt']).encode()
        ).hexdigest()
        
        return password_hash == user_data['hash']

# ソルトの効果
"""
パスワード: "password123"
ユーザーA: salt="a1b2c3" → hash="x1y2z3..."
ユーザーB: salt="d4e5f6" → hash="p9q8r7..."
→ 同じパスワードでも異なるハッシュ値
"""
```

#### 適応的ハッシュ関数の使用

**bcryptの実装と利点：**
```python
import bcrypt

class ModernPasswordAuth:
    def __init__(self, work_factor=12):
        self.users = {}
        self.work_factor = work_factor
    
    def register(self, username, password):
        # bcryptは自動的にソルトを生成し、結果に含める
        password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt(self.work_factor)
        )
        self.users[username] = password_hash
    
    def authenticate(self, username, password):
        stored_hash = self.users.get(username)
        if not stored_hash:
            # タイミング攻撃を防ぐため、ダミーの検証を実行
            bcrypt.checkpw(b"dummy", b"$2b$12$dummy.hash.value")
            return False
        
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
    
    def update_work_factor_if_needed(self, username, password):
        """ワークファクターが古い場合、更新する"""
        stored_hash = self.users.get(username)
        if not stored_hash:
            return
        
        # 現在のワークファクターを確認
        current_wf = int(stored_hash.decode().split('$')[2])
        
        if current_wf < self.work_factor:
            # より強力なハッシュに更新
            new_hash = bcrypt.hashpw(
                password.encode('utf-8'),
                bcrypt.gensalt(self.work_factor)
            )
            self.users[username] = new_hash
            print(f"Updated work factor from {current_wf} to {self.work_factor}")

# パフォーマンス測定
import time

def measure_hash_time(password, work_factor):
    start = time.time()
    bcrypt.hashpw(password.encode(), bcrypt.gensalt(work_factor))
    return time.time() - start

# ワークファクターと計算時間の関係
for wf in [8, 10, 12, 14]:
    duration = measure_hash_time("test_password", wf)
    print(f"Work factor {wf}: {duration:.3f} seconds")
```

### 2.2.3 パスワードの脆弱性と攻撃手法

#### 攻撃手法の詳細

**1. 辞書攻撃：**
```python
class DictionaryAttack:
    def __init__(self, dictionary_file):
        with open(dictionary_file, 'r') as f:
            self.common_passwords = [line.strip() for line in f]
    
    def attempt_crack(self, username, auth_system):
        for password in self.common_passwords:
            if auth_system.authenticate(username, password):
                return password
        return None

# よく使われるパスワードのパターン
common_patterns = [
    'password', 'Password1', 'P@ssw0rd',
    '123456', '12345678', '123456789',
    'qwerty', 'abc123', 'football',
    'monkey', 'letmein', 'dragon'
]
```

**2. ブルートフォース攻撃：**
```python
import itertools
import string

class BruteForceAttack:
    def __init__(self):
        self.charset = string.ascii_letters + string.digits + "!@#$%"
    
    def calculate_combinations(self, length):
        """可能な組み合わせ数を計算"""
        return len(self.charset) ** length
    
    def estimate_crack_time(self, length, hashes_per_second):
        """推定解析時間を計算"""
        combinations = self.calculate_combinations(length)
        seconds = combinations / hashes_per_second
        
        units = [
            ('years', 365 * 24 * 60 * 60),
            ('days', 24 * 60 * 60),
            ('hours', 60 * 60),
            ('minutes', 60),
            ('seconds', 1)
        ]
        
        for unit_name, unit_seconds in units:
            if seconds >= unit_seconds:
                return f"{seconds / unit_seconds:.1f} {unit_name}"
        
        return f"{seconds:.1f} seconds"

# 解析時間の推定
attacker = BruteForceAttack()
for length in range(6, 13):
    time_md5 = attacker.estimate_crack_time(length, 164_100_000_000)  # GPU
    time_bcrypt = attacker.estimate_crack_time(length, 32_500)  # GPU
    print(f"Length {length}: MD5={time_md5}, bcrypt={time_bcrypt}")
```

#### パスワードポリシーの限界

**典型的なポリシーとその問題：**
```python
class PasswordPolicy:
    def __init__(self):
        self.rules = {
            'min_length': 8,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special': True,
            'max_length': 20,  # 問題：なぜ上限？
            'history': 5,      # 過去5回のパスワード禁止
            'max_age_days': 90 # 定期変更の強制
        }
    
    def validate(self, password, history=[]):
        issues = []
        
        if len(password) < self.rules['min_length']:
            issues.append("Too short")
        
        # これらのルールがユーザーの行動に与える影響
        """
        結果として生まれるパスワード:
        - Password1! → Password2! → Password3!
        - Summer2024! → Fall2024! → Winter2024!
        - Company123! → Company124! → Company125!
        """
        
        return len(issues) == 0, issues

# より良いアプローチ：パスフレーズ
def generate_passphrase(word_count=4):
    """記憶しやすく強力なパスフレーズを生成"""
    import random
    
    # 一般的な単語のリスト（実際はもっと大きなリストを使用）
    words = ['correct', 'horse', 'battery', 'staple', 'cloud', 
             'mountain', 'river', 'sunset', 'coffee', 'purple']
    
    passphrase = random.sample(words, word_count)
    return ' '.join(passphrase)

# エントロピーの比較
import math

def calculate_entropy(charset_size, length):
    return math.log2(charset_size ** length)

# 複雑な8文字 vs シンプルな4単語
complex_8char = calculate_entropy(72, 8)  # 72文字種、8文字
simple_4words = calculate_entropy(7776, 4)  # 7776単語、4単語

print(f"Complex password (8 chars): {complex_8char:.1f} bits")
print(f"Simple passphrase (4 words): {simple_4words:.1f} bits")
```

### 2.2.4 パスワード管理の現実的な解決策

#### パスワードマネージャーの重要性

```python
class PasswordManager:
    """パスワードマネージャーの基本的な実装例"""
    def __init__(self, master_password):
        self.master_key = self.derive_key(master_password)
        self.vault = {}  # 暗号化されたパスワードを保存
    
    def derive_key(self, master_password):
        """マスターパスワードから暗号化キーを導出"""
        import hashlib
        import pbkdf2
        
        salt = b'stable_salt_for_demo'  # 実際はユーザーごとに異なるsalt
        return pbkdf2.PBKDF2(
            master_password, 
            salt, 
            iterations=100000
        ).read(32)
    
    def generate_password(self, length=20, memorizable=False):
        """強力なパスワードを自動生成"""
        if memorizable:
            # 記憶可能なパスフレーズ
            return generate_passphrase()
        else:
            # ランダムな強力パスワード
            import secrets
            import string
            
            charset = string.ascii_letters + string.digits + "!@#$%^&*"
            return ''.join(secrets.choice(charset) for _ in range(length))
    
    def save_password(self, site, username, password=None):
        """パスワードを暗号化して保存"""
        if password is None:
            password = self.generate_password()
        
        encrypted = self.encrypt(password)
        self.vault[site] = {
            'username': username,
            'password': encrypted
        }
        return password
```

## 2.3 多要素認証（MFA）の必要性 - コストと効果のバランス

### 2.3.1 MFA導入の費用対効果分析

#### 実際のコスト計算

```python
class MFACostAnalysis:
    def __init__(self):
        self.costs = {
            'sms_otp': {
                'setup': 1000,  # 初期実装費用（USD）
                'per_user_monthly': 0.10,  # SMS送信費用
                'support_hours_monthly': 20  # サポート時間
            },
            'totp_app': {
                'setup': 2000,
                'per_user_monthly': 0,  # アプリは無料
                'support_hours_monthly': 10
            },
            'hardware_token': {
                'setup': 3000,
                'per_user_monthly': 2.50,  # トークン費用
                'support_hours_monthly': 5
            },
            'biometric': {
                'setup': 5000,
                'per_user_monthly': 0,
                'support_hours_monthly': 15
            }
        }
        
        self.benefits = {
            'reduced_breaches': 0.999,  # 99.9%の侵害削減
            'password_reset_reduction': 0.7,  # 70%削減
            'compliance_bonus': True,
            'insurance_discount': 0.15  # 15%割引
        }
    
    def calculate_roi(self, method, user_count, years=3):
        """ROI（投資収益率）を計算"""
        cost = self.costs[method]
        
        # 総コスト計算
        total_cost = cost['setup']
        total_cost += cost['per_user_monthly'] * user_count * 12 * years
        total_cost += cost['support_hours_monthly'] * 50 * 12 * years  # $50/hour
        
        # 利益計算（セキュリティ侵害の防止）
        avg_breach_cost = 4_500_000  # 平均的な侵害コスト
        breach_probability_without_mfa = 0.3  # 3年間で30%
        prevented_loss = avg_breach_cost * breach_probability_without_mfa * self.benefits['reduced_breaches']
        
        # パスワードリセットコスト削減
        reset_cost_per_incident = 70
        resets_per_user_year = 2
        reset_savings = reset_cost_per_incident * resets_per_user_year * user_count * years * self.benefits['password_reset_reduction']
        
        total_benefit = prevented_loss + reset_savings
        roi = (total_benefit - total_cost) / total_cost * 100
        
        return {
            'total_cost': total_cost,
            'total_benefit': total_benefit,
            'roi_percentage': roi,
            'payback_months': (total_cost / (total_benefit / (years * 12)))
        }

# 分析実行
analyzer = MFACostAnalysis()
for method in ['sms_otp', 'totp_app', 'hardware_token']:
    result = analyzer.calculate_roi(method, user_count=1000)
    print(f"\n{method}:")
    print(f"  ROI: {result['roi_percentage']:.1f}%")
    print(f"  Payback: {result['payback_months']:.1f} months")
```

### 2.3.2 段階的なMFA導入戦略

#### リスクベースのアプローチ

```python
class RiskBasedMFA:
    def __init__(self):
        self.risk_factors = {
            'login_location': {'weight': 0.3, 'threshold': 100},  # km from usual
            'device_trust': {'weight': 0.3, 'threshold': 0.5},
            'time_unusual': {'weight': 0.2, 'threshold': 3},  # hours from usual
            'failed_attempts': {'weight': 0.2, 'threshold': 2}
        }
    
    def calculate_risk_score(self, login_context):
        """ログインコンテキストからリスクスコアを計算"""
        score = 0
        
        # 地理的異常
        if login_context['distance_from_usual'] > self.risk_factors['login_location']['threshold']:
            score += self.risk_factors['login_location']['weight']
        
        # デバイスの信頼性
        if login_context['device_trust_score'] < self.risk_factors['device_trust']['threshold']:
            score += self.risk_factors['device_trust']['weight']
        
        # 時間的異常
        if abs(login_context['hour_difference']) > self.risk_factors['time_unusual']['threshold']:
            score += self.risk_factors['time_unusual']['weight']
        
        # 失敗試行
        if login_context['recent_failures'] > self.risk_factors['failed_attempts']['threshold']:
            score += self.risk_factors['failed_attempts']['weight']
        
        return score
    
    def determine_mfa_requirement(self, user, risk_score):
        """リスクスコアに基づいてMFA要件を決定"""
        if risk_score < 0.3:
            return None  # MFA不要
        elif risk_score < 0.6:
            return 'totp'  # 標準的なMFA
        elif risk_score < 0.8:
            return 'totp+sms'  # 強化MFA
        else:
            return 'totp+biometric'  # 最高レベルMFA
    
    def adaptive_authentication_flow(self, user, login_context):
        """適応的認証フロー"""
        # パスワード認証（必須）
        if not self.verify_password(user, login_context['password']):
            return False, "Invalid password"
        
        # リスク評価
        risk_score = self.calculate_risk_score(login_context)
        mfa_requirement = self.determine_mfa_requirement(user, risk_score)
        
        # MFAが必要な場合
        if mfa_requirement:
            mfa_result = self.perform_mfa(user, mfa_requirement)
            if not mfa_result:
                return False, f"MFA required: {mfa_requirement}"
        
        # 認証成功後の処理
        self.update_user_baseline(user, login_context)
        return True, "Authentication successful"
```

### 2.3.3 ユーザビリティとセキュリティのバランス

#### UXを考慮したMFA実装

```python
class UserFriendlyMFA:
    def __init__(self):
        self.trusted_devices = {}  # device_id -> trust_info
        self.user_preferences = {}  # user_id -> preferences
    
    def setup_mfa_with_recovery(self, user_id):
        """ユーザーフレンドリーなMFAセットアップ"""
        setup_flow = {
            'primary_method': None,
            'backup_methods': [],
            'recovery_codes': []
        }
        
        # 1. プライマリ方式の選択を促す
        print("Choose your preferred authentication method:")
        print("1. Authenticator app (most secure)")
        print("2. SMS (convenient)")
        print("3. Security key (most convenient)")
        
        # 2. バックアップ方式の設定を必須に
        print("\nSet up a backup method (required):")
        
        # 3. リカバリーコードの生成
        recovery_codes = self.generate_recovery_codes()
        setup_flow['recovery_codes'] = recovery_codes
        
        # 4. 明確な説明とともに保存を促す
        print("\nIMPORTANT: Save these recovery codes:")
        print("You'll need them if you lose access to your phone")
        for code in recovery_codes:
            print(f"  • {code}")
        
        return setup_flow
    
    def generate_recovery_codes(self, count=10):
        """人間が読みやすいリカバリーコードを生成"""
        import secrets
        codes = []
        
        for _ in range(count):
            # 読みやすい形式: XXXX-XXXX-XXXX
            parts = []
            for _ in range(3):
                part = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') 
                              for _ in range(4))
                parts.append(part)
            codes.append('-'.join(parts))
        
        return codes
    
    def remember_device_securely(self, user_id, device_info, duration_days=30):
        """デバイスを安全に記憶"""
        import hmac
        import json
        
        device_fingerprint = self.calculate_device_fingerprint(device_info)
        
        # デバイストークンの生成
        device_token = secrets.token_urlsafe(32)
        
        # サーバー側で保存する情報
        trust_info = {
            'user_id': user_id,
            'fingerprint': device_fingerprint,
            'trusted_until': time.time() + (duration_days * 24 * 60 * 60),
            'token_hash': hashlib.sha256(device_token.encode()).hexdigest()
        }
        
        self.trusted_devices[device_fingerprint] = trust_info
        
        # クライアントに返すトークン
        return device_token
    
    def calculate_device_fingerprint(self, device_info):
        """デバイスフィンガープリントを計算"""
        # ブラウザ情報を組み合わせて一意性を確保
        fingerprint_data = {
            'user_agent': device_info.get('user_agent'),
            'accept_language': device_info.get('accept_language'),
            'screen_resolution': device_info.get('screen_resolution'),
            'timezone': device_info.get('timezone'),
            'canvas_fingerprint': device_info.get('canvas_fingerprint')
        }
        
        # 安定したハッシュ値を生成
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()
```

## 2.4 生体認証とその課題 - プライバシーと利便性のトレードオフ

### 2.4.1 生体認証の技術的実装

#### 特徴抽出とテンプレート生成

```python
import numpy as np
from typing import List, Tuple, Optional

class BiometricSystem:
    def __init__(self):
        self.templates = {}  # 生体テンプレートのデータベース
        self.privacy_preserving = True
    
    def extract_minutiae_points(self, fingerprint_image) -> List[Tuple[int, int, float]]:
        """指紋から特徴点を抽出（簡略化した例）"""
        # 実際の実装では画像処理ライブラリを使用
        minutiae = []
        
        # リッジエンディング（隆線の終端）の検出
        # バイファーケーション（隆線の分岐）の検出
        # 各特徴点の座標と角度を記録
        
        # ダミーデータ（実際は画像処理で抽出）
        minutiae = [
            (120, 150, 45.0),   # (x, y, angle)
            (200, 180, 90.0),
            (150, 220, 135.0),
        ]
        
        return minutiae
    
    def create_cancelable_template(self, biometric_features):
        """キャンセラブルバイオメトリクスの実装"""
        # 生体情報を直接保存しない
        # 変換関数を適用して、元に戻せない形式に
        
        # ランダム射影による変換
        random_matrix = np.random.randn(len(biometric_features), len(biometric_features))
        transformed = np.dot(biometric_features, random_matrix)
        
        # さらにハッシュ化
        template_hash = hashlib.sha256(transformed.tobytes()).hexdigest()
        
        return {
            'template': template_hash,
            'transform_id': 'random_projection_v1',
            'metadata': {
                'created_at': time.time(),
                'quality_score': self.assess_quality(biometric_features)
            }
        }
    
    def match_templates(self, probe_template, stored_template, threshold=0.95):
        """テンプレートマッチング"""
        # ハミング距離やユークリッド距離での比較
        similarity = self.calculate_similarity(probe_template, stored_template)
        
        # 閾値判定
        return similarity >= threshold
    
    def implement_liveness_detection(self, biometric_input):
        """なりすまし防止のための生体検知"""
        checks = {
            'motion_detected': False,
            'texture_analysis': False,
            'thermal_signature': False,
            'pulse_detected': False
        }
        
        # 顔認証の場合の例
        if biometric_input['type'] == 'face':
            # まばたき検出
            checks['motion_detected'] = self.detect_eye_blink(biometric_input)
            
            # テクスチャ分析（写真vs実物）
            checks['texture_analysis'] = self.analyze_skin_texture(biometric_input)
        
        # 指紋認証の場合
        elif biometric_input['type'] == 'fingerprint':
            # 汗腺の活動検出
            checks['pulse_detected'] = self.detect_pulse(biometric_input)
            
            # 温度チェック
            checks['thermal_signature'] = self.check_temperature(biometric_input)
        
        # 総合判定
        return sum(checks.values()) >= 2
```

### 2.4.2 プライバシー保護技術

#### 生体情報の保護

```python
class PrivacyPreservingBiometrics:
    def __init__(self):
        self.homomorphic_encryption = True
        self.secure_multiparty = True
    
    def implement_biometric_hashing(self, biometric_data):
        """生体ハッシュの実装"""
        # 1. 特徴抽出
        features = self.extract_features(biometric_data)
        
        # 2. エラー訂正符号の適用
        # 生体情報の微小な変動を吸収
        ecc_encoded = self.apply_error_correction(features)
        
        # 3. ハッシュ関数の適用
        bio_hash = hashlib.sha256(ecc_encoded).hexdigest()
        
        return bio_hash
    
    def fuzzy_commitment_scheme(self, biometric_data, secret_key):
        """ファジーコミットメント方式"""
        # 生体情報とシークレットキーを結合
        # 認証時に生体情報から鍵を復元
        
        features = self.extract_features(biometric_data)
        
        # リードソロモン符号でエンコード
        codeword = self.reed_solomon_encode(secret_key)
        
        # XOR演算でコミット
        commitment = self.xor_arrays(features, codeword)
        
        return {
            'commitment': commitment,
            'hash': hashlib.sha256(secret_key).hexdigest()
        }
    
    def implement_federated_biometrics(self):
        """連合学習を使った生体認証"""
        class FederatedBiometricModel:
            def __init__(self):
                self.local_models = {}
                self.global_model = None
            
            def train_local_model(self, user_id, biometric_samples):
                """ローカルでモデルを訓練"""
                # ユーザーのデバイス上で実行
                # 生データはデバイスから出ない
                local_model = self.create_model()
                local_model.train(biometric_samples)
                
                # モデルの重みのみを送信
                model_weights = local_model.get_weights()
                return model_weights
            
            def aggregate_models(self, model_weights_list):
                """モデルの集約（サーバー側）"""
                # Federated Averagingアルゴリズム
                averaged_weights = np.mean(model_weights_list, axis=0)
                self.global_model.set_weights(averaged_weights)
        
        return FederatedBiometricModel()
```

### 2.4.3 生体認証の課題と対策

#### 技術的課題

```python
class BiometricChallenges:
    def __init__(self):
        self.challenges = {
            'permanence': {
                'issue': '生体情報は変更不可能',
                'impact': '漏洩時の影響が永続的',
                'mitigation': 'キャンセラブルバイオメトリクス'
            },
            'accuracy': {
                'issue': '完璧ではない認識精度',
                'impact': 'FARとFRRのトレードオフ',
                'mitigation': 'マルチモーダル認証'
            },
            'spoofing': {
                'issue': '偽造攻撃の可能性',
                'impact': 'シリコン指紋、写真、3Dマスク',
                'mitigation': '生体検知技術'
            },
            'privacy': {
                'issue': 'センシティブな個人情報',
                'impact': '健康情報の漏洩リスク',
                'mitigation': 'テンプレート保護技術'
            }
        }
    
    def implement_multimodal_biometrics(self):
        """マルチモーダル生体認証の実装"""
        class MultimodalBiometric:
            def __init__(self):
                self.modalities = {
                    'face': {'weight': 0.4, 'threshold': 0.92},
                    'voice': {'weight': 0.3, 'threshold': 0.88},
                    'behavior': {'weight': 0.3, 'threshold': 0.85}
                }
            
            def fuse_scores(self, individual_scores):
                """スコアレベルフュージョン"""
                # 重み付き平均
                weighted_sum = 0
                total_weight = 0
                
                for modality, score in individual_scores.items():
                    if modality in self.modalities:
                        weighted_sum += score * self.modalities[modality]['weight']
                        total_weight += self.modalities[modality]['weight']
                
                if total_weight > 0:
                    final_score = weighted_sum / total_weight
                else:
                    final_score = 0
                
                return final_score
            
            def adaptive_fusion(self, individual_scores, context):
                """コンテキストに応じた適応的フュージョン"""
                # 環境に応じて重みを調整
                if context['noise_level'] > 0.7:
                    # 騒音が多い場合、音声認証の重みを下げる
                    self.modalities['voice']['weight'] *= 0.5
                
                if context['lighting'] < 0.3:
                    # 照明が悪い場合、顔認証の重みを下げる
                    self.modalities['face']['weight'] *= 0.5
                
                # 重みの正規化
                total = sum(m['weight'] for m in self.modalities.values())
                for modality in self.modalities:
                    self.modalities[modality]['weight'] /= total
                
                return self.fuse_scores(individual_scores)
        
        return MultimodalBiometric()
```

#### 社会的・倫理的課題

```python
class BiometricEthics:
    def __init__(self):
        self.ethical_guidelines = {
            'consent': {
                'requirement': '明示的な同意の取得',
                'implementation': self.implement_consent_management
            },
            'purpose_limitation': {
                'requirement': '目的外使用の禁止',
                'implementation': self.implement_purpose_binding
            },
            'data_minimization': {
                'requirement': '必要最小限のデータ収集',
                'implementation': self.implement_data_minimization
            },
            'transparency': {
                'requirement': '処理の透明性確保',
                'implementation': self.implement_audit_trail
            }
        }
    
    def implement_consent_management(self, user_id):
        """同意管理の実装"""
        consent_record = {
            'user_id': user_id,
            'timestamp': time.time(),
            'consent_items': {
                'biometric_collection': False,
                'biometric_storage': False,
                'biometric_processing': False,
                'data_sharing': False
            },
            'purpose': 'authentication_only',
            'retention_period': '2_years',
            'withdrawal_method': 'available'
        }
        
        # インフォームドコンセントの確保
        print("Biometric Data Collection Notice:")
        print("- What: Facial features for authentication")
        print("- Why: Secure access to your account")
        print("- How long: 2 years or until withdrawn")
        print("- Your rights: Access, deletion, portability")
        
        return consent_record
    
    def implement_gdpr_compliance(self):
        """GDPR準拠の実装"""
        class GDPRCompliantBiometrics:
            def __init__(self):
                self.lawful_basis = 'explicit_consent'
                self.data_protection_impact_assessment = True
            
            def right_to_erasure(self, user_id):
                """忘れられる権利の実装"""
                # 1. すべての生体テンプレートを削除
                self.delete_biometric_templates(user_id)
                
                # 2. バックアップからも削除
                self.delete_from_backups(user_id)
                
                # 3. 削除証明書の発行
                deletion_certificate = {
                    'user_id': user_id,
                    'deleted_at': time.time(),
                    'data_types': ['biometric_templates', 'raw_biometric_data'],
                    'confirmation': hashlib.sha256(f"{user_id}{time.time()}".encode()).hexdigest()
                }
                
                return deletion_certificate
            
            def data_portability(self, user_id):
                """データポータビリティの実装"""
                # 機械可読形式でのエクスポート
                user_data = {
                    'biometric_metadata': self.get_metadata(user_id),
                    'consent_history': self.get_consent_history(user_id),
                    'access_logs': self.get_access_logs(user_id)
                }
                
                # 生体情報そのものは含めない（セキュリティリスク）
                return json.dumps(user_data, indent=2)
        
        return GDPRCompliantBiometrics()
```

## まとめ

この章では、認証技術の基礎として以下を学びました：

1. **認証の3要素**
   - 各要素の特性と適用場面
   - 単一要素の限界と多要素の必要性

2. **パスワード認証の進化と限界**
   - ハッシュ化技術の発展
   - 現代的な脅威への対応

3. **多要素認証の実装**
   - コストと効果のバランス
   - ユーザビリティの考慮

4. **生体認証の可能性と課題**
   - プライバシー保護技術
   - 倫理的考慮事項

次章では、これらの認証された利用者に対して、適切な権限を付与する「認可」の仕組みについて詳しく学んでいきます。

## 演習問題

### 問題1：パスワードハッシュ化の実装
以下の要件を満たすパスワード認証システムを実装しなさい：
- bcryptを使用したハッシュ化
- 適切なワークファクターの設定
- タイミング攻撃への対策
- パスワード強度の検証

### 問題2：TOTP実装の比較
Google AuthenticatorとAuthyの実装を比較し、以下の観点から分析しなさい：
- セキュリティ機能の違い
- バックアップとリカバリー
- ユーザビリティ
- 企業での採用における考慮事項

### 問題3：生体認証システムの設計
中規模企業（従業員500名）向けの生体認証システムを設計しなさい。以下を含むこと：
- 認証方式の選択とその理由
- プライバシー保護の対策
- フォールバック認証の設計
- 予算とROIの試算

### 問題4：MFA導入計画
既存のパスワードのみのシステムにMFAを導入する計画を立てなさい：
- 段階的な展開計画
- ユーザー教育プログラム
- サポート体制
- 成功指標の定義

### 問題5：セキュリティインシデント対応
以下のシナリオに対する対応策を検討しなさい：
「従業員の生体認証データベースへの不正アクセスが発見された。影響範囲は不明。」
- 初動対応
- 影響調査
- 利用者への通知
- 再発防止策

### チャレンジ問題：次世代認証の提案
現在の認証技術の課題を踏まえ、5年後の認証システムを提案しなさい。以下を考慮すること：
- 量子コンピュータへの耐性
- プライバシー規制の強化
- ユーザー体験の向上
- 実装可能性
