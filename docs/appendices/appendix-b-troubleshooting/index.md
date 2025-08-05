---
layout: book
order: 17
title: "付録B: トラブルシューティング"
---
# 付録B トラブルシューティングガイド

## B.1 認証が失敗する場合

### B.1.1 パスワード認証の問題

#### 症状：正しいパスワードでもログインできない

**確認ポイント**：

```python
# デバッグコード例
def debug_password_auth(username, password):
    print(f"1. ユーザー検索: {username}")
    user = User.find_by_username(username)
    if not user:
        print("   → ユーザーが見つかりません")
        return
    
    print(f"2. アカウント状態: active={user.is_active}")
    if not user.is_active:
        print("   → アカウントが無効化されています")
        return
    
    print(f"3. パスワードハッシュ形式: {user.password_hash[:20]}...")
    
    # ハッシュアルゴリズムの確認
    if user.password_hash.startswith("$2b$"):
        print("   → bcrypt形式")
    elif user.password_hash.startswith("$argon2"):
        print("   → Argon2形式")
    
    print(f"4. パスワード検証実行")
    is_valid = verify_password(password, user.password_hash)
    print(f"   → 結果: {is_valid}")
```

**よくある原因と対策**：

| 原因 | 対策 | 確認方法 |
|------|------|----------|
| 文字エンコーディング不一致 | UTF-8統一 | `password.encode('utf-8')` |
| ハッシュアルゴリズム不一致 | 移行処理実装 | ハッシュプレフィックス確認 |
| 空白文字の扱い | trim()処理統一 | 前後空白の有無確認 |
| 大文字小文字の扱い | 仕様明確化 | ポリシー文書化 |

#### 症状：パスワードリセットが機能しない

**チェックリスト**：

```yaml
email_configuration:
  - [ ] SMTPサーバー接続確認
  - [ ] 送信元メールアドレスのSPF/DKIM設定
  - [ ] メールテンプレートの変数展開
  - [ ] リンクの有効期限設定

token_generation:
  - [ ] トークンの一意性
  - [ ] 適切な有効期限（推奨：1-2時間）
  - [ ] 使用済みトークンの無効化
  - [ ] タイムゾーンの扱い

security_checks:
  - [ ] レート制限の実装
  - [ ] 同一ユーザーの複数リクエスト制御
  - [ ] トークンの暗号学的安全性
  - [ ] HTTPSでのみ送信
```

### B.1.2 多要素認証の問題

#### 症状：TOTP認証で時刻ずれエラー

**診断スクリプト**：

```python
import pyotp
import time
from datetime import datetime, timezone

def diagnose_totp_issue(secret, user_input_code):
    """TOTP問題の診断"""
    totp = pyotp.TOTP(secret)
    
    # 現在時刻での正しいコード
    current_time = time.time()
    correct_code = totp.at(current_time)
    
    print(f"サーバー時刻: {datetime.now(timezone.utc)}")
    print(f"正しいコード: {correct_code}")
    print(f"入力コード: {user_input_code}")
    
    # 時間窓での検証
    for offset in range(-3, 4):  # ±90秒
        time_at_offset = current_time + (offset * 30)
        code_at_offset = totp.at(time_at_offset)
        
        if code_at_offset == user_input_code:
            print(f"✓ コードは{offset * 30}秒のずれで一致")
            return True
    
    print("✗ 時間窓内で一致するコードなし")
    
    # よくある問題の確認
    if len(user_input_code) != 6:
        print("! コードの桁数が正しくありません")
    
    if not user_input_code.isdigit():
        print("! コードに数字以外が含まれています")
    
    return False
```

**対策実装**：

```python
class FlexibleTOTPVerifier:
    def __init__(self, window=1, future_window=0):
        """
        window: 過去方向の許容ステップ数
        future_window: 未来方向の許容ステップ数
        """
        self.window = window
        self.future_window = future_window
    
    def verify(self, secret, token, for_time=None):
        """柔軟なTOTP検証"""
        if for_time is None:
            for_time = time.time()
        
        # pyotpのverifyメソッドを使用（時間窓対応）
        totp = pyotp.TOTP(secret)
        
        # 通常の検証
        if totp.verify(token, for_time, valid_window=self.window):
            return True, 0
        
        # 未来方向の検証（クライアント時刻が進んでいる場合）
        if self.future_window > 0:
            for i in range(1, self.future_window + 1):
                future_time = for_time + (i * 30)
                if totp.verify(token, future_time, valid_window=0):
                    return True, i * 30
        
        return False, None
```

### B.1.3 WebAuthn/FIDO2の問題

#### 症状：ブラウザが認証器を認識しない

**ブラウザ互換性チェック**：

```javascript
async function checkWebAuthnSupport() {
    const report = {
        supported: false,
        create: false,
        get: false,
        platformAuthenticator: false,
        conditionalMediation: false,
        userVerifying: false
    };
    
    // 基本的なサポート
    if (window.PublicKeyCredential) {
        report.supported = true;
        
        // create/getの確認
        report.create = typeof navigator.credentials.create === 'function';
        report.get = typeof navigator.credentials.get === 'function';
        
        // プラットフォーム認証器
        if (PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
            report.platformAuthenticator = 
                await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        }
        
        // Conditional Mediation (パスキー自動入力)
        if (PublicKeyCredential.isConditionalMediationAvailable) {
            report.conditionalMediation = 
                await PublicKeyCredential.isConditionalMediationAvailable();
        }
    }
    
    console.table(report);
    return report;
}

// HTTPS確認
if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
    console.error('WebAuthnはHTTPS環境でのみ動作します');
}
```

**一般的なエラーと対処法**：

```javascript
class WebAuthnErrorHandler {
    handleError(error) {
        const errorMap = {
            'NotAllowedError': {
                message: 'ユーザーが認証をキャンセルしました',
                action: 'retry',
                userMessage: 'もう一度お試しください'
            },
            'InvalidStateError': {
                message: '認証器がすでに登録されています',
                action: 'use_existing',
                userMessage: 'この認証器は登録済みです'
            },
            'NotSupportedError': {
                message: 'この認証器タイプはサポートされていません',
                action: 'fallback',
                userMessage: '別の認証方法をお試しください'
            },
            'SecurityError': {
                message: 'セキュリティ要件を満たしていません',
                action: 'check_https',
                userMessage: 'HTTPS接続を確認してください'
            },
            'AbortError': {
                message: '操作がタイムアウトしました',
                action: 'retry',
                userMessage: '時間内に認証を完了してください'
            }
        };
        
        const errorInfo = errorMap[error.name] || {
            message: error.message,
            action: 'contact_support',
            userMessage: 'エラーが発生しました'
        };
        
        console.error(`WebAuthn Error: ${error.name}`, error);
        return errorInfo;
    }
}
```

## B.2 セッション管理の問題

### B.2.1 セッションが維持されない

#### 症状：ログイン直後にセッションが切れる

**診断手順**：

```python
def diagnose_session_issue(request, response):
    """セッション問題の診断"""
    issues = []
    
    # 1. Cookieの設定確認
    set_cookie_header = response.headers.get('Set-Cookie', '')
    
    if 'SameSite=None' in set_cookie_header and 'Secure' not in set_cookie_header:
        issues.append("SameSite=NoneにはSecure属性が必須")
    
    if 'HttpOnly' not in set_cookie_header:
        issues.append("HttpOnly属性が設定されていません（XSS脆弱性）")
    
    # 2. ドメイン設定の確認
    cookie_domain = extract_domain_from_cookie(set_cookie_header)
    request_host = request.headers.get('Host', '')
    
    if cookie_domain and not request_host.endswith(cookie_domain):
        issues.append(f"Cookieドメイン({cookie_domain})とリクエストホスト({request_host})が不一致")
    
    # 3. パス設定の確認
    cookie_path = extract_path_from_cookie(set_cookie_header)
    if cookie_path != '/':
        issues.append(f"Cookieパスが制限されています: {cookie_path}")
    
    # 4. プロキシ設定の確認
    x_forwarded_proto = request.headers.get('X-Forwarded-Proto')
    if x_forwarded_proto == 'http' and 'Secure' in set_cookie_header:
        issues.append("プロキシ背後でHTTP通信しているがSecure Cookieを設定")
    
    return issues
```

**Cookieトラブルシューティング表**：

| 問題 | 原因 | 解決策 |
|------|------|--------|
| Safari/iOSで動作しない | SameSite=None未設定 | 明示的に設定 + Secure必須 |
| サブドメイン間で共有されない | Domain属性なし | `.example.com`形式で設定 |
| APIコールで送信されない | CORS設定不備 | `credentials: 'include'` |
| 開発環境で動作しない | Secure属性 | localhost例外処理追加 |

### B.2.2 分散環境でのセッション不整合

#### 症状：ロードバランサー配下でログイン状態が安定しない

**セッションストレージ診断**：

```python
class SessionStorageDiagnostics:
    def __init__(self, redis_clients):
        self.redis_clients = redis_clients  # 複数のRedisノード
    
    async def check_session_replication(self, session_id):
        """セッションレプリケーションの確認"""
        results = {}
        
        for node_name, client in self.redis_clients.items():
            try:
                # セッションデータの取得
                session_data = await client.get(f"session:{session_id}")
                
                if session_data:
                    results[node_name] = {
                        'exists': True,
                        'size': len(session_data),
                        'ttl': await client.ttl(f"session:{session_id}")
                    }
                else:
                    results[node_name] = {'exists': False}
                    
            except Exception as e:
                results[node_name] = {'error': str(e)}
        
        # 整合性チェック
        unique_sessions = set(
            r.get('size', 0) for r in results.values() 
            if r.get('exists')
        )
        
        if len(unique_sessions) > 1:
            print("警告: ノード間でセッションデータのサイズが異なります")
        
        return results
    
    async def test_session_persistence(self):
        """セッション永続性テスト"""
        test_session_id = f"test_{uuid.uuid4()}"
        test_data = {"user": "test", "timestamp": time.time()}
        
        # 書き込みテスト
        write_results = {}
        for node_name, client in self.redis_clients.items():
            start = time.time()
            try:
                await client.setex(
                    f"session:{test_session_id}",
                    300,  # 5分
                    json.dumps(test_data)
                )
                write_results[node_name] = {
                    'success': True,
                    'latency': time.time() - start
                }
            except Exception as e:
                write_results[node_name] = {
                    'success': False,
                    'error': str(e)
                }
        
        # レプリケーション待機
        await asyncio.sleep(0.5)
        
        # 読み取りテスト
        read_results = await self.check_session_replication(test_session_id)
        
        return {
            'write_results': write_results,
            'read_results': read_results,
            'replication_ok': all(r.get('exists') for r in read_results.values())
        }
```

## B.3 パフォーマンス問題

### B.3.1 認証処理が遅い

#### 症状：ログインに数秒かかる

**パフォーマンスプロファイリング**：

```python
import cProfile
import pstats
from io import StringIO

class AuthPerformanceProfiler:
    def profile_authentication(self, username, password):
        """認証処理のプロファイリング"""
        pr = cProfile.Profile()
        pr.enable()
        
        # 認証処理の実行
        try:
            result = authenticate_user(username, password)
        finally:
            pr.disable()
        
        # 結果の解析
        s = StringIO()
        ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
        ps.print_stats(20)  # 上位20個の関数
        
        # ボトルネックの特定
        profile_data = s.getvalue()
        
        # パスワードハッシュ処理の時間
        bcrypt_time = self._extract_time(profile_data, 'bcrypt')
        db_time = self._extract_time(profile_data, 'database')
        
        recommendations = []
        
        if bcrypt_time > 0.5:
            recommendations.append({
                'issue': 'bcryptコストファクターが高すぎる',
                'current': bcrypt_time,
                'recommendation': 'コストファクターを12に調整'
            })
        
        if db_time > 0.1:
            recommendations.append({
                'issue': 'データベースクエリが遅い',
                'current': db_time,
                'recommendation': 'インデックスの追加、コネクションプーリング'
            })
        
        return {
            'total_time': pr.total_tt,
            'profile': profile_data,
            'recommendations': recommendations
        }
```

**最適化チェックリスト**：

```yaml
database_optimization:
  - [ ] ユーザーテーブルのインデックス
    - username/emailカラム
    - 複合インデックスの検討
  - [ ] N+1クエリの解消
    - 権限情報の事前読み込み
    - JOINまたはバッチ取得
  - [ ] コネクションプーリング
    - 適切なプールサイズ
    - コネクション再利用

caching_strategy:
  - [ ] ユーザー情報のキャッシュ
    - TTL: 5-10分
    - 更新時の無効化
  - [ ] 権限情報のキャッシュ
    - TTL: 1時間
    - 役割変更時の無効化
  - [ ] セッションストアの最適化
    - Redisパイプライニング
    - バッチ操作

hash_optimization:
  - [ ] 適切なコストファクター
    - bcrypt: 10-12
    - argon2: メモリとCPUのバランス
  - [ ] ハッシュ処理の非同期化
    - ワーカースレッド使用
    - イベントループのブロッキング回避
```

### B.3.2 大量ログイン時の障害

#### 症状：朝のラッシュ時にシステムダウン

**負荷シミュレーション**：

```python
import asyncio
import aiohttp
import time
from datetime import datetime, timedelta

class LoadTestSimulator:
    def __init__(self, base_url, total_users=10000):
        self.base_url = base_url
        self.total_users = total_users
        self.results = []
    
    async def simulate_morning_rush(self):
        """朝のログインラッシュをシミュレート"""
        # 7:00-9:00の2時間で、ピークは8:00
        async def user_login(user_id, delay):
            await asyncio.sleep(delay)
            
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.post(
                        f"{self.base_url}/auth/login",
                        json={
                            "username": f"user{user_id}",
                            "password": "password"
                        },
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as response:
                        end_time = time.time()
                        
                        self.results.append({
                            'user_id': user_id,
                            'status': response.status,
                            'response_time': end_time - start_time,
                            'timestamp': datetime.now()
                        })
                        
                except asyncio.TimeoutError:
                    self.results.append({
                        'user_id': user_id,
                        'status': 'timeout',
                        'response_time': 30,
                        'timestamp': datetime.now()
                    })
                except Exception as e:
                    self.results.append({
                        'user_id': user_id,
                        'status': 'error',
                        'error': str(e),
                        'timestamp': datetime.now()
                    })
        
        # 正規分布でログイン時刻を分散
        tasks = []
        for i in range(self.total_users):
            # 平均60分（8:00）、標準偏差20分
            delay = max(0, np.random.normal(60, 20) * 60)
            tasks.append(user_login(i, delay))
        
        start_time = time.time()
        await asyncio.gather(*tasks)
        total_time = time.time() - start_time
        
        # 結果の分析
        successful = sum(1 for r in self.results if r.get('status') == 200)
        failed = len(self.results) - successful
        avg_response = np.mean([
            r['response_time'] for r in self.results 
            if r.get('status') == 200
        ])
        
        return {
            'total_users': self.total_users,
            'successful_logins': successful,
            'failed_logins': failed,
            'success_rate': successful / self.total_users * 100,
            'average_response_time': avg_response,
            'total_test_time': total_time,
            'requests_per_second': self.total_users / total_time
        }
```

**スケーリング対策**：

```python
class AutoScalingStrategy:
    def __init__(self):
        self.metrics_history = []
        self.scaling_decisions = []
    
    def analyze_and_recommend(self, current_metrics):
        """メトリクスに基づくスケーリング推奨"""
        recommendations = []
        
        # CPU使用率ベース
        if current_metrics['cpu_usage'] > 80:
            recommendations.append({
                'type': 'scale_out',
                'reason': 'CPU使用率が80%を超過',
                'action': 'インスタンスを2台追加',
                'priority': 'high'
            })
        
        # レスポンスタイムベース
        if current_metrics['p95_response_time'] > 1000:  # 1秒
            recommendations.append({
                'type': 'optimize',
                'reason': 'レスポンスタイムが遅い',
                'action': 'キャッシュ層の追加',
                'priority': 'medium'
            })
        
        # エラー率ベース
        if current_metrics['error_rate'] > 0.01:  # 1%
            recommendations.append({
                'type': 'investigate',
                'reason': 'エラー率が高い',
                'action': 'ログ分析とデバッグ',
                'priority': 'high'
            })
        
        # 予測的スケーリング
        if self._predict_traffic_spike(current_metrics['timestamp']):
            recommendations.append({
                'type': 'pre_scale',
                'reason': '過去のパターンから負荷増大を予測',
                'action': '30分前にインスタンス追加',
                'priority': 'medium'
            })
        
        return recommendations
```

## B.4 セキュリティインシデント対応

### B.4.1 不正アクセスの検知と対応

#### 症状：異常なログイン試行の増加

**リアルタイム検知システム**：

```python
class SecurityIncidentDetector:
    def __init__(self):
        self.thresholds = {
            'failed_login_rate': 10,  # 5分間で10回
            'geo_velocity': 1000,     # km/h
            'concurrent_sessions': 5,  # 同時セッション数
            'unusual_hour_login': (0, 5)  # 深夜帯
        }
    
    async def analyze_login_attempt(self, event):
        """ログイン試行の分析"""
        user_id = event['user_id']
        
        # 1. ブルートフォース検知
        recent_failures = await self.get_recent_failures(user_id)
        if len(recent_failures) >= self.thresholds['failed_login_rate']:
            return {
                'risk_level': 'critical',
                'threat_type': 'brute_force',
                'action': 'block_and_notify',
                'details': f'{len(recent_failures)}回の失敗'
            }
        
        # 2. 地理的異常検知
        last_location = await self.get_last_login_location(user_id)
        if last_location:
            velocity = self.calculate_velocity(
                last_location, 
                event['location'],
                event['timestamp'] - last_location['timestamp']
            )
            
            if velocity > self.thresholds['geo_velocity']:
                return {
                    'risk_level': 'high',
                    'threat_type': 'impossible_travel',
                    'action': 'require_2fa',
                    'details': f'移動速度: {velocity}km/h'
                }
        
        # 3. 同時セッション検知
        active_sessions = await self.get_active_sessions(user_id)
        if len(active_sessions) >= self.thresholds['concurrent_sessions']:
            return {
                'risk_level': 'medium',
                'threat_type': 'concurrent_sessions',
                'action': 'notify_user',
                'details': f'{len(active_sessions)}個の同時セッション'
            }
        
        return {'risk_level': 'low', 'action': 'allow'}
```

**インシデント対応プレイブック**：

```yaml
incident_response_playbook:
  brute_force_attack:
    detection:
      - threshold: "10 failed attempts in 5 minutes"
      - pattern: "Sequential username attempts"
    
    immediate_actions:
      - block_ip_address:
          duration: "24 hours"
          scope: "application_level"
      - enable_captcha:
          affected_ips: "attacking_ip_range"
      - notify_security_team:
          priority: "high"
          channels: ["slack", "pagerduty"]
    
    investigation:
      - check_logs:
          timeframe: "last_24_hours"
          focus: ["source_ips", "user_agents", "attempted_usernames"]
      - analyze_pattern:
          type: ["credential_stuffing", "dictionary_attack", "targeted"]
    
    mitigation:
      - implement_rate_limiting:
          limit: "3 attempts per 5 minutes"
      - enforce_account_lockout:
          threshold: "5 failed attempts"
          duration: "30 minutes"
      - consider_ip_reputation:
          service: "abuseipdb"
          
  account_takeover:
    detection:
      - indicators: ["unusual_location", "new_device", "suspicious_activity"]
    
    immediate_actions:
      - suspend_account:
          grace_period: "0"
      - invalidate_all_sessions:
          except: "verified_devices"
      - force_password_reset:
          method: "secure_email_link"
      
    user_communication:
      - send_notification:
          channels: ["email", "sms", "push"]
          template: "security_alert"
      - provide_instructions:
          content: ["verify_recent_activity", "secure_account", "contact_support"]
```

### B.4.2 データ漏洩の痕跡

#### 症状：異常なデータアクセスパターン

**フォレンジック分析ツール**：

```python
class AuthForensicsAnalyzer:
    def __init__(self, log_sources):
        self.log_sources = log_sources
        
    async def analyze_user_activity(self, user_id, timeframe):
        """ユーザーアクティビティの詳細分析"""
        
        # すべてのログソースから情報収集
        auth_logs = await self.log_sources['auth'].query(user_id, timeframe)
        access_logs = await self.log_sources['access'].query(user_id, timeframe)
        audit_logs = await self.log_sources['audit'].query(user_id, timeframe)
        
        # タイムライン構築
        timeline = self.build_timeline(auth_logs, access_logs, audit_logs)
        
        # 異常パターンの検出
        anomalies = []
        
        # 1. 大量データアクセス
        data_access_volume = self.calculate_data_access_volume(access_logs)
        if data_access_volume > self.get_user_baseline(user_id) * 10:
            anomalies.append({
                'type': 'excessive_data_access',
                'severity': 'high',
                'volume': data_access_volume,
                'timeframe': self.identify_peak_period(access_logs)
            })
        
        # 2. 異常なアクセスパターン
        access_pattern = self.analyze_access_pattern(access_logs)
        if access_pattern['is_automated']:
            anomalies.append({
                'type': 'automated_access',
                'severity': 'critical',
                'indicators': access_pattern['indicators'],
                'confidence': access_pattern['confidence']
            })
        
        # 3. 権限昇格の痕跡
        privilege_changes = self.detect_privilege_escalation(audit_logs)
        if privilege_changes:
            anomalies.append({
                'type': 'privilege_escalation',
                'severity': 'critical',
                'changes': privilege_changes
            })
        
        return {
            'user_id': user_id,
            'timeframe': timeframe,
            'timeline': timeline,
            'anomalies': anomalies,
            'risk_score': self.calculate_risk_score(anomalies),
            'recommendations': self.generate_recommendations(anomalies)
        }
    
    def generate_forensics_report(self, analysis_results):
        """フォレンジックレポートの生成"""
        return {
            'executive_summary': self.create_executive_summary(analysis_results),
            'technical_details': {
                'timeline': analysis_results['timeline'],
                'anomalies': analysis_results['anomalies'],
                'evidence': self.collect_evidence(analysis_results)
            },
            'impact_assessment': self.assess_impact(analysis_results),
            'remediation_steps': self.recommend_remediation(analysis_results),
            'legal_considerations': self.identify_legal_requirements(analysis_results)
        }
```

## B.5 一般的なエラーメッセージと対処法

### B.5.1 エラーメッセージ対応表

| エラーメッセージ | 考えられる原因 | 対処法 |
|-----------------|---------------|--------|
| "Invalid CSRF token" | セッション切れ、Cookie無効 | ページリロード、Cookie設定確認 |
| "Token signature verification failed" | 秘密鍵不一致、改ざん | 鍵設定確認、トークン再発行 |
| "Rate limit exceeded" | 短時間の多数リクエスト | レート制限値の調整、分散処理 |
| "Session expired" | タイムアウト、Redis接続断 | セッション延長、Redis監視 |
| "Invalid state parameter" | OAuth state不一致 | セッション設定、CSRF対策確認 |
| "Authenticator not found" | WebAuthn登録なし | 登録フロー案内、フォールバック |

### B.5.2 デバッグ用ユーティリティ

```python
class AuthDebugger:
    """認証デバッグ用ユーティリティ"""
    
    @staticmethod
    def decode_jwt_unsafe(token):
        """JWTをデコード（検証なし、デバッグ用のみ）"""
        try:
            parts = token.split('.')
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2],
                'expires_at': datetime.fromtimestamp(payload.get('exp', 0)),
                'issued_at': datetime.fromtimestamp(payload.get('iat', 0))
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def test_password_encoding(password):
        """パスワードエンコーディングのテスト"""
        encodings = {
            'utf-8': password.encode('utf-8'),
            'latin-1': password.encode('latin-1', errors='ignore'),
            'ascii': password.encode('ascii', errors='ignore')
        }
        
        results = {}
        for encoding, encoded in encodings.items():
            results[encoding] = {
                'bytes': encoded,
                'hex': encoded.hex(),
                'length': len(encoded)
            }
        
        return results
    
    @staticmethod
    def verify_system_time():
        """システム時刻の確認"""
        import ntplib
        
        try:
            ntp_client = ntplib.NTPClient()
            response = ntp_client.request('pool.ntp.org')
            
            local_time = time.time()
            ntp_time = response.tx_time
            diff = local_time - ntp_time
            
            return {
                'local_time': datetime.fromtimestamp(local_time),
                'ntp_time': datetime.fromtimestamp(ntp_time),
                'difference_seconds': diff,
                'synchronized': abs(diff) < 5
            }
        except Exception as e:
            return {'error': str(e)}
```