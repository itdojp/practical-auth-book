# 付録A 環境構築ガイド

## A.1 開発環境のセットアップ

### A.1.1 必要なツールとバージョン

認証認可システムの開発に必要な環境を構築します。本書のサンプルコードを動作させるために、以下のツールをインストールしてください。

```python
class DevelopmentEnvironment:
    """開発環境のセットアップガイド"""
    
    def required_tools(self):
        """必要なツールとバージョン"""
        
        return {
            'languages': {
                'python': {
                    'version': '3.9+',
                    'install': {
                        'mac': 'brew install python@3.11',
                        'ubuntu': 'sudo apt-get install python3.11',
                        'windows': 'Download from python.org or use pyenv-win'
                    },
                    'verify': 'python --version'
                },
                'nodejs': {
                    'version': '18.x LTS or 20.x LTS',
                    'install': {
                        'mac': 'brew install node',
                        'ubuntu': 'curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash - && sudo apt-get install -y nodejs',
                        'windows': 'Download from nodejs.org or use nvm-windows'
                    },
                    'verify': 'node --version && npm --version'
                },
                'java': {
                    'version': '17+ (LTS)',
                    'install': {
                        'mac': 'brew install openjdk@17',
                        'ubuntu': 'sudo apt-get install openjdk-17-jdk',
                        'windows': 'Download from adoptium.net'
                    },
                    'verify': 'java -version'
                },
                'go': {
                    'version': '1.21+',
                    'install': {
                        'mac': 'brew install go',
                        'ubuntu': 'sudo snap install go --classic',
                        'windows': 'Download from go.dev'
                    },
                    'verify': 'go version'
                }
            },
            
            'databases': {
                'postgresql': {
                    'version': '15+',
                    'install': {
                        'mac': 'brew install postgresql@15 && brew services start postgresql@15',
                        'ubuntu': 'sudo apt-get install postgresql-15',
                        'windows': 'Download from postgresql.org',
                        'docker': 'docker run -d --name postgres -e POSTGRES_PASSWORD=password -p 5432:5432 postgres:15'
                    },
                    'verify': 'psql --version'
                },
                'redis': {
                    'version': '7+',
                    'install': {
                        'mac': 'brew install redis && brew services start redis',
                        'ubuntu': 'sudo apt-get install redis-server',
                        'windows': 'Use WSL2 or Docker',
                        'docker': 'docker run -d --name redis -p 6379:6379 redis:7-alpine'
                    },
                    'verify': 'redis-cli --version'
                }
            },
            
            'tools': {
                'docker': {
                    'version': '24+',
                    'install': 'Download Docker Desktop from docker.com',
                    'verify': 'docker --version && docker compose version'
                },
                'git': {
                    'version': '2.40+',
                    'install': {
                        'mac': 'brew install git',
                        'ubuntu': 'sudo apt-get install git',
                        'windows': 'Download from git-scm.com'
                    },
                    'verify': 'git --version'
                },
                'curl': {
                    'install': 'Usually pre-installed, or install via package manager',
                    'verify': 'curl --version'
                },
                'jq': {
                    'install': {
                        'mac': 'brew install jq',
                        'ubuntu': 'sudo apt-get install jq',
                        'windows': 'Download from github.com/stedolan/jq'
                    },
                    'verify': 'jq --version'
                }
            }
        }
```

### A.1.2 統合開発環境（IDE）のセットアップ

```python
class IDESetup:
    """IDE設定ガイド"""
    
    def vscode_setup(self):
        """Visual Studio Codeの設定"""
        
        return {
            'extensions': [
                {
                    'name': 'Python',
                    'id': 'ms-python.python',
                    'purpose': 'Python開発サポート'
                },
                {
                    'name': 'Pylance',
                    'id': 'ms-python.vscode-pylance',
                    'purpose': '高度なPython言語サポート'
                },
                {
                    'name': 'ESLint',
                    'id': 'dbaeumer.vscode-eslint',
                    'purpose': 'JavaScript/TypeScriptリンティング'
                },
                {
                    'name': 'Prettier',
                    'id': 'esbenp.prettier-vscode',
                    'purpose': 'コードフォーマッター'
                },
                {
                    'name': 'Docker',
                    'id': 'ms-azuretools.vscode-docker',
                    'purpose': 'Dockerサポート'
                },
                {
                    'name': 'Thunder Client',
                    'id': 'rangav.vscode-thunder-client',
                    'purpose': 'REST APIテスト'
                },
                {
                    'name': 'GitLens',
                    'id': 'eamodio.gitlens',
                    'purpose': 'Git統合強化'
                }
            ],
            
            'settings': '''
            {
              "editor.formatOnSave": true,
              "editor.rulers": [80, 120],
              "editor.tabSize": 4,
              
              "[python]": {
                "editor.defaultFormatter": "ms-python.black-formatter"
              },
              
              "[javascript]": {
                "editor.defaultFormatter": "esbenp.prettier-vscode",
                "editor.tabSize": 2
              },
              
              "[typescript]": {
                "editor.defaultFormatter": "esbenp.prettier-vscode",
                "editor.tabSize": 2
              },
              
              "python.linting.enabled": true,
              "python.linting.pylintEnabled": true,
              "python.linting.flake8Enabled": true,
              "python.testing.pytestEnabled": true,
              
              "files.exclude": {
                "**/__pycache__": true,
                "**/*.pyc": true,
                "**/node_modules": true,
                "**/.pytest_cache": true
              }
            }
            '''
        }
    
    def jetbrains_setup(self):
        """JetBrains IDE（PyCharm/IntelliJ）の設定"""
        
        return {
            'plugins': [
                'Python',
                'Node.js',
                'Docker',
                'Database Tools',
                'HTTP Client',
                '.env files support',
                'Markdown'
            ],
            
            'run_configurations': '''
            <!-- PyCharm Run Configuration -->
            <component name="ProjectRunConfigurationManager">
              <configuration default="false" name="Auth Service" type="Python">
                <module name="auth-service" />
                <option name="INTERPRETER_OPTIONS" value="" />
                <option name="PARENT_ENVS" value="true" />
                <envs>
                  <env name="PYTHONUNBUFFERED" value="1" />
                  <env name="DATABASE_URL" value="postgresql://localhost/authdb" />
                  <env name="REDIS_URL" value="redis://localhost:6379" />
                  <env name="JWT_SECRET" value="development-secret" />
                  <env name="ENVIRONMENT" value="development" />
                </envs>
                <option name="WORKING_DIRECTORY" value="$PROJECT_DIR$" />
                <option name="IS_MODULE_SDK" value="true" />
                <option name="ADD_CONTENT_ROOTS" value="true" />
                <option name="ADD_SOURCE_ROOTS" value="true" />
                <option name="SCRIPT_NAME" value="$PROJECT_DIR$/main.py" />
                <option name="PARAMETERS" value="" />
              </configuration>
            </component>
            '''
        }
```

## A.2 プロジェクトのセットアップ

### A.2.1 リポジトリのクローンと初期設定

```bash
# リポジトリのクローン
git clone https://github.com/your-org/practical-auth-book-examples.git
cd practical-auth-book-examples

# Pythonプロジェクトのセットアップ
cd python-examples
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Node.jsプロジェクトのセットアップ
cd ../nodejs-examples
npm install
npm run build

# Javaプロジェクトのセットアップ
cd ../java-examples
./mvnw install

# Goプロジェクトのセットアップ
cd ../go-examples
go mod download
go build ./...
```

### A.2.2 Docker Composeによる統合環境

```yaml
version: '3.9'

services:
  # PostgreSQLデータベース
  postgres:
    image: postgres:15-alpine
    container_name: auth-postgres
    environment:
      POSTGRES_USER: authuser
      POSTGRES_PASSWORD: authpass
      POSTGRES_DB: authdb
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authuser"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Redis
  redis:
    image: redis:7-alpine
    container_name: auth-redis
    ports:
      - "6379:6379"
    command: redis-server --requirepass authredispass
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Keycloak（OAuth/OIDC プロバイダー）
  keycloak:
    image: quay.io/keycloak/keycloak:22.0
    container_name: auth-keycloak
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: authuser
      KC_DB_PASSWORD: authpass
    ports:
      - "8080:8080"
    command: start-dev
    depends_on:
      postgres:
        condition: service_healthy

  # Mailhog（メール送信テスト）
  mailhog:
    image: mailhog/mailhog:latest
    container_name: auth-mailhog
    ports:
      - "1025:1025"  # SMTP
      - "8025:8025"  # Web UI

  # Adminer（データベース管理）
  adminer:
    image: adminer:latest
    container_name: auth-adminer
    ports:
      - "8081:8080"
    depends_on:
      - postgres

volumes:
  postgres_data:
  redis_data:
```

### A.2.3 環境変数の設定

```python
class EnvironmentConfiguration:
    """環境変数設定ガイド"""
    
    def create_env_file(self):
        """.envファイルのテンプレート"""
        
        return '''
# Application Settings
APP_NAME=AuthService
APP_ENV=development
APP_PORT=3000
APP_HOST=0.0.0.0
LOG_LEVEL=debug

# Database Configuration
DATABASE_URL=postgresql://authuser:authpass@localhost:5432/authdb
DATABASE_POOL_SIZE=20
DATABASE_POOL_TIMEOUT=30
DATABASE_SSL_MODE=prefer

# Redis Configuration
REDIS_URL=redis://:authredispass@localhost:6379/0
REDIS_POOL_SIZE=10
REDIS_KEY_PREFIX=auth:

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-key-change-in-production
JWT_PUBLIC_KEY_PATH=./keys/jwt_public.pem
JWT_PRIVATE_KEY_PATH=./keys/jwt_private.pem
JWT_ALGORITHM=RS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30

# Session Configuration
SESSION_SECRET=your-session-secret-change-in-production
SESSION_COOKIE_NAME=auth_session
SESSION_COOKIE_SECURE=false  # true in production
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=lax
SESSION_TIMEOUT_MINUTES=60

# OAuth2 Configuration
OAUTH2_GOOGLE_CLIENT_ID=your-google-client-id
OAUTH2_GOOGLE_CLIENT_SECRET=your-google-client-secret
OAUTH2_GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google/callback

OAUTH2_GITHUB_CLIENT_ID=your-github-client-id
OAUTH2_GITHUB_CLIENT_SECRET=your-github-client-secret
OAUTH2_GITHUB_REDIRECT_URI=http://localhost:3000/auth/github/callback

# Security Settings
BCRYPT_ROUNDS=12
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_HISTORY_COUNT=5

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_WINDOW_MS=900000  # 15 minutes
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_LOGIN_MAX_ATTEMPTS=5
RATE_LIMIT_LOGIN_WINDOW_MS=900000

# CORS Settings
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=Content-Type,Authorization
CORS_ALLOW_CREDENTIALS=true

# Email Configuration
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_SECURE=false
SMTP_USER=
SMTP_PASS=
EMAIL_FROM=noreply@authservice.local

# Monitoring
METRICS_ENABLED=true
METRICS_PORT=9090
TRACING_ENABLED=true
TRACING_ENDPOINT=http://localhost:4318/v1/traces
        '''
    
    def setup_ssl_certificates(self):
        """SSL証明書の生成"""
        
        return '''
        #!/bin/bash
        
        # 開発用の自己署名証明書を生成
        
        # ディレクトリ作成
        mkdir -p certs
        cd certs
        
        # RSA秘密鍵の生成（JWT用）
        openssl genrsa -out jwt_private.pem 4096
        openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
        
        # HTTPS用の証明書生成
        openssl req -x509 -newkey rsa:4096 -nodes \
          -keyout server.key \
          -out server.crt \
          -days 365 \
          -subj "/C=JP/ST=Tokyo/L=Tokyo/O=AuthService/CN=localhost"
        
        # 証明書の情報表示
        openssl x509 -in server.crt -text -noout
        
        echo "証明書の生成が完了しました："
        echo "  - JWT秘密鍵: certs/jwt_private.pem"
        echo "  - JWT公開鍵: certs/jwt_public.pem"
        echo "  - HTTPS秘密鍵: certs/server.key"
        echo "  - HTTPS証明書: certs/server.crt"
        '''
```

## A.3 サンプルアプリケーションの実行

### A.3.1 各言語でのサンプル実行

```python
class SampleApplicationRunner:
    """サンプルアプリケーションの実行ガイド"""
    
    def run_python_sample(self):
        """Pythonサンプルの実行"""
        
        return '''
        # 1. データベースのマイグレーション
        cd python-examples
        alembic upgrade head
        
        # 2. アプリケーションの起動
        uvicorn main:app --reload --host 0.0.0.0 --port 8000
        
        # 3. 動作確認
        # ヘルスチェック
        curl http://localhost:8000/health
        
        # ユーザー登録
        curl -X POST http://localhost:8000/api/v1/auth/register \
          -H "Content-Type: application/json" \
          -d '{
            "email": "test@example.com",
            "password": "SecurePass123!",
            "name": "Test User"
          }'
        
        # ログイン
        curl -X POST http://localhost:8000/api/v1/auth/login \
          -H "Content-Type: application/json" \
          -d '{
            "email": "test@example.com",
            "password": "SecurePass123!"
          }'
        '''
    
    def run_nodejs_sample(self):
        """Node.jsサンプルの実行"""
        
        return '''
        # 1. データベースのマイグレーション
        cd nodejs-examples
        npm run db:migrate
        
        # 2. アプリケーションの起動（開発モード）
        npm run dev
        
        # 3. プロダクションビルドと実行
        npm run build
        npm start
        
        # 4. テストの実行
        npm test
        npm run test:e2e
        '''
    
    def run_java_sample(self):
        """Javaサンプルの実行"""
        
        return '''
        # 1. アプリケーションのビルド
        cd java-examples
        ./mvnw clean package
        
        # 2. アプリケーションの起動
        java -jar target/auth-service-1.0.0.jar \
          --spring.profiles.active=dev
        
        # または、開発モードで起動
        ./mvnw spring-boot:run
        '''
    
    def run_go_sample(self):
        """Goサンプルの実行"""
        
        return '''
        # 1. アプリケーションのビルド
        cd go-examples
        go build -o auth-service cmd/server/main.go
        
        # 2. アプリケーションの起動
        ./auth-service
        
        # または、Air（ホットリロード）を使用
        go install github.com/cosmtrek/air@latest
        air
        '''
```

### A.3.2 統合テストの実行

```python
class IntegrationTestRunner:
    """統合テストの実行ガイド"""
    
    def setup_test_environment(self):
        """テスト環境のセットアップ"""
        
        return '''
        # Docker Composeでテスト環境を起動
        docker compose -f docker-compose.test.yml up -d
        
        # データベースの初期化を待つ
        ./scripts/wait-for-it.sh localhost:5432 -t 30
        ./scripts/wait-for-it.sh localhost:6379 -t 30
        
        # テストデータの投入
        docker compose -f docker-compose.test.yml \
          exec postgres psql -U authuser -d authdb \
          -f /docker-entrypoint-initdb.d/test-data.sql
        '''
    
    def run_integration_tests(self):
        """統合テストスイートの実行"""
        
        return {
            'test_script': '''
            #!/bin/bash
            
            # 環境変数の設定
            export TEST_DATABASE_URL="postgresql://authuser:authpass@localhost:5432/authdb_test"
            export TEST_REDIS_URL="redis://:authredispass@localhost:6379/1"
            
            echo "=== Running Python Integration Tests ==="
            cd python-examples
            pytest tests/integration -v --cov=app
            
            echo "=== Running Node.js Integration Tests ==="
            cd ../nodejs-examples
            npm run test:integration
            
            echo "=== Running Java Integration Tests ==="
            cd ../java-examples
            ./mvnw test -Dtest="*IntegrationTest"
            
            echo "=== Running Go Integration Tests ==="
            cd ../go-examples
            go test ./tests/integration/... -v
            ''',
            
            'e2e_test': '''
            # Playwright E2Eテスト
            cd e2e-tests
            npm install
            npx playwright install
            npm run test:e2e
            
            # テストレポートの生成
            npx playwright show-report
            '''
        }
```

## A.4 トラブルシューティング

### A.4.1 よくある問題と解決方法

```python
class TroubleshootingGuide:
    """トラブルシューティングガイド"""
    
    def common_issues(self):
        """よくある問題と解決方法"""
        
        return {
            'database_connection': {
                'error': "FATAL: password authentication failed for user 'authuser'",
                'cause': 'データベースの認証情報が正しくない',
                'solution': [
                    '1. .envファイルのDATABASE_URLを確認',
                    '2. PostgreSQLサービスが起動しているか確認',
                    '3. docker compose logs postgres でログを確認',
                    '4. データベースユーザーの作成: CREATE USER authuser WITH PASSWORD \'authpass\';'
                ]
            },
            
            'redis_connection': {
                'error': "Error: Redis connection to localhost:6379 failed",
                'cause': 'Redisサービスが起動していない、または認証が必要',
                'solution': [
                    '1. Redisサービスの状態確認: redis-cli ping',
                    '2. パスワード付きの接続: redis-cli -a authredispass ping',
                    '3. docker compose up -d redis でRedisを起動'
                ]
            },
            
            'jwt_key_error': {
                'error': "FileNotFoundError: JWT private key not found",
                'cause': 'JWT署名用の鍵ファイルが存在しない',
                'solution': [
                    '1. 鍵ファイルの生成スクリプトを実行: ./scripts/generate-keys.sh',
                    '2. 環境変数JWT_PRIVATE_KEY_PATHのパスを確認',
                    '3. ファイルの権限を確認: chmod 600 keys/jwt_private.pem'
                ]
            },
            
            'cors_error': {
                'error': "Access to XMLHttpRequest blocked by CORS policy",
                'cause': 'CORSの設定が適切でない',
                'solution': [
                    '1. CORS_ALLOWED_ORIGINSにフロントエンドのURLを追加',
                    '2. プリフライトリクエストの処理を確認',
                    '3. 認証情報を含む場合はCORS_ALLOW_CREDENTIALS=true'
                ]
            },
            
            'port_already_in_use': {
                'error': "Error: listen EADDRINUSE: address already in use :::3000",
                'cause': 'ポートが既に使用されている',
                'solution': [
                    '1. 使用中のプロセスを確認: lsof -i :3000',
                    '2. プロセスを終了: kill -9 <PID>',
                    '3. 別のポートを使用: APP_PORT=3001'
                ]
            }
        }
    
    def debugging_tips(self):
        """デバッグのヒント"""
        
        return '''
        # ログレベルの変更
        export LOG_LEVEL=debug
        
        # SQLクエリのログ出力（Python/SQLAlchemy）
        export SQLALCHEMY_ECHO=true
        
        # HTTPリクエスト/レスポンスのログ（Node.js）
        export DEBUG=express:*
        
        # デバッガーのアタッチ（VS Code）
        {
          "type": "python",
          "request": "attach",
          "name": "Attach to Remote",
          "connect": {
            "host": "localhost",
            "port": 5678
          }
        }
        
        # メモリリークの検出
        node --inspect=0.0.0.0:9229 app.js
        # Chrome DevToolsでchrome://inspect にアクセス
        '''
```

### A.4.2 パフォーマンスチューニング

```python
class PerformanceTuning:
    """パフォーマンスチューニングガイド"""
    
    def database_optimization(self):
        """データベースの最適化"""
        
        return '''
        -- インデックスの作成
        CREATE INDEX idx_users_email ON users(email);
        CREATE INDEX idx_sessions_user_id ON sessions(user_id);
        CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
        CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
        
        -- パーティショニング（大規模データの場合）
        CREATE TABLE audit_logs_2024_01 PARTITION OF audit_logs
        FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
        
        -- 接続プールの設定
        # PostgreSQL (postgresql.conf)
        max_connections = 200
        shared_buffers = 256MB
        effective_cache_size = 1GB
        
        # アプリケーション側
        DATABASE_POOL_SIZE=20
        DATABASE_POOL_TIMEOUT=30
        '''
    
    def application_optimization(self):
        """アプリケーションの最適化"""
        
        return {
            'caching_strategy': '''
            # Redisキャッシュの実装
            class CacheService:
                def __init__(self, redis_client):
                    self.redis = redis_client
                    self.default_ttl = 3600  # 1時間
                
                async def get_user_permissions(self, user_id: str):
                    cache_key = f"permissions:{user_id}"
                    
                    # キャッシュから取得
                    cached = await self.redis.get(cache_key)
                    if cached:
                        return json.loads(cached)
                    
                    # DBから取得してキャッシュ
                    permissions = await self.db.get_user_permissions(user_id)
                    await self.redis.setex(
                        cache_key, 
                        self.default_ttl, 
                        json.dumps(permissions)
                    )
                    
                    return permissions
            ''',
            
            'connection_pooling': '''
            # データベース接続プール
            from sqlalchemy.pool import QueuePool
            
            engine = create_engine(
                DATABASE_URL,
                poolclass=QueuePool,
                pool_size=20,
                max_overflow=0,
                pool_pre_ping=True,
                pool_recycle=3600
            )
            ''',
            
            'async_processing': '''
            # 非同期処理の活用
            import asyncio
            from concurrent.futures import ThreadPoolExecutor
            
            executor = ThreadPoolExecutor(max_workers=4)
            
            async def verify_password_async(plain_password, hashed_password):
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    executor,
                    bcrypt.checkpw,
                    plain_password.encode('utf-8'),
                    hashed_password.encode('utf-8')
                )
            '''
        }
```

## A.5 本番環境へのデプロイ準備

### A.5.1 セキュリティチェックリスト

```python
class ProductionReadinessChecklist:
    """本番環境準備チェックリスト"""
    
    def security_checklist(self):
        """セキュリティチェックリスト"""
        
        return {
            'secrets_management': [
                '□ すべてのシークレットが環境変数または安全なストレージに保存されている',
                '□ デフォルトのパスワードやキーが変更されている',
                '□ JWT署名キーが十分に強力（最低2048ビット）',
                '□ データベースパスワードが強力で一意',
                '□ APIキーのローテーション計画がある'
            ],
            
            'network_security': [
                '□ HTTPSが有効化されている',
                '□ TLS 1.2以上のみを許可',
                '□ HSTSヘッダーが設定されている',
                '□ 適切なCORS設定',
                '□ 不要なポートが閉じられている'
            ],
            
            'application_security': [
                '□ SQLインジェクション対策（パラメータ化クエリ）',
                '□ XSS対策（出力エスケープ）',
                '□ CSRF対策トークン',
                '□ レート制限の実装',
                '□ セキュリティヘッダーの設定'
            ],
            
            'authentication_security': [
                '□ パスワードポリシーの強制',
                '□ アカウントロックアウトメカニズム',
                '□ MFAの実装',
                '□ セッションタイムアウト',
                '□ 安全なパスワードリセットフロー'
            ],
            
            'monitoring_and_logging': [
                '□ セキュリティイベントのログ記録',
                '□ 異常検知アラートの設定',
                '□ ログの安全な保存',
                '□ 監査ログの実装',
                '□ インシデント対応計画'
            ]
        }
    
    def deployment_checklist(self):
        """デプロイメントチェックリスト"""
        
        return '''
        #!/bin/bash
        
        echo "=== Production Deployment Checklist ==="
        
        # 1. 環境変数の確認
        echo "Checking environment variables..."
        required_vars=(
            "DATABASE_URL"
            "REDIS_URL"
            "JWT_SECRET_KEY"
            "SESSION_SECRET"
            "APP_ENV"
        )
        
        for var in "${required_vars[@]}"; do
            if [ -z "${!var}" ]; then
                echo "ERROR: $var is not set"
                exit 1
            fi
        done
        
        # 2. データベースマイグレーション
        echo "Running database migrations..."
        alembic upgrade head
        
        # 3. 静的ファイルの収集
        echo "Collecting static files..."
        python manage.py collectstatic --noinput
        
        # 4. ヘルスチェック
        echo "Running health checks..."
        curl -f http://localhost:8000/health || exit 1
        
        # 5. スモークテスト
        echo "Running smoke tests..."
        pytest tests/smoke -v
        
        echo "=== Deployment checklist completed ==="
        '''
```

## まとめ

この付録では、認証認可システムの開発に必要な環境構築から本番デプロイの準備まで、実践的なガイドを提供しました。各ツールのインストール方法、設定ファイルのテンプレート、トラブルシューティングのヒントを参考に、スムーズに開発を進めてください。

セキュリティは継続的な取り組みです。定期的にセキュリティチェックリストを確認し、最新のベストプラクティスに従ってシステムを更新することを忘れないでください。