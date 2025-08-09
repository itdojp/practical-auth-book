# Authentication and Authorization Flow Diagrams

## OAuth 2.0 Authorization Code Flow

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant Client as Client App
    participant AuthServer as Authorization Server
    participant Resource as Resource Server
    
    User->>Browser: Access Application
    Browser->>Client: Request Protected Resource
    Client->>Browser: Redirect to Auth Server
    Browser->>AuthServer: Authorization Request
    AuthServer->>User: Login Page
    User->>AuthServer: Credentials
    AuthServer->>User: Consent Screen
    User->>AuthServer: Grant Permission
    AuthServer->>Browser: Authorization Code
    Browser->>Client: Code
    Client->>AuthServer: Exchange Code for Token
    Note over Client,AuthServer: Backend Channel (Secure)
    AuthServer->>Client: Access Token & Refresh Token
    Client->>Resource: API Request + Access Token
    Resource->>Resource: Validate Token
    Resource->>Client: Protected Data
    Client->>Browser: Display Data
    Browser->>User: View Protected Resource
```

## JWT Token Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Created: User Authentication
    Created --> Signed: Add Claims & Sign
    Signed --> Transmitted: Send to Client
    Transmitted --> Stored: Client Storage
    Stored --> Used: API Requests
    Used --> Validated: Server Validation
    
    Validated --> Accepted: Valid Token
    Validated --> Rejected: Invalid/Expired
    
    Accepted --> Used: Continue Usage
    Rejected --> Refresh: Has Refresh Token
    Rejected --> Expired: No Refresh Token
    
    Refresh --> Created: New Token Issued
    Expired --> [*]: Re-authentication Required
    
    Stored --> Revoked: Security Event
    Revoked --> [*]: Token Blacklisted
```

## Multi-Factor Authentication Flow

```mermaid
flowchart TD
    Start[Login Request] --> Creds[Username/Password]
    Creds --> ValidateCreds{Valid?}
    
    ValidateCreds -->|No| Failed1[Authentication Failed]
    ValidateCreds -->|Yes| MFACheck{MFA Enabled?}
    
    MFACheck -->|No| Success[Login Success]
    MFACheck -->|Yes| MFAType{MFA Method}
    
    MFAType -->|SMS| SendSMS[Send SMS Code]
    MFAType -->|TOTP| ShowTOTP[Request TOTP]
    MFAType -->|Hardware| RequestHW[Request Hardware Token]
    
    SendSMS --> EnterCode[User Enters Code]
    ShowTOTP --> EnterCode
    RequestHW --> EnterCode
    
    EnterCode --> ValidateMFA{Valid Code?}
    
    ValidateMFA -->|No| Retry{Retry Count}
    ValidateMFA -->|Yes| Success
    
    Retry -->|< Max| EnterCode
    Retry -->|>= Max| Locked[Account Locked]
    
    Failed1 --> End[End]
    Success --> End
    Locked --> End
    
    style Failed1 fill:#ffcccc
    style Locked fill:#ffcccc
    style Success fill:#ccffcc
```

## Session Management State Diagram

```mermaid
stateDiagram-v2
    [*] --> Created: User Login
    Created --> Active: Session Established
    
    Active --> Active: User Activity
    Active --> Idle: No Activity
    
    Idle --> Active: User Returns
    Idle --> Warning: Near Timeout
    
    Warning --> Active: User Activity
    Warning --> Expired: Timeout
    
    Active --> Invalidated: User Logout
    Active --> Revoked: Security Event
    
    Expired --> [*]: Session Ended
    Invalidated --> [*]: Session Ended
    Revoked --> [*]: Session Ended
    
    note right of Active
        Session refreshed
        on each activity
    end note
    
    note right of Warning
        Warning shown
        before expiration
    end note
```

## Microservices Authentication Architecture

```mermaid
graph TB
    subgraph "Client Applications"
        Web[Web App]
        Mobile[Mobile App]
        Desktop[Desktop App]
    end
    
    subgraph "API Gateway"
        Gateway[API Gateway]
        AuthFilter[Auth Filter]
    end
    
    subgraph "Identity Service"
        IdP[Identity Provider]
        TokenService[Token Service]
        UserDB[(User Database)]
    end
    
    subgraph "Microservices"
        Service1[User Service]
        Service2[Order Service]
        Service3[Payment Service]
        Service4[Inventory Service]
    end
    
    Web --> Gateway
    Mobile --> Gateway
    Desktop --> Gateway
    
    Gateway --> AuthFilter
    AuthFilter <--> IdP
    
    IdP --> TokenService
    TokenService --> UserDB
    
    AuthFilter --> Service1
    AuthFilter --> Service2
    AuthFilter --> Service3
    AuthFilter --> Service4
    
    Service1 -.->|Verify| TokenService
    Service2 -.->|Verify| TokenService
    Service3 -.->|Verify| TokenService
    Service4 -.->|Verify| TokenService
    
    style IdP fill:#e6f3ff
    style TokenService fill:#ffe6e6
    style AuthFilter fill:#e6ffe6
```