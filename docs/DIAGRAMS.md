# authgent — Visual Architecture & Flow Diagrams

## What Is authgent?

```mermaid
graph TB
    subgraph "The Problem"
        H[👤 Human] -->|"auth code + PKCE"| A[🤖 Agent A<br/>Orchestrator]
        A -->|"passes token"| B[🤖 Agent B<br/>Search Agent]
        B -->|"passes token"| C[🤖 Agent C<br/>DB Agent]
        C -->|"queries"| DB[(Database)]
        
        style A fill:#ff6b6b,color:#fff
        style B fill:#ff6b6b,color:#fff
        style C fill:#ff6b6b,color:#fff
    end

    Q1["❌ Who authorized C to query the DB?"]
    Q2["❌ Was scope reduced at each hop?"]
    Q3["❌ Is this token stolen from a log?"]
    Q4["❌ Can we revoke the whole chain?"]
```

```mermaid
graph TB
    subgraph "The Solution — authgent"
        H[👤 Human] -->|"1. auth code + PKCE"| AUTH[🔐 authgent server]
        AUTH -->|"2. scoped token"| A[🤖 Agent A<br/>Orchestrator]
        A -->|"3. token exchange<br/>scope: search:execute"| AUTH
        AUTH -->|"4. delegated token<br/>act: orchestrator"| B[🤖 Agent B<br/>Search Agent]
        B -->|"5. token exchange<br/>scope: db:read"| AUTH
        AUTH -->|"6. delegated token<br/>act: search → orchestrator"| C[🤖 Agent C<br/>DB Agent]
        C -->|"7. DPoP-protected request"| DB[(Database)]

        style AUTH fill:#4ecdc4,color:#fff,stroke:#333,stroke-width:3px
        style A fill:#45b7d1,color:#fff
        style B fill:#45b7d1,color:#fff
        style C fill:#45b7d1,color:#fff
    end

    R1["✅ Full delegation chain in every token"]
    R2["✅ Scope shrinks at each hop"]
    R3["✅ DPoP = token bound to sender key"]
    R4["✅ Revoke parent → all children die"]
```

---

## System Architecture

```mermaid
graph TB
    subgraph "Clients"
        HUMAN[👤 Human<br/>Browser / CLI]
        AGENT_A[🤖 Agent A]
        AGENT_B[🤖 Agent B]
        AGENT_C[🤖 Agent C]
        MCP[🔌 MCP Client]
        EXT_IDP[🏢 Auth0 / Okta<br/>External IdP]
    end

    subgraph "authgent-server"
        direction TB
        subgraph "Endpoints"
            TOKEN[POST /token]
            AUTHZ[GET/POST /authorize]
            REG[POST /register]
            INTRO[POST /introspect]
            REVOKE[POST /revoke]
            DEVICE[POST /device/authorize]
            STEPUP[POST /stepup]
            AGENTS[CRUD /agents]
            WK[GET /.well-known/*]
        end

        subgraph "Services"
            TS[TokenService]
            DS[DelegationService]
            DPOP_S[DPoPService]
            JS[JWKSService]
            AS[AuditService]
            AGS[AgentService]
            CS[ConsentService]
            SUS[StepUpService]
        end

        subgraph "Providers (Pluggable)"
            ATT[Attestation]
            POL[Policy]
            HITL_P[HITL]
            KS[KeyStore]
            EVT[Events]
            CE[ClaimEnricher]
        end

        subgraph "Data Layer"
            DB[(SQLite dev<br/>PostgreSQL prod)]
        end

        TOKEN --> TS
        AUTHZ --> CS
        AGENTS --> AGS
        STEPUP --> SUS
        TS --> DS
        TS --> DPOP_S
        TS --> JS
        TS --> AS
        DS --> DB
        JS --> DB
        AGS --> DB
    end

    HUMAN -->|"auth code + PKCE"| AUTHZ
    AGENT_A -->|"client_credentials"| TOKEN
    AGENT_A -->|"token exchange"| TOKEN
    AGENT_B -->|"token exchange"| TOKEN
    MCP -->|"discovery"| WK
    EXT_IDP -.->|"id_token exchange"| TOKEN

    subgraph "SDKs"
        PY_SDK[🐍 Python SDK<br/>pip install authgent]
        TS_SDK[📦 TypeScript SDK<br/>npm install authgent]
    end

    PY_SDK -->|"verify / delegate / DPoP"| TOKEN
    TS_SDK -->|"verify / delegate / DPoP"| TOKEN

    style DB fill:#f9f,stroke:#333
```

---

## Flow 1: Agent Gets Its Own Token (Client Credentials)

```mermaid
sequenceDiagram
    participant A as 🤖 Agent A (Orchestrator)
    participant S as 🔐 authgent server
    participant DB as 💾 Database

    Note over A: Agent was registered via<br/>POST /agents or POST /register

    A->>S: POST /token<br/>grant_type=client_credentials<br/>client_id=agnt_xxx<br/>client_secret=sec_xxx<br/>scope=search:execute db:read
    
    S->>DB: Verify client credentials (bcrypt)
    DB-->>S: ✅ Client valid
    
    S->>DB: Load active ES256 signing key
    DB-->>S: Key (kid: key_01)
    
    S->>S: Build JWT claims:<br/>sub=client:agnt_xxx<br/>scope=search:execute db:read<br/>iss=http://localhost:8000<br/>exp=now+900s<br/>jti=unique_id
    
    S->>S: Sign with ES256 private key
    
    S-->>A: 200 OK<br/>{ access_token: "eyJ...",<br/>  token_type: "Bearer",<br/>  expires_in: 900,<br/>  scope: "search:execute db:read" }

    Note over A: Token payload:<br/>{ sub: "client:agnt_xxx",<br/>  scope: "search:execute db:read",<br/>  iss: "http://localhost:8000",<br/>  jti: "tok_abc123" }
```

---

## Flow 2: Agent Delegates to Another Agent (Token Exchange)

This is **the core differentiator** — what nobody else does.

```mermaid
sequenceDiagram
    participant A as 🤖 Agent A<br/>(Orchestrator)
    participant S as 🔐 authgent server
    participant B as 🤖 Agent B<br/>(Search Agent)

    Note over A: A has token with<br/>scope: search:execute db:read

    A->>S: POST /token<br/>grant_type=token-exchange<br/>subject_token=A's_token<br/>audience=agent:search-bot<br/>scope=search:execute<br/>client_id=agnt_A<br/>client_secret=sec_A

    S->>S: Verify A's token (signature + expiry + blocklist)
    S->>S: Check: requested scope ⊆ parent scope?<br/>search:execute ⊆ {search:execute, db:read} ✅
    S->>S: Check: delegation depth < max (5)?<br/>depth=1 < 5 ✅
    
    S->>S: Build delegated JWT:<br/>sub=client:agnt_A (original subject)<br/>scope=search:execute (NARROWED)<br/>act: { sub: "client:agnt_A" } ← WHO DELEGATED
    
    S->>S: Create signed delegation receipt<br/>(chain_hash commits to full auth chain)
    
    S-->>A: 200 OK<br/>{ access_token: "eyJ...(delegated)",<br/>  issued_token_type: "access_token" }

    A->>B: Here's your token for the search task
    
    Note over B: Token payload:<br/>{ sub: "client:agnt_A",<br/>  scope: "search:execute",<br/>  act: { sub: "client:agnt_A" },<br/>  aud: "agent:search-bot" }

    Note over B: B can now do ANOTHER exchange<br/>to delegate to Agent C →<br/>act nests deeper each hop
```

---

## Flow 3: Multi-Hop Delegation Chain (3 Agents Deep)

```mermaid
sequenceDiagram
    participant H as 👤 Human (Alice)
    participant S as 🔐 authgent
    participant A as 🤖 Orchestrator
    participant B as 🤖 Search Agent
    participant C as 🤖 DB Agent

    H->>S: Auth Code + PKCE
    S-->>H: token (sub: user:alice, scope: read write search db:query)
    H->>A: Here, act on my behalf

    Note over A: Hop 0 token:<br/>{ sub: "user:alice",<br/>  scope: "read write search db:query" }

    A->>S: Token Exchange → scope: search:execute
    S-->>A: Delegated token for B

    Note over A: Hop 1 token:<br/>{ sub: "user:alice",<br/>  scope: "search:execute",<br/>  act: { sub: "client:orchestrator" } }

    A->>B: Execute search with this token
    B->>S: Token Exchange → scope: db:read
    S-->>B: Delegated token for C

    Note over B: Hop 2 token:<br/>{ sub: "user:alice",<br/>  scope: "db:read",<br/>  act: {<br/>    sub: "client:search-agent",<br/>    act: { sub: "client:orchestrator" }<br/>  } }

    B->>C: Query the DB with this token
    C->>C: Verify chain:<br/>✅ scope: db:read (narrow enough)<br/>✅ chain depth: 2 (< max 5)<br/>✅ human root: user:alice<br/>✅ all actors authorized

    C-->>B: Query results
    B-->>A: Search results
    A-->>H: Final answer

    Note over S: 📋 Audit trail captures<br/>every delegation hop with<br/>signed receipts
```

---

## Flow 4: DPoP — Token Can't Be Replayed from Logs

```mermaid
sequenceDiagram
    participant A as 🤖 Agent
    participant S as 🔐 authgent
    participant API as 🌐 Protected API
    participant L as 📋 Log System

    A->>A: Generate ephemeral EC key pair<br/>(private key never leaves memory)

    A->>S: POST /token + DPoP proof header<br/>(proof = JWT signed with ephemeral key,<br/> contains: htm=POST, htu=/token, iat=now)

    S->>S: Verify DPoP proof<br/>Extract JKT (key thumbprint)
    S->>S: Bind token to JKT via cnf claim

    S-->>A: { access_token: "eyJ...",<br/>  token_type: "DPoP" }

    Note over A: Token has:<br/>cnf: { jkt: "thumbprint-of-agent-key" }

    A->>API: GET /data<br/>Authorization: DPoP eyJ...<br/>DPoP: eyJ...(fresh proof for this request)

    API->>API: Verify: proof.jkt == token.cnf.jkt ✅<br/>Verify: proof.htm == GET ✅<br/>Verify: proof.htu == /data ✅

    API-->>A: 200 OK { data: ... }

    Note over L: Log captures:<br/>Authorization: DPoP eyJ...<br/>Token appears in LangChain trace

    L->>API: 🔴 Attacker replays token from log<br/>Authorization: DPoP eyJ...<br/>(but can't create valid DPoP proof<br/>without the ephemeral private key!)

    API-->>L: ❌ 401 Invalid DPoP proof
    
    Note over L: Token is USELESS without<br/>the private key that<br/>never left the agent's memory
```

---

## Flow 5: Human-in-the-Loop Step-Up Authorization

```mermaid
sequenceDiagram
    participant A as 🤖 Agent
    participant S as 🔐 authgent
    participant H as 👤 Human Reviewer

    A->>A: Working on task...<br/>hits sensitive operation:<br/>"delete user records"

    A->>S: POST /stepup<br/>{ agent_id: "search-bot",<br/>  action: "delete_records",<br/>  scope: "db:delete",<br/>  resource: "users table" }

    S-->>A: 202 Accepted<br/>{ id: "su_abc123",<br/>  status: "pending",<br/>  expires_at: "..." }

    loop Poll every 2 seconds
        A->>S: GET /stepup/su_abc123
        S-->>A: { status: "pending" }
    end

    Note over H: Notification arrives<br/>(Slack, email, dashboard)

    H->>S: POST /stepup/su_abc123/approve<br/>{ approved_by: "alice@company.com" }

    S-->>H: { status: "approved" }

    A->>S: GET /stepup/su_abc123
    S-->>A: { status: "approved" ✅ }

    A->>A: Proceed with delete_records<br/>(now has human authorization)

    Note over S: Audit log records:<br/>who approved, when,<br/>what action, which agent
```

---

## Flow 6: Device Authorization (Headless / CLI Agents)

```mermaid
sequenceDiagram
    participant CLI as 🖥️ CLI Agent<br/>(no browser)
    participant S as 🔐 authgent
    participant H as 👤 Human<br/>(separate device)

    CLI->>S: POST /device/authorize<br/>client_id=cli-agent<br/>scope=tools:execute

    S-->>CLI: { device_code: "dev_xxx",<br/>  user_code: "ABCD-1234",<br/>  verification_uri: "http://auth.example/device",<br/>  expires_in: 600 }

    CLI->>CLI: Display to user:<br/>"Go to http://auth.example/device<br/> and enter code: ABCD-1234"

    loop Agent polls every 5 seconds
        CLI->>S: POST /device/token<br/>device_code=dev_xxx
        S-->>CLI: { error: "authorization_pending" }
    end

    H->>S: Opens browser, enters ABCD-1234
    H->>S: POST /device/complete (approve)

    CLI->>S: POST /device/token<br/>device_code=dev_xxx
    S-->>CLI: { access_token: "eyJ...",<br/>  token_type: "Bearer" }

    Note over CLI: CLI agent now has<br/>a proper OAuth token!<br/>No browser needed on<br/>the agent's machine.
```

---

## Flow 7: Bridge from Auth0/Okta (External IdP Token Exchange)

```mermaid
sequenceDiagram
    participant H as 👤 Human
    participant IDP as 🏢 Auth0 / Okta
    participant A as 🤖 Agent
    participant S as 🔐 authgent

    H->>IDP: Login (standard OAuth)
    IDP-->>H: id_token (JWT from Auth0)
    H->>A: Here's my Auth0 id_token,<br/>do this task for me

    A->>S: POST /token<br/>grant_type=token-exchange<br/>subject_token=AUTH0_ID_TOKEN<br/>subject_token_type=id_token<br/>client_id=agnt_A<br/>client_secret=sec_A

    S->>S: Fetch Auth0 JWKS<br/>Verify id_token signature<br/>Check issuer in trusted list<br/>Check audience matches

    S->>S: Create delegation token:<br/>sub=user:alice@auth0<br/>act: { sub: "client:agnt_A" }

    S-->>A: authgent access_token<br/>(now in authgent's delegation system)

    A->>S: Exchange → Agent B (scope narrowed)
    S-->>A: Delegated token with act chain

    Note over A: Auth0 issued the<br/>FIRST token.<br/>authgent handles the<br/>DELEGATION CHAIN after that.
```

---

## Token Anatomy (What's Inside Each JWT)

```mermaid
graph LR
    subgraph "Hop 0 — Direct Token"
        T0["{ 
          sub: 'user:alice',
          scope: 'read write search db:query',
          iss: 'http://localhost:8000',
          aud: 'https://api.example.com',
          exp: 1711380000,
          jti: 'tok_001',
          cnf: { jkt: 'dpop-key-A' }
        }"]
    end

    subgraph "Hop 1 — Orchestrator Delegated"
        T1["{ 
          sub: 'user:alice',
          scope: 'search:execute',
          act: { sub: 'client:orchestrator' },
          aud: 'agent:search-bot',
          jti: 'tok_002',
          cnf: { jkt: 'dpop-key-B' }
        }"]
    end

    subgraph "Hop 2 — Search Agent Delegated"
        T2["{
          sub: 'user:alice',
          scope: 'db:read',
          act: { 
            sub: 'client:search-agent',
            act: { sub: 'client:orchestrator' }
          },
          aud: 'agent:db-reader',
          jti: 'tok_003',
          cnf: { jkt: 'dpop-key-C' }
        }"]
    end

    T0 -->|"scope narrows<br/>act added<br/>DPoP rebound"| T1
    T1 -->|"scope narrows<br/>act nests<br/>DPoP rebound"| T2

    style T0 fill:#e8f5e9
    style T1 fill:#fff3e0
    style T2 fill:#fce4ec
```

---

## Signed Delegation Receipts (Chain Splicing Defense)

```mermaid
graph TD
    subgraph "Normal Chain"
        R1[Receipt 1<br/>chain_hash: H₁<br/>parent: tok_001<br/>child: tok_002]
        R2[Receipt 2<br/>chain_hash: H₂ = SHA256{H₁ + tok_002}<br/>parent: tok_002<br/>child: tok_003]
        R1 --> R2
    end

    subgraph "🔴 Splice Attack"
        EVIL[Attacker takes tok_002<br/>from Chain X and tries<br/>to use it in Chain Y]
        EVIL -->|"chain_hash won't match!"| FAIL[❌ Receipt verification<br/>FAILS — chain_hash<br/>doesn't match Y's history]
    end

    subgraph "Verification"
        V[Verifier recomputes:<br/>expected_hash = SHA256{prev_receipt + parent_jti}<br/>actual_hash from receipt<br/>MUST MATCH]
    end

    style FAIL fill:#ff6b6b,color:#fff
    style V fill:#4ecdc4,color:#fff
```
