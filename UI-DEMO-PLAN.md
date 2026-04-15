# AAuth Protocol Demo UI — Implementation Plan

## Context

The AAuth project has 12 CLI-based demo phases (`demo_phase1.py` through `demo_phase12.py`) demonstrating the protocol's signing modes, resource access patterns, missions, delegation, and federation. Currently all demos print to the terminal.

This plan builds a **modern, interactive web UI** that visualizes these protocol flows — sequence diagrams, JWT tokens, HTTP headers, payloads, and signatures — **without running actual servers**. All data is generated using the real `aauth` Python library, producing cryptographically valid JWTs and signatures identical to what the running demos produce.

The UI is organized around **SPEC.md concepts** (signing modes, resource access modes, missions) rather than phase numbers.

---

## Tech Stack

| Layer | Choice | Why |
|-------|--------|-----|
| **Framework** | Next.js 14+ (App Router) + TypeScript | File-based routing, static export, great DX |
| **Components** | shadcn/ui (Radix + Tailwind CSS) | Professional, fully customizable, no heavy dependency |
| **Animation** | Framer Motion | Timeline-based orchestration for sequence diagram animations |
| **Diagrams** | Custom React SVG components | Pixel-perfect animation/click control (mermaid can't do this) |
| **Code/JSON** | `react-json-view-lite` + `prism-react-renderer` | Lightweight syntax highlighting |
| **State** | Zustand | Minimal boilerplate for step/play/panel state |
| **Data** | Python generator → static JSON fixtures | Real crypto from `aauth` lib, deployable as static site |
| **Theme** | Dark theme with participant accent colors | Agent=blue, Resource=green, PS=purple, AS=orange |

---

## Project Structure

```
aauth-demo-ui/
├── frontend/                        # Next.js app
│   ├── app/
│   │   ├── layout.tsx               # Root layout with AppShell
│   │   ├── page.tsx                 # Landing page
│   │   ├── signing/
│   │   │   ├── pseudonymous/page.tsx    # sig=hwk (Phase 1)
│   │   │   ├── identity/page.tsx        # sig=jwks_uri (Phase 2)
│   │   │   └── compare/page.tsx         # Side-by-side signing modes
│   │   ├── access/
│   │   │   ├── identity-based/page.tsx  # 2-party identity access
│   │   │   ├── federated/page.tsx       # 4-party autonomous (Phase 3)
│   │   │   ├── user-delegation/page.tsx # Deferred + consent (Phase 4)
│   │   │   ├── ps-managed/page.tsx      # PS-AS federation (Phase 11)
│   │   │   └── compare/page.tsx         # Access mode comparison
│   │   ├── missions/
│   │   │   ├── lifecycle/page.tsx       # Proposal/approval (Phase 5)
│   │   │   ├── proactive-authz/page.tsx # Proactive + mission (Phase 10)
│   │   │   ├── end-to-end/page.tsx      # Full lifecycle (Phase 12)
│   │   │   └── compare/page.tsx         # With vs without missions
│   │   └── advanced/
│   │       ├── delegation/page.tsx      # Agent delegation (Phase 6)
│   │       ├── call-chaining/page.tsx   # R1→R2 chaining (Phase 7)
│   │       ├── clarification/page.tsx   # Clarification chat (Phase 8)
│   │       └── interaction-chaining/page.tsx  # Interaction chaining (Phase 9)
│   ├── components/
│   │   ├── core/                    # Reusable visualization components
│   │   │   ├── SequenceDiagram.tsx
│   │   │   ├── JWTViewer.tsx
│   │   │   ├── HeaderInspector.tsx
│   │   │   ├── SignatureVisualizer.tsx
│   │   │   ├── PayloadViewer.tsx
│   │   │   └── StepController.tsx
│   │   ├── layout/                  # App shell components
│   │   │   ├── AppShell.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   └── TopBar.tsx
│   │   └── scenarios/               # Scenario-specific components
│   │       ├── ScenarioPage.tsx
│   │       ├── ComparisonView.tsx
│   │       ├── ParticipantCard.tsx
│   │       ├── TokenFlowDiagram.tsx
│   │       ├── DeferredResponseTimeline.tsx
│   │       ├── MissionBlobViewer.tsx
│   │       ├── S256ChainVisualization.tsx
│   │       ├── ActClaimTree.tsx
│   │       ├── TrustDiagram.tsx
│   │       ├── ClarificationChat.tsx
│   │       └── InteractionChainDiagram.tsx
│   └── lib/
│       ├── types.ts                 # TypeScript interfaces
│       ├── store.ts                 # Zustand store
│       ├── tooltips.ts              # Claim/header contextual tooltips
│       └── scenarios/               # Generated JSON fixtures
│           ├── pseudonymous.json
│           ├── identity.json
│           ├── federated.json
│           ├── user-delegation.json
│           └── ...
└── backend/
    ├── generate.py                  # Main generator entry point
    └── scenarios/
        ├── signing.py               # Signing mode data generators
        ├── access.py                # Access mode data generators
        ├── missions.py              # Mission data generators
        └── advanced.py              # Advanced pattern generators
```

---

## Navigation Structure

The sidebar organizes demos by **spec concept**, not phase number:

```
📡 Message Signing
  ├── Pseudonymous (sig=hwk)          → Phase 1
  ├── Agent Identity (sig=jwks_uri)   → Phase 2
  └── Compare Signing Modes

🔐 Resource Access
  ├── Identity-Based (2-party)        → Phase 2 variant
  ├── Federated / Autonomous (4-party)→ Phase 3
  ├── User Delegation (deferred)      → Phase 4
  ├── PS-AS Federation Trust          → Phase 11
  └── Compare Access Modes

📋 Missions
  ├── Proposal & Approval             → Phase 5
  ├── Proactive Authorization         → Phase 10
  ├── End-to-End Lifecycle            → Phase 12
  └── With vs Without Missions

⚡ Advanced Patterns
  ├── Agent Delegation                → Phase 6
  ├── Call Chaining                   → Phase 7
  ├── Clarification Chat              → Phase 8
  └── Interaction Chaining            → Phase 9
```

---

## Data Generation Strategy

The Python backend generator (`backend/generate.py`) produces realistic JSON fixtures by calling the actual `aauth` library. This is the **key architectural decision** — demos show real cryptographic output, not hand-crafted mocks.

### Key `aauth` library functions used:

| Function | From | Produces |
|----------|------|----------|
| `generate_ed25519_keypair()` | `aauth/keys/keypair.py` | Real Ed25519 key pairs |
| `public_key_to_jwk()` | `aauth/keys/jwk.py` | JWK representations |
| `calculate_jwk_thumbprint()` | `aauth/keys/jwk.py` | JKT thumbprints for `agent_jkt` |
| `sign_request()` | `aauth/signing/signer.py` | Real Signature-Input, Signature, Signature-Key headers |
| `create_agent_token()` | `aauth/tokens/agent_token.py` | `aa-agent+jwt` tokens |
| `create_resource_token()` | `aauth/tokens/resource_token.py` | `aa-resource+jwt` tokens |
| `create_auth_token()` | `aauth/tokens/auth_token.py` | `aa-auth+jwt` tokens |
| `parse_token_claims()` | `aauth/tokens/auth_token.py` | Decoded JWT header + payload |

### Fixture format (per scenario):

```typescript
interface Scenario {
  id: string;
  title: string;
  description: string;
  spec_section: string;
  category: 'signing' | 'access' | 'missions' | 'advanced';
  participants: Participant[];
  steps: ProtocolStep[];
}

interface ProtocolStep {
  step: number;
  from: string;           // participant id
  to: string;             // participant id
  label: string;          // short description
  method: string;         // GET, POST, etc.
  url: string;
  request_headers: Record<string, string>;
  request_body?: any;
  response_status: number;
  response_headers: Record<string, string>;
  response_body?: any;
  tokens: DecodedToken[];
  signature?: SignatureDetails;
  annotations: string[];  // spec references, explanatory notes
}

interface DecodedToken {
  name: string;           // "Resource Token", "Auth Token", etc.
  typ: string;            // "aa-resource+jwt", "aa-auth+jwt", etc.
  raw: string;            // Full JWT string
  header: Record<string, any>;
  payload: Record<string, any>;
  signature_b64: string;
}

interface SignatureDetails {
  scheme: string;         // hwk, jwks_uri, jwt
  signature_base: string;
  signature_input: string;
  signature_key: string;
  covered_components: string[];
}

interface Participant {
  id: string;
  label: string;
  type: 'agent' | 'resource' | 'person-server' | 'access-server' | 'user' | 'delegate';
  color: string;
  port?: number;
  metadata_url?: string;
  jwks_url?: string;
}
```

---

## Implementation Phases

### Phase 1: Foundation
**Goal:** Project scaffolding, layout shell, landing page, data pipeline.

| Task | Details |
|------|---------|
| **1.1 Project setup** | `create-next-app` with App Router, TS, Tailwind. Install shadcn/ui, Framer Motion, Zustand. Configure dark theme with participant accent colors. |
| **1.2 Layout shell** | `AppShell.tsx` (sidebar + content), `Sidebar.tsx` (collapsible, organized by spec concept), `TopBar.tsx` (title, spec link, theme toggle). Responsive: sidebar → hamburger on mobile. |
| **1.3 Landing page** | Hero paragraph, grid of 8 cards (4 signing modes + 4 access modes), each linking to its section with a mini diagram preview. |
| **1.4 Data generator** | Python script using `aauth` library. Generate JSON fixtures for all scenarios. Output to `frontend/lib/scenarios/`. |
| **1.5 TypeScript types** | `Scenario`, `ProtocolStep`, `DecodedToken`, `SignatureDetails`, `Participant` interfaces. |

---

### Phase 2: Core Visualization Components
**Goal:** Build the reusable building blocks every scenario page uses.

#### 2.1 Sequence Diagram (`SequenceDiagram.tsx`)
- Custom SVG: vertical lifelines per participant, horizontal arrows for messages
- Framer Motion `pathLength` for arrow draw-on animation
- **Step-by-step mode:** Play button auto-advances, or click step indicators to jump
- **Click arrow** → opens detail panel for that step
- **Color coding:** 200=green, 401=amber, 202=blue, errors=red; responses dashed
- Current step highlighted, past steps dimmed, future steps grayed

#### 2.2 JWT Viewer (`JWTViewer.tsx`)
- **Three-panel:** Header (red), Payload (purple), Signature (blue) — jwt.io color scheme
- Left: raw JWT string with color-coded dot-separated sections
- Right: decoded JSON with syntax highlighting
- **Hover tooltips** on claims explaining AAuth context:
  - `dwk` → "Well-known metadata document for key discovery"
  - `cnf.jwk` → "Proof-of-possession key bound to this token"
  - `agent_jkt` → "JWK Thumbprint of agent's signing key"
  - `act` → "Authorized actor chain (delegation/chaining)"
- Special rendering for `mission` claim (s256 hash + link to blob)
- Tree view for nested `act` claims

#### 2.3 Header Inspector (`HeaderInspector.tsx`)
- Request/Response tabs with key-value display
- **Smart parsing** for AAuth headers:
  - `Signature-Key` → parse scheme, parameters inline
  - `Signature-Input` → show covered components with tooltips
  - `Accept-Signature` → show sigkey type with explanation
  - `AAuth-Requirement` → show requirement type + embedded tokens
  - `AAuth-Mission` → show approver and s256
  - `AAuth-Capabilities` → show capability list
- **Clickable tokens** in headers open JWT Viewer in slide-out panel

#### 2.4 HTTP Signature Visualizer (`SignatureVisualizer.tsx`)
- Signature base string with each covered component highlighted
- Maps request parts → signature base lines visually
- Breaks down `Signature-Input` parameters and `Signature-Key` by scheme
- Visual: "What was signed?" vs "What was sent?" comparison

#### 2.5 Step Controller (`StepController.tsx`)
- Bottom toolbar: prev/next buttons, step indicator dots, play/pause, speed control
- Zustand store: `currentStep`, `isPlaying`, `speed`, `expandedPanels`
- Keyboard: left/right arrows for nav, space for play/pause

#### 2.6 Scenario Page Wrapper (`ScenarioPage.tsx`)
- Reusable: takes `Scenario` JSON, renders sequence diagram + step controller + detail panels
- Every scenario page uses this wrapper — just imports its fixture and renders

---

### Phase 3: Simple Demos — Signing Modes
**Goal:** First interactive scenarios. Pseudonymous signing and agent identity.

#### 3.1 Pseudonymous Signing (`/signing/pseudonymous`) — Phase 1
- **Participants:** Agent, Resource
- **Flow:**
  1. Agent sends unsigned `GET /data` → Resource returns `401` with `Accept-Signature: sig=("@method" "@authority" "@path");sigkey=jkt`
  2. Agent signs with `scheme=hwk` (inline Ed25519 public key in `Signature-Key`) → retries
  3. Resource verifies signature → `200 OK`
- **Key visualization:** HTTP Signature Visualizer showing signature base with `@method`, `@authority`, `@path`, `signature-key` components. Inline public key = no identity, just proof-of-possession.

#### 3.2 Agent Identity via JWKS (`/signing/identity`) — Phase 2
- **Participants:** Agent, Resource
- **Flow:**
  1. `GET /data-jwks` → `401` with `Accept-Signature: sigkey=uri`
  2. Agent signs with `scheme=jwks_uri` (Signature-Key contains `id`, `kid`, `dwk`)
  3. Resource fetches `/.well-known/aauth-agent.json` → `/jwks.json` → verifies → `200`
- **Key visualization:** Discovery flow (metadata fetch → JWKS fetch → key match by `kid`). Side-by-side: pseudonymous = "I have a key" vs identity = "I am agent X, verify via my JWKS."

#### 3.3 Signing Mode Comparison (`/signing/compare`)
- Table: Anonymous | Pseudonymous (hwk) | Identity (jwks_uri) | Agent Token (jwt)
- Per mode: what headers are present, what resource learns about agent, trust level
- Interactive toggle: select two modes, see diff view of Signature-Key header

---

### Phase 4: Authorization Flows — Resource Access Modes
**Goal:** The four resource access modes from the spec.

#### 4.1 Identity-Based Access (`/access/identity-based`)
- **2-party:** Agent signs with `sig=jwks_uri`, Resource decides based on identity alone
- No tokens exchanged beyond the signature
- Resource fetches JWKS, looks up agent in its own policy store

#### 4.2 Federated / Autonomous (`/access/federated`) — Phase 3
- **Participants:** Agent, Resource, Person Server, Access Server
- **Flow (5 steps):**
  1. `GET /data-auth` with `sig=jwks_uri` → `401` + resource token (`aa-resource+jwt`) in `AAuth-Requirement`
  2. Agent → PS `POST /token` with `{resource_token}`
  3. PS → AS `POST /token` (federation, HTTPSig with PS identity)
  4. AS issues auth token (`aa-auth+jwt`) → PS → Agent
  5. Agent retries with auth token in `AAuth-Access` → `200`
- **Token visualizations:**
  - Resource token: `iss`=resource, `aud`=AS, `agent`, `agent_jkt`, `scope`, `dwk=aauth-resource.json`
  - Auth token: `iss`=AS, `aud`=resource, `agent`=`aauth:local@domain`, `cnf.jwk`, `dwk=aauth-access.json`, `act`

#### 4.3 User Delegation (`/access/user-delegation`) — Phase 4
- **Participants:** Agent, Resource, PS, AS, User
- **Flow (7 steps):** Same as 4.2 but AS returns `202 Accepted` + pending URL + interaction code → User opens interaction URL, authenticates, grants consent → Agent polls pending URL → auth token
- **Key visualizations:** `202` response body (`{pending_url, interaction}`), polling timeline (202→202→200), consent page mockup

#### 4.4 PS-AS Federation Trust (`/access/ps-managed`) — Phase 11
- Same as 4.2 but emphasize:
  - `ps` claim in agent token
  - PS is the **only** entity that calls AS token endpoints
  - `trusted_person_servers` configuration on AS
  - HTTPSig from PS→AS uses `sig=jwks_uri` with PS identity
- **Trust diagram** showing which entities trust which

#### 4.5 Access Mode Comparison (`/access/compare`)
- Select 2 modes, see sequence diagrams side-by-side
- Highlight which steps are added in the more complex mode

#### New components:
- `TokenFlowDiagram.tsx` — clickable token boxes connected by arrows showing token lifecycle
- `DeferredResponseTimeline.tsx` — horizontal timeline showing polling iterations with status codes

---

### Phase 5: Missions and Advanced Features
**Goal:** Mission lifecycle, agent delegation, call chaining.

#### 5.1 Mission Proposal & Approval (`/missions/lifecycle`) — Phase 5
- **Participants:** Agent, PS
- **Flow:**
  1. Agent `POST /mission` with `{description (markdown), tools: [{name, description}]}`
  2. PS builds mission blob, computes `s256 = SHA-256(blob_bytes)`
  3. Returns blob body + `AAuth-Mission: approver="<PS_URL>"; s256="<SHA256>"` header
- **Visualizations:**
  - Mission description rendered as Markdown
  - Tool list with descriptions
  - SHA-256 computation: input bytes → output hash
  - `AAuth-Mission` header breakdown
  - `AAuth-Capabilities` header (PS capabilities merged with agent capabilities)

#### 5.2 Proactive Authorization + Missions (`/missions/proactive-authz`) — Phase 10
- **Flow:**
  1. Agent proposes mission (from 5.1)
  2. Agent `POST /authorize` on Resource with `AAuth-Mission` + `AAuth-Capabilities` headers, `sig=jwt`
  3. Resource issues resource token with `mission` claim (`{approver, s256}`)
  4. Agent → PS → AS federation, mission claim preserved at each hop
  5. Agent accesses resource with auth token
- **Key visualization:** `mission` claim flowing through all three tokens with s256 match verification at each hop

#### 5.3 Full Mission Lifecycle (`/missions/end-to-end`) — Phase 12
- Complete end-to-end: PS metadata discovery (`/.well-known/aauth-person.json`) → proposal → approval → proactive authz → PS→AS federation → resource access
- **Visualize:** Complete s256 chain traced from proposal through every token

#### 5.4 Agent Delegation (`/advanced/delegation`) — Phase 6
- **Participants:** Agent Server, Delegate, Resource, AS
- **Flow:**
  1. Delegate `POST /delegate/token` on Agent Server
  2. Agent Server issues `aa-agent+jwt` with `cnf.jwk` = delegate's public key
  3. Delegate uses `scheme=jwt` (agent token in Signature-Key) to sign requests
  4. Delegate obtains resource token → auth token from AS
  5. Auth token `agent` = `aauth:delegate-1@127.0.0.1`
- **Key visualization:** Agent token structure showing `iss`=agent server, `sub`=delegate, `cnf.jwk`=delegate key. Delegate *becomes* the agent from resource/AS perspective.

#### 5.5 Call Chaining (`/advanced/call-chaining`) — Phase 7
- **Participants:** Agent, R1, AS1, PS, R2, AS2 (6 participants!)
- **Flow:**
  1. Agent → R1 via normal autonomous flow (Agent→R1→PS→AS1)
  2. R1 needs data from R2 to fulfill request
  3. R1 acts as agent: sends R2's resource token + upstream auth token to PS
  4. PS evaluates chain, federates with AS2
  5. AS2 issues auth token with nested `act` claims
  6. R1 → R2 → R1 → Agent (200)
- **Key visualization:** Nested `act` claims: `{sub: "resource1", act: {sub: "agent1"}}`. 6-participant sequence diagram. Trust: AS2 `trusted_auth_servers` includes AS1.

#### 5.6 Missions Comparison (`/missions/compare`)
- Same flow shown with and without missions
- Highlight additional headers (`AAuth-Mission`, `AAuth-Capabilities`) and token claims (`mission`)

#### New components:
- `MissionBlobViewer.tsx` — renders mission blob with Markdown, tools, s256
- `S256ChainVisualization.tsx` — s256 flowing through token chain with checkmarks
- `ActClaimTree.tsx` — tree view for nested `act` claims
- `TrustDiagram.tsx` — network graph of trust relationships

---

### Phase 6: Interaction Patterns
**Goal:** The most complex interaction patterns — clarification and interaction chaining.

#### 6.1 Clarification Chat (`/advanced/clarification`) — Phase 8
- **Participants:** Agent, Resource, AS, User
- **Flow:**
  1. Agent → Resource → 401 + resource token
  2. Agent → AS → 202 + pending URL (consent required)
  3. AS poses clarification question; agent polls, gets `requirement=clarification`
  4. Agent `POST` clarification_response to pending URL
  5. AS records answer, includes in consent context
  6. User grants consent → agent polls → auth token → 200
- **Two variants:** clarification-capable agent (`AAuth-Capabilities: clarification`) vs non-capable (AS skips clarification)
- **Visualization:** Chat bubble UI showing Q&A exchange

#### 6.2 Interaction Chaining (`/advanced/interaction-chaining`) — Phase 9
- **Participants:** Agent, R1, AS1, R2, AS2, User
- **Flow:**
  1. Agent → R1 (autonomous flow, no consent on AS1)
  2. R1 → R2 (call chaining)
  3. AS2 requires consent → returns 202 + interaction
  4. R1 **bubbles 202 back**: returns its own 202 + pending URL + interaction to Agent
  5. User opens R1's `/interact` → redirects to AS2's interact page → consents
  6. R1 polls AS2's pending URL → auth token for R2
  7. R1 → R2 → R1 → Agent (200)
- **Key visualization:** Interaction bubble-up chain (AS2→R1→Agent→User), redirect flow, parallel polling timelines (agent polling R1, R1 polling AS2)

#### New components:
- `ClarificationChat.tsx` — chat bubble UI for Q&A during consent
- `InteractionChainDiagram.tsx` — shows interaction URL bubbling back through chain
- `ParallelPollingTimeline.tsx` — two stacked timelines for simultaneous polling

---

### Phase 7: Polish
**Goal:** Animations, responsive design, comparison features, export, discoverability.

| Feature | Details |
|---------|---------|
| **Animation polish** | Token "flight" animation between participants. Smooth step transitions with content panel slide-in/out. JWT viewer unfold animation. Skeleton loading states. |
| **Responsive** | Mobile: horizontal-scroll diagrams, stacked panels, sidebar→bottom sheet. Tablet: 2-column. Desktop: 3-column (sidebar + diagram + detail). |
| **Export** | "Copy as cURL" per request step. "Copy JWT" per token. "Copy Scenario JSON" for full fixture. |
| **Deep links** | Each step addressable: `/access/federated?step=3`. Shareable URLs. |
| **Spec references** | Annotations link to SPEC.md sections. Hover tooltips with section titles. "View in Spec" button. |
| **Search** | Global search for header names, claim names, concepts → finds which scenarios demonstrate them. |
| **Glossary** | All AAuth terms with definitions and links to relevant scenarios. |

---

## Mapping: Spec Concepts → Demo Phases → UI Routes

| Spec Concept | Demo Phase(s) | UI Route |
|-------------|---------------|----------|
| Pseudonymous signing (sig=hwk) | Phase 1 | `/signing/pseudonymous` |
| Agent identity (sig=jwks_uri) | Phase 2 | `/signing/identity` |
| Identity-based access (2-party) | Phase 2 variant | `/access/identity-based` |
| Federated/autonomous access (4-party) | Phase 3 | `/access/federated` |
| User delegation (deferred responses) | Phase 4 | `/access/user-delegation` |
| Mission proposal & approval | Phase 5 | `/missions/lifecycle` |
| Agent delegation | Phase 6 | `/advanced/delegation` |
| Call chaining (R1→R2) | Phase 7 | `/advanced/call-chaining` |
| Clarification chat | Phase 8 | `/advanced/clarification` |
| Interaction chaining | Phase 9 | `/advanced/interaction-chaining` |
| Proactive authorization + missions | Phase 10 | `/missions/proactive-authz` |
| PS-AS federation trust | Phase 11 | `/access/ps-managed` |
| Full mission lifecycle | Phase 12 | `/missions/end-to-end` |

---

## Verification Plan

1. `cd backend && python generate.py` — generates all JSON fixtures without errors
2. `cd frontend && npm run build` — Next.js builds with no TypeScript errors
3. `npm run dev` — navigate every route, verify sequence diagrams render and animate
4. Click through every step in every scenario — verify headers, JWTs, payloads display correctly
5. Verify JWT claims match what the existing `demo_phase*.py` scripts produce
6. Test responsive layout at 375px, 768px, 1440px widths
7. Verify keyboard navigation (arrow keys, space) works in step controller
