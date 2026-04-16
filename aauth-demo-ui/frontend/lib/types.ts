// ─── Participants ─────────────────────────────────────────────────────────────

export type ParticipantType =
  | "agent"
  | "resource"
  | "person-server"
  | "access-server"
  | "user"
  | "delegate";

export interface Participant {
  id: string;
  label: string;
  type: ParticipantType;
  port?: number;
  metadata_url?: string;
  jwks_url?: string;
}

// ─── Tokens ───────────────────────────────────────────────────────────────────

export interface DecodedToken {
  name: string;         // e.g. "Resource Token", "Auth Token"
  typ: string;          // e.g. "aa-resource+jwt"
  raw: string;          // Full JWT string
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature_b64: string;
}

// ─── HTTP Signatures ──────────────────────────────────────────────────────────

export interface SignatureDetails {
  scheme: string;              // hwk | jwks_uri | jwt
  signature_base: string;      // The exact signature base string
  signature_input: string;     // Signature-Input header value
  signature_key: string;       // Signature-Key header value
  covered_components: string[];
}

// ─── Protocol Steps ──────────────────────────────────────────────────────────

export interface ProtocolStep {
  step: number;
  from: string;                        // participant id
  to: string;                          // participant id
  label: string;                       // short description for the arrow
  method: string;
  url: string;
  request_headers: Record<string, string>;
  request_body?: unknown;
  response_status: number;
  response_headers: Record<string, string>;
  response_body?: unknown;
  tokens: DecodedToken[];
  signature?: SignatureDetails;
  annotations: string[];               // explanatory notes / spec references
  is_response?: boolean;               // true for response arrows
}

export interface TokenFlowEvent {
  step: number;
  participant: string;
  label: string;
  kind: "issued" | "forwarded" | "returned" | "presented";
}

export interface TokenFlow {
  token: string;
  label: string;
  tokenType?: string;
  accent?: "resource" | "auth" | "agent";
  events: TokenFlowEvent[];
}

export interface DeferredTimelineEvent {
  step: number;
  status: number;
  label: string;
  detail: string;
}

export interface DeferredTimeline {
  title: string;
  events: DeferredTimelineEvent[];
}

export interface MissionTool {
  name: string;
  description: string;
}

export interface MissionBlobData {
  title: string;
  description: string;
  markdown: string;
  /** Required per SPEC.md §1261 — approved tool list returned in the mission blob */
  approved_tools: MissionTool[];
  approver: string;
  /** Required per SPEC.md §1261 — agent identifier on the approved blob */
  agent: string;
  /** Required per SPEC.md §1261 — ISO 8601 timestamp; ensures s256 uniqueness */
  approved_at: string;
  s256: string;
  capabilities?: string[];
}

export interface S256ChainLink {
  label: string;
  source: string;
  s256: string;
  detail: string;
}

// ─── Scenarios ────────────────────────────────────────────────────────────────

export type ScenarioCategory = "signing" | "access" | "missions" | "advanced";

export interface ScenarioVariant {
  description: string;
  participants: Participant[];
  steps: ProtocolStep[];
  token_flow?: TokenFlow[];
  deferred_timeline?: DeferredTimeline;
}

export interface Scenario {
  id: string;
  title: string;
  description: string;
  spec_section?: string;
  category: ScenarioCategory;
  demo_phase?: number;
  participants: Participant[];
  steps: ProtocolStep[];
  token_flow?: TokenFlow[];
  deferred_timeline?: DeferredTimeline;
  mission_blob?: MissionBlobData;
  s256_chain?: S256ChainLink[];
  /** Optional interactive/user-approval variant of this scenario */
  interactive?: ScenarioVariant;
}

// ─── Navigation ───────────────────────────────────────────────────────────────

export interface NavItem {
  label: string;
  href: string;
  phase?: number;
  description?: string;
}

export interface NavSection {
  title: string;
  icon: string;
  items: NavItem[];
}
