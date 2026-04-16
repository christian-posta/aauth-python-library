import Link from "next/link";
import { ArrowRight, CheckCircle, XCircle } from "lucide-react";

const WITHOUT = {
  label: "Without Missions",
  color: "text-zinc-400",
  border: "border-zinc-700",
  headers: {
    request: {
      "Signature-Key": 'sig=jwt;jwt="eyJhbGc...agent-token..."',
      "Signature-Input": 'sig=("@method" "@authority" "@path" "signature-key")',
      Signature: "sig=:base64url…:",
    },
    resourceToken: {
      iss: "https://api.example",
      aud: "https://as.example",
      agent: "aauth:local@agent.example",
      agent_jkt: "abc123…",
      scope: "read",
    },
    authToken: {
      iss: "https://as.example",
      aud: "https://api.example",
      agent: "aauth:local@agent.example",
      act: { sub: "aauth:local@agent.example" },
      cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: "..." } },
      scope: "read",
    },
  },
};

const WITH = {
  label: "With Missions",
  color: "text-purple-400",
  border: "border-purple-500/40",
  headers: {
    request: {
      "Signature-Key": 'sig=jwt;jwt="eyJhbGc...agent-token..."',
      "AAuth-Mission": 'approver="https://ps.example"; s256="sha256ofmission…"',
      "AAuth-Capabilities": "interaction, clarification",
      "Signature-Input": 'sig=("@method" "@authority" "@path" "signature-key" "aauth-mission")',
      Signature: "sig=:base64url…:",
    },
    missionBlob: {
      approver: "https://ps.example",
      agent: "aauth:local@agent.example",
      approved_at: "2026-04-14T17:14:54Z",
      description: "# Task …",
      approved_tools: [
        { name: "FeedbackReader", description: "Read customer feedback records" },
        { name: "ReportWriter", description: "Write the summary report" },
      ],
      capabilities: ["interaction", "clarification"],
    },
    resourceToken: {
      iss: "https://api.example",
      aud: "https://as.example",
      agent: "aauth:local@agent.example",
      agent_jkt: "abc123…",
      scope: "read",
      mission: { approver: "https://ps.example", s256: "sha256ofmission…" },
    },
    authToken: {
      iss: "https://as.example",
      aud: "https://api.example",
      agent: "aauth:local@agent.example",
      act: { sub: "aauth:local@agent.example" },
      cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: "..." } },
      scope: "read",
      mission: { approver: "https://ps.example", s256: "sha256ofmission…" },
    },
  },
};

const ADDITIONS = [
  { item: "AAuth-Mission header on requests", with: true },
  { item: "AAuth-Capabilities header", with: true },
  { item: "aauth-mission in signature components", with: true },
  { item: "mission claim in resource token", with: true },
  { item: "mission claim in auth token", with: true },
  { item: "PS /mission endpoint for proposals", with: true },
  { item: "s256 verification at each hop", with: true },
  { item: "Mission log at PS", with: true },
  { item: "Pre-approved tools (optional)", with: true },
  { item: "HTTP Message Signatures", with: true, without: true },
  { item: "Resource token exchange", with: true, without: true },
  { item: "PS-AS federation (federated mode)", with: true, without: true },
  { item: "Proof-of-possession (cnf)", with: true, without: true },
];

function HeaderBlock({ data }: { data: Record<string, unknown> }) {
  return (
    <pre className="text-[10px] font-mono text-muted-foreground leading-relaxed whitespace-pre-wrap break-all bg-muted/30 rounded-md p-3">
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

export default function MissionsComparePage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-10 space-y-10">
      <div className="space-y-2">
        <p className="text-xs font-semibold text-purple-400 uppercase tracking-wider">Missions</p>
        <h1 className="text-3xl font-bold">With vs Without Missions</h1>
        <p className="text-muted-foreground max-w-2xl">
          Missions are an optional governance layer that works with any resource access mode that
          has a Person Server. They add mission context to every token in the chain — without
          changing the underlying signing or federation mechanics.
        </p>
      </div>

      {/* What missions add */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">What missions add</h2>
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground">Protocol element</th>
                <th className="px-4 py-3 text-center text-xs font-semibold text-zinc-400">Without</th>
                <th className="px-4 py-3 text-center text-xs font-semibold text-purple-400">With Missions</th>
              </tr>
            </thead>
            <tbody>
              {ADDITIONS.map((a, i) => (
                <tr key={a.item} className={`border-b border-border ${i % 2 ? "bg-muted/10" : ""}`}>
                  <td className="px-5 py-3 text-xs text-muted-foreground">{a.item}</td>
                  <td className="px-4 py-3">
                    <div className="flex justify-center">
                      {a.without
                        ? <CheckCircle className="h-4 w-4 text-green-400" />
                        : <XCircle className="h-4 w-4 text-zinc-700" />}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex justify-center">
                      <CheckCircle className="h-4 w-4 text-green-400" />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Token diff */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Token claim differences</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {[WITHOUT, WITH].map((mode) => (
            <div key={mode.label} className={`rounded-xl border ${mode.border} bg-card p-5 space-y-4`}>
              <p className={`font-semibold text-sm ${mode.color}`}>{mode.label}</p>

              <div className="space-y-2">
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Request Headers</p>
                <HeaderBlock data={mode.headers.request as Record<string, unknown>} />
              </div>
              {"missionBlob" in mode.headers && (
                <div className="space-y-2">
                  <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Mission Blob (from PS /mission approval)</p>
                  <HeaderBlock data={(mode.headers as { missionBlob: Record<string, unknown> }).missionBlob} />
                </div>
              )}
              <div className="space-y-2">
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Resource Token (aa-resource+jwt payload)</p>
                <HeaderBlock data={mode.headers.resourceToken as Record<string, unknown>} />
              </div>
              <div className="space-y-2">
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Auth Token (aa-auth+jwt payload)</p>
                <HeaderBlock data={mode.headers.authToken as Record<string, unknown>} />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Mission lifecycle summary */}
      <section className="rounded-xl border border-border bg-card p-6 space-y-4">
        <h2 className="text-sm font-semibold">Mission Lifecycle (Before Authorization)</h2>
        <ol className="space-y-2 text-sm text-muted-foreground">
          {[
            "Agent fetches PS well-known metadata to find mission_endpoint.",
            'Agent POSTs mission proposal: {"description": "# Task...", "tools": [...]}.',
            "PS cannot approve without the user — returns 202 + AAuth-Requirement with interaction URL.",
            "User opens the interaction URL, reviews the description and tools, and approves.",
            "Agent polls the pending URL; PS returns 200 with the approved mission blob (approver, agent, approved_at, description, approved_tools, capabilities).",
            'AAuth-Mission: approver="..."; s256="sha256..." header is set on the 200 response.',
            "Agent verifies SHA-256(response_body_bytes) == s256 from the header and stores the bytes as received.",
            "Agent includes AAuth-Mission on all subsequent requests; when the mission terminates, the PS returns mission_terminated for any mission-bound request.",
          ].map((step, i) => (
            <li key={i} className="flex items-start gap-3">
              <span className="shrink-0 text-[10px] font-mono text-muted-foreground/50 mt-1">{i + 1}.</span>
              <span>{step}</span>
            </li>
          ))}
        </ol>
        <div className="flex flex-wrap gap-3 pt-2">
          <Link href="/missions/lifecycle" className="flex items-center gap-1 text-xs font-medium text-purple-400 hover:text-purple-300 transition-colors">
            Mission Proposal Demo <ArrowRight className="h-3 w-3" />
          </Link>
          <Link href="/missions/end-to-end" className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors">
            End-to-End Lifecycle <ArrowRight className="h-3 w-3" />
          </Link>
          <Link href="/missions/completion" className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors">
            Mission Completion <ArrowRight className="h-3 w-3" />
          </Link>
          <Link href="/missions/audit" className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors">
            Audit Endpoint <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
      </section>
    </div>
  );
}
