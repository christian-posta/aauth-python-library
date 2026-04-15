import Link from "next/link";
import { ArrowRight } from "lucide-react";

const MODES = [
  {
    id: "identity-based",
    label: "Identity-Based",
    parties: "2-party",
    color: "text-green-400",
    border: "border-green-500/30",
    href: "/access/identity-based",
    participants: ["Agent", "Resource"],
    flow: [
      { arrow: "Agent → Resource", note: "Signed request (sig=jwks_uri)" },
      { arrow: "Resource → Agent", note: "200 OK (access decision by identity)" },
    ],
    tokens: [],
    infra: "None — just the agent and resource",
    useCase: "Replacing API keys. No external infra needed.",
    tradeoff: "Resource must maintain its own access policy",
  },
  {
    id: "user-delegation",
    label: "User Delegation",
    parties: "5-party deferred",
    color: "text-blue-400",
    border: "border-blue-500/30",
    href: "/access/user-delegation",
    participants: ["Agent", "Resource", "Person Server", "Access Server", "User"],
    flow: [
      { arrow: "Agent → Resource", note: "Signed request → 401 + resource token" },
      { arrow: "Agent → PS → AS", note: "Federation request reaches AS" },
      { arrow: "AS → PS → Agent", note: "202 + pending URL + interaction URL" },
      { arrow: "User → AS", note: "Authenticate and approve consent" },
      { arrow: "Agent → PS", note: "Poll pending URL: 202 → 202 → 200" },
      { arrow: "Agent → Resource", note: "Present auth token → 200" },
    ],
    tokens: ["aa-resource+jwt", "aa-agent+jwt", "aa-auth+jwt"],
    infra: "Person Server + Access Server + user interaction",
    useCase: "When human consent is required before delegated agent access",
    tradeoff: "Extra round-trips and polling before access is granted",
  },
  {
    id: "ps-managed",
    label: "PS-Managed",
    parties: "4-party",
    color: "text-purple-400",
    border: "border-purple-500/30",
    href: "/access/federated",
    participants: ["Agent", "Resource", "Person Server", "Access Server"],
    flow: [
      { arrow: "Agent → Resource", note: "Signed request → 401 + resource token" },
      { arrow: "Agent → PS", note: "POST resource token" },
      { arrow: "PS → AS", note: "Federation: PS signs + forwards" },
      { arrow: "AS → PS → Agent", note: "Auth token returned" },
      { arrow: "Agent → Resource", note: "Present auth token → 200" },
    ],
    tokens: ["aa-resource+jwt", "aa-agent+jwt", "aa-auth+jwt (from AS)"],
    infra: "Person Server + Access Server",
    useCase: "Autonomous cross-domain access with explicit AS policy enforcement",
    tradeoff: "More moving parts; PS and AS must trust each other",
  },
  {
    id: "federated",
    label: "PS-AS Federation Trust",
    parties: "4-party trust focus",
    color: "text-orange-400",
    border: "border-orange-500/30",
    href: "/access/ps-managed",
    participants: ["Agent", "Resource", "Person Server", "Access Server"],
    flow: [
      { arrow: "Agent → Resource", note: "Signed request → 401 + resource token (aud=AS)" },
      { arrow: "Agent → PS", note: "POST resource token" },
      { arrow: "PS → AS", note: "Trusted PS federates using its own jwks_uri identity" },
      { arrow: "AS → PS", note: "AS honors only trusted_person_servers" },
      { arrow: "Agent → Resource", note: "Present auth token → 200" },
    ],
    tokens: ["aa-agent+jwt (ps claim)", "aa-resource+jwt", "aa-auth+jwt"],
    infra: "Person Server + Access Server",
    useCase: "Explaining trust boundaries and PS-only token endpoint access",
    tradeoff: "Same topology as federated mode, but the trust model must be made explicit",
  },
];

export default function AccessComparePage() {
  return (
    <div className="mx-auto max-w-6xl px-6 py-10 space-y-10">
      <div className="space-y-2">
        <p className="text-xs font-semibold text-green-400 uppercase tracking-wider">Resource Access</p>
        <h1 className="text-3xl font-bold">Resource Access Mode Comparison</h1>
        <p className="text-muted-foreground max-w-2xl">
          AAuth defines four resource access modes, from simple 2-party identity checks to full
          4-party federation with a Person Server and Access Server. Each mode builds on the previous.
        </p>
      </div>

      {/* Mode cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {MODES.map((m) => (
          <div key={m.id} className={`rounded-xl border ${m.border} bg-card p-5 space-y-4`}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className={`font-semibold ${m.color}`}>{m.label}</p>
                <p className="text-[10px] font-mono text-muted-foreground mt-0.5">{m.parties}</p>
              </div>
              <Link href={m.href} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors shrink-0">
                Live demo <ArrowRight className="h-3 w-3" />
              </Link>
            </div>

            {/* Participants */}
            <div className="flex flex-wrap gap-2">
              {m.participants.map((p) => {
                const colors: Record<string, string> = {
                  Agent: "bg-participant-agent", Resource: "bg-participant-resource",
                  "Person Server": "bg-participant-ps", "Access Server": "bg-participant-as",
                  User: "bg-participant-user",
                };
                return (
                  <span key={p} className={`${colors[p] ?? "bg-muted"} rounded px-2 py-0.5 text-[10px] font-semibold`}>
                    {p}
                  </span>
                );
              })}
            </div>

            {/* Flow */}
            <div className="space-y-1.5">
              {m.flow.map((step, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <span className="font-mono text-muted-foreground/50 shrink-0 mt-px">{i + 1}.</span>
                  <div>
                    <span className="font-mono text-foreground/80">{step.arrow}</span>
                    <span className="text-muted-foreground ml-2">{step.note}</span>
                  </div>
                </div>
              ))}
            </div>

            {/* Tokens */}
            {m.tokens.length > 0 && (
              <div className="space-y-1">
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Tokens</p>
                <div className="flex flex-wrap gap-1.5">
                  {m.tokens.map((t) => (
                    <span key={t} className="text-[10px] font-mono bg-muted rounded px-2 py-0.5 text-muted-foreground">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-3 text-xs border-t border-border pt-3">
              <div>
                <p className="text-muted-foreground/60 text-[10px] uppercase tracking-wider mb-1">Infrastructure</p>
                <p className="text-muted-foreground">{m.infra}</p>
              </div>
              <div>
                <p className="text-muted-foreground/60 text-[10px] uppercase tracking-wider mb-1">Best for</p>
                <p className="text-muted-foreground">{m.useCase}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Progressive complexity note */}
      <div className="rounded-xl border border-border bg-card p-6 space-y-3">
        <h2 className="text-sm font-semibold">Progressive Adoption</h2>
        <p className="text-sm text-muted-foreground max-w-3xl leading-relaxed">
          Each mode is independently deployable. A resource can start with identity-based access
          (just verify the agent&apos;s signature) and later add a PS or AS without changing the agent&apos;s
          signing approach. The main change is what the resource returns in its `401` challenge and
          which downstream party mints the eventual access token.
        </p>
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-muted-foreground">
          <span className="text-green-400">Identity-Based</span>
          <ArrowRight className="h-3 w-3" />
          <span className="text-blue-400">User Delegation</span>
          <ArrowRight className="h-3 w-3" />
          <span className="text-purple-400">PS-Managed</span>
          <ArrowRight className="h-3 w-3" />
          <span className="text-orange-400">PS-AS Trust</span>
        </div>
      </div>
    </div>
  );
}
