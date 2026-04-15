import Link from "next/link";
import { Radio, Lock, FileText, Zap, ArrowRight, Shield, GitBranch, Users } from "lucide-react";

const SIGNING_CARDS = [
  {
    href: "/signing/pseudonymous",
    label: "Pseudonymous",
    sublabel: "sig=hwk",
    desc: "HTTP Message Signing with a symmetric key. No identity — just proof-of-possession.",
    color: "border-blue-500/30 hover:border-blue-500/60",
    dot: "bg-blue-500",
    phase: 1,
  },
  {
    href: "/signing/identity",
    label: "Agent Identity",
    sublabel: "sig=jwks_uri",
    desc: "Cryptographic identity via JWKS URI. Resource discovers the agent's public key.",
    color: "border-blue-500/30 hover:border-blue-500/60",
    dot: "bg-blue-400",
    phase: 2,
  },
  {
    href: "/access/federated",
    label: "Federated Access",
    sublabel: "4-party auth",
    desc: "Agent signs the request, then exchanges a resource token through the PS and AS to get an auth token.",
    color: "border-blue-500/30 hover:border-blue-500/60",
    dot: "bg-blue-300",
    phase: 3,
  },
  {
    href: "/signing/compare",
    label: "Compare Modes",
    sublabel: "side-by-side",
    desc: "See all signing modes compared — headers, trust level, what the resource learns.",
    color: "border-zinc-700 hover:border-zinc-500",
    dot: "bg-zinc-500",
  },
];

const ACCESS_CARDS = [
  {
    href: "/access/identity-based",
    label: "Identity-Based",
    sublabel: "2-party",
    desc: "Agent signs request; resource decides based on cryptographic identity alone.",
    color: "border-green-500/30 hover:border-green-500/60",
    dot: "bg-green-500",
  },
  {
    href: "/access/user-delegation",
    label: "User Delegation",
    sublabel: "deferred 202",
    desc: "AS defers token issuance with pending and interaction URLs while the user approves in the browser.",
    color: "border-green-500/30 hover:border-green-500/60",
    dot: "bg-green-400",
    phase: 4,
  },
  {
    href: "/access/federated",
    label: "Federated / Autonomous",
    sublabel: "4-party",
    desc: "Agent, Resource, Person Server, and Access Server complete the autonomous token exchange.",
    color: "border-green-500/30 hover:border-green-500/60",
    dot: "bg-green-300",
    phase: 3,
  },
  {
    href: "/access/ps-managed",
    label: "PS-AS Trust",
    sublabel: "trust model",
    desc: "Same 4-party topology, but focused on trusted person servers and PS-only federation to the AS.",
    color: "border-green-500/30 hover:border-green-500/60",
    dot: "bg-emerald-300",
    phase: 11,
  },
];

const FEATURE_ROWS = [
  {
    icon: FileText,
    color: "text-purple-400",
    title: "Missions",
    desc: "Agent proposes a mission (markdown description + tools). PS approves, computes s256 hash. Mission context flows through the entire token chain.",
    links: [
      { label: "Proposal & Approval", href: "/missions/lifecycle" },
      { label: "End-to-End", href: "/missions/end-to-end" },
    ],
  },
  {
    icon: GitBranch,
    color: "text-orange-400",
    title: "Call Chaining",
    desc: "Resource 1 acts as agent to call Resource 2. Nested act claims trace the full delegation chain. PS federates across AS1 and AS2.",
    links: [{ label: "Call Chaining", href: "/advanced/call-chaining" }],
  },
  {
    icon: Users,
    color: "text-orange-300",
    title: "Clarification & Interaction",
    desc: "AS can pose clarification questions during consent. Downstream interactions bubble back through the chain to the original agent.",
    links: [
      { label: "Clarification Chat", href: "/advanced/clarification" },
      { label: "Interaction Chaining", href: "/advanced/interaction-chaining" },
    ],
  },
];

function ScenarioCard({
  href,
  label,
  sublabel,
  desc,
  color,
  dot,
  phase,
}: (typeof SIGNING_CARDS)[0]) {
  return (
    <Link
      href={href}
      className={`group relative flex flex-col gap-3 rounded-xl border bg-card p-5 transition-all duration-200 ${color}`}
    >
      <div className="flex items-center gap-2">
        <div className={`h-2 w-2 rounded-full ${dot}`} />
        <span className="font-semibold text-sm">{label}</span>
        <span className="text-xs text-muted-foreground font-mono">{sublabel}</span>
        {phase !== undefined && (
          <span className="ml-auto text-[10px] font-mono text-muted-foreground/50">
            phase {phase}
          </span>
        )}
      </div>
      <p className="text-sm text-muted-foreground leading-relaxed">{desc}</p>
      <div className="flex items-center gap-1 text-xs font-medium text-muted-foreground group-hover:text-foreground transition-colors mt-auto">
        Explore <ArrowRight className="h-3 w-3" />
      </div>
    </Link>
  );
}

export default function HomePage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-12 space-y-16">
      {/* Hero */}
      <div className="space-y-4">
        <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
          <Shield className="h-3.5 w-3.5" />
          <span>AAuth Protocol — Autonomous Authorization</span>
        </div>
        <h1 className="text-4xl font-bold tracking-tight">
          Protocol Explorer
        </h1>
        <p className="max-w-2xl text-lg text-muted-foreground leading-relaxed">
          An interactive visualizer for the AAuth protocol. Explore signing modes, resource access
          patterns, missions, delegation, and federation — with real JWT tokens, HTTP signatures,
          headers, and payloads rendered at every step.
        </p>
        <div className="flex flex-wrap gap-2 pt-2">
          {["HTTP Message Signatures (RFC 9421)", "aa-agent+jwt", "aa-resource+jwt", "aa-auth+jwt", "AAuth-Mission"].map(
            (tag) => (
              <span
                key={tag}
                className="rounded-full border border-border bg-muted px-3 py-1 text-xs font-mono text-muted-foreground"
              >
                {tag}
              </span>
            )
          )}
        </div>
      </div>

      {/* Message Signing */}
      <section className="space-y-4">
        <div className="flex items-center gap-2">
          <Radio className="h-4 w-4 text-blue-400" />
          <h2 className="text-lg font-semibold">Message Signing</h2>
          <span className="text-sm text-muted-foreground">
            How agents prove identity on requests
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {SIGNING_CARDS.map((c) => (
            <ScenarioCard key={c.href} {...c} />
          ))}
        </div>
      </section>

      {/* Resource Access */}
      <section className="space-y-4">
        <div className="flex items-center gap-2">
          <Lock className="h-4 w-4 text-green-400" />
          <h2 className="text-lg font-semibold">Resource Access Modes</h2>
          <span className="text-sm text-muted-foreground">
            From 2-party identity to full 4-party federation
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {ACCESS_CARDS.map((c) => (
            <ScenarioCard key={c.href + c.label} {...c} />
          ))}
        </div>
      </section>

      {/* Advanced Features */}
      <section className="space-y-4">
        <div className="flex items-center gap-2">
          <Zap className="h-4 w-4 text-orange-400" />
          <h2 className="text-lg font-semibold">Advanced Patterns</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {FEATURE_ROWS.map(({ icon: Icon, color, title, desc, links }) => (
            <div
              key={title}
              className="rounded-xl border border-border bg-card p-5 space-y-3"
            >
              <div className="flex items-center gap-2">
                <Icon className={`h-4 w-4 ${color}`} />
                <span className="font-semibold text-sm">{title}</span>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed">{desc}</p>
              <div className="flex flex-wrap gap-2">
                {links.map((l) => (
                  <Link
                    key={l.href}
                    href={l.href}
                    className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {l.label} <ArrowRight className="h-3 w-3" />
                  </Link>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Architecture overview */}
      <section className="rounded-xl border border-border bg-card p-6 space-y-4">
        <h2 className="font-semibold">Protocol Architecture</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          {[
            { label: "Agent", color: "bg-participant-agent", desc: "Makes signed requests, holds keys, proposes missions" },
            { label: "Resource", color: "bg-participant-resource", desc: "Protected API; issues resource tokens, verifies auth" },
            { label: "Person Server", color: "bg-participant-ps", desc: "Represents the user; manages missions, federates to AS" },
            { label: "Access Server", color: "bg-participant-as", desc: "Issues auth tokens; enforces resource access policy" },
          ].map(({ label, color, desc }) => (
            <div key={label} className="space-y-2">
              <div className={`${color} rounded-md px-3 py-1.5 text-xs font-semibold w-fit`}>
                {label}
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
