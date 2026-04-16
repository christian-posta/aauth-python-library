import Link from "next/link";
import { ArrowRight, Shield, Radio, Lock, FileText, BookOpen } from "lucide-react";
import { cn } from "@/lib/utils";

const FOUNDATIONS_LINKS = [
  {
    href: "/foundations/profile",
    label: "HTTP Signatures Profile",
    desc: "What AAuth pins from RFC 9421",
  },
  {
    href: "/foundations/schemes",
    label: "Signature-Key Schemes",
    desc: "The four schemes, side-by-side",
  },
  {
    href: "/foundations/errors",
    label: "Error Model",
    desc: "Signature-Error codes",
  },
];

const LAYERS = [
  {
    title: "Identity",
    Icon: Radio,
    accent: "border-blue-500/35 hover:border-blue-500/55",
    iconWrap: "bg-blue-500/15 text-blue-400",
    body: "How an agent cryptographically proves who it is on every request — from pseudonymous keys (no account) to agent tokens that bind a signing key to an identifier. Built on HTTP Message Signatures and the Signature-Key header.",
    links: [
      { href: "/signing/compare", label: "Compare signing modes" },
      { href: "/foundations/schemes", label: "Signature-Key schemes" },
    ],
  },
  {
    title: "Resource access",
    Icon: Lock,
    accent: "border-green-500/35 hover:border-green-500/55",
    iconWrap: "bg-green-500/15 text-green-400",
    body: "How a protected API decides what the agent may do — from identity-only access through two-party flows, three-party flows with a Person Server, and four-party federation with an Access Server.",
    links: [{ href: "/access/compare", label: "Compare access modes" }],
  },
  {
    title: "Mission",
    Icon: FileText,
    accent: "border-purple-500/35 hover:border-purple-500/55",
    iconWrap: "bg-purple-500/15 text-purple-400",
    body: "Optional governance: the agent proposes a mission; the Person Server approves, scopes permissions, and threads mission context through tokens. Also covers delegation across resources and advanced interaction patterns.",
    links: [
      { href: "/missions/compare", label: "Missions vs no mission" },
      { href: "/missions/lifecycle", label: "Proposal & approval" },
      { href: "/advanced/call-chaining", label: "Call chaining" },
    ],
  },
];

function LayerCard({
  title,
  Icon,
  accent,
  iconWrap,
  body,
  links,
}: (typeof LAYERS)[number]) {
  return (
    <div
      className={cn(
        "rounded-xl border bg-card p-6 flex flex-col gap-4 transition-colors",
        accent
      )}
    >
      <div className="flex items-start gap-3">
        <div
          className={cn(
            "flex h-10 w-10 shrink-0 items-center justify-center rounded-lg",
            iconWrap
          )}
        >
          <Icon className="h-5 w-5" />
        </div>
        <div className="space-y-2 min-w-0">
          <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
          <p className="text-sm text-muted-foreground leading-relaxed">{body}</p>
        </div>
      </div>
      <div className="flex flex-wrap gap-2 pt-1">
        {links.map((l) => (
          <Link
            key={l.href}
            href={l.href}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background/60 px-3 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground hover:bg-accent/50 transition-colors"
          >
            {l.label}
            <ArrowRight className="h-3 w-3 opacity-70" />
          </Link>
        ))}
      </div>
    </div>
  );
}

export default function HomePage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-12 space-y-14">
      {/* Hero */}
      <div className="space-y-4">
        <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
          <Shield className="h-3.5 w-3.5" />
          <span>AAuth Protocol — Autonomous Authorization</span>
        </div>
        <h1 className="text-4xl font-bold tracking-tight">Protocol Explorer</h1>
        <p className="max-w-2xl text-lg text-muted-foreground leading-relaxed">
          An interactive walkthrough of the AAuth protocol. Pick a scenario, step through the
          requests, and see the real headers and tokens at each hop.
        </p>
      </div>

      {/* Participants */}
      <section className="rounded-xl border border-border bg-card p-6 space-y-4">
        <div className="space-y-1">
          <h2 className="font-semibold">The four participants</h2>
          <p className="text-xs text-muted-foreground">
            Every scenario involves some subset of these roles. Use the sidebar to drill into each
            area.
          </p>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          {[
            {
              label: "Agent",
              color: "bg-participant-agent",
              desc: "Makes signed requests, holds keys, proposes missions",
            },
            {
              label: "Resource",
              color: "bg-participant-resource",
              desc: "Protected API; issues resource tokens, verifies auth",
            },
            {
              label: "Person Server",
              color: "bg-participant-ps",
              desc: "Represents the user; manages missions, federates to AS",
            },
            {
              label: "Access Server",
              color: "bg-participant-as",
              desc: "Issues auth tokens; enforces resource access policy",
            },
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

      {/* Three layers */}
      <section className="space-y-4">
        <div className="space-y-1">
          <h2 className="text-lg font-semibold">Three layers</h2>
          <p className="text-sm text-muted-foreground max-w-2xl">
            AAuth stacks identity proof, authorization against resources, and optional mission
            governance. Each layer links to comparison or entry pages; the sidebar lists every
            scenario.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-4">
          {LAYERS.map((layer) => (
            <LayerCard key={layer.title} {...layer} />
          ))}
        </div>
      </section>

      {/* Spec reference */}
      <section className="rounded-xl border border-dashed border-border/70 bg-muted/10 p-5 space-y-3">
        <div className="flex items-center gap-2 flex-wrap">
          <BookOpen className="h-3.5 w-3.5 text-muted-foreground" />
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Spec reference
          </p>
          <span className="text-xs text-muted-foreground">
            How AAuth profiles RFC 9421 and the Signature-Key draft
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {FOUNDATIONS_LINKS.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className="group flex items-center justify-between gap-2 rounded-md border border-border/50 bg-background/40 px-3 py-2 hover:border-cyan-500/40 hover:bg-background/80 transition-colors"
            >
              <div className="min-w-0">
                <p className="text-xs font-medium truncate">{l.label}</p>
                <p className="text-[11px] text-muted-foreground truncate">{l.desc}</p>
              </div>
              <ArrowRight className="h-3 w-3 text-muted-foreground group-hover:text-foreground shrink-0" />
            </Link>
          ))}
        </div>
      </section>
    </div>
  );
}
