import Link from "next/link";
import { ArrowRight, CheckCircle, XCircle, ExternalLink, Layers } from "lucide-react";

const COVERED_COMPONENTS = [
  { name: "@method", required: "base", desc: "HTTP request method (RFC 9421 §2.2.1)" },
  { name: "@authority", required: "base", desc: "Target host (RFC 9421 §2.2.3)" },
  { name: "@path", required: "base", desc: "Request path (RFC 9421 §2.2.6)" },
  {
    name: "signature-key",
    required: "base",
    desc: "Binds Signature-Key header to the signature — prevents scheme/identity substitution",
  },
  {
    name: "authorization",
    required: "conditional",
    desc: "REQUIRED when presenting an AAuth-Access token — binds token to request",
  },
  {
    name: "content-digest",
    required: "optional",
    desc: "Body integrity (RFC 9530). Resources opt in via additional_signature_components",
  },
];

const DWK_VALUES = [
  { value: "aauth-agent.json", owner: "Agent server", contains: "agent token issuer keys" },
  { value: "aauth-resource.json", owner: "Resource", contains: "resource token issuer keys" },
  { value: "aauth-person.json", owner: "Person server", contains: "auth-token & permission keys" },
  { value: "aauth-access.json", owner: "Access server", contains: "auth-token issuer keys" },
];

const ALGORITHMS = [
  {
    alg: "Ed25519 (EdDSA)",
    level: "MUST",
    rfc: "RFC 8032",
    notes: "Recommended default for both agents and servers.",
  },
  {
    alg: "ECDSA P-256 (deterministic)",
    level: "SHOULD",
    rfc: "RFC 6979",
    notes: "Deterministic signatures per RFC 6979 required.",
  },
  {
    alg: "alg=none",
    level: "MUST NOT",
    rfc: "—",
    notes: "Never accepted by AAuth verifiers.",
  },
];

export default function SignaturesProfilePage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-10 space-y-12">
      {/* Header */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-cyan-400" />
          <p className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Foundations</p>
        </div>
        <h1 className="text-3xl font-bold tracking-tight">HTTP Signatures Profile</h1>
        <p className="text-muted-foreground max-w-3xl leading-relaxed">
          AAuth doesn&apos;t reinvent signing — it profiles two existing specs. This page lists exactly
          what AAuth pins down: the algorithms it requires, the components that MUST be covered, the
          timestamp window, and the well-known document names used for key discovery.
        </p>
      </div>

      {/* Relationship diagram */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          How the specs compose
        </h2>
        <div className="rounded-xl border border-border bg-card p-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="rounded-lg border border-cyan-500/40 bg-cyan-500/5 p-4 space-y-2">
              <p className="text-xs font-semibold text-cyan-300">AAuth SPEC</p>
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                Profiles 4 schemes, pins Ed25519/P-256, fixes base covered components, sets 60s
                validity window, defines <code className="text-[10px]">dwk</code> values.
              </p>
            </div>
            <div className="rounded-lg border border-border bg-muted/20 p-4 space-y-2">
              <p className="text-xs font-semibold text-foreground">RFC 9421</p>
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                HTTP Message Signatures. Defines <code className="text-[10px]">Signature-Input</code>,{" "}
                <code className="text-[10px]">Signature</code>, covered components, and signature
                base construction.
              </p>
            </div>
            <div className="rounded-lg border border-border bg-muted/20 p-4 space-y-2">
              <p className="text-xs font-semibold text-foreground">Signature-Key draft</p>
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                Defines the <code className="text-[10px]">Signature-Key</code> header with 5 schemes
                (<code className="text-[10px]">hwk, jkt-jwt, jwks_uri, jwt, x509</code>),{" "}
                <code className="text-[10px]">Accept-Signature sigkey</code>, and{" "}
                <code className="text-[10px]">Signature-Error</code>.
              </p>
            </div>
          </div>
          <p className="mt-4 text-xs text-muted-foreground leading-relaxed">
            Every AAuth request includes three headers — <code className="text-[10px]">Signature-Key</code>,{" "}
            <code className="text-[10px]">Signature-Input</code>, <code className="text-[10px]">Signature</code>
            {" "}— and follows the profile rules below.
          </p>
        </div>
      </section>

      {/* Algorithms */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Algorithms
        </h2>
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground">Algorithm</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground w-32">Level</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground w-32">Reference</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground">Notes</th>
              </tr>
            </thead>
            <tbody>
              {ALGORITHMS.map((a, i) => (
                <tr key={a.alg} className={`border-b border-border ${i % 2 ? "bg-muted/10" : ""}`}>
                  <td className="px-5 py-3 text-sm font-mono">{a.alg}</td>
                  <td className="px-5 py-3 text-xs">
                    <span
                      className={
                        a.level === "MUST"
                          ? "text-green-400 font-semibold"
                          : a.level === "SHOULD"
                            ? "text-blue-400 font-semibold"
                            : "text-red-400 font-semibold"
                      }
                    >
                      {a.level}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-xs text-muted-foreground">{a.rfc}</td>
                  <td className="px-5 py-3 text-xs text-muted-foreground">{a.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-[11px] text-muted-foreground">
          Spec: <code className="text-[10px] bg-muted/50 rounded px-1">§HTTP Message Signatures Profile · Signature Algorithms</code>
        </p>
      </section>

      {/* Covered components */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Covered components
        </h2>
        <p className="text-sm text-muted-foreground max-w-3xl">
          Every AAuth signature MUST cover the four base components. Resources can require more via
          the <code className="text-[11px] bg-muted rounded px-1">additional_signature_components</code>{" "}
          field in their metadata. A missing component returns{" "}
          <code className="text-[11px] bg-muted rounded px-1">invalid_input</code> with{" "}
          <code className="text-[11px] bg-muted rounded px-1">required_input</code>.
        </p>
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground w-48">Component</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground w-32">Requirement</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground">Why</th>
              </tr>
            </thead>
            <tbody>
              {COVERED_COMPONENTS.map((c, i) => (
                <tr key={c.name} className={`border-b border-border ${i % 2 ? "bg-muted/10" : ""}`}>
                  <td className="px-5 py-3 text-sm font-mono text-blue-300">{c.name}</td>
                  <td className="px-5 py-3 text-xs">
                    {c.required === "base" && (
                      <span className="inline-flex items-center gap-1 text-green-400 font-semibold">
                        <CheckCircle className="h-3 w-3" /> base
                      </span>
                    )}
                    {c.required === "conditional" && (
                      <span className="text-blue-300 font-semibold">conditional</span>
                    )}
                    {c.required === "optional" && (
                      <span className="inline-flex items-center gap-1 text-muted-foreground">
                        <XCircle className="h-3 w-3 text-zinc-600" /> optional
                      </span>
                    )}
                  </td>
                  <td className="px-5 py-3 text-xs text-muted-foreground leading-relaxed">{c.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Signature parameters */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Signature parameters
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-xl border border-border bg-card p-5 space-y-2">
            <p className="text-sm font-semibold text-foreground">created (Unix time)</p>
            <p className="text-xs text-muted-foreground leading-relaxed">
              REQUIRED on every signature. The server rejects signatures outside a validity window
              relative to its current time.
            </p>
            <pre className="mt-2 rounded bg-muted/50 p-2.5 text-[10px] font-mono text-blue-300 overflow-x-auto">
{`Signature-Input: sig=("@method" "@authority"
    "@path" "signature-key");created=1730217600`}
            </pre>
          </div>
          <div className="rounded-xl border border-border bg-card p-5 space-y-2">
            <p className="text-sm font-semibold text-foreground">
              Validity window <span className="text-muted-foreground font-normal">(default 60s)</span>
            </p>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Resources can advertise a larger or smaller window via{" "}
              <code className="text-[10px] bg-muted/50 rounded px-1">signature_window</code> in
              their metadata. Clock skew must be handled by NTP.
            </p>
            <pre className="mt-2 rounded bg-muted/50 p-2.5 text-[10px] font-mono text-muted-foreground overflow-x-auto">
{`{
  "signature_window": 120
}`}
            </pre>
          </div>
        </div>
      </section>

      {/* dwk values */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Key discovery — <code className="text-[11px] bg-muted rounded px-1">dwk</code> values
        </h2>
        <p className="text-sm text-muted-foreground max-w-3xl">
          The Signature-Key draft defines the <code className="text-[11px] bg-muted rounded px-1">dwk</code>{" "}
          (&quot;dot well-known&quot;) parameter abstractly. AAuth pins four concrete values — one per role —
          each rooted at <code className="text-[11px] bg-muted rounded px-1">{`{iss}/.well-known/{dwk}`}</code>.
        </p>
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground">dwk value</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground">Published by</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground">Contains</th>
              </tr>
            </thead>
            <tbody>
              {DWK_VALUES.map((d, i) => (
                <tr key={d.value} className={`border-b border-border ${i % 2 ? "bg-muted/10" : ""}`}>
                  <td className="px-5 py-3 text-sm font-mono text-cyan-300">{d.value}</td>
                  <td className="px-5 py-3 text-xs text-muted-foreground">{d.owner}</td>
                  <td className="px-5 py-3 text-xs text-muted-foreground">{d.contains}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Next */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Link
          href="/foundations/schemes"
          className="group rounded-xl border border-border bg-card p-5 space-y-2 hover:border-cyan-500/40 transition-colors"
        >
          <p className="text-xs font-semibold text-cyan-400">Next</p>
          <p className="text-sm font-semibold">Signature-Key Schemes →</p>
          <p className="text-xs text-muted-foreground leading-relaxed">
            The four schemes AAuth uses (and the one it doesn&apos;t).
          </p>
          <span className="inline-flex items-center gap-1 text-xs text-muted-foreground group-hover:text-foreground">
            Explore <ArrowRight className="h-3 w-3" />
          </span>
        </Link>
        <Link
          href="/foundations/errors"
          className="group rounded-xl border border-border bg-card p-5 space-y-2 hover:border-cyan-500/40 transition-colors"
        >
          <p className="text-xs font-semibold text-cyan-400">See also</p>
          <p className="text-sm font-semibold">Error Model →</p>
          <p className="text-xs text-muted-foreground leading-relaxed">
            How verification failures are signaled with <code className="text-[10px]">Signature-Error</code>.
          </p>
          <span className="inline-flex items-center gap-1 text-xs text-muted-foreground group-hover:text-foreground">
            Explore <ArrowRight className="h-3 w-3" />
          </span>
        </Link>
      </section>

      {/* Further reading */}
      <section className="rounded-xl border border-border bg-card p-6 space-y-3">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Further reading
        </p>
        <ul className="space-y-2 text-sm">
          <li>
            <a
              href="https://www.rfc-editor.org/rfc/rfc9421"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-muted-foreground hover:text-foreground"
            >
              RFC 9421 — HTTP Message Signatures <ExternalLink className="h-3 w-3" />
            </a>
          </li>
          <li>
            <a
              href="https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-muted-foreground hover:text-foreground"
            >
              draft-hardt-httpbis-signature-key — Signature-Key header & schemes{" "}
              <ExternalLink className="h-3 w-3" />
            </a>
          </li>
          <li>
            <span className="text-muted-foreground">
              AAuth SPEC · §HTTP Message Signatures Profile
            </span>
          </li>
        </ul>
      </section>
    </div>
  );
}
