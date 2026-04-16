import Link from "next/link";
import { ArrowRight, ExternalLink, Layers, CheckCircle, XCircle } from "lucide-react";

const SCHEMES = [
  {
    id: "hwk",
    name: "hwk",
    fullName: "Header Web Key",
    inAAuth: true,
    tier: "Pseudonymous",
    tierColor: "text-blue-400",
    tierBorder: "border-blue-500/40",
    summary:
      "Public key inline in the header. Self-contained verification — no fetches, no issuer, no identity.",
    example:
      'sig=hwk;kty="OKP";crv="Ed25519";x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"',
    whenUsed:
      "Agents with no identity infrastructure; rate-limiting by key; anonymous-but-accountable access.",
    trust: "Key possession only — verifier learns a stable JWK Thumbprint, nothing more.",
    href: "/signing/pseudonymous",
  },
  {
    id: "jkt-jwt",
    name: "jkt-jwt",
    fullName: "JKT JWT Self-Issued Key Delegation",
    inAAuth: true,
    tier: "Pseudonymous",
    tierColor: "text-blue-400",
    tierBorder: "border-blue-500/40",
    summary:
      "A JWT signed by an enclave/hardware key delegates to a fast ephemeral signing key via the cnf claim. Identity is a JWK Thumbprint URN (TOFU).",
    example: 'sig=jkt-jwt;jwt="eyJ0eXAiOiJqa3Qtc…"',
    whenUsed:
      "Agent-token renewal from a stable hardware key (SPEC §Agent Token Acquisition); mobile/IoT agents with secure enclaves.",
    trust:
      "Persistent pseudonymous identity tied to the enclave key; ephemeral key signs requests at line rate.",
    href: "/signing/hardware-backed",
  },
  {
    id: "jwks_uri",
    name: "jwks_uri",
    fullName: "JWKS URI Discovery",
    inAAuth: true,
    tier: "Identity",
    tierColor: "text-green-400",
    tierBorder: "border-green-500/40",
    summary:
      "The Signature-Key references an HTTPS identifier. The verifier fetches {id}/.well-known/{dwk}, reads jwks_uri, resolves the kid.",
    example:
      'sig=jwks_uri;id="https://agent.example";dwk="aauth-agent.json";kid="key-1"',
    whenUsed:
      "Raw agent identity — before an agent has an agent token. Also how AAuth tokens' issuers' keys are discovered.",
    trust:
      "Cryptographic identity bound to an HTTPS origin. Verifier learns the full agent identifier.",
    href: "/signing/identity",
  },
  {
    id: "jwt",
    name: "jwt",
    fullName: "JWT Confirmation Key",
    inAAuth: true,
    tier: "Identity",
    tierColor: "text-green-400",
    tierBorder: "border-green-500/40",
    summary:
      "A signed JWT (with iss + dwk) carries the public key in its cnf claim. Verifier checks the JWT, then verifies the HTTP signature with the cnf key.",
    example: 'sig=jwt;jwt="eyJhbGciOiJFZERTQSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9…"',
    whenUsed:
      "Agent tokens (aa-agent+jwt), resource tokens (aa-resource+jwt), and auth tokens (aa-auth+jwt) are all presented this way.",
    trust:
      "Identity + key binding vouched for by a signed issuer. The JWT typ identifies which AAuth token it is.",
    href: "/signing/agent-tokens",
  },
];

const NOT_USED = [
  {
    id: "x509",
    name: "x509",
    fullName: "X.509 Certificate Chain",
    reason:
      "AAuth relies on JWK-based discovery (dwk + jwks_uri) and doesn't depend on PKI. The scheme remains available in the draft for deployments that need it, but AAuth neither requires nor defines behavior around it.",
  },
];

export default function SchemesPage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-10 space-y-12">
      {/* Header */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-cyan-400" />
          <p className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Foundations</p>
        </div>
        <h1 className="text-3xl font-bold tracking-tight">Signature-Key Schemes</h1>
        <p className="text-muted-foreground max-w-3xl leading-relaxed">
          The Signature-Key draft defines five schemes. AAuth profiles four of them, grouped into
          two trust tiers. This page is the one-stop map of which scheme does what and where each
          lives in the protocol.
        </p>
      </div>

      {/* Tier overview */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Two tiers, four schemes
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-xl border border-blue-500/40 bg-blue-500/5 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-blue-300">Pseudonymous tier</p>
              <code className="text-[10px] font-mono text-blue-300 bg-blue-500/10 rounded px-2 py-0.5">
                sigkey=jkt
              </code>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Verifier learns a stable JWK Thumbprint — no identity. Useful for rate-limiting,
              anonymous-but-accountable access, hardware-backed device identity.
            </p>
            <div className="flex flex-wrap gap-2">
              <code className="text-[11px] font-mono text-blue-300 bg-blue-500/10 rounded px-2 py-0.5">
                sig=hwk
              </code>
              <code className="text-[11px] font-mono text-blue-300 bg-blue-500/10 rounded px-2 py-0.5">
                sig=jkt-jwt
              </code>
            </div>
          </div>
          <div className="rounded-xl border border-green-500/40 bg-green-500/5 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-green-300">Identity tier</p>
              <code className="text-[10px] font-mono text-green-300 bg-green-500/10 rounded px-2 py-0.5">
                sigkey=uri
              </code>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Verifier learns a verifiable identifier — an HTTPS origin or an issuer-signed JWT.
              This is how AAuth tokens (agent/resource/auth) are presented.
            </p>
            <div className="flex flex-wrap gap-2">
              <code className="text-[11px] font-mono text-green-300 bg-green-500/10 rounded px-2 py-0.5">
                sig=jwks_uri
              </code>
              <code className="text-[11px] font-mono text-green-300 bg-green-500/10 rounded px-2 py-0.5">
                sig=jwt
              </code>
            </div>
          </div>
        </div>
        <p className="text-[11px] text-muted-foreground">
          The tier values (<code className="text-[10px]">jkt</code>, <code className="text-[10px]">uri</code>)
          are what a resource asks for in its <code className="text-[10px]">Accept-Signature: sigkey=…</code> challenge.
        </p>
      </section>

      {/* Schemes */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Schemes AAuth uses
        </h2>
        <div className="grid grid-cols-1 gap-4">
          {SCHEMES.map((s) => (
            <div
              key={s.id}
              className={`rounded-xl border ${s.tierBorder} bg-card p-5 space-y-3`}
            >
              <div className="flex flex-wrap items-baseline gap-3">
                <code className={`text-sm font-mono font-semibold ${s.tierColor}`}>
                  sig={s.name}
                </code>
                <span className="text-xs text-muted-foreground">{s.fullName}</span>
                <span className={`ml-auto text-[10px] font-mono ${s.tierColor} uppercase tracking-wider`}>
                  {s.tier}
                </span>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed">{s.summary}</p>
              <pre className="rounded bg-muted/50 p-3 text-[10px] font-mono text-muted-foreground overflow-x-auto">
                Signature-Key: {s.example}
              </pre>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                <div className="space-y-1">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    When AAuth uses it
                  </p>
                  <p className="text-xs text-muted-foreground leading-relaxed">{s.whenUsed}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    What the verifier learns
                  </p>
                  <p className="text-xs text-muted-foreground leading-relaxed">{s.trust}</p>
                </div>
              </div>
              <Link
                href={s.href}
                className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
              >
                Live demo <ArrowRight className="h-3 w-3" />
              </Link>
            </div>
          ))}
        </div>
      </section>

      {/* Not used */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Not used by AAuth
        </h2>
        <div className="grid grid-cols-1 gap-4">
          {NOT_USED.map((s) => (
            <div
              key={s.id}
              className="rounded-xl border border-dashed border-border bg-muted/10 p-5 space-y-2"
            >
              <div className="flex flex-wrap items-baseline gap-3">
                <code className="text-sm font-mono font-semibold text-muted-foreground">
                  sig={s.name}
                </code>
                <span className="text-xs text-muted-foreground">{s.fullName}</span>
                <span className="ml-auto inline-flex items-center gap-1 text-[10px] font-mono text-zinc-500 uppercase tracking-wider">
                  <XCircle className="h-3 w-3" /> not in AAuth
                </span>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">{s.reason}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Capability matrix */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Scheme properties at a glance
        </h2>
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground">Property</th>
                {SCHEMES.map((s) => (
                  <th key={s.id} className="px-4 py-3 text-center">
                    <code className={`text-xs font-mono ${s.tierColor}`}>{s.name}</code>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                { label: "Reveals identity", values: [false, false, true, true] },
                { label: "Requires network fetch", values: [false, false, true, "maybe"] },
                { label: "Embeds a JWT", values: [false, true, false, true] },
                { label: "Hardware-backed (typical)", values: [false, true, false, false] },
                { label: "Carries AAuth token", values: [false, false, false, true] },
              ].map((row, i) => (
                <tr key={row.label} className={`border-b border-border ${i % 2 ? "bg-muted/10" : ""}`}>
                  <td className="px-5 py-3 text-xs text-muted-foreground">{row.label}</td>
                  {row.values.map((v, j) => (
                    <td key={j} className="px-4 py-3">
                      <div className="flex justify-center">
                        {v === true && <CheckCircle className="h-4 w-4 text-green-400" />}
                        {v === false && <XCircle className="h-4 w-4 text-zinc-700" />}
                        {v === "maybe" && (
                          <span className="text-[10px] font-mono text-muted-foreground">
                            if iss+dwk present
                          </span>
                        )}
                      </div>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Further reading */}
      <section className="rounded-xl border border-border bg-card p-6 space-y-3">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Further reading
        </p>
        <ul className="space-y-2 text-sm">
          <li>
            <Link
              href="/foundations/profile"
              className="inline-flex items-center gap-1.5 text-muted-foreground hover:text-foreground"
            >
              ← HTTP Signatures Profile (what AAuth pins down)
            </Link>
          </li>
          <li>
            <a
              href="https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-muted-foreground hover:text-foreground"
            >
              draft-hardt-httpbis-signature-key · full scheme grammar, structured-fields parsing,
              label correlation, multiple-signature rules, and the scheme registry{" "}
              <ExternalLink className="h-3 w-3" />
            </a>
          </li>
        </ul>
      </section>
    </div>
  );
}
