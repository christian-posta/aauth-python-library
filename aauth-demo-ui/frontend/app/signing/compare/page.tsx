import Link from "next/link";
import { ArrowRight, CheckCircle, XCircle } from "lucide-react";

const MODES = [
  {
    id: "anonymous",
    label: "Anonymous",
    sublabel: "No signature",
    color: "text-zinc-400",
    border: "border-zinc-700",
    href: null,
    sigKeyHeader: "(none — no Signature-Key header)",
    sigKeyHighlight: "text-zinc-500",
    trustLevel: "None",
    resourceLearns: "Nothing",
    useCase: "Public endpoints, no access control needed",
    features: { proofOfKey: false, agentId: false, replayProtect: false, jwks: false },
  },
  {
    id: "hwk",
    label: "Pseudonymous",
    sublabel: "sig=hwk",
    color: "text-blue-400",
    border: "border-blue-500/40",
    href: "/signing/pseudonymous",
    sigKeyHeader: 'sig=hwk;jwk={"kty":"OKP","crv":"Ed25519","x":"<pub>","kid":"k1"}',
    sigKeyHighlight: "text-blue-300",
    trustLevel: "Key possession",
    resourceLearns: "A specific key signed this — identity unknown",
    useCase: "Anonymous but accountable access, rate-limiting by key",
    features: { proofOfKey: true, agentId: false, replayProtect: false, jwks: false },
  },
  {
    id: "jwks_uri",
    label: "Agent Identity",
    sublabel: "sig=jwks_uri",
    color: "text-green-400",
    border: "border-green-500/40",
    href: "/signing/identity",
    sigKeyHeader: 'sig=jwks_uri;id="http://agent:8001";kid="key-1"',
    sigKeyHighlight: "text-green-300",
    trustLevel: "Cryptographic identity",
    resourceLearns: "Full agent identifier + verifiable public key (via JWKS)",
    useCase: "Access control by agent identity, replacing API keys",
    features: { proofOfKey: true, agentId: true, replayProtect: false, jwks: true },
  },
  {
    id: "jwt",
    label: "Agent Token",
    sublabel: "sig=jwt",
    color: "text-purple-400",
    border: "border-purple-500/40",
    href: "/access/federated",
    sigKeyHeader: 'sig=jwt;jwt="eyJhbGciOiJFZERTQSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9…"',
    sigKeyHighlight: "text-purple-300",
    trustLevel: "Signed identity + Person Server",
    resourceLearns: "Agent identity, PS URL, bound signing key, delegation chain",
    useCase: "Full PS-AS authorization flows, mission context",
    features: { proofOfKey: true, agentId: true, replayProtect: true, jwks: true },
  },
];

const FEATURES: { key: keyof typeof MODES[0]["features"]; label: string }[] = [
  { key: "proofOfKey", label: "Proof of key possession" },
  { key: "agentId", label: "Agent identifier disclosed to resource" },
  { key: "replayProtect", label: "Replay protection (jti claim)" },
  { key: "jwks", label: "Remote key discovery (JWKS)" },
];

export default function SigningComparePage() {
  return (
    <div className="mx-auto max-w-6xl px-6 py-10 space-y-10">
      <div className="space-y-2">
        <p className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Message Signing</p>
        <h1 className="text-3xl font-bold">Signing Mode Comparison</h1>
        <p className="text-muted-foreground max-w-2xl">
          All AAuth signing modes use HTTP Message Signatures (RFC 9421). The difference is what appears
          in the <code className="text-[11px] bg-muted rounded px-1">Signature-Key</code> header —
          and what the resource learns about who made the request.
        </p>
      </div>

      {/* Signature-Key header */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Signature-Key Header</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          {MODES.map((m) => (
            <div key={m.id} className={`rounded-xl border ${m.border} bg-card p-4 space-y-3`}>
              <div>
                <p className={`text-sm font-semibold ${m.color}`}>{m.label}</p>
                <p className="text-[10px] font-mono text-muted-foreground mt-0.5">{m.sublabel}</p>
              </div>
              <div className="rounded-md bg-muted/50 p-2.5 min-h-[60px] flex items-start">
                <p className={`text-[10px] font-mono leading-relaxed break-all ${m.sigKeyHighlight}`}>
                  {m.sigKeyHeader}
                </p>
              </div>
              {m.href ? (
                <Link href={m.href} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors">
                  Live demo <ArrowRight className="h-3 w-3" />
                </Link>
              ) : (
                <span className="text-xs text-zinc-600">No demo</span>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* Feature matrix */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Capabilities</h2>
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground w-64">Feature</th>
                {MODES.map((m) => (
                  <th key={m.id} className="px-4 py-3 text-center">
                    <span className={`text-xs font-semibold ${m.color}`}>{m.label}</span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {FEATURES.map((f, i) => (
                <tr key={f.key} className={`border-b border-border ${i % 2 ? "bg-muted/10" : ""}`}>
                  <td className="px-5 py-3 text-xs text-muted-foreground">{f.label}</td>
                  {MODES.map((m) => (
                    <td key={m.id} className="px-4 py-3">
                      <div className="flex justify-center">
                        {m.features[f.key]
                          ? <CheckCircle className="h-4 w-4 text-green-400" />
                          : <XCircle className="h-4 w-4 text-zinc-700" />}
                      </div>
                    </td>
                  ))}
                </tr>
              ))}
              <tr className="border-b border-border bg-muted/5">
                <td className="px-5 py-3 text-xs text-muted-foreground">Trust level</td>
                {MODES.map((m) => (
                  <td key={m.id} className="px-4 py-3 text-center text-xs text-muted-foreground">{m.trustLevel}</td>
                ))}
              </tr>
              <tr>
                <td className="px-5 py-3 text-xs text-muted-foreground">Resource learns</td>
                {MODES.map((m) => (
                  <td key={m.id} className="px-4 py-3 text-center text-[11px] text-muted-foreground leading-snug">{m.resourceLearns}</td>
                ))}
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Use cases */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">When to use each</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          {MODES.map((m) => (
            <div key={m.id} className={`rounded-xl border ${m.border} bg-card p-4 space-y-2`}>
              <p className={`text-xs font-semibold ${m.color}`}>{m.label}</p>
              <p className="text-xs text-muted-foreground leading-relaxed">{m.useCase}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Anatomy */}
      <section className="rounded-xl border border-border bg-card p-6 space-y-4">
        <h2 className="text-sm font-semibold">Anatomy of an HTTP Message Signature (all modes)</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[
            {
              step: "1. Build signature base",
              code: `"@method": GET\n"@authority": resource:8002\n"@path": /data\n"signature-key": sig=hwk;…\n"@signature-params": (…);created=1700000000`,
            },
            {
              step: "2. Sign with Ed25519 private key",
              code: `Signature-Input: sig=\n  ("@method" "@authority"\n   "@path" "signature-key")\n  ;created=1700000000\n  ;alg="ed25519"`,
            },
            {
              step: "3. Attach 3 headers to request",
              code: `Signature-Key: sig=<scheme>…\nSignature-Input: sig=(…)\nSignature: sig=:base64url…:`,
            },
          ].map(({ step, code }) => (
            <div key={step} className="space-y-2">
              <p className="text-[11px] font-semibold text-foreground">{step}</p>
              <pre className="rounded bg-muted/50 p-3 text-[10px] font-mono text-muted-foreground leading-relaxed whitespace-pre-wrap break-all">
                {code}
              </pre>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
