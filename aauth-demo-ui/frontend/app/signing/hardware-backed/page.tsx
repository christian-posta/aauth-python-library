import Link from "next/link";
import { ArrowRight, ExternalLink, Radio, Shield, Cpu, RefreshCw } from "lucide-react";

export default function HardwareBackedPage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-10 space-y-12">
      {/* Header */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Radio className="h-4 w-4 text-blue-400" />
          <p className="text-xs font-semibold text-blue-400 uppercase tracking-wider">
            Message Signing · Pseudonymous tier
          </p>
        </div>
        <div className="flex flex-wrap items-baseline gap-3">
          <h1 className="text-3xl font-bold tracking-tight">Hardware-backed</h1>
          <code className="text-sm font-mono text-blue-300 bg-blue-500/10 rounded px-2 py-0.5">
            sig=jkt-jwt
          </code>
        </div>
        <p className="text-muted-foreground max-w-3xl leading-relaxed">
          An enclave/hardware key signs a JWT that delegates signing authority to a fast ephemeral
          key. Requests are signed at line rate by the ephemeral key; the JWT proves the delegation
          came from the hardware-held identity.
        </p>
      </div>

      {/* Why this exists */}
      <section className="rounded-xl border border-border bg-card p-6 space-y-3">
        <div className="flex items-center gap-2">
          <Cpu className="h-4 w-4 text-blue-400" />
          <h2 className="text-sm font-semibold">Why a second pseudonymous scheme?</h2>
        </div>
        <p className="text-sm text-muted-foreground leading-relaxed">
          <code className="text-[11px] bg-muted rounded px-1">sig=hwk</code> is a self-contained
          inline public key — ephemeral by nature. But many devices (TPM, Secure Enclave, StrongBox)
          hold a <em>stable</em> private key in hardware that is slow to sign and may require user
          interaction (biometric, PIN).
        </p>
        <p className="text-sm text-muted-foreground leading-relaxed">
          <code className="text-[11px] bg-muted rounded px-1">sig=jkt-jwt</code> (&quot;jacket jot&quot;)
          bridges the two: the enclave key signs one JWT, and that JWT delegates to a fast software
          key that signs every request. The hardware key&apos;s JWK Thumbprint URN is the stable
          pseudonymous identity — no registration, no authority.
        </p>
      </section>

      {/* How it works */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          How it works
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[
            {
              step: "1",
              title: "Identity key",
              body: "A long-lived keypair lives in the hardware enclave.",
            },
            {
              step: "2",
              title: "Ephemeral key",
              body: "A short-lived software keypair is generated per session.",
            },
            {
              step: "3",
              title: "Delegation JWT",
              body: "Enclave signs a JWT binding the ephemeral pub key via the cnf claim.",
            },
            {
              step: "4",
              title: "Fast signing",
              body: "Every HTTP request is signed by the ephemeral key; the JWT proves authorization.",
            },
          ].map((s) => (
            <div key={s.step} className="rounded-xl border border-border bg-card p-4 space-y-2">
              <div className="flex items-center gap-2">
                <span className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-blue-500/20 text-[10px] font-mono text-blue-300">
                  {s.step}
                </span>
                <p className="text-xs font-semibold text-foreground">{s.title}</p>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">{s.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* On the wire */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          On the wire
        </h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="rounded-xl border border-border bg-card p-4 space-y-2">
            <p className="text-xs font-semibold text-muted-foreground">
              Request headers
            </p>
            <pre className="rounded bg-muted/50 p-3 text-[10px] font-mono text-muted-foreground overflow-x-auto leading-relaxed">
{`GET /data HTTP/1.1
Host: api.example
Signature-Input: sig=("@method" "@authority"
    "@path" "signature-key");created=1730217600
Signature: sig=:<ephemeral-key-sig>:
Signature-Key: sig=jkt-jwt;jwt="eyJ0eXA…"`}
            </pre>
          </div>
          <div className="rounded-xl border border-border bg-card p-4 space-y-2">
            <p className="text-xs font-semibold text-muted-foreground">
              JWT header & payload (inside <code className="text-[10px]">jwt=</code>)
            </p>
            <pre className="rounded bg-muted/50 p-3 text-[10px] font-mono text-muted-foreground overflow-x-auto leading-relaxed">
{`// header
{
  "typ": "jkt-s256+jwt",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}

// payload
{
  "iss": "urn:jkt:sha-256:NzbLsXh8…",
  "iat": 1730217000,
  "exp": 1730303400,
  "cnf": {
    "jwk": {
      "kty": "OKP", "crv": "Ed25519",
      "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    }
  }
}`}
            </pre>
          </div>
        </div>
        <p className="text-[11px] text-muted-foreground">
          The verifier checks the JWT (enclave signature → thumbprint → <code className="text-[10px]">iss</code>{" "}
          equality), extracts <code className="text-[10px]">cnf.jwk</code>, then verifies the HTTP
          signature with that ephemeral key.
        </p>
      </section>

      {/* When AAuth uses it */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          When AAuth uses it
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-xl border border-border bg-card p-5 space-y-2">
            <div className="flex items-center gap-2">
              <RefreshCw className="h-4 w-4 text-blue-400" />
              <p className="text-sm font-semibold">Agent-token renewal from a stable key</p>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              When an agent&apos;s ephemeral agent token expires, the agent can renew it by sending a
              new ephemeral public key in a <code className="text-[10px]">sig=jkt-jwt</code>{" "}
              request signed by the stable hardware key — no user re-login required. Recorded at
              enrollment, verified on renewal.
            </p>
            <p className="text-[10px] text-muted-foreground">
              SPEC · §Agent Token Acquisition
            </p>
          </div>
          <div className="rounded-xl border border-border bg-card p-5 space-y-2">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-blue-400" />
              <p className="text-sm font-semibold">Mobile / IoT / laptop agents</p>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Any agent whose platform offers a secure enclave (iOS Secure Enclave, Android
              StrongBox, Windows TPM, macOS Keychain). Gives the resource a stable thumbprint for
              per-device rate limiting / reputation without collecting identity.
            </p>
          </div>
        </div>
      </section>

      {/* vs hwk */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          hwk vs jkt-jwt
        </h2>
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground">&nbsp;</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-blue-400">sig=hwk</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-blue-400">sig=jkt-jwt</th>
              </tr>
            </thead>
            <tbody>
              {[
                {
                  label: "Key lifetime",
                  hwk: "Per session (ephemeral)",
                  jkt: "Hardware identity key is stable; ephemeral key rotates with JWT exp",
                },
                {
                  label: "Identity",
                  hwk: "JWK Thumbprint of the inline key",
                  jkt: "JWK Thumbprint URN of the enclave key — stable across sessions",
                },
                {
                  label: "Performance cost",
                  hwk: "One signature per request (fast)",
                  jkt: "One enclave signature per JWT lifetime + fast signature per request",
                },
                {
                  label: "Trust model",
                  hwk: "TOFU on the inline key",
                  jkt: "TOFU on the enclave thumbprint — implies but does not prove hardware protection",
                },
              ].map((row, i) => (
                <tr key={row.label} className={`border-b border-border ${i % 2 ? "bg-muted/10" : ""}`}>
                  <td className="px-5 py-3 text-xs text-muted-foreground">{row.label}</td>
                  <td className="px-5 py-3 text-xs text-muted-foreground leading-relaxed">{row.hwk}</td>
                  <td className="px-5 py-3 text-xs text-muted-foreground leading-relaxed">{row.jkt}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Further reading */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Link
          href="/signing/pseudonymous"
          className="group rounded-xl border border-border bg-card p-5 space-y-2 hover:border-blue-500/40 transition-colors"
        >
          <p className="text-xs font-semibold text-blue-400">Same tier</p>
          <p className="text-sm font-semibold">Pseudonymous (sig=hwk) →</p>
          <p className="text-xs text-muted-foreground leading-relaxed">
            The inline-key variant — no hardware, no JWT wrapper.
          </p>
          <span className="inline-flex items-center gap-1 text-xs text-muted-foreground group-hover:text-foreground">
            Explore <ArrowRight className="h-3 w-3" />
          </span>
        </Link>
        <Link
          href="/foundations/schemes"
          className="group rounded-xl border border-border bg-card p-5 space-y-2 hover:border-cyan-500/40 transition-colors"
        >
          <p className="text-xs font-semibold text-cyan-400">Foundations</p>
          <p className="text-sm font-semibold">Signature-Key Schemes →</p>
          <p className="text-xs text-muted-foreground leading-relaxed">
            All four schemes AAuth uses, side-by-side.
          </p>
          <span className="inline-flex items-center gap-1 text-xs text-muted-foreground group-hover:text-foreground">
            Explore <ArrowRight className="h-3 w-3" />
          </span>
        </Link>
      </section>

      <section className="rounded-xl border border-border bg-card p-6 space-y-3">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Further reading
        </p>
        <ul className="space-y-2 text-sm">
          <li>
            <span className="text-muted-foreground">
              AAuth SPEC · §Agent Token Acquisition (renewal via stable key)
            </span>
          </li>
          <li>
            <a
              href="https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-muted-foreground hover:text-foreground"
            >
              draft-hardt-httpbis-signature-key · §3.4 jkt-jwt scheme{" "}
              <ExternalLink className="h-3 w-3" />
            </a>
          </li>
          <li>
            <a
              href="https://www.rfc-editor.org/rfc/rfc7638"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-muted-foreground hover:text-foreground"
            >
              RFC 7638 — JSON Web Key Thumbprint <ExternalLink className="h-3 w-3" />
            </a>
          </li>
          <li>
            <a
              href="https://www.rfc-editor.org/rfc/rfc7800"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-muted-foreground hover:text-foreground"
            >
              RFC 7800 — Proof-of-Possession Key Semantics for JWTs{" "}
              <ExternalLink className="h-3 w-3" />
            </a>
          </li>
        </ul>
      </section>
    </div>
  );
}
