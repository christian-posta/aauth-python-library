import Link from "next/link";
import { ArrowRight, ExternalLink, Layers, AlertCircle } from "lucide-react";

const ERROR_CODES = [
  {
    code: "invalid_request",
    status: "400 / 401",
    when: "Required signature header (Signature, Signature-Input, or Signature-Key) is missing or malformed.",
    extra: null,
  },
  {
    code: "invalid_input",
    status: "401",
    when: "Signature-Input does not cover all required components.",
    extra: (
      <>
        Response SHOULD include{" "}
        <code className="text-[10px] bg-muted/50 rounded px-1">required_input</code> listing the
        components the server requires.
      </>
    ),
  },
  {
    code: "invalid_signature",
    status: "401",
    when: "Signature does not verify, or the created timestamp is outside the validity window.",
    extra: null,
  },
  {
    code: "unsupported_algorithm",
    status: "401",
    when: "The signing algorithm in the key/signature is not on the server's accept list.",
    extra: (
      <>
        Response MUST include{" "}
        <code className="text-[10px] bg-muted/50 rounded px-1">supported_algorithms</code> listing
        the algorithms the server accepts.
      </>
    ),
  },
  {
    code: "invalid_key",
    status: "401",
    when: "The public key in Signature-Key could not be parsed, is malformed, or doesn't meet trust requirements.",
    extra: null,
  },
  {
    code: "unknown_key",
    status: "401",
    when: "For sig=jwks_uri — the referenced kid was not found at the published jwks_uri.",
    extra: (
      <>
        Server SHOULD re-fetch the JWKS once before returning this to handle key rotation
        gracefully.
      </>
    ),
  },
  {
    code: "invalid_jwt",
    status: "401",
    when: "For sig=jwt or sig=jkt-jwt — the JWT is malformed or its signature failed verification.",
    extra: null,
  },
  {
    code: "expired_jwt",
    status: "401",
    when: "For sig=jwt or sig=jkt-jwt — the JWT exp claim is in the past.",
    extra: null,
  },
];

export default function ErrorModelPage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-10 space-y-12">
      {/* Header */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-cyan-400" />
          <p className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Foundations</p>
        </div>
        <h1 className="text-3xl font-bold tracking-tight">Error Model</h1>
        <p className="text-muted-foreground max-w-3xl leading-relaxed">
          AAuth adopts the <code className="text-[11px] bg-muted rounded px-1">Signature-Error</code>{" "}
          response header from the Signature-Key draft. Every verification failure returns a{" "}
          <code className="text-[11px] bg-muted rounded px-1">401</code> with a machine-readable
          error code — the response body is not authoritative.
        </p>
      </div>

      {/* Anatomy */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Anatomy
        </h2>
        <div className="rounded-xl border border-border bg-card p-6 space-y-4">
          <pre className="rounded bg-muted/50 p-4 text-[11px] font-mono text-muted-foreground overflow-x-auto">
{`HTTP/1.1 401 Unauthorized
Signature-Error: error=invalid_input,
    required_input=("@method" "@authority" "@path"
    "signature-key" "content-digest")
Content-Type: application/problem+json

{
  "type": "urn:ietf:params:sig-error:invalid_input",
  "title": "Missing required covered components",
  "status": 401
}`}
          </pre>
          <p className="text-xs text-muted-foreground leading-relaxed">
            The header is the authoritative source. Problem Details (RFC 9457) in the body is a
            convenience for operators — machine clients MUST read the header.
          </p>
        </div>
      </section>

      {/* Error codes */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Error codes AAuth uses
        </h2>
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground w-56">
                  error
                </th>
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground w-32">
                  Status
                </th>
                <th className="text-left px-5 py-3 text-xs font-medium text-muted-foreground">
                  When it fires
                </th>
              </tr>
            </thead>
            <tbody>
              {ERROR_CODES.map((e, i) => (
                <tr
                  key={e.code}
                  className={`border-b border-border ${i % 2 ? "bg-muted/10" : ""}`}
                >
                  <td className="px-5 py-4 align-top">
                    <code className="text-[11px] font-mono text-red-300 bg-red-500/10 rounded px-2 py-0.5">
                      {e.code}
                    </code>
                  </td>
                  <td className="px-5 py-4 align-top text-xs text-muted-foreground font-mono">
                    {e.status}
                  </td>
                  <td className="px-5 py-4 align-top text-xs text-muted-foreground leading-relaxed space-y-2">
                    <p>{e.when}</p>
                    {e.extra && <p className="text-[11px] text-muted-foreground/80">{e.extra}</p>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* 403 vs 401 */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Authentication vs Authorization
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-xl border border-red-500/40 bg-red-500/5 p-5 space-y-2">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-red-300" />
              <p className="text-sm font-semibold text-red-300">401 + Signature-Error</p>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              The signature or its keying material is wrong. The client can (and often should)
              retry with corrected parameters.
            </p>
          </div>
          <div className="rounded-xl border border-border bg-card p-5 space-y-2">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-muted-foreground" />
              <p className="text-sm font-semibold text-foreground">403 Forbidden</p>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Signature verified and identity is known, but policy denies the request. The response
              MUST NOT include <code className="text-[10px]">Signature-Error</code> or{" "}
              <code className="text-[10px]">Accept-Signature</code> — this isn&apos;t a signing
              problem.
            </p>
          </div>
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
              ← HTTP Signatures Profile
            </Link>
          </li>
          <li>
            <Link
              href="/foundations/schemes"
              className="inline-flex items-center gap-1.5 text-muted-foreground hover:text-foreground"
            >
              Signature-Key Schemes <ArrowRight className="h-3 w-3" />
            </Link>
          </li>
          <li>
            <a
              href="https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-muted-foreground hover:text-foreground"
            >
              draft-hardt-httpbis-signature-key · §5 Signature-Error <ExternalLink className="h-3 w-3" />
            </a>
          </li>
        </ul>
      </section>
    </div>
  );
}
