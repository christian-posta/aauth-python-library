"use client";

import { useState } from "react";
import { DecodedToken } from "@/lib/types";
import { cn } from "@/lib/utils";
import { Copy, Check } from "lucide-react";

const CLAIM_TOOLTIPS: Record<string, string> = {
  typ: "Token type identifier. aa-agent+jwt = Agent Token, aa-resource+jwt = Resource Token, aa-auth+jwt = Auth Token",
  iss: "Issuer — who created and signed this token",
  sub: "Subject — who or what the token is about",
  aud: "Audience — which party should accept this token",
  iat: "Issued At — Unix timestamp when the token was created",
  exp: "Expiration — Unix timestamp after which the token is invalid",
  jti: "JWT ID — unique identifier for this token (prevents replay)",
  dwk: "Discovery Well-Known — the metadata document path for key discovery (e.g. aauth-agent.json)",
  cnf: "Confirmation — proof-of-possession claim binding this token to a key",
  jwk: "JSON Web Key — the public key bound to this token",
  agent: "Agent identifier in aauth: URI format (e.g. aauth:local@domain)",
  agent_jkt: "JWK Thumbprint of the agent's signing key — used for key binding",
  ps: "Person Server URL — the PS that represents this agent's user",
  scope: "Authorized scope/permissions granted by this token",
  mission: "Mission reference — approver URL and s256 hash of the mission blob",
  approver: "Person Server URL that approved this mission",
  s256: "SHA-256 hash of the mission blob — immutable mission fingerprint",
  act: "Authorized actor chain — records delegation/call-chaining path",
  resource: "Resource identifier this token grants access to",
};

function ClaimTooltip({ name }: { name: string }) {
  const tip = CLAIM_TOOLTIPS[name];
  if (!tip) return null;
  return (
    <span className="group/tip relative inline-block">
      <span className="ml-1 cursor-help text-[10px] text-muted-foreground/50 underline decoration-dotted">
        ?
      </span>
      <span className="pointer-events-none absolute left-full top-0 z-50 ml-2 hidden w-64 rounded-md border border-border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-lg group-hover/tip:block">
        {tip}
      </span>
    </span>
  );
}

function JSONValue({ value, depth = 0 }: { value: unknown; depth?: number }) {
  const [open, setOpen] = useState(depth < 2);

  if (value === null) return <span className="text-zinc-500">null</span>;
  if (typeof value === "boolean")
    return <span className="text-orange-400">{value.toString()}</span>;
  if (typeof value === "number")
    return <span className="text-green-400">{value}</span>;
  if (typeof value === "string") {
    // If it looks like a JWT, truncate it
    if (value.split(".").length === 3 && value.length > 60) {
      return (
        <span className="text-yellow-300 font-mono text-[11px]">
          &quot;{value.slice(0, 30)}…&quot;
        </span>
      );
    }
    return <span className="text-yellow-300">&quot;{value}&quot;</span>;
  }

  if (Array.isArray(value)) {
    if (!open)
      return (
        <button
          className="text-zinc-400 hover:text-foreground"
          onClick={() => setOpen(true)}
        >
          [{value.length} items]
        </button>
      );
    return (
      <span>
        [
        <div className="ml-4">
          {value.map((v, i) => (
            <div key={i}>
              <JSONValue value={v} depth={depth + 1} />
              {i < value.length - 1 && ","}
            </div>
          ))}
        </div>
        ]
      </span>
    );
  }

  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (!open)
      return (
        <button
          className="text-zinc-400 hover:text-foreground"
          onClick={() => setOpen(true)}
        >
          {`{${entries.length} fields}`}
        </button>
      );
    return (
      <span>
        {"{"}
        <div className="ml-4">
          {entries.map(([k, v], i) => (
            <div key={k} className="flex flex-wrap items-start gap-x-1">
              <span className="text-blue-300">
                &quot;{k}&quot;
                <ClaimTooltip name={k} />
              </span>
              <span className="text-zinc-500">:</span>
              <span>
                <JSONValue value={v} depth={depth + 1} />
              </span>
              {i < entries.length - 1 && <span className="text-zinc-500">,</span>}
            </div>
          ))}
        </div>
        {"}"}
      </span>
    );
  }

  return <span>{String(value)}</span>;
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      className="text-muted-foreground hover:text-foreground transition-colors"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

interface JWTViewerProps {
  token: DecodedToken;
}

export function JWTViewer({ token }: JWTViewerProps) {
  const [activeTab, setActiveTab] = useState<"decoded" | "raw">("decoded");

  const parts = token.raw.split(".");
  const [rawHeader, rawPayload, rawSig] = parts;

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      {/* Title bar */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-border bg-muted/30">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold">{token.name}</span>
          <span className="text-[10px] font-mono text-muted-foreground bg-muted rounded px-1.5 py-0.5">
            {token.typ}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex rounded-md border border-border overflow-hidden text-xs">
            {(["decoded", "raw"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={cn(
                  "px-2.5 py-1 transition-colors",
                  activeTab === tab
                    ? "bg-accent text-foreground"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                {tab}
              </button>
            ))}
          </div>
          <CopyButton text={token.raw} />
        </div>
      </div>

      {activeTab === "raw" ? (
        /* Raw JWT with color-coded sections */
        <div className="p-4 font-mono text-[11px] leading-relaxed break-all">
          <span className="text-red-400">{rawHeader}</span>
          <span className="text-zinc-500">.</span>
          <span className="text-purple-400">{rawPayload}</span>
          <span className="text-zinc-500">.</span>
          <span className="text-blue-400">{rawSig}</span>
        </div>
      ) : (
        /* Decoded view */
        <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-border">
          {/* Header */}
          <div className="p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="h-2 w-2 rounded-full bg-red-400" />
              <span className="text-xs font-semibold text-red-400">Header</span>
            </div>
            <pre className="text-[12px] font-mono leading-relaxed">
              <JSONValue value={token.header} depth={0} />
            </pre>
          </div>

          {/* Payload */}
          <div className="p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="h-2 w-2 rounded-full bg-purple-400" />
              <span className="text-xs font-semibold text-purple-400">Payload</span>
            </div>
            <pre className="text-[12px] font-mono leading-relaxed">
              <JSONValue value={token.payload} depth={0} />
            </pre>
          </div>
        </div>
      )}

      {/* Signature strip */}
      <div className="border-t border-border bg-muted/20 px-4 py-2 flex items-center gap-2">
        <div className="h-2 w-2 rounded-full bg-blue-400 shrink-0" />
        <span className="text-[10px] font-mono text-muted-foreground truncate">
          sig: {token.signature_b64.slice(0, 32)}…
        </span>
        <CopyButton text={token.signature_b64} />
      </div>
    </div>
  );
}
