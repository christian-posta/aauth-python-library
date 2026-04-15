"use client";

import { useState } from "react";
import { Copy, Check, ChevronDown, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

const HEADER_TOOLTIPS: Record<string, string> = {
  "Signature-Key": "Binds the signing key to the request. Format: sig=<scheme>;id=<uri>;kid=<kid>",
  "Signature-Input": "Declares which components are covered by the signature and signature parameters",
  "Signature": "The actual HTTP message signature value (base64url encoded)",
  "Accept-Signature": "Challenge from resource — specifies which signing scheme is required",
  "AAuth-Requirement": "Resource's authorization challenge — contains resource token the agent must exchange",
  "AAuth-Access": "Carries auth token or opaque access token for resource access",
  "AAuth-Mission": "References an approved mission by approver URL and s256 hash of the mission blob",
  "AAuth-Capabilities": "Lists capabilities the agent supports (e.g. clarification, interaction)",
  "Content-Type": "Media type of the request/response body",
  Authorization: "Bearer token for resource access (opaque or JWT)",
};

const AAUTH_HEADER_KEYS = new Set([
  "signature-key",
  "signature-input",
  "signature",
  "accept-signature",
  "aauth-requirement",
  "aauth-access",
  "aauth-mission",
  "aauth-capabilities",
]);

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      className="shrink-0 text-muted-foreground hover:text-foreground transition-colors"
    >
      {copied ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}

function HeaderRow({ name, value }: { name: string; value: string }) {
  const [open, setOpen] = useState(false);
  const lower = name.toLowerCase();
  const isAAuth = AAUTH_HEADER_KEYS.has(lower);
  const tooltip = HEADER_TOOLTIPS[name] ?? HEADER_TOOLTIPS[name.replace(/^aauth-/i, "AAuth-")];
  const isLong = value.length > 80;

  return (
    <div
      className={cn(
        "border-b border-border last:border-0",
        isAAuth && "bg-blue-500/5"
      )}
    >
      <div className="flex items-start gap-3 px-4 py-2.5">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 mb-0.5">
            <span
              className={cn(
                "text-[11px] font-semibold font-mono",
                isAAuth ? "text-blue-400" : "text-foreground/80"
              )}
            >
              {name}
            </span>
            {isAAuth && (
              <span className="text-[9px] font-medium bg-blue-500/15 text-blue-400 rounded px-1.5 py-0.5">
                AAuth
              </span>
            )}
            {tooltip && (
              <span className="group relative inline-block">
                <span className="cursor-help text-[10px] text-muted-foreground/40 underline decoration-dotted">
                  ?
                </span>
                <span className="pointer-events-none absolute left-full top-0 z-50 ml-2 hidden w-72 rounded-md border border-border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-lg group-hover:block">
                  {tooltip}
                </span>
              </span>
            )}
          </div>
          {isLong ? (
            <div>
              <p className="text-[11px] font-mono text-muted-foreground break-all">
                {open ? value : value.slice(0, 80) + "…"}
              </p>
              <button
                onClick={() => setOpen((o) => !o)}
                className="flex items-center gap-1 text-[10px] text-muted-foreground/60 hover:text-muted-foreground mt-1"
              >
                {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                {open ? "collapse" : "expand"}
              </button>
            </div>
          ) : (
            <p className="text-[11px] font-mono text-muted-foreground break-all">{value}</p>
          )}
        </div>
        <CopyButton text={value} />
      </div>
    </div>
  );
}

interface HeaderInspectorProps {
  requestHeaders: Record<string, string>;
  responseHeaders: Record<string, string>;
  requestBody?: unknown;
  responseBody?: unknown;
  responseStatus?: number;
  method?: string;
  url?: string;
}

export function HeaderInspector({
  requestHeaders,
  responseHeaders,
  requestBody,
  responseBody,
  responseStatus,
  method,
  url,
}: HeaderInspectorProps) {
  const [tab, setTab] = useState<"request" | "response">("request");

  const headers = tab === "request" ? requestHeaders : responseHeaders;
  const body = tab === "request" ? requestBody : responseBody;

  const statusColor =
    responseStatus && responseStatus < 300
      ? "text-green-400"
      : responseStatus && responseStatus < 400
      ? "text-blue-400"
      : "text-amber-400";

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      {/* Tab bar */}
      <div className="flex items-center justify-between border-b border-border bg-muted/20 px-4 py-2">
        <div className="flex gap-1">
          {(["request", "response"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                "rounded px-3 py-1 text-xs font-medium transition-colors",
                tab === t
                  ? "bg-accent text-foreground"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>
        {responseStatus && tab === "response" && (
          <span className={`text-xs font-mono font-bold ${statusColor}`}>{responseStatus}</span>
        )}
      </div>

      {/* Request line */}
      {tab === "request" && method && url && (
        <div className="flex items-baseline gap-2 px-4 py-2.5 border-b border-border bg-muted/5">
          <span className="text-[11px] font-mono font-bold text-foreground/70 shrink-0">{method}</span>
          <span className="text-[11px] font-mono text-sky-400 break-all">{url}</span>
        </div>
      )}

      {/* Headers */}
      <div className="divide-y divide-border">
        {Object.entries(headers).length === 0 ? (
          <p className="px-4 py-3 text-xs text-muted-foreground">No headers</p>
        ) : (
          Object.entries(headers).map(([name, value]) => (
            <HeaderRow key={name} name={name} value={value} />
          ))
        )}
      </div>

      {/* Body */}
      {body !== undefined && body !== null && (
        <div className="border-t border-border bg-muted/10">
          <div className="px-4 py-2 flex items-center gap-2 border-b border-border">
            <span className="text-xs font-semibold text-muted-foreground">Body</span>
            <CopyButton text={typeof body === "string" ? body : JSON.stringify(body, null, 2)} />
          </div>
          <pre className="px-4 py-3 text-[11px] font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap break-all">
            {typeof body === "string" ? body : JSON.stringify(body, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
