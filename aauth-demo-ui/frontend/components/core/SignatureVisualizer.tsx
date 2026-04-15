"use client";

import { SignatureDetails } from "@/lib/types";
import { cn } from "@/lib/utils";

const COMPONENT_COLORS: Record<string, string> = {
  "@method": "text-blue-400",
  "@authority": "text-green-400",
  "@path": "text-purple-400",
  "@query": "text-orange-400",
  "@request-target": "text-cyan-400",
  "content-digest": "text-yellow-400",
  "signature-key": "text-pink-400",
  "content-type": "text-indigo-400",
};

function getComponentColor(comp: string): string {
  return COMPONENT_COLORS[comp] ?? "text-zinc-300";
}

interface SignatureVisualizerProps {
  signature: SignatureDetails;
}

export function SignatureVisualizer({ signature }: SignatureVisualizerProps) {
  const baseLines = signature.signature_base.split("\n");

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="px-4 py-2.5 border-b border-border bg-muted/20">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold">HTTP Signature</span>
          <span className="text-[10px] font-mono bg-muted rounded px-1.5 py-0.5 text-muted-foreground">
            scheme={signature.scheme}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-border">
        {/* Covered components */}
        <div className="p-4 space-y-3">
          <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
            Covered Components
          </p>
          <div className="space-y-1.5">
            {signature.covered_components.map((comp) => (
              <div
                key={comp}
                className={cn(
                  "flex items-center gap-2 text-[11px] font-mono",
                  getComponentColor(comp)
                )}
              >
                <span className="h-1.5 w-1.5 rounded-full bg-current shrink-0" />
                {comp}
              </div>
            ))}
          </div>
        </div>

        {/* Signature base */}
        <div className="p-4 space-y-3">
          <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
            Signature Base
          </p>
          <div className="space-y-0.5">
            {baseLines.map((line, i) => {
              const matchedComp = signature.covered_components.find(
                (c) => line.startsWith(`"${c}"`)
              );
              return (
                <div
                  key={i}
                  className={cn(
                    "text-[11px] font-mono leading-relaxed",
                    matchedComp ? getComponentColor(matchedComp) : "text-muted-foreground"
                  )}
                >
                  {line}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Signature-Key header */}
      <div className="border-t border-border bg-muted/10 px-4 py-3 space-y-2">
        <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
          Signature-Key Header
        </p>
        <p className="text-[11px] font-mono text-zinc-300 break-all leading-relaxed">
          {signature.signature_key}
        </p>
      </div>

      {/* Signature-Input header */}
      <div className="border-t border-border bg-muted/10 px-4 py-3 space-y-2">
        <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
          Signature-Input Header
        </p>
        <p className="text-[11px] font-mono text-zinc-300 break-all leading-relaxed">
          {signature.signature_input}
        </p>
      </div>
    </div>
  );
}
