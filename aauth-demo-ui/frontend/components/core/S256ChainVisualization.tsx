"use client";

import { CheckCircle2, Hash } from "lucide-react";
import { S256ChainLink } from "@/lib/types";

interface S256ChainVisualizationProps {
  links: S256ChainLink[];
}

export function S256ChainVisualization({ links }: S256ChainVisualizationProps) {
  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="border-b border-border bg-muted/20 px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Hash className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs font-semibold">s256 Chain</span>
        </div>
      </div>

      <div className="space-y-3 p-4">
        {links.map((link, index) => (
          <div key={`${link.label}-${index}`} className="flex items-start gap-3">
            <div className="pt-0.5">
              <CheckCircle2 className="h-4 w-4 text-green-400" />
            </div>
            <div className="min-w-0 flex-1 rounded-lg border border-border bg-muted/10 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-semibold">{link.label}</span>
                <span className="rounded bg-muted px-2 py-0.5 text-[10px] font-mono text-muted-foreground">
                  {link.source}
                </span>
              </div>
              <p className="mt-2 break-all font-mono text-[11px] text-blue-300">
                {link.s256}
              </p>
              <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
                {link.detail}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
