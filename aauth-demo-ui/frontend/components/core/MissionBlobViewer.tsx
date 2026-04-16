"use client";

import { FileText, Wrench } from "lucide-react";
import { MissionBlobData } from "@/lib/types";

interface MissionBlobViewerProps {
  mission: MissionBlobData;
}

export function MissionBlobViewer({ mission }: MissionBlobViewerProps) {
  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="border-b border-border bg-muted/20 px-4 py-2.5">
        <div className="flex items-center gap-2">
          <FileText className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs font-semibold">{mission.title}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 p-4 lg:grid-cols-[1.6fr_1fr]">
        <div className="space-y-3">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Description (Markdown)
            </p>
            <div className="mt-2 rounded-lg border border-border bg-muted/10 p-3">
              <pre className="whitespace-pre-wrap text-[12px] leading-relaxed text-muted-foreground">
                {mission.markdown}
              </pre>
            </div>
          </div>

          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Structured Fields
            </p>
            <div className="mt-2 grid grid-cols-1 gap-1 text-[10px] font-mono text-muted-foreground">
              <div className="flex items-baseline gap-2 rounded bg-muted/30 px-2 py-1">
                <span className="shrink-0 text-muted-foreground/70">approver</span>
                <span className="break-all">{mission.approver}</span>
              </div>
              <div className="flex items-baseline gap-2 rounded bg-muted/30 px-2 py-1">
                <span className="shrink-0 text-muted-foreground/70">agent</span>
                <span className="break-all">{mission.agent}</span>
              </div>
              <div className="flex items-baseline gap-2 rounded bg-muted/30 px-2 py-1">
                <span className="shrink-0 text-muted-foreground/70">approved_at</span>
                <span className="break-all">{mission.approved_at}</span>
              </div>
              <div className="flex items-baseline gap-2 rounded bg-muted/30 px-2 py-1">
                <span className="shrink-0 text-muted-foreground/70">s256</span>
                <span className="break-all">{mission.s256}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-3">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Approved Tools
            </p>
            <div className="mt-2 space-y-2">
              {mission.approved_tools.map((tool) => (
                <div key={tool.name} className="rounded-lg border border-border bg-muted/10 p-3">
                  <div className="flex items-center gap-2">
                    <Wrench className="h-3.5 w-3.5 text-orange-300" />
                    <span className="text-xs font-medium">{tool.name}</span>
                  </div>
                  <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                    {tool.description}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {mission.capabilities && mission.capabilities.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                PS Capabilities
              </p>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {mission.capabilities.map((capability) => (
                  <span
                    key={capability}
                    className="rounded-full border border-border bg-card px-2 py-1 text-[10px] font-mono text-muted-foreground"
                  >
                    {capability}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
