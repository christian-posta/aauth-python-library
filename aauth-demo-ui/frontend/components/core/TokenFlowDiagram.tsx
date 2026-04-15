"use client";

import { ArrowRightLeft, ArrowUpRight } from "lucide-react";
import { Participant, TokenFlow } from "@/lib/types";
import { cn } from "@/lib/utils";

const ACCENT_STYLES = {
  resource: "border-green-500/30 bg-green-500/10 text-green-300",
  auth: "border-blue-500/30 bg-blue-500/10 text-blue-300",
  agent: "border-orange-500/30 bg-orange-500/10 text-orange-300",
};

const EVENT_STYLES = {
  issued: "border border-border bg-muted/20 text-foreground",
  forwarded: "border border-border bg-card text-muted-foreground",
  returned: "border border-border bg-blue-500/10 text-blue-300",
  presented: "border border-border bg-amber-500/10 text-amber-300",
};

interface TokenFlowDiagramProps {
  flows: TokenFlow[];
  participants: Participant[];
  currentStep: number;
  onStepSelect: (step: number) => void;
}

export function TokenFlowDiagram({
  flows,
  participants,
  currentStep,
  onStepSelect,
}: TokenFlowDiagramProps) {
  const participantLabels = new Map(participants.map((participant) => [participant.id, participant.label]));

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="border-b border-border bg-muted/20 px-4 py-2.5">
        <div className="flex items-center gap-2">
          <ArrowRightLeft className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs font-semibold">Token Lifecycle</span>
        </div>
      </div>

      <div className="space-y-4 p-4">
        {flows.map((flow) => (
          <div key={flow.token} className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={cn(
                  "rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider",
                  ACCENT_STYLES[flow.accent ?? "resource"]
                )}
              >
                {flow.label}
              </span>
              {flow.tokenType && (
                <span className="rounded bg-muted px-2 py-0.5 text-[10px] font-mono text-muted-foreground">
                  {flow.tokenType}
                </span>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {flow.events.map((event, index) => {
                const isPast = event.step < currentStep + 1;
                const isCurrent = event.step === currentStep + 1;
                return (
                  <div key={`${flow.token}-${event.step}-${index}`} className="flex items-center gap-2">
                    <button
                      onClick={() => onStepSelect(event.step - 1)}
                      className={cn(
                        "min-w-[148px] rounded-lg px-3 py-2 text-left transition-colors",
                        EVENT_STYLES[event.kind],
                        isCurrent && "ring-1 ring-foreground/30",
                        !isPast && !isCurrent && "opacity-45"
                      )}
                    >
                      <div className="text-[10px] font-mono text-muted-foreground">step {event.step}</div>
                      <div className="mt-1 text-xs font-medium">
                        {participantLabels.get(event.participant) ?? event.participant}
                      </div>
                      <div className="mt-1 text-[11px] leading-relaxed">{event.label}</div>
                    </button>
                    {index < flow.events.length - 1 && (
                      <ArrowUpRight className="h-3.5 w-3.5 text-muted-foreground/50" />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
