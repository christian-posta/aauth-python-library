"use client";

import { Clock3 } from "lucide-react";
import { DeferredTimeline } from "@/lib/types";
import { cn } from "@/lib/utils";

function statusColor(status: number) {
  if (status === 202) return "text-blue-300 border-blue-500/30 bg-blue-500/10";
  if (status >= 200 && status < 300) return "text-green-300 border-green-500/30 bg-green-500/10";
  if (status >= 400) return "text-red-300 border-red-500/30 bg-red-500/10";
  return "text-muted-foreground border-border bg-muted/10";
}

interface DeferredResponseTimelineProps {
  timeline: DeferredTimeline;
  currentStep: number;
  onStepSelect: (step: number) => void;
}

export function DeferredResponseTimeline({
  timeline,
  currentStep,
  onStepSelect,
}: DeferredResponseTimelineProps) {
  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="border-b border-border bg-muted/20 px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Clock3 className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs font-semibold">{timeline.title}</span>
        </div>
      </div>

      <div className="p-4">
        <div className="flex flex-wrap items-start gap-3">
          {timeline.events.map((event, index) => {
            const visible = event.step <= currentStep + 1;
            const active = event.step === currentStep + 1;
            return (
              <div key={`${event.step}-${index}`} className="flex items-center gap-3">
                <button
                  onClick={() => onStepSelect(event.step - 1)}
                  className={cn(
                    "min-w-[170px] rounded-lg border px-3 py-2 text-left transition-colors",
                    statusColor(event.status),
                    !visible && "opacity-40",
                    active && "ring-1 ring-foreground/30"
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] font-mono text-muted-foreground">step {event.step}</span>
                    <span className="text-xs font-mono font-bold">{event.status}</span>
                  </div>
                  <div className="mt-1 text-xs font-medium">{event.label}</div>
                  <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                    {event.detail}
                  </div>
                </button>
                {index < timeline.events.length - 1 && (
                  <div className="pt-5 text-xs font-mono text-muted-foreground/50">
                    →
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
