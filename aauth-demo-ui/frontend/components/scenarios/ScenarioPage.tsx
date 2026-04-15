"use client";

import { useEffect } from "react";
import { motion } from "framer-motion";
import { BookOpen } from "lucide-react";
import { Scenario } from "@/lib/types";
import { useScenarioStore } from "@/lib/store";
import { SequenceDiagram } from "@/components/core/SequenceDiagram";
import { JWTViewer } from "@/components/core/JWTViewer";
import { HeaderInspector } from "@/components/core/HeaderInspector";
import { SignatureVisualizer } from "@/components/core/SignatureVisualizer";
import { StepController } from "@/components/core/StepController";
import { TokenFlowDiagram } from "@/components/core/TokenFlowDiagram";
import { DeferredResponseTimeline } from "@/components/core/DeferredResponseTimeline";
import { MissionBlobViewer } from "@/components/core/MissionBlobViewer";
import { S256ChainVisualization } from "@/components/core/S256ChainVisualization";
import { cn } from "@/lib/utils";

const CATEGORY_COLORS = {
  signing: "text-blue-400 bg-blue-500/10",
  access: "text-green-400 bg-green-500/10",
  missions: "text-purple-400 bg-purple-500/10",
  advanced: "text-orange-400 bg-orange-500/10",
};

interface ScenarioPageProps {
  scenario: Scenario;
}

export function ScenarioPage({ scenario }: ScenarioPageProps) {
  const { currentStep, setCurrentStep, reset, activeVariant, setActiveVariant } = useScenarioStore();

  useEffect(() => {
    reset();
  }, [scenario.id, reset]);

  const variantData =
    activeVariant === "interactive" && scenario.interactive
      ? scenario.interactive
      : null;

  const participants = variantData?.participants ?? scenario.participants;
  const steps = variantData?.steps ?? scenario.steps;
  const description = variantData?.description ?? scenario.description;
  const tokenFlow = variantData?.token_flow ?? scenario.token_flow;
  const deferredTimeline = variantData?.deferred_timeline ?? scenario.deferred_timeline;

  const step = steps[currentStep];
  const stepLabels = steps.map((s) => s.label);

  return (
    <div className="flex flex-col h-full">
      {/* Page header */}
      <div className="border-b border-border px-6 py-4 shrink-0">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  "text-[10px] font-semibold rounded px-2 py-0.5 uppercase tracking-wider",
                  CATEGORY_COLORS[scenario.category]
                )}
              >
                {scenario.category}
              </span>
              {scenario.demo_phase && (
                <span className="text-[10px] font-mono text-muted-foreground">
                  Phase {scenario.demo_phase}
                </span>
              )}
              {/* Autonomous / With User Approval toggle */}
              {scenario.interactive && (
                <div className="ml-2 flex items-center rounded-md border border-border bg-muted/30 p-0.5 text-[11px] font-medium">
                  <button
                    onClick={() => setActiveVariant("autonomous")}
                    className={cn(
                      "rounded px-2.5 py-0.5 transition-colors",
                      activeVariant === "autonomous"
                        ? "bg-background text-foreground shadow-sm"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    Autonomous
                  </button>
                  <button
                    onClick={() => setActiveVariant("interactive")}
                    className={cn(
                      "rounded px-2.5 py-0.5 transition-colors",
                      activeVariant === "interactive"
                        ? "bg-background text-foreground shadow-sm"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    With User Approval
                  </button>
                </div>
              )}
            </div>
            <h1 className="text-xl font-bold">{scenario.title}</h1>
            <p className="text-sm text-muted-foreground max-w-2xl leading-relaxed">
              {description}
            </p>
          </div>
          {scenario.spec_section && (
            <a
              href="#"
              className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <BookOpen className="h-3.5 w-3.5" />
              {scenario.spec_section}
            </a>
          )}
        </div>
      </div>

      {/* Main content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: Sequence diagram + step controller */}
        <div className="flex flex-col border-r border-border w-full lg:w-[420px] xl:w-[520px] shrink-0">
          <div className="flex-1 overflow-auto p-6">
            <SequenceDiagram
              participants={participants}
              steps={steps}
              currentStep={currentStep}
              onStepClick={setCurrentStep}
            />
          </div>

          {/* Step info */}
          {step && (
            <div className="border-t border-border px-4 py-3 bg-muted/10 shrink-0 overflow-hidden">
              <div className="flex items-center gap-2 mb-2 min-w-0">
                <span className="text-[10px] font-mono text-muted-foreground break-all min-w-0">
                  {step.method} {step.url}
                </span>
                <span
                  className={cn(
                    "ml-auto text-[10px] font-mono font-bold shrink-0",
                    step.response_status < 300
                      ? "text-green-400"
                      : step.response_status < 400
                      ? "text-blue-400"
                      : "text-amber-400"
                  )}
                >
                  {step.response_status}
                </span>
              </div>
              {step.annotations.length > 0 && (
                <div className="space-y-1">
                  {step.annotations.map((note, i) => (
                    <p key={i} className="text-xs text-muted-foreground leading-relaxed">
                      {note}
                    </p>
                  ))}
                </div>
              )}
            </div>
          )}

          <div className="p-4 border-t border-border shrink-0">
            <StepController totalSteps={steps.length} stepLabels={stepLabels} />
          </div>
        </div>

        {/* Right: Detail panels */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 min-w-0">
          {step && (
            <motion.div
              key={`${activeVariant}-${currentStep}`}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25 }}
              className="space-y-4"
            >
              {tokenFlow && tokenFlow.length > 0 && (
                <TokenFlowDiagram
                  flows={tokenFlow}
                  participants={participants}
                  currentStep={currentStep}
                  onStepSelect={setCurrentStep}
                />
              )}

              {deferredTimeline && (
                <DeferredResponseTimeline
                  timeline={deferredTimeline}
                  currentStep={currentStep}
                  onStepSelect={setCurrentStep}
                />
              )}

              {scenario.mission_blob && <MissionBlobViewer mission={scenario.mission_blob} />}

              {scenario.s256_chain && scenario.s256_chain.length > 0 && (
                <S256ChainVisualization links={scenario.s256_chain} />
              )}

              {/* Headers & Body */}
              <HeaderInspector
                method={step.method}
                url={step.url}
                requestHeaders={step.request_headers}
                responseHeaders={step.response_headers}
                requestBody={step.request_body}
                responseBody={step.response_body}
                responseStatus={step.response_status}
              />

              {/* HTTP Signature */}
              {step.signature && <SignatureVisualizer signature={step.signature} />}

              {/* Tokens */}
              {step.tokens.length > 0 && (
                <div className="space-y-4">
                  {step.tokens.map((token, i) => (
                    <JWTViewer key={i} token={token} />
                  ))}
                </div>
              )}
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
}
