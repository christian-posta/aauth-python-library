"use client";

import { useEffect, useCallback } from "react";
import { ChevronLeft, ChevronRight, Play, Pause, RotateCcw } from "lucide-react";
import { cn } from "@/lib/utils";
import { useScenarioStore } from "@/lib/store";

interface StepControllerProps {
  totalSteps: number;
  stepLabels?: string[];
}

export function StepController({ totalSteps, stepLabels }: StepControllerProps) {
  const {
    currentStep,
    isPlaying,
    playSpeed,
    setCurrentStep,
    nextStep,
    prevStep,
    setIsPlaying,
    setPlaySpeed,
    reset,
  } = useScenarioStore();

  // Auto-advance when playing
  useEffect(() => {
    if (!isPlaying) return;
    if (currentStep >= totalSteps - 1) {
      setIsPlaying(false);
      return;
    }
    const timer = setTimeout(() => nextStep(totalSteps - 1), playSpeed);
    return () => clearTimeout(timer);
  }, [isPlaying, currentStep, totalSteps, playSpeed, nextStep, setIsPlaying]);

  // Keyboard navigation
  const handleKey = useCallback(
    (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (e.key === "ArrowRight") nextStep(totalSteps - 1);
      if (e.key === "ArrowLeft") prevStep();
      if (e.key === " ") {
        e.preventDefault();
        setIsPlaying(!isPlaying);
      }
    },
    [nextStep, prevStep, isPlaying, setIsPlaying, totalSteps]
  );

  useEffect(() => {
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [handleKey]);

  const speeds = [
    { label: "0.5×", value: 3600 },
    { label: "1×", value: 1800 },
    { label: "2×", value: 900 },
    { label: "3×", value: 450 },
  ];

  return (
    <div className="flex flex-col gap-3 rounded-lg border border-border bg-card px-4 py-3">
      {/* Step dots */}
      <div className="flex items-center gap-1.5 flex-wrap">
        {Array.from({ length: totalSteps }).map((_, i) => (
          <button
            key={i}
            onClick={() => setCurrentStep(i)}
            title={stepLabels?.[i] ?? `Step ${i + 1}`}
            className={cn(
              "h-2 rounded-full transition-all duration-200",
              i === currentStep
                ? "w-6 bg-foreground"
                : i < currentStep
                ? "w-2 bg-foreground/40"
                : "w-2 bg-muted-foreground/20"
            )}
          />
        ))}
        <span className="ml-auto text-xs text-muted-foreground font-mono">
          {currentStep + 1} / {totalSteps}
        </span>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-2">
        <button
          onClick={reset}
          className="p-1.5 rounded text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          title="Reset to start"
        >
          <RotateCcw className="h-3.5 w-3.5" />
        </button>

        <button
          onClick={prevStep}
          disabled={currentStep === 0}
          className="p-1.5 rounded text-muted-foreground hover:text-foreground hover:bg-accent transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
        >
          <ChevronLeft className="h-4 w-4" />
        </button>

        <button
          onClick={() => setIsPlaying(!isPlaying)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-accent text-foreground hover:bg-accent/80 transition-colors text-xs font-medium"
        >
          {isPlaying ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
          {isPlaying ? "Pause" : "Play"}
        </button>

        <button
          onClick={() => nextStep(totalSteps - 1)}
          disabled={currentStep >= totalSteps - 1}
          className="p-1.5 rounded text-muted-foreground hover:text-foreground hover:bg-accent transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
        >
          <ChevronRight className="h-4 w-4" />
        </button>

        <div className="ml-auto flex items-center gap-1 text-xs text-muted-foreground">
          <span className="mr-1">speed</span>
          {speeds.map((s) => (
            <button
              key={s.value}
              onClick={() => setPlaySpeed(s.value)}
              className={cn(
                "rounded px-1.5 py-0.5 transition-colors",
                playSpeed === s.value
                  ? "bg-accent text-foreground"
                  : "hover:text-foreground"
              )}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Current step label */}
      {stepLabels?.[currentStep] && (
        <p className="text-xs text-muted-foreground truncate">
          <span className="font-medium text-foreground">Step {currentStep + 1}:</span>{" "}
          {stepLabels[currentStep]}
        </p>
      )}
    </div>
  );
}
