"use client";
import { create } from "zustand";

interface ScenarioState {
  currentStep: number;
  isPlaying: boolean;
  playSpeed: number; // ms between steps
  expandedPanel: "headers" | "payload" | "jwt" | "signature" | null;
  selectedTokenIndex: number | null;
  activeVariant: "autonomous" | "interactive";

  setCurrentStep: (step: number) => void;
  nextStep: (maxStep: number) => void;
  prevStep: () => void;
  setIsPlaying: (playing: boolean) => void;
  setPlaySpeed: (speed: number) => void;
  setExpandedPanel: (panel: ScenarioState["expandedPanel"]) => void;
  setSelectedTokenIndex: (index: number | null) => void;
  setActiveVariant: (variant: "autonomous" | "interactive") => void;
  reset: () => void;
}

export const useScenarioStore = create<ScenarioState>((set) => ({
  currentStep: 0,
  isPlaying: false,
  playSpeed: 1800,
  expandedPanel: null,
  selectedTokenIndex: null,
  activeVariant: "autonomous",

  setCurrentStep: (step) => set({ currentStep: step, expandedPanel: null, selectedTokenIndex: null }),
  nextStep: (maxStep) =>
    set((state) => ({
      currentStep: Math.min(state.currentStep + 1, maxStep),
      expandedPanel: null,
      selectedTokenIndex: null,
    })),
  prevStep: () =>
    set((state) => ({
      currentStep: Math.max(state.currentStep - 1, 0),
      expandedPanel: null,
      selectedTokenIndex: null,
    })),
  setIsPlaying: (playing) => set({ isPlaying: playing }),
  setPlaySpeed: (speed) => set({ playSpeed: speed }),
  setExpandedPanel: (panel) => set({ expandedPanel: panel }),
  setSelectedTokenIndex: (index) => set({ selectedTokenIndex: index }),
  setActiveVariant: (variant) => set({ activeVariant: variant, currentStep: 0, expandedPanel: null, selectedTokenIndex: null }),
  reset: () =>
    set({
      currentStep: 0,
      isPlaying: false,
      expandedPanel: null,
      selectedTokenIndex: null,
      activeVariant: "autonomous",
    }),
}));
