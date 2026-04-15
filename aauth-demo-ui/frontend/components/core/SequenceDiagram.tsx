"use client";

import { motion } from "framer-motion";
import { Participant, ProtocolStep } from "@/lib/types";
import { cn } from "@/lib/utils";

const PARTICIPANT_COLORS: Record<string, string> = {
  agent: "#60a5fa",       // blue-400
  resource: "#4ade80",    // green-400
  "person-server": "#c084fc", // purple-400
  "access-server": "#fb923c", // orange-400
  user: "#f87171",        // red-400
  delegate: "#38bdf8",    // sky-400
};

const LANE_WIDTH = 140;
const LANE_PADDING = 40;
const HEADER_HEIGHT = 80;
const STEP_HEIGHT = 80;
const ARROW_Y_OFFSET = 28;
const RESPONSE_Y_OFFSET = 52;

function getColor(type: string) {
  return PARTICIPANT_COLORS[type] ?? "#94a3b8";
}

function statusColor(status: number): string {
  if (status === 202) return "#60a5fa";   // blue — deferred/pending
  if (status >= 200 && status < 300) return "#4ade80"; // green — success
  if (status === 401) return "#fbbf24";   // amber — auth challenge
  if (status >= 400) return "#f87171";    // red — error
  return "#94a3b8";
}

interface SequenceDiagramProps {
  participants: Participant[];
  steps: ProtocolStep[];
  currentStep: number;
  onStepClick: (step: number) => void;
}

export function SequenceDiagram({
  participants,
  steps,
  currentStep,
  onStepClick,
}: SequenceDiagramProps) {
  const totalWidth = participants.length * LANE_WIDTH + LANE_PADDING * 2;
  const totalHeight = HEADER_HEIGHT + steps.length * STEP_HEIGHT + 40;

  function laneX(id: string): number {
    const idx = participants.findIndex((p) => p.id === id);
    return LANE_PADDING + idx * LANE_WIDTH + LANE_WIDTH / 2;
  }

  return (
    <div className="overflow-x-auto">
      <svg
        width={totalWidth}
        height={totalHeight}
        className="select-none"
        style={{ minWidth: totalWidth }}
      >
        {/* Participant headers */}
        {participants.map((p) => {
          const x = laneX(p.id);
          const color = getColor(p.type);
          return (
            <g key={p.id}>
              {/* Header box */}
              <rect
                x={x - 54}
                y={8}
                width={108}
                height={36}
                rx={6}
                fill={color + "22"}
                stroke={color}
                strokeWidth={1.5}
              />
              <text
                x={x}
                y={22}
                textAnchor="middle"
                fill={color}
                fontSize={11}
                fontWeight={600}
                fontFamily="var(--font-geist-sans)"
              >
                {p.label}
              </text>
              {p.port && (
                <text
                  x={x}
                  y={36}
                  textAnchor="middle"
                  fill={color + "99"}
                  fontSize={9}
                  fontFamily="var(--font-geist-mono)"
                >
                  :{p.port}
                </text>
              )}
              {/* Lifeline */}
              <line
                x1={x}
                y1={44}
                x2={x}
                y2={totalHeight - 20}
                stroke={color + "33"}
                strokeWidth={1.5}
                strokeDasharray="4 3"
              />
            </g>
          );
        })}

        {/* Steps / arrows */}
        {steps.map((step, idx) => {
          const y = HEADER_HEIGHT + idx * STEP_HEIGHT + ARROW_Y_OFFSET;
          const ry = HEADER_HEIGHT + idx * STEP_HEIGHT + RESPONSE_Y_OFFSET;
          const fromX = laneX(step.from);
          const toX = laneX(step.to);
          const isPast = idx < currentStep;
          const isCurrent = idx === currentStep;
          const isFuture = idx > currentStep;
          const isResponse = step.is_response;
          const arrowColor = isCurrent
            ? statusColor(step.response_status)
            : isPast
            ? statusColor(step.response_status) + "88"
            : "#475569";
          const respColor = isCurrent
            ? statusColor(step.response_status)
            : statusColor(step.response_status) + "66";

          const dir = toX > fromX ? 1 : -1;
          const arrowEndX = toX + dir * -8;
          // Return arrow goes opposite direction
          const retFromX = toX + dir * -14;
          const retEndX = fromX + dir * 14;

          // Show the dashed return arrow for non-is_response steps that have happened
          const showReturn = !isResponse && !isFuture;

          return (
            <g
              key={step.step}
              onClick={() => !isFuture && onStepClick(idx)}
              className={cn(isFuture ? "cursor-default" : "cursor-pointer")}
            >
              {/* Hover area — spans request + response rows */}
              <rect
                x={Math.min(fromX, toX) - 10}
                y={y - 18}
                width={Math.abs(toX - fromX) + 20}
                height={showReturn ? RESPONSE_Y_OFFSET - ARROW_Y_OFFSET + 22 : 36}
                fill="transparent"
              />

              {/* Step number bubble */}
              <circle
                cx={fromX + dir * 20}
                cy={y}
                r={9}
                fill={isCurrent ? arrowColor : "transparent"}
                stroke={isCurrent ? arrowColor : "#475569"}
                strokeWidth={1}
                opacity={isFuture ? 0.3 : 1}
              />
              <text
                x={fromX + dir * 20}
                y={y + 4}
                textAnchor="middle"
                fill={isCurrent ? "#0f172a" : isFuture ? "#475569" : "#94a3b8"}
                fontSize={9}
                fontWeight={600}
                fontFamily="var(--font-geist-mono)"
              >
                {idx + 1}
              </text>

              {/* Request arrow line */}
              {isCurrent ? (
                <motion.line
                  key={`arrow-${idx}`}
                  x1={fromX + dir * 32}
                  y1={y}
                  x2={arrowEndX}
                  y2={y}
                  stroke={arrowColor}
                  strokeWidth={isResponse ? 1.5 : 2}
                  strokeDasharray={isResponse ? "5 3" : undefined}
                  initial={{ pathLength: 0, opacity: 0 }}
                  animate={{ pathLength: 1, opacity: 1 }}
                  transition={{ duration: 0.4, ease: "easeOut" }}
                />
              ) : (
                <line
                  x1={fromX + dir * 32}
                  y1={y}
                  x2={arrowEndX}
                  y2={y}
                  stroke={arrowColor}
                  strokeWidth={isResponse ? 1.5 : 2}
                  strokeDasharray={isResponse ? "5 3" : undefined}
                  opacity={isFuture ? 0.2 : 0.7}
                />
              )}

              {/* Request arrowhead */}
              <polygon
                points={
                  dir > 0
                    ? `${arrowEndX},${y} ${arrowEndX - 8},${y - 4} ${arrowEndX - 8},${y + 4}`
                    : `${arrowEndX},${y} ${arrowEndX + 8},${y - 4} ${arrowEndX + 8},${y + 4}`
                }
                fill={arrowColor}
                opacity={isFuture ? 0.2 : isPast ? 0.6 : 1}
              />

              {/* Label */}
              <text
                x={(fromX + toX) / 2}
                y={y - 8}
                textAnchor="middle"
                fill={isCurrent ? "#f1f5f9" : isFuture ? "#334155" : "#94a3b8"}
                fontSize={10}
                fontWeight={isCurrent ? 600 : 400}
                fontFamily="var(--font-geist-sans)"
              >
                {step.label.length > 28 ? step.label.slice(0, 27) + "…" : step.label}
              </text>

              {/* Dashed return arrow + status badge */}
              {showReturn && (
                <g opacity={isCurrent ? 1 : 0.55}>
                  {/* Return line */}
                  {isCurrent ? (
                    <motion.line
                      key={`ret-${idx}`}
                      x1={retFromX}
                      y1={ry}
                      x2={retEndX}
                      y2={ry}
                      stroke={respColor}
                      strokeWidth={1.5}
                      strokeDasharray="5 3"
                      initial={{ pathLength: 0, opacity: 0 }}
                      animate={{ pathLength: 1, opacity: 1 }}
                      transition={{ duration: 0.4, ease: "easeOut", delay: 0.2 }}
                    />
                  ) : (
                    <line
                      x1={retFromX}
                      y1={ry}
                      x2={retEndX}
                      y2={ry}
                      stroke={respColor}
                      strokeWidth={1.5}
                      strokeDasharray="5 3"
                    />
                  )}
                  {/* Return arrowhead — points back toward fromX */}
                  <polygon
                    points={
                      dir > 0
                        ? `${retEndX},${ry} ${retEndX + 7},${ry - 3.5} ${retEndX + 7},${ry + 3.5}`
                        : `${retEndX},${ry} ${retEndX - 7},${ry - 3.5} ${retEndX - 7},${ry + 3.5}`
                    }
                    fill={respColor}
                  />
                  {/* Status badge on the return arrow */}
                  <rect
                    x={(fromX + toX) / 2 - 18}
                    y={ry - 9}
                    width={36}
                    height={13}
                    rx={3}
                    fill={statusColor(step.response_status) + "22"}
                  />
                  <text
                    x={(fromX + toX) / 2}
                    y={ry + 1}
                    textAnchor="middle"
                    fill={statusColor(step.response_status)}
                    fontSize={9}
                    fontWeight={600}
                    fontFamily="var(--font-geist-mono)"
                  >
                    {step.response_status}
                  </text>
                </g>
              )}

              {/* Status badge for is_response steps (no return arrow) */}
              {isResponse && !isFuture && (
                <g>
                  <rect
                    x={(fromX + toX) / 2 - 18}
                    y={y + 6}
                    width={36}
                    height={13}
                    rx={3}
                    fill={statusColor(step.response_status) + "22"}
                  />
                  <text
                    x={(fromX + toX) / 2}
                    y={y + 16}
                    textAnchor="middle"
                    fill={statusColor(step.response_status)}
                    fontSize={9}
                    fontWeight={600}
                    fontFamily="var(--font-geist-mono)"
                  >
                    {step.response_status}
                  </text>
                </g>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
