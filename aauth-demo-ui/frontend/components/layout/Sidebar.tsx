"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { ChevronDown, ChevronRight, Radio, Lock, FileText, Zap, X } from "lucide-react";
import { cn } from "@/lib/utils";

interface NavItem {
  label: string;
  href: string;
  phase?: number;
  badge?: string;
}

interface NavSection {
  title: string;
  icon: React.ElementType;
  color: string;
  items: NavItem[];
}

const NAV: NavSection[] = [
  {
    title: "Message Signing",
    icon: Radio,
    color: "text-blue-400",
    items: [
      { label: "Pseudonymous (sig=hwk)", href: "/signing/pseudonymous", phase: 1 },
      { label: "Agent Identity (sig=jwks_uri)", href: "/signing/identity", phase: 2 },
      { label: "Compare Modes", href: "/signing/compare" },
    ],
  },
  {
    title: "Resource Access",
    icon: Lock,
    color: "text-green-400",
    items: [
      { label: "Identity-Based (2-party)", href: "/access/identity-based" },
      { label: "Federated / Autonomous", href: "/access/federated", phase: 3 },
      { label: "User Delegation", href: "/access/user-delegation", phase: 4 },
      { label: "PS–AS Federation Trust", href: "/access/ps-managed", phase: 11 },
      { label: "Compare Modes", href: "/access/compare" },
    ],
  },
  {
    title: "Missions",
    icon: FileText,
    color: "text-purple-400",
    items: [
      { label: "Proposal & Approval", href: "/missions/lifecycle", phase: 5 },
      { label: "Proactive Authorization", href: "/missions/proactive-authz", phase: 10 },
      { label: "End-to-End Lifecycle", href: "/missions/end-to-end", phase: 12 },
      { label: "With vs Without Missions", href: "/missions/compare" },
    ],
  },
  {
    title: "Advanced Patterns",
    icon: Zap,
    color: "text-orange-400",
    items: [
      { label: "Agent Delegation", href: "/advanced/delegation", phase: 6 },
      { label: "Call Chaining", href: "/advanced/call-chaining", phase: 7 },
      { label: "Clarification Chat", href: "/advanced/clarification", phase: 8 },
      { label: "Interaction Chaining", href: "/advanced/interaction-chaining", phase: 9 },
    ],
  },
];

function SidebarSection({ section, defaultOpen }: { section: NavSection; defaultOpen: boolean }) {
  const pathname = usePathname();
  const [open, setOpen] = useState(defaultOpen);
  const Icon = section.icon;
  const isActive = section.items.some((i) => pathname === i.href || pathname.startsWith(i.href + "/"));

  return (
    <div className="mb-1">
      <button
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors",
          isActive ? "text-foreground" : "text-muted-foreground hover:text-foreground"
        )}
      >
        <Icon className={cn("h-4 w-4 shrink-0", section.color)} />
        <span className="flex-1 text-left">{section.title}</span>
        {open ? (
          <ChevronDown className="h-3.5 w-3.5 opacity-50" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 opacity-50" />
        )}
      </button>

      {open && (
        <div className="mt-0.5 ml-4 border-l border-border pl-3 space-y-0.5">
          {section.items.map((item) => {
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-2 rounded-md px-2.5 py-1.5 text-sm transition-colors",
                  active
                    ? "bg-accent text-accent-foreground font-medium"
                    : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
                )}
              >
                <span className="flex-1">{item.label}</span>
                {item.phase !== undefined && (
                  <span className="text-[10px] font-mono text-muted-foreground/60 shrink-0">
                    p{item.phase}
                  </span>
                )}
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function Sidebar({ onClose }: { onClose?: () => void }) {
  const pathname = usePathname();

  return (
    <div className="flex h-full flex-col bg-sidebar border-r border-border">
      {/* Header */}
      <div className="flex h-14 items-center justify-between px-4 border-b border-border shrink-0">
        <Link href="/" className="flex items-center gap-2">
          <div className="h-6 w-6 rounded bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
            <span className="text-[10px] font-bold text-white">A²</span>
          </div>
          <span className="font-semibold text-sm tracking-tight">AAuth Explorer</span>
        </Link>
        {onClose && (
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1 rounded">
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-4 px-3">
        {NAV.map((section) => {
          const defaultOpen = section.items.some(
            (i) => pathname === i.href || pathname.startsWith(i.href + "/")
          );
          return (
            <SidebarSection key={section.title} section={section} defaultOpen={defaultOpen || true} />
          );
        })}
      </nav>

      {/* Footer */}
      <div className="shrink-0 border-t border-border px-4 py-3">
        <a
          href="https://github.com"
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          SPEC.md reference ↗
        </a>
      </div>
    </div>
  );
}
