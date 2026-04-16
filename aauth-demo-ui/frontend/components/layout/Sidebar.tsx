"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { ChevronDown, ChevronRight, Radio, Lock, FileText, Zap, Layers, X } from "lucide-react";
import { cn } from "@/lib/utils";

interface NavItem {
  label: string;
  href: string;
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
    title: "Foundations",
    icon: Layers,
    color: "text-cyan-400",
    items: [
      { label: "HTTP Signatures Profile", href: "/foundations/profile" },
      { label: "Signature-Key Schemes", href: "/foundations/schemes" },
      { label: "Error Model", href: "/foundations/errors" },
    ],
  },
  {
    title: "Message Signing",
    icon: Radio,
    color: "text-blue-400",
    items: [
      { label: "Pseudonymous (sig=hwk)", href: "/signing/pseudonymous" },
      { label: "Hardware-backed (sig=jkt-jwt)", href: "/signing/hardware-backed" },
      { label: "Agent Identity (sig=jwks_uri)", href: "/signing/identity" },
      { label: "Agent Tokens (sig=jwt)", href: "/signing/agent-tokens" },
      { label: "Compare Modes", href: "/signing/compare" },
    ],
  },
  {
    title: "Resource Access",
    icon: Lock,
    color: "text-green-400",
    items: [
      { label: "Identity-Based", href: "/access/identity-based" },
      { label: "Resource-Managed (2-party)", href: "/access/resource-managed" },
      { label: "PS-Managed (3-party)", href: "/access/ps-managed" },
      { label: "Federated (4-party)", href: "/access/federated" },
      { label: "Compare Modes", href: "/access/compare" },
    ],
  },
  {
    title: "Missions",
    icon: FileText,
    color: "text-purple-400",
    items: [
      { label: "Proposal & Approval", href: "/missions/lifecycle" },
      { label: "Resource Access", href: "/missions/resource-access" },
      { label: "Out-of-Bounds Access", href: "/missions/out-of-bounds" },
      { label: "Completion", href: "/missions/completion" },
      { label: "Audit Endpoint", href: "/missions/audit" },
      { label: "End-to-End Lifecycle", href: "/missions/end-to-end" },
      { label: "With vs Without Missions", href: "/missions/compare" },
    ],
  },
  {
    title: "Advanced Patterns",
    icon: Zap,
    color: "text-orange-400",
    items: [
      { label: "Call Chaining", href: "/advanced/call-chaining" },
      { label: "Clarification Chat", href: "/advanced/clarification" },
      { label: "Interaction Chaining", href: "/advanced/interaction-chaining" },
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
