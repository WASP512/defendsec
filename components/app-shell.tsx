"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Anchor,
  FileWarning,
  History,
  LayoutDashboard,
  Monitor,
  Package,
  Scale,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { cn } from "@/lib/utils";

const nav = [
  { href: "/", label: "Fleet", icon: LayoutDashboard },
  { href: "/devices", label: "Hosts", icon: Monitor },
  { href: "/advisories", label: "Advisories", icon: ShieldAlert },
  { href: "/patches", label: "Patches", icon: Package },
  { href: "/versions", label: "Versions", icon: History },
  { href: "/integrity", label: "Integrity", icon: FileWarning },
  { href: "/policies", label: "Policies", icon: ShieldCheck },
  { href: "/enroll", label: "Enroll", icon: Terminal },
  { href: "/scope", label: "Scope", icon: Scale },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="flex min-h-full flex-col bg-background lg:flex-row">
      <header className="flex items-center justify-between border-b px-4 py-3 lg:hidden">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <Anchor className="size-5" />
          Keel
        </Link>
        <nav className="flex gap-1 overflow-x-auto">
          {nav.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "rounded-md px-2 py-1 text-sm",
                pathname === item.href
                  ? "bg-foreground text-background"
                  : "text-muted-foreground",
              )}
            >
              {item.label}
            </Link>
          ))}
        </nav>
      </header>
      <aside className="hidden w-56 shrink-0 border-r lg:flex lg:flex-col">
        <Link href="/" className="flex items-center gap-2 px-5 py-6 text-lg font-semibold">
          <Anchor className="size-5" />
          Keel
        </Link>
        <nav className="flex flex-col gap-1 px-3">
          {nav.map((item) => {
            const Icon = item.icon;
            const active =
              item.href === "/"
                ? pathname === "/"
                : pathname === item.href || pathname.startsWith(`${item.href}/`);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-2 rounded-lg px-3 py-2 text-sm",
                  active
                    ? "bg-foreground text-background"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )}
              >
                <Icon className="size-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>
        <p className="mt-auto px-5 py-6 text-xs leading-relaxed text-muted-foreground">
          Self-hosted security inventory. No accounts, no premium tiers.
        </p>
      </aside>
      <main className="min-w-0 flex-1 px-4 py-6 sm:px-8">{children}</main>
    </div>
  );
}
