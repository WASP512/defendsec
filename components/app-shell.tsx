"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Anchor,
  ChevronRight,
  FileWarning,
  History,
  LayoutDashboard,
  LogOut,
  Monitor,
  Package,
  Scale,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Terminal,
} from "lucide-react";
import { Separator } from "@/components/ui/separator";
import { ConsoleTools } from "@/components/console-tools";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
} from "@/components/ui/sidebar";

const nav = [
  { href: "/", label: "Fleet", icon: LayoutDashboard },
  { href: "/devices", label: "Hosts", icon: Monitor },
  { href: "/alerts", label: "Alerts", icon: Siren },
  { href: "/advisories", label: "Advisories", icon: ShieldAlert },
  { href: "/patches", label: "Patches", icon: Package },
  { href: "/versions", label: "Versions", icon: History },
  { href: "/integrity", label: "Integrity", icon: FileWarning },
  { href: "/policies", label: "Policies", icon: ShieldCheck },
  { href: "/audit", label: "Audit", icon: ScrollText },
  { href: "/enroll", label: "Enroll", icon: Terminal },
  { href: "/scope", label: "Scope", icon: Scale },
];

const navGroups = [
  { label: "Monitor", items: nav.slice(0, 4) },
  { label: "Inventory", items: nav.slice(4, 8) },
  { label: "Operations", items: nav.slice(8) },
];

export function AppShell({
  children,
  readOnly,
}: {
  children: React.ReactNode;
  readOnly?: boolean;
}) {
  const pathname = usePathname();
  const visibleNav = readOnly ? nav.filter((item) => item.href !== "/enroll") : nav;
  const current = nav.find((item) =>
    item.href === "/" ? pathname === "/" : pathname === item.href || pathname.startsWith(`${item.href}/`),
  );
  const destinations = navGroups.flatMap((group) =>
    group.items
      .filter((item) => visibleNav.some((visible) => visible.href === item.href))
      .map((item) => ({ ...item, group: group.label })),
  );

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader className="border-b">
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton render={<Link href="/" />} size="lg" tooltip="DefendSec">
                  <span className="flex aspect-square size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                    <Anchor className="size-4" />
                  </span>
                  <span className="grid flex-1 text-left leading-tight group-data-[collapsible=icon]:hidden">
                    <span className="truncate font-semibold">DefendSec</span>
                    <span className="truncate text-xs text-muted-foreground">Security inventory</span>
                  </span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>
        <SidebarContent>
          {navGroups.map((group) => {
            const items = group.items.filter((item) => visibleNav.some((visible) => visible.href === item.href));
            if (items.length === 0) return null;
            return (
              <SidebarGroup key={group.label}>
                <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
                <SidebarGroupContent>
                  <SidebarMenu>
                    {items.map((item) => {
                      const Icon = item.icon;
                      const active =
                        item.href === "/"
                          ? pathname === "/"
                          : pathname === item.href || pathname.startsWith(`${item.href}/`);
                      return (
                        <SidebarMenuItem key={item.href}>
                          <SidebarMenuButton render={<Link href={item.href} />} isActive={active} tooltip={item.label}>
                              <Icon />
                              <span className="group-data-[collapsible=icon]:hidden">{item.label}</span>
                          </SidebarMenuButton>
                        </SidebarMenuItem>
                      );
                    })}
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>
            );
          })}
        </SidebarContent>
        <SidebarFooter className="border-t">
          <SidebarMenu>
            <SidebarMenuItem>
              <form action="/api/logout" method="post">
                <SidebarMenuButton type="submit" tooltip="Sign out">
                  <LogOut />
                  <span className="group-data-[collapsible=icon]:hidden">Sign out</span>
                </SidebarMenuButton>
              </form>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>
      <SidebarInset>
        <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-2 border-b bg-background/95 px-4 backdrop-blur">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mx-1 h-4" />
          <Link href="/" className="text-sm text-muted-foreground hover:text-foreground">
            Console
          </Link>
          <ChevronRight className="size-3.5 text-muted-foreground" />
          <span className="text-sm font-medium">{current?.label ?? "DefendSec"}</span>
          <div className="ml-auto flex items-center gap-1">
            <ConsoleTools destinations={destinations} />
          </div>
        </header>
        <main className="min-w-0 flex-1 p-4 sm:p-6 lg:p-8">
          {readOnly ? (
            <div className="mx-auto mb-6 flex max-w-6xl items-start gap-3 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-950 dark:text-amber-100">
              <ShieldAlert className="mt-0.5 size-4 shrink-0" />
              <p>
                <span className="font-medium">Viewer session.</span> Signed commands, revoke, and
                alert status changes require an admin token.
              </p>
            </div>
          ) : null}
          {children}
        </main>
      </SidebarInset>
    </SidebarProvider>
  );
}
