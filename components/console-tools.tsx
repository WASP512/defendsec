"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Moon, Search, Sun, type LucideIcon } from "lucide-react";
import { useTheme } from "next-themes";
import { Button } from "@/components/ui/button";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut,
} from "@/components/ui/command";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

export type ConsoleDestination = {
  href: string;
  label: string;
  group: string;
  icon: LucideIcon;
};

export function ConsoleTools({ destinations }: { destinations: ConsoleDestination[] }) {
  const router = useRouter();
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => setMounted(true), []);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key.toLowerCase() === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen((value) => !value);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  function navigate(href: string) {
    setOpen(false);
    router.push(href);
  }

  const groups = [...new Set(destinations.map((item) => item.group))];

  return (
    <>
      <Tooltip>
        <TooltipTrigger
          render={
            <Button
              variant="outline"
              size="sm"
              className="hidden gap-2 text-muted-foreground sm:flex"
              onClick={() => setOpen(true)}
            />
          }
        >
          <Search className="size-3.5" />
          <span>Jump to…</span>
          <kbd className="rounded border bg-muted px-1.5 py-0.5 font-mono text-[10px]">⌘K</kbd>
        </TooltipTrigger>
        <TooltipContent>Search console pages</TooltipContent>
      </Tooltip>

      <Tooltip>
        <TooltipTrigger
          render={
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="Toggle color theme"
              disabled={!mounted}
              onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
            />
          }
        >
          {mounted && resolvedTheme === "dark" ? <Sun /> : <Moon />}
        </TooltipTrigger>
        <TooltipContent>
          {mounted && resolvedTheme === "dark" ? "Use light theme" : "Use dark theme"}
        </TooltipContent>
      </Tooltip>

      <CommandDialog open={open} onOpenChange={setOpen} title="Navigate DefendSec">
        <CommandInput placeholder="Search pages…" autoFocus />
        <CommandList>
          <CommandEmpty>No matching page.</CommandEmpty>
          {groups.map((group) => (
            <CommandGroup key={group} heading={group}>
              {destinations
                .filter((item) => item.group === group)
                .map((item) => {
                  const Icon = item.icon;
                  return (
                    <CommandItem key={item.href} value={`${item.label} ${item.group}`} onSelect={() => navigate(item.href)}>
                      <Icon />
                      <span>{item.label}</span>
                      {item.href === "/" ? <CommandShortcut>Home</CommandShortcut> : null}
                    </CommandItem>
                  );
                })}
            </CommandGroup>
          ))}
        </CommandList>
      </CommandDialog>
    </>
  );
}
