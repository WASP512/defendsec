"use client";

import { useRouter } from "next/navigation";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";

/**
 * The provenance drawer. Its open state lives in the URL (?advisory=...), so a
 * view can be shared and the page behind it stays server-rendered; closing it
 * navigates to the same page without the parameter. The content is rendered on
 * the server and passed in.
 */
export function ExposureDrawer({
  title,
  description,
  closeHref,
  children,
}: {
  title: string;
  description: string;
  closeHref: string;
  children: React.ReactNode;
}) {
  const router = useRouter();
  return (
    <Sheet open onOpenChange={(open) => (open ? undefined : router.push(closeHref))}>
      <SheetContent
        side="right"
        data-exposure-drawer
        className="w-full overflow-y-auto data-[side=right]:sm:max-w-2xl"
      >
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription>{description}</SheetDescription>
        </SheetHeader>
        <div className="space-y-5 px-4 pb-6">{children}</div>
      </SheetContent>
    </Sheet>
  );
}
