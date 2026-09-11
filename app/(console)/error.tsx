"use client";

import { EmptyState } from "@/components/console-ui";
import { Button } from "@/components/ui/button";
import { TriangleAlert } from "lucide-react";

export default function ConsoleError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const corrupt =
    error.name === "StoreCorruptError" || /defendsec\.json/i.test(error.message);

  return (
    <div className="mx-auto max-w-xl py-10">
      <EmptyState
        title={corrupt ? "Host database could not be read" : "Something went wrong"}
        description={
          corrupt
            ? "DefendSec will not overwrite a corrupt data/defendsec.json. Restore data/defendsec.json.bak over that file and reload."
            : error.message
        }
        icon={TriangleAlert}
        action={!corrupt ? <Button variant="outline" onClick={reset}>Try again</Button> : null}
      />
    </div>
  );
}
