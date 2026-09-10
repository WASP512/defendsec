"use client";

export default function ConsoleError({
  error,
}: {
  error: Error & { digest?: string };
}) {
  const corrupt = error.name === "StoreCorruptError" || /keel\.json/i.test(error.message);

  return (
    <div className="mx-auto max-w-xl space-y-3 py-10">
      <h1 className="text-2xl font-semibold tracking-tight">
        {corrupt ? "Host database could not be read" : "Something went wrong"}
      </h1>
      <p className="text-sm text-muted-foreground">
        {corrupt
          ? "Keel will not overwrite a corrupt data/keel.json. Restore data/keel.json.bak over that file and reload."
          : error.message}
      </p>
    </div>
  );
}
