import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { isAuthenticatedSession, isReadOnlySession } from "@/lib/auth";

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  if (!(await isAuthenticatedSession())) {
    redirect("/login");
  }
  const readOnly = await isReadOnlySession();
  return <AppShell readOnly={readOnly}>{children}</AppShell>;
}
