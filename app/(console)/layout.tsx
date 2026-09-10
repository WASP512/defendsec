import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { isAdminSession } from "@/lib/auth";

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  if (!(await isAdminSession())) {
    redirect("/login");
  }
  return <AppShell>{children}</AppShell>;
}
