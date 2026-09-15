import { redirect } from "next/navigation";

import { AccountsPanel } from "@/components/accounts-panel";
import { PageHeader } from "@/components/console-ui";
import { CryptoPostureCard } from "@/components/crypto-posture-card";
import {
  currentActorIdentity,
  currentUser,
  isAdminSession,
  isReadOnlySession,
} from "@/lib/auth";
import {
  apidCryptoPosture,
  apidListUsers,
  getIdentityErrorMessage,
} from "@/lib/identity-server";

export const dynamic = "force-dynamic";

export default async function AccountsPage() {
  if (await isReadOnlySession()) {
    redirect("/");
  }
  if (!(await isAdminSession())) {
    redirect("/");
  }

  const me = await currentUser();
  const actorIdentity = await currentActorIdentity();
  const { users, error } = await apidListUsers();
  const posture = await apidCryptoPosture();

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <PageHeader
        title="Accounts"
        description={
          <>
            Operator accounts. Every signed command and audit entry records the
            account that authorised it, so responses can be traced to a person
            rather than a shared token.
          </>
        }
      />
      <AccountsPanel
        users={users}
        currentUserId={me?.id ?? null}
        currentUsername={me?.username ?? null}
        actorIdentity={actorIdentity}
        totpEnabled={me?.totpEnabled ?? false}
        loadError={error ? getIdentityErrorMessage(error) : null}
      />
      <CryptoPostureCard posture={posture} />
    </div>
  );
}
