# Ansible: DefendSec agents

`roles/defendsec_agent` installs and enrolls the agent on Linux, Windows (the
MSI) and macOS, and removes it with `defendsec_agent_state: absent`. It
drives the same installers the console's Enroll page shows, so a host
enrolled by Ansible is the same as one enrolled by hand.

- Downloads are verified. Pass the console's certificate as
  `defendsec_agent_console_ca` when it is self-signed; there is no option to
  skip verification.
- The enroll secret is never logged (`no_log`). Keep it in Ansible Vault.
- Re-running is a no-op on an enrolled host (Linux/macOS: the agent's
  device-id; Windows: the installed MSI).
- Windows needs the `ansible.windows` collection (`requirements.yml`).

See `playbooks/agents.yml` for a complete example. Variables and their
defaults are in `roles/defendsec_agent/defaults/main.yml`.
