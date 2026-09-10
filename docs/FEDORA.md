# Fedora workstation hands-on

DefendSec on a Fedora laptop/desktop for local testing. This is the path we expect you to follow.

## What you need

```bash
sudo dnf install -y golang nodejs npm docker docker-compose-plugin \
  postgresql postgresql-server iptables-nft firewalld jq make git
# Optional: Python agent / OSV ingest
sudo dnf install -y python3 python3-pip
```

Postgres can be Docker (easiest) or system `postgresql-server`.

## One-box lab (console + apid + agent on the same Fedora host)

```bash
git clone <your-repo-url> defendsec && cd defendsec
docker compose up -d postgres
export DATABASE_URL=postgres://defendsec:defendsec@127.0.0.1:5432/defendsec?sslmode=disable
export DEFENDSEC_DATABASE_URL="$DATABASE_URL"

npm install
npm run dev          # console → http://127.0.0.1:47261

# other terminal
make apid agent
./bin/defendsec-apid --data-dir data --db-url "$DEFENDSEC_DATABASE_URL" --tls-hostname "$(hostname -f),$(hostname -I | awk '{print $1}')"

# other terminal — enroll this workstation
export DEFENDSEC_ENROLL_SECRET="$(jq -r .enrollSecret data/defendsec.json)"
./bin/defendsec-agentd \
  --server-http https://127.0.0.1:47262 \
  --server-grpc 127.0.0.1:47263 \
  --tls-server-name localhost \
  --enroll-secret "$DEFENDSEC_ENROLL_SECRET" \
  --state-dir data/agent-mtls
```

Sign in with `data/admin-token.txt` (dev default `defendsec-local-admin` when `DEFENDSEC_ADMIN_TOKEN` is unset).

If enroll TLS fails, wipe `data/pki` once and restart apid so the hostname/IP SAN is baked into a fresh cert, or set `--tls-server-name` to a name that already appears in the cert.

## Fedora-specific behavior

| Area | Expectation |
| --- | --- |
| Packages | Agent uses `rpm` / `dnf check-update` (exit 100 = updates available) |
| Firewall inventory | `firewall-cmd --state` (firewalld) |
| FIM | `/etc/passwd`, `/etc/group`, `/etc/hosts`, `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/*.conf`, `/etc/sudoers`, `/etc/crypto-policies/config` |
| SCA SSH | Reads `/etc/ssh/sshd_config` **and** `/etc/ssh/sshd_config.d/*.conf`. Missing sshd config is skipped (no openssh-server). Obsolete `Protocol 2` check is not used. |
| SCA host | Firewall + disk encryption inventory fields, crypto-policies config, PasswordAuthentication / PermitRootLogin (shared sshd paths). |
| Live `crontab` | Also reads `/var/spool/cron` (Fedora/RHEL layout) |
| Isolate net | Needs root + `DEFENDSEC_ISOLATE_NET=1` + `iptables-nft`. firewalld can coexist awkwardly; prefer flag-only isolate for casual testing. |

## systemd (optional)

```bash
sudo useradd -r -s /sbin/nologin defendsec || true
sudo mkdir -p /etc/defendsec /var/lib/defendsec /var/lib/defendsec-agent
sudo cp bin/defendsec-apid bin/defendsec-agentd /usr/local/bin/
sudo cp packaging/systemd/apid.env.example /etc/defendsec/apid.env
sudo cp packaging/systemd/agentd.env.example /etc/defendsec/agentd.env
# put enroll secret on disk (mode 0600)
jq -r .enrollSecret data/defendsec.json | sudo tee /etc/defendsec/enroll-secret >/dev/null
sudo chmod 600 /etc/defendsec/enroll-secret
# edit TLS hostname / DB URL in the env files
sudo cp packaging/systemd/defendsec-apid.service packaging/systemd/defendsec-agentd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now defendsec-apid defendsec-agentd
```

If the agent is on another host, set `DEFENDSEC_SERVER_HTTP`, `DEFENDSEC_SERVER_GRPC`, and `DEFENDSEC_TLS_SERVER_NAME` in `agentd.env` to the control plane address, and pass `--tls-hostname <that-name-or-ip>` when creating the apid cert (or wipe `data/pki` / `/var/lib/defendsec/pki` once so SANs regenerate).

## Suggested smoke checklist

1. Host appears online on **Devices** with OS name/version from `/etc/os-release` (e.g. Fedora 41), not `Linux` / `go1.x`.
2. **Patches** shows `dnf` pending updates (or empty with status ok).
3. **Alerts** — touch a watched file as root (`sudo touch /etc/hosts`) and confirm FIM drift.
4. Host **Signed response** → live query `processes`, `listening_ports`, `os_info`, `systemd_units`.
5. Save a query; re-run from Saved queries.
6. Isolate without `DEFENDSEC_ISOLATE_NET` → flag only; Release clears it.
7. Viewer token: set `DEFENDSEC_VIEWER_TOKEN` on apid + console; confirm commands return 403.

## SELinux note

Binaries under `/usr/local/bin` usually run fine. If the agent cannot read enroll secret or write state under `/var/lib/defendsec-agent`, check `ausearch -m AVC -ts recent` and adjust contexts or keep the lab under your home directory with `make`/`./bin` instead of systemd.
