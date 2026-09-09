# Keel

Self-hosted **security inventory** for machines you enroll. No accounts, premium flags, or subscriptions.

The agent reports versions, pending patches, and hashes of a small file set. The console matches software against a local advisory catalog, tracks integrity drift, and runs snapshot policies. This is not FleetDM and it is not MDM.

The in-app [Scope](/scope) page maps what is easy, what is ordinary (OSV/NVD ingest, patch orchestration), and where vendor MDM becomes the wall.

## Run the console

```bash
npm install
npm run dev
```

Open [http://127.0.0.1:47261](http://127.0.0.1:47261). The first visit loads a sample fleet with advisories, patches, and integrity events. Remove those hosts anytime, then enroll real machines.

Production:

```bash
npm run build
npm start
```

Host state is `data/keel.json`. Back it up with the rest of the server.

## Enroll a host

```bash
python3 agent/keel-agent.py --server http://YOUR_SERVER:47261 --enroll-secret SECRET
```

Copy the exact command from **Enroll**. Python 3 standard library only. The agent stores a node key beside the script and checks in every 30 seconds.

Optional extra integrity paths (OS path separator):

```bash
KEEL_FIM_PATHS=/etc/hostname python3 agent/keel-agent.py --server URL --enroll-secret SECRET --once
```

## What you get

- Host list with online/offline (two-minute window)
- Software version records across hosts
- Pending patches (`apt list --upgradable` on Debian/Ubuntu)
- Advisory matches from `lib/advisories.ts` with acknowledge / reopen
- File integrity on `/etc/passwd`, `/etc/hosts`, `sshd_config`, and similar
- Policies: check-in, encryption, firewall, supported OS, high/critical advisories, patches, FIM

## What you do not get

- Live NVD/OSV synchronization (the catalog is local on purpose)
- Remote patch install / reboot orchestration
- Lock, wipe, DEP, configuration profiles, Windows CSP
- Enterprise FIM (inotify, signed baselines, noisy-path tuning)

If you need stolen-device wipe, keep a real MDM next to this plane.
