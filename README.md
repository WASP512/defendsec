# Keel

Self-hosted host inventory. Enroll machines with a Python agent, see them in a console, and run a handful of snapshot policies. There are no accounts, premium flags, or subscriptions.

This is **not** a FleetDM replacement. Fleet’s hard parts are live osquery at scale and vendor MDM (Apple Business Manager, Windows MDM, Android Enterprise). Keel is the first layer you can actually own without those contracts: enroll, heartbeat, inventory, report.

The in-app [Scope](/scope) page spells out what is easy, what is ordinary product work, and where MDM becomes the wall.

## Run the console

```bash
npm install
npm run dev
```

Open [http://127.0.0.1:47261](http://127.0.0.1:47261). The first visit loads a sample fleet so the UI is populated. Remove those hosts anytime, then enroll real machines.

Production:

```bash
npm run build
npm start
```

Host state is a JSON file at `data/keel.json`. Back it up with the rest of the server.

## Enroll a host

On a machine that can reach the server:

```bash
python3 agent/keel-agent.py --server http://YOUR_SERVER:47261 --enroll-secret SECRET
```

Copy the exact command from **Enroll**. The agent uses the Python 3 standard library only. It stores a node key beside the script and checks in every 30 seconds.

```bash
python3 agent/keel-agent.py --server http://127.0.0.1:47261 --enroll-secret SECRET --once
```

## What you get

- Host list with online/offline (two-minute window)
- Hardware, user, addresses, software snapshot
- Policies: agent checking in, disk encryption, firewall, supported OS
- Enroll secret rotate

## What you do not get

- Lock, wipe, DEP, configuration profiles, Windows CSP
- Live osquery, packs, or differential query results
- CVE feeds, CIS benchmarks, or automatic remediation
- Multi-tenant SSO / teams (you can add those; they are not the expensive part)

If you need stolen-device wipe, keep a real MDM next to this inventory plane rather than trying to clone all of Fleet.
