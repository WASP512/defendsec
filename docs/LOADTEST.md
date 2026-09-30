# Load test: 10,000 hosts (roadmap 5.5)

`cmd/defendsec-loadtest` drives a real `defendsec-apid` with simulated agents.
Each one generates its own key, enrolls over HTTPS, holds its own mTLS gRPC
connection, reports an inventory of 80 packages (the agent's cap), and then
heartbeats every 20 seconds (the agent's default). While that runs, it calls
the fleet API the console uses every 10 seconds: the first page, a search, a
platform-and-status filter, the summary, and a walk of the entire fleet 500 at
a time.

## Result

One machine: 4 vCPU, 15 GB RAM, PostgreSQL 16 on the same host, the load
generator on the same host too (so it competes with apid for CPU). Fresh
database, 10,000 agents, 5 minutes of steady state after enrollment.

| Operation | Count | Errors | p50 | p95 | p99 | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| enroll | 10,000 | 0 | 90 ms | 128 ms | 153 ms | 184 ms |
| inventory report | 10,000 | 0 | 62 ms | 536 ms | 715 ms | 776 ms |
| heartbeat | 139,988 | 0 | 1.6 ms | 3.4 ms | 9.7 ms | 131 ms |
| API: first page of 50 | 29 | 0 | 11 ms | 17 ms | 22 ms | 22 ms |
| API: search | 29 | 0 | 43 ms | 61 ms | 66 ms | 66 ms |
| API: platform + status filter | 29 | 0 | 1.6 ms | 6.2 ms | 9.6 ms | 9.6 ms |
| API: summary counts | 29 | 0 | 17 ms | 23 ms | 34 ms | 34 ms |
| API: walk all 10,000 (500/page) | 29 | 0 | 233 ms | 517 ms | 585 ms | 585 ms |

- All 10,000 enrolled in 14.6 s. Heartbeats ran at 467/s against 500/s nominal.
  The difference is the ramp: each agent sends its first heartbeat one interval
  after its inventory report, which lands at a random point in the first
  interval.
- apid's resident memory was 1.9 GB, most of it 10,000 TLS connections and the
  in-memory device state, including every host's software list.
- Restart: apid reloaded 10,000 devices from Postgres at start, and the final
  export on shutdown wrote all 10,000 to `defendsec-agents.json`.

## What the first run found

The first 10k run passed with zero errors and was not acceptable. **Inventory
reports took 68 seconds at the median** and heartbeats 7 seconds at p99:

1. **The alert list was prepended**, so every new alert copied all 5,000 held
   in memory. At fleet scale that copying and its garbage collection were most
   of apid's CPU. Alerts are now appended, and trimmed in batches.
2. **Every configuration check asked Postgres separately** whether its alert
   was open, and asked again to resolve it, which came to hundreds of
   thousands of queries through a 10-connection pool within a minute. Each
   report now loads the device's open alerts in one query and only queries
   when there is something to change.
3. **Every heartbeat rewrote the whole state file** (81 MB at 10,000 hosts),
   and rewrote every JSONB column of the device row. State is now held in
   memory with Postgres as the durable copy. The file is written as an export
   every 30 seconds, serialised outside the lock, and heartbeats update only
   liveness columns.
4. Smaller fixes: an id index for device lookups, and SCA packs cached for a
   minute instead of parsed on every report.

These were found with the CPU profile `DEFENDSEC_PPROF_ADDR=127.0.0.1:6060`
exposes (loopback only).

## Console pages

With the same 10,000 hosts, the console pages measured:

| Page | Before | After |
| --- | --- | --- |
| Hosts (`/devices`, paged by the control plane) | read the whole fleet file | 38 ms |
| Fleet overview (`/`) | 26 s, 42 MB of HTML | 6.7 s, 246 KB |
| Policies | 20 s | 3.8 s |
| Advisories | 3.3 s | 3.3 s |

**The overview, Policies and Advisories pages still compute over the whole
fleet**, by parsing the exported state file and matching advisories per host
in the console. That takes 3–7 seconds at 10,000 hosts. Moving those
aggregates into the control plane is the next step. Until then they are usable
at this size, but not fast.

## Reproduce

```bash
DEFENDSEC_PPROF_ADDR=127.0.0.1:6060 defendsec-apid -data-dir /tmp/lt \
  -enroll-secret S -admin-token T -db-url postgres://…/defendsec_load &
go run ./cmd/defendsec-loadtest -agents 10000 -duration 5m \
  -enroll-secret S -admin-token T -apid-pid $! -out result.json
```

The tool exits non-zero if any operation had an error. It trusts apid's CA on
first use, the way the agent does, so run it only against a test instance.
