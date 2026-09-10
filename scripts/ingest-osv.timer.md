# Scheduling OSV ingest

Optional. Packaged installs do **not** enable this timer automatically.

Run `scripts/ingest-osv.py` on a schedule so advisories stay current. Requires
`DEFENDSEC_DATABASE_URL` (or `DATABASE_URL`) and `psycopg`.

## Cron

Daily at 03:15 UTC:

```cron
15 3 * * * cd /opt/defendsec && DEFENDSEC_DATABASE_URL=postgres://defendsec:defendsec@127.0.0.1:5432/defendsec /usr/bin/python3 scripts/ingest-osv.py >> /var/log/defendsec-osv-ingest.log 2>&1
```

Override packages for a one-off run:

```bash
python3 scripts/ingest-osv.py --packages openssl,openssh-server,git
```

## systemd timer

`/etc/systemd/system/defendsec-osv-ingest.service`:

```ini
[Unit]
Description=DefendSec OSV advisory ingest
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/defendsec
Environment=DEFENDSEC_DATABASE_URL=postgres://defendsec:defendsec@127.0.0.1:5432/defendsec
ExecStart=/usr/bin/python3 scripts/ingest-osv.py
User=defendsec
```

`/etc/systemd/system/defendsec-osv-ingest.timer`:

```ini
[Unit]
Description=Daily DefendSec OSV ingest

[Timer]
OnCalendar=*-*-* 03:15:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now defendsec-osv-ingest.timer
```

After a successful run, `meta.osv_last_ingest` is updated and shown on the
Advisories console page.
