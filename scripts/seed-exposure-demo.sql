-- Synthetic demo data for the exposure view (slice 5). SYNTHETIC: every host,
-- advisory and number below is invented. CVE-2099-* does not exist. Used to take
-- the screenshots in docs/screenshots/ and to look at the console without a
-- fleet; it proves rendering, not matching.
--
--   1. start defendsec-apid once against an empty database (it applies the
--      migrations), then stop it
--   2. run this file against that database
--   3. start defendsec-apid and the console against it
--
-- It empties the tables it fills, so it refuses to run unless the database
-- name contains "demo".

DO $$
BEGIN
  IF current_database() NOT LIKE '%demo%' THEN
    RAISE EXCEPTION 'refusing to seed %: the database name must contain "demo"', current_database();
  END IF;
END
$$;

TRUNCATE vuln_findings, vuln_finding_intervals, host_vuln_state, alerts, feed_status,
         advisory_ranges, advisories, feed_snapshots, audit_periods, devices,
         surface_finding_intervals, surface_findings, surface_observations, surface_scans, surface_assets CASCADE;

-- ---- feeds: one snapshot a day old, every feed confirmed current ---------------
INSERT INTO feed_snapshots (id, created_at, feeds)
OVERRIDING SYSTEM VALUE
VALUES (1, now() - interval '1 day 2 hours', jsonb_build_array(
  jsonb_build_object('name', 'ubuntu-jammy', 'url', 'https://example.invalid/demo/ubuntu-jammy', 'fetched_at', now() - interval '1 day 2 hours',
                     'sha256', encode(sha256('demo-ubuntu-jammy'::bytea), 'hex'), 'record_count', 4210),
  jsonb_build_object('name', 'rhel-9', 'url', 'https://example.invalid/demo/rhel-9', 'fetched_at', now() - interval '1 day 2 hours',
                     'sha256', encode(sha256('demo-rhel-9'::bytea), 'hex'), 'record_count', 1830),
  jsonb_build_object('name', 'rocky-9', 'url', 'https://example.invalid/demo/rocky-9', 'fetched_at', now() - interval '1 day 2 hours',
                     'sha256', encode(sha256('demo-rocky-9'::bytea), 'hex'), 'record_count', 960),
  jsonb_build_object('name', 'kev', 'url', 'https://example.invalid/demo/kev', 'fetched_at', now() - interval '1 day 2 hours',
                     'sha256', encode(sha256('demo-kev'::bytea), 'hex'), 'record_count', 1210),
  jsonb_build_object('name', 'epss', 'url', 'https://example.invalid/demo/epss', 'fetched_at', now() - interval '1 day 2 hours',
                     'sha256', encode(sha256('demo-epss'::bytea), 'hex'), 'record_count', 250000)));
-- A first snapshot 80 days ago, so the trend has history to draw.
INSERT INTO feed_snapshots (id, created_at, feeds)
OVERRIDING SYSTEM VALUE
VALUES (0, now() - interval '80 days', '[]'::jsonb);

INSERT INTO feed_status (name, kind, url, last_attempt_at, last_success_at, record_count, sha256, snapshot_id)
SELECT f->>'name', f->>'name', f->>'url', now() - interval '6 hours', now() - interval '6 hours',
       (f->>'record_count')::bigint, f->>'sha256', 1
FROM feed_snapshots s, jsonb_array_elements(s.feeds) f WHERE s.id = 1;

-- ---- hosts ---------------------------------------------------------------------
CREATE TEMP TABLE demo_hosts (id text, hostname text, platform text, os_name text, os_version text,
                              distro text, rel text, seen interval, coverage text);
INSERT INTO demo_hosts
SELECT 'demo-web-' || lpad(n::text, 2, '0'), 'demo-web-' || lpad(n::text, 2, '0'), 'linux', 'Ubuntu', '22.04', 'ubuntu', '22.04', interval '3 minutes', 'covered'
FROM generate_series(1, 8) n
UNION ALL
SELECT 'demo-app-' || lpad(n::text, 2, '0'), 'demo-app-' || lpad(n::text, 2, '0'), 'linux', 'Ubuntu', '22.04', 'ubuntu', '22.04', interval '9 minutes', 'covered'
FROM generate_series(1, 6) n
UNION ALL
SELECT 'demo-db-' || lpad(n::text, 2, '0'), 'demo-db-' || lpad(n::text, 2, '0'), 'linux', 'Ubuntu', '22.04', 'ubuntu', '22.04', interval '5 minutes', 'covered'
FROM generate_series(1, 2) n
UNION ALL
SELECT 'demo-rocky-' || lpad(n::text, 2, '0'), 'demo-rocky-' || lpad(n::text, 2, '0'), 'linux', 'Rocky Linux', '9.4', 'rocky', '9', interval '4 minutes', 'covered'
FROM generate_series(1, 3) n
UNION ALL VALUES
  ('demo-old-01', 'demo-old-01', 'linux', 'Debian GNU/Linux', '10', 'debian', '10', interval '6 minutes', 'no_feed'),
  ('demo-dc-01', 'demo-dc-01', 'windows', 'Windows Server 2016', '10.0.14393', '', '', interval '2 minutes', 'no_distro'),
  ('demo-laptop-07', 'demo-laptop-07', 'linux', 'Ubuntu', '22.04', 'ubuntu', '22.04', interval '11 days', 'covered'),
  ('demo-laptop-12', 'demo-laptop-12', 'linux', 'Ubuntu', '22.04', 'ubuntu', '22.04', interval '16 days', 'covered'),
  ('demo-laptop-15', 'demo-laptop-15', 'linux', 'Ubuntu', '22.04', 'ubuntu', '22.04', interval '23 days', 'covered');

INSERT INTO devices (id, hostname, platform, os_name, os_version, distro, distro_release, package_manager, last_seen, enrolled_at, software)
SELECT id, hostname, platform, os_name, os_version, distro, rel,
       CASE WHEN distro = 'rocky' THEN 'rpm' WHEN platform = 'windows' THEN '' ELSE 'dpkg' END,
       now() - seen, now() - interval '120 days', '[]'::jsonb
FROM demo_hosts;

INSERT INTO host_vuln_state (device_id, distro, release, coverage, packages, distro_mapped, snapshot_id, matched_at)
SELECT id, distro, rel, coverage, 480, 120, 1, now() - seen FROM demo_hosts;

-- ---- advisories: invented ids, with a spread of KEV / EPSS / CVSS -------------------
CREATE TEMP TABLE demo_adv (id text, sev text, kev boolean, kev_days int, epss numeric, cvss numeric,
                            pkg text, summary text, kind text, nhosts int, opened_days int, fixed_ver text);
INSERT INTO demo_adv VALUES
  ('CVE-2099-0101', 'critical', true,  40,  0.94, 9.8, 'demo-libssl',  'Heap overflow in a TLS library, remote code execution',      'finding', 8, 33, '3.0.2-0ubuntu1.19'),
  ('CVE-2099-0102', 'high',     true,  9,   0.71, 8.1, 'demo-httpd',   'Request smuggling in the web server',                        'finding', 5, 9,  '2.4.52-1ubuntu4.14'),
  ('CVE-2099-0103', 'high',     true,  400, 0.55, 7.8, 'demo-sudo',    'Local privilege escalation in sudo',                         'finding', 3, 61, '1.9.9-1ubuntu2.5'),
  ('CVE-2099-0104', 'medium',   false, 0,   0.62, 6.5, 'demo-curl',    'Cookie handling flaw in curl',                               'finding', 10, 14, '7.81.0-1ubuntu1.20'),
  ('CVE-2099-0105', 'critical', false, 0,   0.31, 9.1, 'demo-glib',    'Integer overflow in glib',                                   'finding', 4, 22, '2.72.4-0ubuntu2.6'),
  ('CVE-2099-0106', 'critical', false, 0,   0.04, 9.8, 'demo-xml',     'Use after free in an XML parser',                            'finding', 6, 27, '2.9.13+dfsg-1ubuntu0.8'),
  ('CVE-2099-0107', 'high',     false, 0,   NULL, 7.5, 'demo-tar',     'Path traversal in tar',                                      'finding', 2, 5,  '1.34+dfsg-1ubuntu0.1.22.04.3'),
  ('CVE-2099-0108', 'medium',   false, 0,   0.12, 5.3, 'demo-python',  'Denial of service in the HTTP client',                       'finding', 12, 41, '3.10.12-1~22.04.12'),
  ('CVE-2099-0109', 'low',      false, 0,   NULL, NULL,'demo-less',    'Minor information disclosure in a pager',                    'finding', 1, 3,  '590-1ubuntu0.22.04.4'),
  ('CVE-2099-0201', 'high',     true,  14,  0.88, 8.8, 'demo-vpn-gw',  'Authentication bypass in a VPN gateway, no vendor fix yet',  'unfixed', 1, 14, ''),
  ('CVE-2099-0202', 'high',     true,  20,  0.80, 7.8, 'kernel-core',  'Kernel privilege escalation, fixed by Red Hat, not yet by Rocky', 'awaiting_vendor', 3, 2, '0:5.14.0-687.60.1.el9_8'),
  ('CVE-2099-0203', 'medium',   false, 0,   0.07, 5.5, 'demo-lib2',    'Memory leak, upstream has not released a fix',               'unfixed', 6, 30, ''),
  ('CVE-2099-0204', 'medium',   false, 0,   NULL, 5.9, 'openssl',      'Timing side channel, fixed by Red Hat, not yet by Rocky',    'awaiting_vendor', 3, 2, '1:3.0.7-28.el9_8');

INSERT INTO advisories (id, cve, severity, summary, source, kev, kev_added, epss, epss_date, cvss_score, snapshot_id, package, below)
SELECT id, id, sev, summary, 'demo', kev, CASE WHEN kev THEN (current_date - kev_days) END, epss,
       CASE WHEN epss IS NOT NULL THEN current_date - 1 END, cvss, 1, '', ''
FROM demo_adv;

-- ---- open findings -------------------------------------------------------------------
-- Fixable and no-fix findings go on the Ubuntu hosts, awaiting_vendor on the Rocky
-- ones; the first n hosts of the right kind, offset by advisory so they differ.
INSERT INTO vuln_findings (device_id, advisory_id, family, snapshot_id, feed, feed_date, kind, basis, package, source_package,
                           installed, fixed, fix_state, cve, severity, summary, kev, epss, cvss_score, reason,
                           upstream_fixed_on, first_seen, last_seen)
SELECT h.id, a.id, a.pkg, 1,
       CASE WHEN h.distro = 'rocky' THEN 'rhel-9' ELSE 'ubuntu-jammy' END, now() - interval '1 day 2 hours',
       a.kind, 'distro', a.pkg, a.pkg, '1.0-demo', a.fixed_ver,
       CASE a.kind WHEN 'finding' THEN 'fixed' WHEN 'awaiting_vendor' THEN 'fixed' ELSE 'affected' END,
       a.id, a.sev, a.summary, a.kev, a.epss, a.cvss,
       CASE WHEN a.kind = 'awaiting_vendor' THEN 'fixed upstream by Red Hat in ' || a.fixed_ver || ' on 2026-10-22; not yet released by Rocky Linux' ELSE '' END,
       CASE WHEN a.kind = 'awaiting_vendor' THEN DATE '2026-10-22' END,
       now() - make_interval(days => a.opened_days, hours => (hashtext(h.id || a.id) & 7)),
       now() - interval '30 minutes'
FROM demo_adv a
JOIN LATERAL (
  SELECT id, distro, row_number() OVER (ORDER BY hashtext(id || a.id)) AS rn
  FROM demo_hosts
  WHERE ((a.kind = 'awaiting_vendor') = (distro = 'rocky')) AND (distro = 'rocky' OR (distro = 'ubuntu' AND seen < interval '1 hour'))
) h ON h.rn <= a.nhosts;

-- ---- findings that closed, with how they closed (trend + "resolved" list) --------------
CREATE TEMP TABLE demo_done (id text, sev text, kev boolean, epss numeric, cvss numeric, pkg text, summary text,
                             opened int, closed int, resolution text, n int);
INSERT INTO demo_done VALUES
  ('CVE-2099-0301', 'high',     true,  0.90, 8.8, 'demo-ssh',   'Pre-auth flaw in an SSH server',          70, 52, 'fixed',           7),
  ('CVE-2099-0302', 'critical', false, 0.35, 9.0, 'demo-zlib',  'Buffer overflow in a compression library', 55, 31, 'fixed',           9),
  ('CVE-2099-0303', 'medium',   false, 0.10, 5.0, 'demo-ftp',   'Flaw in an FTP daemon that was removed',   45, 20, 'package_removed', 3),
  ('CVE-2099-0304', 'high',     true,  0.62, 7.5, 'demo-dns',   'Resolver cache poisoning',                 38, 12, 'fixed',           5),
  ('CVE-2099-0305', 'medium',   false, 0.05, 6.1, 'demo-perl',  'Regular expression denial of service',     28, 6,  'fixed',           8);

INSERT INTO advisories (id, cve, severity, summary, source, kev, kev_added, epss, cvss_score, snapshot_id, package, below)
SELECT id, id, sev, summary, 'demo', kev, CASE WHEN kev THEN current_date - opened - 5 END, epss, cvss, 1, '', '' FROM demo_done;

INSERT INTO vuln_findings (device_id, advisory_id, family, snapshot_id, feed, feed_date, kind, basis, package, source_package,
                           installed, fixed, fix_state, cve, severity, summary, kev, epss, cvss_score, reason,
                           first_seen, last_seen, resolved_at, resolution, resolved_installed)
SELECT h.id, d.id, d.pkg, 1, 'ubuntu-jammy', now() - interval '20 days', 'finding', 'distro', d.pkg, d.pkg,
       '1.0-demo', '1.1-demo', 'fixed', d.id, d.sev, d.summary, d.kev, d.epss, d.cvss, '',
       now() - make_interval(days => d.opened, hours => (hashtext(h.id || d.id) & 7)),
       now() - make_interval(days => d.closed),
       now() - make_interval(days => d.closed, hours => (hashtext(h.id || d.id) & 3)),
       d.resolution,
       CASE d.resolution WHEN 'fixed' THEN '1.1-demo' ELSE '' END
FROM demo_done d
JOIN LATERAL (
  SELECT id, row_number() OVER (ORDER BY hashtext(id || d.id)) AS rn
  FROM demo_hosts WHERE distro = 'ubuntu' AND seen < interval '1 hour'
) h ON h.rn <= d.n;

-- ---- failed configuration checks (SCA alerts) -------------------------------------------
INSERT INTO alerts (id, device_id, hostname, kind, severity, title, summary, status, source_type, source_id)
SELECT 'demo-sca-' || n, 'demo-web-' || lpad(((n % 8) + 1)::text, 2, '0'), 'demo-web-' || lpad(((n % 8) + 1)::text, 2, '0'), 'sca',
       (ARRAY['high','high','medium','medium','medium','low','low','critical'])[(n % 8) + 1],
       'Check failed ' || n, 'Demo failed configuration check', 'open', 'sca', 'demo-check-' || n
FROM generate_series(0, 9) n;

-- ---- audit periods for the trend window selector ---------------------------------------------
INSERT INTO audit_periods (id, name, framework, starts_at, ends_at, notes, created_by)
VALUES ('demo-q3', '2026 Q3', 'cis-v8', '2026-07-01', '2026-09-30 23:59:59+00', 'demo', 'demo'),
       ('demo-q4', '2026 Q4', 'cis-v8', '2026-10-01', '2026-12-31 23:59:59+00', 'demo', 'demo');
UPDATE audit_periods SET closed_at = '2026-10-05', closed_by = 'demo' WHERE id = 'demo-q3';

-- ---- external surface (slice 7b) ------------------------------------------------------------
-- Invented assets on example.com / example.net and RFC 5737 addresses. The scans are plain rows
-- with no chained audit entry, so an evidence export of this database lists them as unattested
-- (see docs/SURFACE.md): rendering is what this proves, not scanning.
INSERT INTO surface_assets (id, kind, value, label, dkim_selectors, shared_hosting, mail_host, authorised, authorised_by, authorised_at,
                            created_by, created_at, last_scan_at, removed_at)
OVERRIDING SYSTEM VALUE VALUES
  (1, 'domain',   'demo-client.example.com',     'Client domain',       '{}', false, false, true,  'demo', now() - interval '80 days', 'demo', now() - interval '80 days', now() - interval '2 hours', NULL),
  (2, 'hostname', 'www.demo-client.example.com', 'Public web site',     '{}', false, false, true,  'demo', now() - interval '80 days', 'demo', now() - interval '80 days', now() - interval '2 hours', NULL),
  (3, 'ip',       '192.0.2.10',                  'Office firewall',     '{}', false, false, true,  'demo', now() - interval '80 days', 'demo', now() - interval '80 days', now() - interval '2 hours', NULL),
  (4, 'ip',       '198.51.100.7',                'Mail relay',          '{}', false, true,  true,  'demo', now() - interval '80 days', 'demo', now() - interval '80 days', now() - interval '2 hours', NULL),
  (5, 'domain',   'unconfirmed.example.net',     'Not yet confirmed',   '{}', false, false, false, '',     NULL,                         'demo', now() - interval '3 days',  NULL,                         NULL);
SELECT setval(pg_get_serial_sequence('surface_assets', 'id'), 5);

-- A first scan 80 days ago and the latest two hours ago, for each confirmed asset.
INSERT INTO surface_scans (id, asset_id, triggered_by, started_at, finished_at, checks_assessed, checks_not_assessed, findings_open, changes)
OVERRIDING SYSTEM VALUE VALUES
  (1, 1, 'manual',   now() - interval '80 days 6 seconds', now() - interval '80 days', 8, 1, 0, '[]'),
  (2, 2, 'manual',   now() - interval '80 days 4 seconds', now() - interval '80 days', 2, 0, 0, '[]'),
  (3, 3, 'manual',   now() - interval '80 days 3 seconds', now() - interval '80 days', 1, 0, 0, '[]'),
  (4, 4, 'manual',   now() - interval '80 days 3 seconds', now() - interval '80 days', 1, 0, 0, '[]'),
  (5, 1, 'schedule', now() - interval '2 hours 6 seconds', now() - interval '2 hours', 8, 1, 6, '[]'),
  (6, 2, 'schedule', now() - interval '2 hours 4 seconds', now() - interval '2 hours', 2, 0, 1, '[]'),
  (7, 3, 'schedule', now() - interval '2 hours 3 seconds', now() - interval '2 hours', 1, 0, 3, '[]'),
  (8, 4, 'schedule', now() - interval '2 hours 3 seconds', now() - interval '2 hours', 1, 0, 0, '[]');
SELECT setval(pg_get_serial_sequence('surface_scans', 'id'), 8);

-- The raw record behind each check of the latest scan; the drawer shows these.
INSERT INTO surface_observations (scan_id, asset_id, check_group, assessed, reason, observed, observed_at) VALUES
  (5, 1, 'spf',    true,  '', '{"host":"demo-client.example.com","record":"v=spf1 include:_spf.example.net -all","lookups":3}', now() - interval '2 hours'),
  (5, 1, 'dmarc',  true,  '', '{"host":"_dmarc.demo-client.example.com","record":"v=DMARC1; p=none; rua=mailto:dmarc@demo-client.example.com"}', now() - interval '2 hours'),
  (5, 1, 'dkim',   false, 'no selector found among 9 checked: declare your selector', '{"checked":["google","selector1","selector2","s1","s2","k1","default","dkim","mail"]}', now() - interval '2 hours'),
  (5, 1, 'caa',    true,  '', '{"host":"demo-client.example.com","records":[]}', now() - interval '2 hours'),
  (5, 1, 'mta-sts',true,  '', '{"host":"_mta-sts.demo-client.example.com","records":[]}', now() - interval '2 hours'),
  (5, 1, 'dnssec', true,  '', '{"ds":[],"validated":false}', now() - interval '2 hours'),
  (6, 2, 'tls-cert', true, '', '{"host":"www.demo-client.example.com","notAfter":"2026-10-28T09:12:00Z","daysLeft":4,"issuer":"Example Demo CA","sha256":"demo0f3c9a51"}', now() - interval '2 hours'),
  (7, 3, 'ports',  true,  '', '{"address":"192.0.2.10","checked":[21,22,23,25,445,1433,3306,3389,5432,5900,6379,8080,9200,27017],"open":[22,445,3389]}', now() - interval '2 hours'),
  (8, 4, 'ports',  true,  '', '{"address":"198.51.100.7","checked":[21,22,23,25,445,1433,3306,3389,5432,5900,6379,8080,9200,27017],"open":[25]}', now() - interval '2 hours');

-- Open findings. first_seen/last_seen/last_scan_id say what the drawer reports.
INSERT INTO surface_findings (asset_id, check_group, finding_id, subject, severity, title, detail, fix, evidence, controls,
                              first_seen, last_seen, first_scan_id, last_scan_id) VALUES
  (3, 'ports', 'ports.open', '445/tcp', 'critical', 'SMB (445/tcp) is reachable from the internet',
   'A TCP connection to 192.0.2.10 port 445 succeeded. SMB is meant for the local network; reachable here it is the entry point of most ransomware worms. Reachable means the service answered, not that it is vulnerable.',
   'Remove the port forward for 445/tcp on the firewall. If a remote user needs file access, use a VPN.',
   '{"port":445,"service":"smb","state":"open","address":"192.0.2.10"}', '{cis-v8:12.2,nist-800-53:SC-7}', now() - interval '12 days', now() - interval '2 hours', 3, 7),
  (3, 'ports', 'ports.open', '3389/tcp', 'high', 'RDP (3389/tcp) is reachable from the internet',
   'A TCP connection to 192.0.2.10 port 3389 succeeded. Remote Desktop exposed to the internet is a common way in. Reachable means the service answered, not that it is vulnerable.',
   'Remove the port forward for 3389/tcp, or put RDP behind a VPN or a gateway with multi-factor authentication.',
   '{"port":3389,"service":"rdp","state":"open","address":"192.0.2.10"}', '{cis-v8:12.2,nist-800-53:SC-7}', now() - interval '12 days', now() - interval '2 hours', 3, 7),
  (3, 'ports', 'ports.open', '22/tcp', 'info', 'SSH (22/tcp) is reachable',
   'Normal on a server; noted so it is a decision, not a surprise.', 'Allow SSH only from known addresses if you can.',
   '{"port":22,"service":"ssh","state":"open","address":"192.0.2.10"}', '{}', now() - interval '12 days', now() - interval '2 hours', 3, 7),
  (2, 'tls-cert', 'tls.expires_soon', 'www.demo-client.example.com', 'high', 'Certificate expires in 4 days',
   'The certificate presented by www.demo-client.example.com expires on 2026-10-28.', 'Renew the certificate now; check why automatic renewal did not run.',
   '{"notAfter":"2026-10-28T09:12:00Z","daysLeft":4,"issuer":"Example Demo CA","sha256":"demo0f3c9a51"}', '{cis-v8:3.10,nist-800-53:SC-8}', now() - interval '1 day', now() - interval '2 hours', 6, 6),
  (1, 'dmarc', 'dmarc.p_none', 'demo-client.example.com', 'medium', 'DMARC policy is p=none',
   'The DMARC record asks receivers to monitor, not to reject, mail that fails authentication, so spoofed mail from your domain is still delivered.',
   'Move to p=quarantine, then p=reject, once the reports at the rua address show your real mail passing.',
   '{"record":"v=DMARC1; p=none; rua=mailto:dmarc@demo-client.example.com","host":"_dmarc.demo-client.example.com"}', '{cis-v8:9.5,nist-800-53:SI-8}', now() - interval '20 days', now() - interval '2 hours', 5, 5),
  (1, 'caa', 'caa.missing', 'demo-client.example.com', 'low', 'No CAA record',
   'Without a CAA record any certificate authority may issue for the domain.', 'Publish a CAA record naming the authorities you use.',
   '{"host":"demo-client.example.com","records":[]}', '{cis-v8:3.10}', now() - interval '80 days', now() - interval '2 hours', 1, 5),
  (1, 'mta-sts', 'mtasts.missing', 'demo-client.example.com', 'low', 'No MTA-STS policy',
   'Senders cannot be told to insist on encrypted delivery to your mail servers.', 'Publish an MTA-STS policy, starting in testing mode.',
   '{"host":"_mta-sts.demo-client.example.com","records":[]}', '{cis-v8:9.5}', now() - interval '80 days', now() - interval '2 hours', 1, 5),
  (1, 'dnssec', 'dnssec.unsigned', 'demo-client.example.com', 'info', 'The zone is not signed with DNSSEC',
   'Common for small businesses; noted for completeness.', 'Enable DNSSEC at the registrar and DNS host if both support it.',
   '{"ds":[],"validated":false}', '{}', now() - interval '80 days', now() - interval '2 hours', 1, 5);

-- Findings that closed: someone fixed SPF and set up DMARC, and an exposed port on the mail relay was shut.
INSERT INTO surface_findings (asset_id, check_group, finding_id, subject, severity, title, detail, fix, evidence, controls,
                              first_seen, last_seen, resolved_at, first_scan_id, last_scan_id) VALUES
  (1, 'spf', 'spf.missing', 'demo-client.example.com', 'high', 'No SPF record', 'Anyone can send mail claiming to be your domain.', 'Publish an SPF record.',
   '{"host":"demo-client.example.com","records":[]}', '{cis-v8:9.5}', now() - interval '80 days', now() - interval '41 days', now() - interval '40 days', 1, 5),
  (1, 'dmarc', 'dmarc.missing', 'demo-client.example.com', 'high', 'No DMARC record', 'Receivers cannot tell what to do with mail that fails authentication.', 'Publish a DMARC record.',
   '{"host":"_dmarc.demo-client.example.com","records":[]}', '{cis-v8:9.5}', now() - interval '80 days', now() - interval '61 days', now() - interval '60 days', 1, 5),
  (4, 'ports', 'ports.open', '3389/tcp', 'high', 'RDP (3389/tcp) is reachable from the internet', 'A TCP connection succeeded.', 'Remove the port forward.',
   '{"port":3389,"service":"rdp","state":"open","address":"198.51.100.7"}', '{cis-v8:12.2}', now() - interval '80 days', now() - interval '9 days', now() - interval '8 days', 4, 8),
  (4, 'ports', 'ports.open', '445/tcp', 'critical', 'SMB (445/tcp) is reachable from the internet', 'A TCP connection succeeded.', 'Remove the port forward.',
   '{"port":445,"service":"smb","state":"open","address":"198.51.100.7"}', '{cis-v8:12.2}', now() - interval '80 days', now() - interval '33 days', now() - interval '32 days', 4, 8);

-- DMARC p=none was closed for ten days (someone tried p=quarantine) and came back: the interval that
-- ended is kept, and first_seen above restarted when it reopened.
INSERT INTO surface_finding_intervals (asset_id, finding_id, subject, severity, opened_at, closed_at)
VALUES (1, 'dmarc.p_none', 'demo-client.example.com', 'medium', now() - interval '58 days', now() - interval '30 days');

-- ---- application end-of-life (slice 10) -----------------------------------------------------------
-- Software from a third-party repository whose upstream stopped supporting the release. Invented
-- hosts; the product calendar dates are the real ones from endoflife.date (PHP 8.0 ended 2023-11-26),
-- but no calendar is loaded here: rendering and ranking are what this proves. Two past security
-- support (urgent band, after KEV and the urgent surface findings) and one past active support only
-- (with the low CVSS-only findings, after every vulnerability that has an EPSS score).
CREATE TEMP TABLE demo_eol (product text, label text, cycle text, stage text, stage_from date, eol_from date, eoas_from date,
                            pkg text, installed text, origin text, repo text, upgrade text, hostpat text, nhosts int, opened int);
INSERT INTO demo_eol VALUES
  ('php',    'PHP',     '8.0', 'eol',  DATE '2023-11-26', DATE '2023-11-26', DATE '2022-11-26', 'php8.0-cli', '1:8.0.30-25+ubuntu22.04.1+deb.sury.org+1', 'LP-PPA-ondrej-php', 'https://ppa.launchpadcontent.net/ondrej/php/ubuntu', '8.4', 'demo-web-%', 3, 40),
  ('nodejs', 'Node.js', '16',  'eol',  DATE '2023-09-11', DATE '2023-09-11', DATE '2022-10-18', 'nodejs',     '16.20.2-1nodesource1',                    'NodeSource',        'https://deb.nodesource.com/node_16.x',                '22', 'demo-app-%', 2, 25),
  ('php',    'PHP',     '8.2', 'eoas', DATE '2024-12-31', DATE '2026-12-31', DATE '2024-12-31', 'php8.2-fpm',  '8.2.12-1+ubuntu22.04.1+deb.sury.org+1',   'LP-PPA-ondrej-php', 'https://ppa.launchpadcontent.net/ondrej/php/ubuntu', '8.4', 'demo-app-%', 2, 18);

INSERT INTO vuln_findings (device_id, advisory_id, family, snapshot_id, feed, feed_date, kind, basis, package, source_package,
                           installed, fixed, fix_state, cve, severity, summary, kev, epss, cvss_score, reason,
                           eol_product, eol_cycle, eol_stage, eol_date, origin, origin_repo, eol_detail, first_seen, last_seen)
SELECT h.id, 'EOL:' || e.product || ':' || e.cycle, e.product, 1, 'endoflife', now() - interval '1 day 2 hours', 'eol', 'lifecycle',
       e.pkg, e.product, e.installed, '',
       CASE e.stage WHEN 'eol' THEN 'end_of_life' ELSE 'end_of_active_support' END,
       '', CASE e.stage WHEN 'eol' THEN 'high' ELSE 'low' END,
       CASE e.stage WHEN 'eol' THEN e.label || ' ' || e.cycle || ' reached end of life on ' || e.eol_from
                    ELSE e.label || ' ' || e.cycle || ' left active support on ' || e.eoas_from END,
       false, NULL, NULL, 'installed from ' || e.origin || ', not the distribution',
       e.product, e.cycle, e.stage, e.stage_from, e.origin, e.repo,
       jsonb_build_object('product', e.product, 'productLabel', e.label, 'cycle', e.cycle, 'stage', e.stage,
                          'stageFrom', e.stage_from::text, 'eolFrom', e.eol_from::text, 'eoasFrom', e.eoas_from::text,
                          'packages', jsonb_build_array(e.pkg), 'origin', e.origin, 'originRepo', e.repo,
                          'upgradeTo', e.upgrade),
       now() - make_interval(days => e.opened), now() - interval '30 minutes'
FROM demo_eol e
JOIN LATERAL (
  SELECT id, row_number() OVER (ORDER BY hashtext(id || e.product || e.cycle)) AS rn
  FROM demo_hosts WHERE id LIKE e.hostpat AND seen < interval '1 hour'
) h ON h.rn <= e.nhosts;

UPDATE host_vuln_state SET eol_mapped = 4, eol_distro = 1, eol_unknown = 0
WHERE device_id IN (SELECT device_id FROM vuln_findings WHERE kind = 'eol');

-- ---- Supported OS for Windows, by edition and build (slice 10) ------------------------------------
-- The real endoflife.date rows (fetched 2026-10-24) for the four cycles below, and Windows hosts that
-- share builds: Server 2016 and Windows 10 LTSB 2016 are both build 14393 and get opposite answers.
INSERT INTO eol_releases (product, cycle, label, eoas_from, eol_from, eoes_from, is_lts, latest, snapshot_id) VALUES
  ('windows-server', '2019',          'Microsoft Windows Server', '2024-01-09', '2029-01-09', NULL,         true,  '10.0.17763', 1),
  ('windows-server', '2016',          'Microsoft Windows Server', '2022-01-11', '2027-01-12', '2030-01-12', true,  '10.0.14393', 1),
  ('windows',        '10-22h2',       'Microsoft Windows',        '2025-10-14', '2025-10-14', '2028-10-10', false, '10.0.19045', 1),
  ('windows',        '10-1607-e-lts', 'Microsoft Windows',        '2021-10-12', '2026-10-13', '2029-10-13', true,  '10.0.14393', 1)
ON CONFLICT (product, cycle) DO NOTHING;

UPDATE devices SET os_edition = 'ServerStandard' WHERE id = 'demo-dc-01';
INSERT INTO devices (id, hostname, platform, os_name, os_version, os_edition, distro, distro_release, package_manager, last_seen, enrolled_at, software)
VALUES
  ('demo-pc-02', 'demo-pc-02', 'windows', 'Microsoft Windows 10 Pro', '10.0.19045', 'Professional', '', '', '', now() - interval '6 minutes', now() - interval '120 days', '[]'::jsonb),
  ('demo-pc-03', 'demo-pc-03', 'windows', 'Microsoft Windows 10 Enterprise 2016 LTSB', '10.0.14393', 'EnterpriseS', '', '', '', now() - interval '8 minutes', now() - interval '120 days', '[]'::jsonb);
