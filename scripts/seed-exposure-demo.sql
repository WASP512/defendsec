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
         advisory_ranges, advisories, feed_snapshots, audit_periods, devices CASCADE;

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
