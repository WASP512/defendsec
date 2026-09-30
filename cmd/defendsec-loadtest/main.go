// defendsec-loadtest drives a real defendsec-apid with simulated agents
// (roadmap 5.5): each one enrolls over HTTPS with its own key, holds its own
// mTLS gRPC connection, reports an inventory, and heartbeats on the agent's
// schedule. While that runs it pages through the fleet API the console uses.
//
// It measures the control plane, not the network: run it next to apid.
//
//	defendsec-loadtest -agents 10000 -duration 5m \
//	  -enroll-secret SECRET -admin-token TOKEN -apid-pid $(pidof defendsec-apid)
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	defendsecv1 "defendsec/internal/gen/defendsec/v1"
)

// buildCommit is stamped by the build like every other binary's.
var buildCommit = "unknown"

type opts struct {
	serverHTTP, serverGRPC, serverName, secret string
	adminURL, adminToken                       string
	agents, concurrency, software              int
	heartbeat, duration                        time.Duration
	apidPID                                    int
	out                                        string
}

type agent struct {
	id     string
	host   string
	conn   *grpc.ClientConn
	client defendsecv1.AgentControlClient
}

// recorder collects latencies per operation.
type recorder struct {
	mu     sync.Mutex
	lat    map[string][]time.Duration
	errs   map[string]int
	sample map[string]string
}

func newRecorder() *recorder {
	return &recorder{lat: map[string][]time.Duration{}, errs: map[string]int{}, sample: map[string]string{}}
}

func (r *recorder) add(op string, d time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.errs[op]++
		if r.sample[op] == "" {
			r.sample[op] = err.Error()
		}
		return
	}
	r.lat[op] = append(r.lat[op], d)
}

type opStats struct {
	Count  int     `json:"count"`
	Errors int     `json:"errors"`
	P50ms  float64 `json:"p50Ms"`
	P95ms  float64 `json:"p95Ms"`
	P99ms  float64 `json:"p99Ms"`
	MaxMs  float64 `json:"maxMs"`
	Sample string  `json:"firstError,omitempty"`
}

func (r *recorder) stats() map[string]opStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]opStats{}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	for op := range mergeKeys(r.lat, r.errs) {
		l := append([]time.Duration(nil), r.lat[op]...)
		sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
		s := opStats{Count: len(l), Errors: r.errs[op], Sample: r.sample[op]}
		if n := len(l); n > 0 {
			s.P50ms, s.P95ms, s.P99ms, s.MaxMs = ms(l[n*50/100]), ms(l[n*95/100]), ms(l[min(n-1, n*99/100)]), ms(l[n-1])
		}
		out[op] = s
	}
	return out
}

func mergeKeys(a map[string][]time.Duration, b map[string]int) map[string]bool {
	k := map[string]bool{}
	for x := range a {
		k[x] = true
	}
	for x := range b {
		k[x] = true
	}
	return k
}

func main() {
	var o opts
	flag.StringVar(&o.serverHTTP, "server-http", "https://127.0.0.1:47262", "apid HTTPS base")
	flag.StringVar(&o.serverGRPC, "server-grpc", "127.0.0.1:47263", "apid gRPC address")
	flag.StringVar(&o.serverName, "tls-server-name", "localhost", "server certificate name")
	flag.StringVar(&o.secret, "enroll-secret", os.Getenv("DEFENDSEC_ENROLL_SECRET"), "enroll secret")
	flag.StringVar(&o.adminURL, "admin-url", "http://127.0.0.1:47264", "apid admin API")
	flag.StringVar(&o.adminToken, "admin-token", os.Getenv("DEFENDSEC_ADMIN_TOKEN"), "admin token")
	flag.IntVar(&o.agents, "agents", 1000, "simulated agents")
	flag.IntVar(&o.concurrency, "concurrency", 64, "parallel enrollments")
	flag.IntVar(&o.software, "software", 80, "software items per inventory (the agent's cap)")
	flag.DurationVar(&o.heartbeat, "heartbeat", 20*time.Second, "heartbeat interval (the agent's default)")
	flag.DurationVar(&o.duration, "duration", 2*time.Minute, "steady-state duration after enrollment")
	flag.IntVar(&o.apidPID, "apid-pid", 0, "apid pid, to report its memory")
	flag.StringVar(&o.out, "out", "", "write the report as JSON here")
	version := flag.Bool("version", false, "print the build commit and exit")
	flag.Parse()
	if *version {
		fmt.Println(buildCommit)
		return
	}
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "loadtest:", err)
		os.Exit(1)
	}
}

func run(o opts) error {
	rec := newRecorder()
	ca, err := fetchCA(o.serverHTTP)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return fmt.Errorf("bad CA from server")
	}
	httpc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		MaxIdleConnsPerHost: o.concurrency,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: o.serverName},
	}}

	// Phase 1: enroll.
	fmt.Printf("enrolling %d agents (%d at a time)…\n", o.agents, o.concurrency)
	start := time.Now()
	agents := make([]*agent, o.agents)
	jobs := make(chan int)
	var wg sync.WaitGroup
	var enrolled atomic.Int64
	for w := 0; w < o.concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				t := time.Now()
				a, err := enroll(httpc, o, pool, i)
				rec.add("enroll", time.Since(t), err)
				if err == nil {
					agents[i] = a
					if n := enrolled.Add(1); n%1000 == 0 {
						fmt.Printf("  %d enrolled\n", n)
					}
				}
			}
		}()
	}
	for i := 0; i < o.agents; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	enrollTook := time.Since(start)
	live := agents[:0]
	for _, a := range agents {
		if a != nil {
			live = append(live, a)
		}
	}
	fmt.Printf("enrolled %d in %s\n", len(live), enrollTook.Round(time.Millisecond))
	defer func() {
		for _, a := range live {
			a.conn.Close()
		}
	}()

	// Phase 2: steady state. Each agent reports inventory once, at a random
	// point in its first interval, then heartbeats on the interval — the
	// load shape of a fleet that has been running, not of one booting.
	fmt.Printf("steady state for %s: heartbeat every %s…\n", o.duration, o.heartbeat)
	ctx, cancel := context.WithTimeout(context.Background(), o.duration)
	defer cancel()
	var hb atomic.Int64
	for _, a := range live {
		wg.Add(1)
		go func(a *agent) {
			defer wg.Done()
			offset := time.Duration(mrand.Int64N(int64(o.heartbeat)))
			select {
			case <-ctx.Done():
				return
			case <-time.After(offset):
			}
			t := time.Now()
			_, err := a.client.ReportInventory(ctx, inventory(a, o.software))
			if ctx.Err() == nil {
				rec.add("inventory", time.Since(t), err)
			}
			tick := time.NewTicker(o.heartbeat)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					t := time.Now()
					_, err := a.client.Heartbeat(ctx, &defendsecv1.HeartbeatRequest{
						Hostname: a.host, Platform: "linux", OsName: "LoadTest Linux", OsVersion: "1", Arch: "amd64",
						UptimeSeconds: int64(time.Since(start).Seconds()),
					})
					if ctx.Err() == nil {
						rec.add("heartbeat", time.Since(t), err)
						hb.Add(1)
					}
				}
			}
		}(a)
	}

	// The console's queries, while the fleet is live.
	admin := &http.Client{Timeout: 60 * time.Second}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			for op, path := range map[string]string{
				"api: first page (50)":        "/v1/devices?limit=50",
				"api: search":                 "/v1/devices?limit=50&q=lt-host-00042",
				"api: filter platform+status": "/v1/devices?limit=50&platform=linux&status=offline",
				"api: summary":                "/v1/devices/summary",
			} {
				t0 := time.Now()
				_, err := adminGET(admin, o, path)
				rec.add(op, time.Since(t0), err)
			}
			t0 := time.Now()
			n, err := walkFleet(admin, o)
			rec.add("api: walk whole fleet (500/page)", time.Since(t0), err)
			if err == nil && n < len(live) {
				rec.add("api: walk whole fleet (500/page)", 0, fmt.Errorf("walk saw %d devices, want at least %d", n, len(live)))
			}
		}
	}()
	wg.Wait()

	st := rec.stats()
	report := map[string]any{
		"agentsRequested": o.agents,
		"agentsEnrolled":  len(live),
		"enrollSeconds":   enrollTook.Seconds(),
		"heartbeatPerSec": float64(hb.Load()) / o.duration.Seconds(),
		"expectedPerSec":  float64(len(live)) / o.heartbeat.Seconds(),
		"operations":      st,
	}
	if o.apidPID > 0 {
		report["apidRssMb"] = rssMB(o.apidPID)
	}
	printReport(report, st)
	if o.out != "" {
		raw, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(o.out, raw, 0o644); err != nil {
			return err
		}
	}
	for op, s := range st {
		if s.Errors > 0 {
			return fmt.Errorf("%d errors in %q (first: %s)", s.Errors, op, s.Sample)
		}
	}
	return nil
}

func printReport(r map[string]any, st map[string]opStats) {
	fmt.Println()
	fmt.Printf("agents enrolled:   %v / %v in %.1fs\n", r["agentsEnrolled"], r["agentsRequested"], r["enrollSeconds"])
	fmt.Printf("heartbeats/s:      %.1f achieved, %.1f expected\n", r["heartbeatPerSec"], r["expectedPerSec"])
	if v, ok := r["apidRssMb"]; ok {
		fmt.Printf("apid RSS:          %v MB\n", v)
	}
	var ops []string
	for op := range st {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	fmt.Printf("\n%-36s %8s %6s %9s %9s %9s %9s\n", "operation", "count", "errors", "p50 ms", "p95 ms", "p99 ms", "max ms")
	for _, op := range ops {
		s := st[op]
		fmt.Printf("%-36s %8d %6d %9.1f %9.1f %9.1f %9.1f\n", op, s.Count, s.Errors, s.P50ms, s.P95ms, s.P99ms, s.MaxMs)
	}
}

func fetchCA(base string) ([]byte, error) {
	// Trust on first use, as the agent does. The load test runs beside apid.
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TOFU for a local test harness, as agentd does
	}}
	resp, err := c.Get(base + "/v1/ca")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<16))
}

func enroll(c *http.Client, o opts, pool *x509.CertPool, i int) (*agent, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	host := fmt.Sprintf("lt-host-%05d", i)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: host}}, key)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{
		"enrollSecret": o.secret, "hostname": host,
		"csrPem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
	})
	resp, err := c.Post(o.serverHTTP+"/v1/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll: %s %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var out struct {
		DeviceID string `json:"deviceId"`
		CertPEM  string `json:"certPem"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair([]byte(out.CertPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(o.serverGRPC, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: o.serverName, Certificates: []tls.Certificate{cert},
	})))
	if err != nil {
		return nil, err
	}
	return &agent{id: out.DeviceID, host: host, conn: conn, client: defendsecv1.NewAgentControlClient(conn)}, nil
}

func inventory(a *agent, n int) *defendsecv1.InventoryReport {
	r := &defendsecv1.InventoryReport{
		Host:   &defendsecv1.HeartbeatRequest{Hostname: a.host, Platform: "linux", OsName: "LoadTest Linux", OsVersion: "1", Arch: "amd64"},
		Serial: "LT" + a.id[:8], HardwareModel: "loadtest", Cpu: "virtual", MemoryMb: 8192,
		IpAddresses: []string{"10.0.0.1"}, Username: "root", PatchInventory: "ok",
	}
	for i := 0; i < n; i++ {
		r.Software = append(r.Software, &defendsecv1.SoftwareItem{Name: "pkg-" + strconv.Itoa(i), Version: "1.0." + strconv.Itoa(i)})
	}
	return r
}

func adminGET(c *http.Client, o opts, path string) ([]byte, error) {
	req, _ := http.NewRequest(http.MethodGet, o.adminURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+o.adminToken)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s %s", path, resp.Status, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func walkFleet(c *http.Client, o opts) (int, error) {
	cursor, n := "", 0
	for {
		raw, err := adminGET(c, o, "/v1/devices?limit=500&cursor="+url.QueryEscape(cursor))
		if err != nil {
			return n, err
		}
		var page struct {
			Devices []json.RawMessage `json:"devices"`
			Next    string            `json:"next"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return n, err
		}
		n += len(page.Devices)
		if page.Next == "" {
			return n, nil
		}
		cursor = page.Next
	}
}

func rssMB(pid int) float64 {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				kb, _ := strconv.ParseFloat(f[1], 64)
				return kb / 1024
			}
		}
	}
	return 0
}
