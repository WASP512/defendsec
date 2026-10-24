package runner

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestConfigDefaults(t *testing.T) {
	c, err := ConfigFromEnv(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.CacheDir != "/var/lib/defendsec/feeds" || c.DataDir != "/var/lib/defendsec" {
		t.Errorf("dirs = %q %q", c.CacheDir, c.DataDir)
	}
	if !reflect.DeepEqual(c.Enabled, DefaultEnabled) || len(c.OSVEcosystems) != 0 {
		t.Errorf("enabled = %v osv = %v", c.Enabled, c.OSVEcosystems)
	}
	if !reflect.DeepEqual(c.DebianReleases, []string{"bookworm", "trixie"}) || c.FetchTimeout != 30*time.Minute {
		t.Errorf("debian = %v timeout = %v", c.DebianReleases, c.FetchTimeout)
	}
	specs, err := Select(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range specs {
		if s.Kind == KindOSV {
			t.Errorf("OSV feed %s enabled by default", s.Name)
		}
	}
}

func TestConfigFromEnv(t *testing.T) {
	c, err := ConfigFromEnv(env(map[string]string{
		"DEFENDSEC_FEEDS_CACHE_DIR":                 "/srv/feeds",
		"DEFENDSEC_FEEDS_ENABLED":                   " kev , ubuntu-jammy,,kev ",
		"DEFENDSEC_FEEDS_OSV_ECOSYSTEMS":            "PyPI,npm",
		"DEFENDSEC_FEEDS_MAX_BYTES":                 "12345",
		"DEFENDSEC_FEEDS_TIMEOUT":                   "45m",
		"DEFENDSEC_FEEDS_URL_UBUNTU_JAMMY":          "https://mirror.example/jammy.xml.bz2?token=abc",
		"DEFENDSEC_FEEDS_URL_OSV_PYPI":              "http://127.0.0.1:9/pypi.zip",
		"DEFENDSEC_FEEDS_TRUSTED_KEYS":              "/a.pem, /b.pem",
		"DEFENDSEC_FEEDS_DEBIAN_RELEASES":           "trixie",
		"DEFENDSEC_FEEDS_URL_SOMETHING_NONEXISTENT": "https://ignored.example/x",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.CacheDir != "/srv/feeds" || c.MaxBytes != 12345 || c.FetchTimeout != 45*time.Minute {
		t.Errorf("config = %+v", c)
	}
	if !reflect.DeepEqual(c.TrustedKeys, []string{"/a.pem", "/b.pem"}) {
		t.Errorf("trusted = %v", c.TrustedKeys)
	}
	specs, err := Select(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 || specs[0].Name != "ubuntu-jammy" || specs[1].Name != "kev" {
		t.Fatalf("specs = %+v (duplicates dropped; range feeds before KEV)", specs)
	}
	if specs[0].URL != "https://mirror.example/jammy.xml.bz2?token=abc" {
		t.Errorf("mirror override not applied: %q", specs[0].URL)
	}
	cat := map[string]Spec{}
	for _, s := range Catalog(c) {
		cat[s.Name] = s
	}
	if cat["osv-pypi"].URL != "http://127.0.0.1:9/pypi.zip" || cat["osv-pypi"].Ecosystem != "PyPI" || cat["osv-npm"].Ecosystem != "npm" {
		t.Errorf("osv specs = %+v %+v", cat["osv-pypi"], cat["osv-npm"])
	}
	if got := cat["debian"].Releases; len(got) != 1 || got["trixie"] != "13" {
		t.Errorf("debian releases = %v", got)
	}
}

func TestConfigErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"bad max":        {map[string]string{"DEFENDSEC_FEEDS_MAX_BYTES": "lots"}, "MAX_BYTES"},
		"zero max":       {map[string]string{"DEFENDSEC_FEEDS_MAX_BYTES": "0"}, "MAX_BYTES"},
		"bad timeout":    {map[string]string{"DEFENDSEC_FEEDS_TIMEOUT": "soon"}, "TIMEOUT"},
		"plain http url": {map[string]string{"DEFENDSEC_FEEDS_URL_KEV": "http://mirror.example/kev.json"}, "https"},
		"creds in url":   {map[string]string{"DEFENDSEC_FEEDS_URL_KEV": "https://u:p@mirror.example/kev.json"}, "credentials"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ConfigFromEnv(env(tc.env))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"unknown feed":    {map[string]string{"DEFENDSEC_FEEDS_ENABLED": "kev,nonsense"}, "unknown feed"},
		"bad osv eco":     {map[string]string{"DEFENDSEC_FEEDS_OSV_ECOSYSTEMS": "../etc"}, "not a valid ecosystem"},
		"bad debian":      {map[string]string{"DEFENDSEC_FEEDS_DEBIAN_RELEASES": "bookworm,woody"}, "unknown release"},
		"osv not enabled": {map[string]string{"DEFENDSEC_FEEDS_ENABLED": "osv-pypi"}, "unknown feed"},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := ConfigFromEnv(env(tc.env))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Select(c); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Select err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestScopes(t *testing.T) {
	c, _ := ConfigFromEnv(env(map[string]string{"DEFENDSEC_FEEDS_OSV_ECOSYSTEMS": "PyPI"}))
	got := map[string][]string{}
	for _, s := range Catalog(c) {
		for _, sc := range s.Scopes() {
			got[s.Name] = append(got[s.Name], sc.Distro+"/"+sc.Release+"/"+sc.Ecosystem)
		}
	}
	want := map[string][]string{
		"ubuntu-jammy":    {"ubuntu/22.04/"},
		"debian":          {"debian/12/", "debian/13/"},
		"rhel-9":          {"rhel/9/"},
		"suse-leap-16.0":  {"opensuse-leap/16.0/"},
		"suse-tumbleweed": {"opensuse-tumbleweed//"},
		"osv-pypi":        {"//PyPI"},
	}
	for name, w := range want {
		if !reflect.DeepEqual(got[name], w) {
			t.Errorf("%s scopes = %v, want %v", name, got[name], w)
		}
	}
	if len(got["kev"])+len(got["epss"]) != 0 {
		t.Error("KEV/EPSS must own no range scope")
	}
}

func TestOnly(t *testing.T) {
	c, _ := ConfigFromEnv(env(nil))
	specs, _ := Select(c)
	got, err := Only(specs, []string{"kev", "debian"})
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v err %v", got, err)
	}
	if got[0].Name != "debian" || got[1].Name != "kev" { // run order is kept
		t.Errorf("order = %s, %s", got[0].Name, got[1].Name)
	}
	if _, err := Only(specs, []string{"kev", "osv-pypi"}); err == nil {
		t.Error("--only with a feed that is not enabled accepted")
	}
	if all, _ := Only(specs, nil); len(all) != len(specs) {
		t.Error("no --only must keep everything")
	}
}

func TestLoadEnvFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "feeds.env")
	os.WriteFile(p, []byte(`# comment
DEFENDSEC_DATABASE_URL="postgres://u@h/db?sslmode=disable"
export DEFENDSEC_FEEDS_ENABLED=kev,epss
DEFENDSEC_FEEDS_CACHE_DIR='/srv/cache'

ALREADY_SET=from-file
EMPTY=
`), 0o600)
	set := map[string]string{}
	err := LoadEnvFile(p,
		func(k string) (string, bool) { v, ok := map[string]string{"ALREADY_SET": "from-env"}[k]; return v, ok },
		func(k, v string) error { set[k] = v; return nil })
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"DEFENDSEC_DATABASE_URL":    "postgres://u@h/db?sslmode=disable",
		"DEFENDSEC_FEEDS_ENABLED":   "kev,epss",
		"DEFENDSEC_FEEDS_CACHE_DIR": "/srv/cache",
		"EMPTY":                     "",
	}
	if !reflect.DeepEqual(set, want) {
		t.Errorf("set = %v, want %v (a variable already in the environment must win)", set, want)
	}
	if err := LoadEnvFile(filepath.Join(t.TempDir(), "absent"), nil, nil); !os.IsNotExist(err) {
		t.Errorf("absent file err = %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.env")
	os.WriteFile(bad, []byte("this is not an assignment\n"), 0o600)
	if err := LoadEnvFile(bad, func(string) (string, bool) { return "", false }, func(k, v string) error { return nil }); err == nil || !strings.Contains(err.Error(), "bad.env:1") {
		t.Errorf("malformed line err = %v", err)
	}
}
