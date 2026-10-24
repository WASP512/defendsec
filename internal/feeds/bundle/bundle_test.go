package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"defendsec/internal/feeds/fetch"
	"defendsec/internal/sign"
)

type member struct {
	hdr  tar.Header
	data []byte
}

func mkKey(t *testing.T) *sign.Key {
	t.Helper()
	k, err := sign.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func cacheFile(t *testing.T, dir, name, body string) Input {
	t.Helper()
	p := filepath.Join(dir, name+".data")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	return Input{Name: name, Kind: "test", Path: p, Meta: fetch.Meta{
		URL: "https://example.invalid/" + name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)),
		FetchedAt: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC),
	}}
}

// makeBundle writes a two-feed bundle and returns its path.
func makeBundle(t *testing.T, key *sign.Key) string {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "feeds.tar")
	err := Write(out, key, []Input{cacheFile(t, dir, "kev", `{"kev":true}`), cacheFile(t, dir, "ubuntu-jammy", "oval bytes")},
		time.Date(2026, 10, 23, 13, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func readMembers(t *testing.T, path string) []member {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	var out []member
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out = append(out, member{hdr: *h, data: b})
	}
}

func writeMembers(t *testing.T, ms []member) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mutated.tar")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	for _, m := range ms {
		h := m.hdr
		h.Size = int64(len(m.data))
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		tw.Write(m.data)
	}
	tw.Close()
	f.Close()
	return p
}

func find(ms []member, name string) int {
	for i, m := range ms {
		if m.hdr.Name == name {
			return i
		}
	}
	return -1
}

func read(t *testing.T, path string, keys ...ed25519.PublicKey) (*Verified, error) {
	t.Helper()
	return Read(path, keys, t.TempDir())
}

func TestRoundTrip(t *testing.T) {
	key := mkKey(t)
	path := makeBundle(t, key)
	v, err := read(t, path, key.Public)
	if err != nil {
		t.Fatal(err)
	}
	if v.SignerID != key.KeyID() || v.Manifest.KeyID != key.KeyID() {
		t.Errorf("signer %q manifest key %q, want %q", v.SignerID, v.Manifest.KeyID, key.KeyID())
	}
	if len(v.Manifest.Feeds) != 2 || v.Manifest.Feeds[0].Name != "kev" || v.Manifest.Feeds[1].Name != "ubuntu-jammy" {
		t.Fatalf("manifest feeds = %+v", v.Manifest.Feeds)
	}
	if got, _ := os.ReadFile(v.FilePaths["kev"]); string(got) != `{"kev":true}` {
		t.Errorf("staged kev = %q", got)
	}
	if got, _ := os.ReadFile(v.FilePaths["ubuntu-jammy"]); string(got) != "oval bytes" {
		t.Errorf("staged ubuntu = %q", got)
	}
	if !v.Manifest.Feeds[0].FetchedAt.Equal(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("fetched_at = %v", v.Manifest.Feeds[0].FetchedAt)
	}
	// Any one of several trusted keys is enough.
	if _, err := read(t, path, mkKey(t).Public, key.Public); err != nil {
		t.Errorf("second trusted key not tried: %v", err)
	}
}

func TestRejectsUntrustedSigner(t *testing.T) {
	key, other := mkKey(t), mkKey(t)
	path := makeBundle(t, key)
	_, err := read(t, path, other.Public)
	if err == nil || !strings.Contains(err.Error(), "does not verify against any trusted key") || !strings.Contains(err.Error(), key.KeyID()) {
		t.Fatalf("err = %v", err)
	}
	if _, err := read(t, path); err == nil || !strings.Contains(err.Error(), "no trusted public keys") {
		t.Errorf("no keys: err = %v", err)
	}
}

func TestAttackerResignsWithOwnKey(t *testing.T) {
	// Replace a feed, recompute SHA256SUMS and the manifest, sign with the
	// attacker's key, and put the attacker's key in signer.pub. The victim
	// trusts only the real key, so this must fail.
	key, attacker := mkKey(t), mkKey(t)
	forged := makeBundle(t, attacker)
	if _, err := read(t, forged, key.Public); err == nil {
		t.Fatal("bundle signed by an untrusted key was accepted")
	}
}

func TestTamperingIsDetected(t *testing.T) {
	key := mkKey(t)
	good := makeBundle(t, key)

	cases := map[string]struct {
		mutate func(ms []member) []member
		want   string
	}{
		"flipped byte in feed data": {func(ms []member) []member {
			ms[find(ms, "feeds/kev/data")].data[0] ^= 1
			return ms
		}, "does not match its signed digest"},
		"manifest edited": {func(ms []member) []member {
			i := find(ms, "manifest.json")
			ms[i].data = bytes.Replace(ms[i].data, []byte("2026-10-23T12:00:00Z"), []byte("2026-12-31T12:00:00Z"), 1)
			return ms
		}, "does not match its signed digest"},
		"sums edited, signature kept": {func(ms []member) []member {
			i := find(ms, "SHA256SUMS")
			ms[i].data = bytes.Replace(ms[i].data, []byte("a"), []byte("b"), 1)
			return ms
		}, "signature does not verify"},
		"unsigned extra feed": {func(ms []member) []member {
			return append(ms, member{hdr: tar.Header{Name: "feeds/extra/data", Typeflag: tar.TypeReg, Mode: 0o644}, data: []byte("x")})
		}, "not covered by SHA256SUMS"},
		"path traversal member": {func(ms []member) []member {
			return append(ms, member{hdr: tar.Header{Name: "../../etc/cron.d/x", Typeflag: tar.TypeReg, Mode: 0o644}, data: []byte("x")})
		}, "unexpected member"},
		"absolute path member": {func(ms []member) []member {
			return append(ms, member{hdr: tar.Header{Name: "/etc/passwd", Typeflag: tar.TypeReg, Mode: 0o644}, data: []byte("x")})
		}, "unexpected member"},
		"nested feed path": {func(ms []member) []member {
			return append(ms, member{hdr: tar.Header{Name: "feeds/a/b/data", Typeflag: tar.TypeReg, Mode: 0o644}, data: []byte("x")})
		}, "unexpected member"},
		"symlink member": {func(ms []member) []member {
			return append(ms, member{hdr: tar.Header{Name: "feeds/evil/data", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}})
		}, "not a regular file"},
		"duplicate member": {func(ms []member) []member {
			return append(ms, ms[find(ms, "feeds/kev/data")])
		}, "appears twice"},
		"missing signature": {func(ms []member) []member {
			i := find(ms, "SHA256SUMS.sig")
			return append(ms[:i], ms[i+1:]...)
		}, "missing SHA256SUMS.sig"},
		"missing feed data": {func(ms []member) []member {
			i := find(ms, "feeds/kev/data")
			return append(ms[:i], ms[i+1:]...)
		}, "does not contain it"},
		"garbage signature": {func(ms []member) []member {
			ms[find(ms, "SHA256SUMS.sig")].data = []byte("!!!not base64!!!")
			return ms
		}, "not base64"},
		"wrong-length signature": {func(ms []member) []member {
			ms[find(ms, "SHA256SUMS.sig")].data = []byte(base64.StdEncoding.EncodeToString([]byte("short")))
			return ms
		}, "signature does not verify"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeMembers(t, tc.mutate(readMembers(t, good)))
			stage := t.TempDir()
			_, err := Read(path, []ed25519.PublicKey{key.Public}, stage)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestSignedButUndescribedFeedIsRejected(t *testing.T) {
	// A signer who adds a file to SHA256SUMS but not to the manifest: the
	// signature is valid, the manifest disagrees.
	key := mkKey(t)
	ms := readMembers(t, makeBundle(t, key))
	extra := []byte("sneaky")
	sum := sha256.Sum256(extra)
	i := find(ms, "SHA256SUMS")
	ms[i].data = append(ms[i].data, []byte(hex.EncodeToString(sum[:])+"  feeds/sneaky/data\n")...)
	ms[find(ms, "SHA256SUMS.sig")].data = []byte(base64.StdEncoding.EncodeToString(key.SignBlob(Domain, ms[i].data)))
	ms = append(ms, member{hdr: tar.Header{Name: "feeds/sneaky/data", Typeflag: tar.TypeReg, Mode: 0o644}, data: extra})
	_, err := read(t, writeMembers(t, ms), key.Public)
	if err == nil || !strings.Contains(err.Error(), "not described by the manifest") {
		t.Fatalf("err = %v", err)
	}
}

func TestSignatureFromAnotherDomainIsRejected(t *testing.T) {
	key := mkKey(t)
	ms := readMembers(t, makeBundle(t, key))
	sums := ms[find(ms, "SHA256SUMS")].data
	ms[find(ms, "SHA256SUMS.sig")].data = []byte(base64.StdEncoding.EncodeToString(key.SignBlob("defendsec-cmd-v1", sums)))
	if _, err := read(t, writeMembers(t, ms), key.Public); err == nil {
		t.Fatal("signature made under another domain accepted")
	}
}

func TestTruncatedAndNonTar(t *testing.T) {
	key := mkKey(t)
	good := makeBundle(t, key)
	raw, _ := os.ReadFile(good)
	cut := filepath.Join(t.TempDir(), "cut.tar")
	os.WriteFile(cut, raw[:len(raw)/2], 0o600)
	if _, err := read(t, cut, key.Public); err == nil {
		t.Error("truncated archive accepted")
	}
	junk := filepath.Join(t.TempDir(), "junk")
	os.WriteFile(junk, []byte(strings.Repeat("not a tar archive ", 100)), 0o600)
	if _, err := read(t, junk, key.Public); err == nil {
		t.Error("non-tar accepted")
	}
	if _, err := read(t, filepath.Join(t.TempDir(), "absent"), key.Public); err == nil {
		t.Error("missing file accepted")
	}
}

func TestWriteRefusesModifiedCacheFile(t *testing.T) {
	key := mkKey(t)
	dir := t.TempDir()
	in := cacheFile(t, dir, "kev", "original")
	os.WriteFile(in.Path, []byte("tampered"), 0o600)
	err := Write(filepath.Join(dir, "out.tar"), key, []Input{in}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "does not match its recorded digest") {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "out.tar")); serr == nil {
		t.Error("a bundle was written anyway")
	}
	if err := Write(filepath.Join(dir, "o.tar"), key, nil, time.Now()); err == nil {
		t.Error("empty export accepted")
	}
	bad := cacheFile(t, dir, "ok", "x")
	bad.Name = "../bad"
	if err := Write(filepath.Join(dir, "o.tar"), key, []Input{bad}, time.Now()); err == nil {
		t.Error("bad feed name accepted")
	}
	a := cacheFile(t, dir, "dup", "x")
	if err := Write(filepath.Join(dir, "o.tar"), key, []Input{a, a}, time.Now()); err == nil {
		t.Error("duplicate feed accepted")
	}
}

func TestReadWritesOnlyInsideStageDir(t *testing.T) {
	key := mkKey(t)
	path := makeBundle(t, key)
	stage := t.TempDir()
	v, err := Read(path, []ed25519.PublicKey{key.Public}, stage)
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range v.FilePaths {
		if filepath.Dir(p) != stage {
			t.Errorf("%s staged at %s, outside %s", name, p, stage)
		}
		if strings.Contains(filepath.Base(p), name) {
			t.Errorf("staged file name %q is derived from archive content", filepath.Base(p))
		}
	}
}
