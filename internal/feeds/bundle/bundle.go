// Package bundle writes and verifies signed feed bundles for air-gapped
// installs.
//
// A bundle is a tar archive:
//
//	manifest.json        what is inside (feed names, URLs, fetch times, digests)
//	feeds/<name>/data    each feed file exactly as published
//	SHA256SUMS           sha256 of manifest.json and every feeds/<name>/data
//	SHA256SUMS.sig       base64 Ed25519 signature over SHA256SUMS (domain "defendsec-feeds-v1")
//	signer.pub           the signer's public key, informational only
//
// The signature covers SHA256SUMS, and SHA256SUMS covers everything else, so
// one signature authenticates the whole archive. Read verifies the signature
// against keys the CALLER trusts. The signer.pub inside the archive is never
// used to decide trust: an attacker who can alter the archive can alter that
// file too.
//
// Read refuses anything that is not exactly the layout above (extra members,
// duplicates, links, odd paths, oversize members) and never writes outside the
// staging directory it is given.
package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"defendsec/internal/feeds/fetch"
	"defendsec/internal/sign"
)

// Domain separates bundle signatures from every other use of the control key.
const Domain = "defendsec-feeds-v1"

// Format is the manifest's format identifier.
const Format = "defendsec-feeds-bundle/1"

const (
	manifestName = "manifest.json"
	sumsName     = "SHA256SUMS"
	sigName      = "SHA256SUMS.sig"
	pubName      = "signer.pub"

	maxSmallMember = 1 << 20 // manifest, sums, signature, public key
	// MaxFeedBytes bounds one feed file inside a bundle.
	MaxFeedBytes = 4 << 30
	maxFeeds     = 256
)

// ManifestFeed describes one feed file in a bundle.
type ManifestFeed struct {
	Name      string    `json:"name"`
	Kind      string    `json:"kind,omitempty"`
	URL       string    `json:"url"`
	FetchedAt time.Time `json:"fetched_at"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
}

// Manifest is manifest.json.
type Manifest struct {
	Format    string         `json:"format"`
	CreatedAt time.Time      `json:"created_at"`
	KeyID     string         `json:"key_id"`
	Feeds     []ManifestFeed `json:"feeds"`
}

// Input is one feed file to put in a bundle.
type Input struct {
	Name string
	Kind string
	Path string
	Meta fetch.Meta
}

func memberName(feed string) string { return "feeds/" + feed + "/data" }

// Write builds a bundle at outPath signed with key. Each input's file is
// re-hashed and must match its recorded digest: a cache file that has changed
// since it was fetched is an error, not something to sign.
func Write(outPath string, key *sign.Key, inputs []Input, now time.Time) error {
	if len(inputs) == 0 {
		return errors.New("bundle: nothing to export")
	}
	if len(inputs) > maxFeeds {
		return fmt.Errorf("bundle: %d feeds exceeds the limit of %d", len(inputs), maxFeeds)
	}
	sorted := append([]Input(nil), inputs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	man := Manifest{Format: Format, CreatedAt: now.UTC(), KeyID: key.KeyID()}
	for i, in := range sorted {
		if !fetch.ValidName(in.Name) {
			return fmt.Errorf("bundle: invalid feed name %q", in.Name)
		}
		if i > 0 && sorted[i-1].Name == in.Name {
			return fmt.Errorf("bundle: feed %q listed twice", in.Name)
		}
		sum, size, err := fetch.FileSHA256(in.Path)
		if err != nil {
			return fmt.Errorf("bundle: %s: %w", in.Name, err)
		}
		if sum != in.Meta.SHA256 || size != in.Meta.Size {
			return fmt.Errorf("bundle: %s: cached file does not match its recorded digest (cache corrupted or modified); refetch it", in.Name)
		}
		man.Feeds = append(man.Feeds, ManifestFeed{
			Name: in.Name, Kind: in.Kind, URL: in.Meta.URL, FetchedAt: in.Meta.FetchedAt.UTC(), SHA256: sum, Size: size,
		})
	}
	manJSON, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	manSum := sha256.Sum256(manJSON)

	var sums bytes.Buffer
	lines := []string{hex.EncodeToString(manSum[:]) + "  " + manifestName}
	for _, f := range man.Feeds {
		lines = append(lines, f.SHA256+"  "+memberName(f.Name))
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i][66:] < lines[j][66:] })
	for _, l := range lines {
		sums.WriteString(l + "\n")
	}
	sig := base64.StdEncoding.EncodeToString(key.SignBlob(Domain, sums.Bytes())) + "\n"

	tmp, err := os.CreateTemp(filepath.Dir(outPath), ".bundle-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	tw := tar.NewWriter(tmp)
	put := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: now.UTC(), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := put(manifestName, manJSON); err != nil {
		return err
	}
	for _, in := range sorted {
		f, err := os.Open(in.Path)
		if err != nil {
			return err
		}
		err = tw.WriteHeader(&tar.Header{Name: memberName(in.Name), Mode: 0o644, Size: in.Meta.Size, ModTime: now.UTC(), Typeflag: tar.TypeReg})
		if err == nil {
			var n int64
			n, err = io.Copy(tw, f)
			if err == nil && n != in.Meta.Size {
				err = fmt.Errorf("bundle: %s changed while exporting", in.Name)
			}
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	for _, m := range []struct {
		name string
		data []byte
	}{{sumsName, sums.Bytes()}, {sigName, []byte(sig)}, {pubName, key.PublicPEM()}} {
		if err := put(m.name, m.data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpName, outPath); err != nil {
		return err
	}
	ok = true
	return nil
}

// Verified is a bundle whose signature and digests checked out. Its files are
// in StageDir; the caller owns (and should remove) that directory.
type Verified struct {
	Manifest  Manifest
	SignerID  string // key ID of the trusted key that verified the signature
	StageDir  string
	FilePaths map[string]string // feed name -> staged file
}

// Read verifies the bundle at path against trusted and stages its feed files in
// stageDir (which must exist and be empty, or be created by the caller with
// os.MkdirTemp). Nothing is staged under a name taken from the archive: files
// are written as stageDir/f<N> and mapped by feed name only after verification.
func Read(path string, trusted []ed25519.PublicKey, stageDir string) (*Verified, error) {
	if len(trusted) == 0 {
		return nil, errors.New("bundle: no trusted public keys configured (set DEFENDSEC_FEEDS_TRUSTED_KEYS, pass --trust-key, or have a control key in the data directory)")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tr := tar.NewReader(f)

	type member struct {
		sum    string
		size   int64
		staged string
	}
	members := map[string]member{}
	small := map[string][]byte{}
	n := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: not a readable tar archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("bundle: member %q is not a regular file", hdr.Name)
		}
		if !allowedMember(hdr.Name) {
			return nil, fmt.Errorf("bundle: unexpected member %q", hdr.Name)
		}
		if _, dup := members[hdr.Name]; dup {
			return nil, fmt.Errorf("bundle: member %q appears twice", hdr.Name)
		}
		if len(members) >= maxFeeds+5 {
			return nil, errors.New("bundle: too many members")
		}
		isFeed := strings.HasPrefix(hdr.Name, "feeds/")
		limit := int64(maxSmallMember)
		if isFeed {
			limit = MaxFeedBytes
		}
		if hdr.Size < 0 || hdr.Size > limit {
			return nil, fmt.Errorf("bundle: member %q is %d bytes, over the %d limit", hdr.Name, hdr.Size, limit)
		}
		h := sha256.New()
		var dst io.Writer = h
		var out *os.File
		staged := ""
		if isFeed {
			n++
			staged = filepath.Join(stageDir, fmt.Sprintf("f%d", n))
			out, err = os.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return nil, err
			}
			dst = io.MultiWriter(out, h)
		}
		var buf bytes.Buffer
		if !isFeed {
			dst = io.MultiWriter(&buf, h)
		}
		got, err := io.Copy(dst, io.LimitReader(tr, hdr.Size))
		if out != nil {
			if cerr := out.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: reading %q: %w", hdr.Name, err)
		}
		if got != hdr.Size {
			return nil, fmt.Errorf("bundle: member %q is truncated", hdr.Name)
		}
		members[hdr.Name] = member{sum: hex.EncodeToString(h.Sum(nil)), size: got, staged: staged}
		if !isFeed {
			small[hdr.Name] = buf.Bytes()
		}
	}
	for _, need := range []string{manifestName, sumsName, sigName} {
		if _, ok := members[need]; !ok {
			return nil, fmt.Errorf("bundle: missing %s", need)
		}
	}

	// 1. Signature over SHA256SUMS, by a key the caller trusts.
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(small[sigName])))
	if err != nil {
		return nil, fmt.Errorf("bundle: signature is not base64: %w", err)
	}
	signer := ""
	for _, pub := range trusted {
		if sign.VerifyBlob(pub, Domain, small[sumsName], sig) == nil {
			signer = sign.PublicKeyID(pub)
			break
		}
	}
	if signer == "" {
		claimed := ""
		if pub, err := sign.ParsePublicPEM(small[pubName]); err == nil {
			claimed = " (bundle says it was signed by key " + sign.PublicKeyID(pub) + ")"
		}
		return nil, fmt.Errorf("bundle: signature does not verify against any trusted key%s", claimed)
	}

	// 2. SHA256SUMS must list exactly manifest.json and the feed files, with
	//    matching digests.
	listed := map[string]string{}
	for _, line := range strings.Split(strings.TrimRight(string(small[sumsName]), "\n"), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 || name == "" {
			return nil, fmt.Errorf("bundle: malformed SHA256SUMS line %q", line)
		}
		if _, dup := listed[name]; dup {
			return nil, fmt.Errorf("bundle: SHA256SUMS lists %q twice", name)
		}
		listed[name] = sum
	}
	for name, m := range members {
		if name == sumsName || name == sigName || name == pubName {
			continue
		}
		want, ok := listed[name]
		if !ok {
			return nil, fmt.Errorf("bundle: %q is not covered by SHA256SUMS", name)
		}
		if want != m.sum {
			return nil, fmt.Errorf("bundle: %q does not match its signed digest", name)
		}
		delete(listed, name)
	}
	for name := range listed {
		return nil, fmt.Errorf("bundle: SHA256SUMS lists %q but the archive does not contain it", name)
	}

	// 3. Manifest agrees with the signed digests.
	var man Manifest
	if err := json.Unmarshal(small[manifestName], &man); err != nil {
		return nil, fmt.Errorf("bundle: manifest: %w", err)
	}
	if man.Format != Format {
		return nil, fmt.Errorf("bundle: format %q, want %q", man.Format, Format)
	}
	v := &Verified{Manifest: man, SignerID: signer, StageDir: stageDir, FilePaths: map[string]string{}}
	seen := map[string]bool{}
	for _, mf := range man.Feeds {
		if !fetch.ValidName(mf.Name) || seen[mf.Name] {
			return nil, fmt.Errorf("bundle: manifest feed name %q is invalid or repeated", mf.Name)
		}
		seen[mf.Name] = true
		m, ok := members[memberName(mf.Name)]
		if !ok {
			return nil, fmt.Errorf("bundle: manifest lists %q but the archive has no data for it", mf.Name)
		}
		if m.sum != mf.SHA256 || m.size != mf.Size {
			return nil, fmt.Errorf("bundle: manifest digest for %q disagrees with the signed file", mf.Name)
		}
		if mf.FetchedAt.IsZero() {
			return nil, fmt.Errorf("bundle: manifest feed %q has no fetched_at", mf.Name)
		}
		v.FilePaths[mf.Name] = m.staged
	}
	for name := range members {
		if strings.HasPrefix(name, "feeds/") && !seen[strings.TrimSuffix(strings.TrimPrefix(name, "feeds/"), "/data")] {
			return nil, fmt.Errorf("bundle: %q is signed but not described by the manifest", name)
		}
	}
	return v, nil
}

func allowedMember(name string) bool {
	switch name {
	case manifestName, sumsName, sigName, pubName:
		return true
	}
	rest, ok := strings.CutPrefix(name, "feeds/")
	if !ok {
		return false
	}
	feed, ok := strings.CutSuffix(rest, "/data")
	return ok && fetch.ValidName(feed)
}
