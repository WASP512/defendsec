package anchor

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"defendsec/internal/auditchain"
)

func TestParseTargets(t *testing.T) {
	got, err := ParseTargets("rfc3161=https://freetsa.org/tsr, file=/var/lib/defendsec/anchors ,peer=https://peer.example/v1/anchors/receive#s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("parsed %d targets, want 3", len(got))
	}
	if got[0].Kind != KindTSA || got[0].Ref != "https://freetsa.org/tsr" {
		t.Errorf("tsa target = %+v", got[0])
	}
	if got[1].Kind != KindFile || got[1].Ref != "/var/lib/defendsec/anchors" {
		t.Errorf("file target = %+v", got[1])
	}
	if got[2].Kind != KindPeer || got[2].Token != "s3cret" ||
		got[2].Ref != "https://peer.example/v1/anchors/receive" {
		t.Errorf("peer target = %+v", got[2])
	}

	// A malformed entry must fail loudly. Skipping it would leave an operator
	// believing they have anchoring they do not have, so they stop looking.
	for _, bad := range []string{
		"nonsense",
		"unknownkind=https://x",
		"rfc3161=not-a-url",
		"peer=ftp://x",
		"file=",
	} {
		if _, err := ParseTargets(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}

	if got, err := ParseTargets("  "); err != nil || len(got) != 0 {
		t.Errorf("empty config = %v, %v", got, err)
	}
}

func TestFileAnchorRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cp := auditchain.Checkpoint{
		ThroughSeq: 42, EntryHash: strings.Repeat("ab", 32),
		At: time.Now().UTC(), SigningKeyID: "key-1",
	}
	p := NewPublisher([]Target{{Kind: KindFile, Ref: dir}}, "server-1")

	recs := p.Publish(context.Background(), cp)
	if len(recs) != 1 || !recs[0].OK() {
		t.Fatalf("publish failed: %+v", recs)
	}

	// Appending must not rewrite: a history that only ever grows is what makes
	// an alteration obvious to whoever reviews the repository.
	cp2 := cp
	cp2.ThroughSeq, cp2.EntryHash = 43, strings.Repeat("cd", 32)
	if recs2 := p.Publish(context.Background(), cp2); !recs2[0].OK() {
		t.Fatalf("second publish failed: %+v", recs2)
	}

	raw, err := os.ReadFile(recs[0].Reference)
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := ParseFileAnchors(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 2 {
		t.Fatalf("file holds %d anchors, want 2 — the first was overwritten", len(anchors))
	}
	if anchors[0].ThroughSeq != 42 || anchors[0].EntryHash != cp.EntryHash {
		t.Errorf("first anchor = %+v", anchors[0])
	}
	if anchors[0].Server != "server-1" || anchors[0].SigningKeyID != "key-1" {
		t.Errorf("anchor does not identify its instance: %+v", anchors[0])
	}

	// The file must live in the target directory and be named by month.
	if filepath.Dir(recs[0].Reference) != dir {
		t.Errorf("anchor written outside the target directory: %s", recs[0].Reference)
	}
}

// The comparison is the whole point: anchors that are written and never
// checked detect nothing.
func TestVerifyAgainstDetectsARebuiltChain(t *testing.T) {
	anchored := strings.Repeat("11", 32)
	rebuilt := strings.Repeat("22", 32)
	now := time.Now().UTC()

	records := []Record{
		{ThroughSeq: 10, EntryHash: anchored, Kind: KindTSA, AnchoredAt: now},
		{ThroughSeq: 20, EntryHash: anchored, Kind: KindFile, AnchoredAt: now},
		{ThroughSeq: 30, EntryHash: anchored, Kind: KindPeer, AnchoredAt: now},
		{ThroughSeq: 40, EntryHash: anchored, Kind: KindTSA, AnchoredAt: now, Error: "authority unreachable"},
	}
	current := map[int64]string{
		10: anchored, // intact
		20: rebuilt,  // rewritten after anchoring
		// 30 absent: anchored history has since been truncated
	}

	vs := VerifyAgainst(records, current)
	byseq := map[int64]Verification{}
	for _, v := range vs {
		byseq[v.Record.ThroughSeq] = v
	}

	if !byseq[10].Matches {
		t.Error("an intact anchor was reported as mismatched")
	}
	if byseq[20].Matches {
		t.Error("a rewritten chain passed the anchor comparison")
	}
	if !strings.Contains(byseq[20].Detail, "rebuilt") {
		t.Errorf("mismatch detail does not name the attack: %q", byseq[20].Detail)
	}
	// A valid signature over the rebuilt chain must not be presented as
	// clearing this — the attacker holds the signing key, which is exactly why
	// anchoring exists.
	if !strings.Contains(byseq[20].Detail, "does not clear this") {
		t.Errorf("mismatch detail leaves room to dismiss it: %q", byseq[20].Detail)
	}
	if byseq[30].Matches {
		t.Error("truncated history passed")
	}
	if !strings.Contains(byseq[30].Detail, "truncated") {
		t.Errorf("truncation detail = %q", byseq[30].Detail)
	}
	if byseq[40].Matches {
		t.Error("a failed anchor was treated as a match")
	}

	// Newest first: the recent history is what an operator checks.
	for i := 1; i < len(vs); i++ {
		if vs[i-1].Record.ThroughSeq < vs[i].Record.ThroughSeq {
			t.Fatal("verifications are not ordered newest first")
		}
	}
}

func TestSummarise(t *testing.T) {
	anchored := strings.Repeat("11", 32)

	// Nothing anchored must say what is still unprotected rather than reading
	// as a clean result.
	s := Summarise(nil)
	if !strings.Contains(s.Verdict, "not against anyone who also holds") {
		t.Errorf("empty verdict does not state the residual risk: %q", s.Verdict)
	}

	all := Summarise(VerifyAgainst(
		[]Record{{ThroughSeq: 1, EntryHash: anchored}},
		map[int64]string{1: anchored}))
	if all.Matching != 1 || all.Mismatched != 0 || !strings.Contains(all.Verdict, "still match") {
		t.Errorf("clean summary = %+v", all)
	}

	bad := Summarise(VerifyAgainst(
		[]Record{{ThroughSeq: 1, EntryHash: anchored}},
		map[int64]string{1: strings.Repeat("99", 32)}))
	if bad.Mismatched != 1 || !strings.Contains(bad.Verdict, "rebuilt ledger") {
		t.Errorf("mismatch summary = %+v", bad)
	}

	failed := Summarise(VerifyAgainst(
		[]Record{{ThroughSeq: 1, EntryHash: anchored, Error: "down"}}, nil))
	if failed.Failed != 1 || !strings.Contains(failed.Verdict, "protect nothing") {
		t.Errorf("all-failed summary = %+v", failed)
	}
}

// A failing target must not cost the anchors at the other targets.
func TestPublishContinuesPastAFailingTarget(t *testing.T) {
	dir := t.TempDir()
	p := NewPublisher([]Target{
		{Kind: KindTSA, Ref: "http://127.0.0.1:1/nope"},
		{Kind: KindFile, Ref: dir},
	}, "server-1")

	recs := p.Publish(context.Background(), auditchain.Checkpoint{
		ThroughSeq: 1, EntryHash: strings.Repeat("ab", 32), At: time.Now().UTC(),
	})
	if len(recs) != 2 {
		t.Fatalf("got %d records, want one per target", len(recs))
	}
	if recs[0].OK() {
		t.Error("the unreachable authority reported success")
	}
	if recs[0].Error == "" {
		t.Error("the failure was not recorded, so it would vanish from the history")
	}
	if !recs[1].OK() {
		t.Errorf("a working target was skipped because an earlier one failed: %s", recs[1].Error)
	}
}

func TestPublishToPeer(t *testing.T) {
	var gotAuth string
	var gotBody PeerAnchorRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = decodeInto(r, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"receipt-1","receivedAt":"2026-09-15T12:00:00Z"}`))
	}))
	defer srv.Close()

	cp := auditchain.Checkpoint{
		ThroughSeq: 7, EntryHash: strings.Repeat("ab", 32),
		At: time.Now().UTC(), SigningKeyID: "key-1", Signature: "sig",
	}
	p := NewPublisher([]Target{{Kind: KindPeer, Ref: srv.URL, Token: "shared"}}, "server-1")
	rec := p.Publish(context.Background(), cp)[0]

	if !rec.OK() {
		t.Fatalf("peer publish failed: %s", rec.Error)
	}
	if gotAuth != "Bearer shared" {
		t.Errorf("peer auth = %q", gotAuth)
	}
	// The checkpoint's own signature must travel, so the peer stores something
	// it can verify rather than a bare hash taken on faith.
	if gotBody.Signature != "sig" || gotBody.SigningKeyID != "key-1" {
		t.Errorf("the peer did not receive the checkpoint signature: %+v", gotBody)
	}
	if rec.Reference != "receipt-1" {
		t.Errorf("reference = %q", rec.Reference)
	}
	if rec.ExternalTime.IsZero() {
		t.Error("the peer's receive time was not recorded")
	}
}

func TestPublishToPeerRejectsBadResponses(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"error status": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		},
		"garbage receipt": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			p := NewPublisher([]Target{{Kind: KindPeer, Ref: srv.URL}}, "s")
			rec := p.Publish(context.Background(), auditchain.Checkpoint{
				ThroughSeq: 1, EntryHash: strings.Repeat("ab", 32), At: time.Now().UTC(),
			})[0]
			if rec.OK() {
				t.Error("a bad peer response was recorded as a successful anchor")
			}
		})
	}
}

// RFC 3161: the nonce and the imprint are what make a token ours rather than
// one replayed from an earlier response.
func TestTimestampResponseChecksImprintAndNonce(t *testing.T) {
	digest := sha256.Sum256([]byte("checkpoint"))
	nonce := big.NewInt(1234567890)

	good := fakeTimestampResponse(t, 0, digest[:], nonce)
	res, err := parseTimestampResponse(good, digest[:], nonce)
	if err != nil {
		t.Fatalf("a well-formed response failed: %v", err)
	}
	if res.Serial == "" || res.GenTime.IsZero() || len(res.Token) == 0 {
		t.Errorf("result is incomplete: %+v", res)
	}

	// A token over a different hash: the authority timestamped something else.
	other := sha256.Sum256([]byte("something else"))
	if _, err := parseTimestampResponse(
		fakeTimestampResponse(t, 0, other[:], nonce), digest[:], nonce); err == nil {
		t.Error("a token over a different hash was accepted")
	}

	// A replayed token, correct hash but a nonce from an earlier request.
	if _, err := parseTimestampResponse(
		fakeTimestampResponse(t, 0, digest[:], big.NewInt(999)), digest[:], nonce); err == nil {
		t.Error("a token with the wrong nonce was accepted, so replays would pass")
	}

	// A refusal must not be read as a grant.
	if _, err := parseTimestampResponse(
		fakeTimestampResponse(t, 2, digest[:], nonce), digest[:], nonce); err == nil {
		t.Error("a rejected request was treated as granted")
	}

	if _, err := parseTimestampResponse([]byte("not der"), digest[:], nonce); err == nil {
		t.Error("garbage parsed as a timestamp response")
	}
}

// Real authorities include the optional Accuracy field. An optional
// asn1.RawValue there swallows the nonce that follows it, which made every
// genuine token look like a replay — so the coexistence is asserted directly.
func TestTimestampResponseHandlesAccuracyBeforeNonce(t *testing.T) {
	digest := sha256.Sum256([]byte("checkpoint"))
	nonce := big.NewInt(4242)

	der := fakeTimestampResponseWithAccuracy(t, digest[:], nonce)
	res, err := parseTimestampResponse(der, digest[:], nonce)
	if err != nil {
		t.Fatalf("a token carrying Accuracy failed: %v", err)
	}
	if res.Serial != "99" {
		t.Errorf("serial = %q", res.Serial)
	}
}

func TestTimestampHashRejectsBadDigests(t *testing.T) {
	p := NewPublisher(nil, "s")
	for _, bad := range []string{"", "zz", "abcd"} {
		if _, err := TimestampHash(context.Background(), p.Client, "http://127.0.0.1:1", bad); err == nil {
			t.Errorf("%q: accepted as a checkpoint hash", bad)
		}
	}
}

// fakeTimestampResponse builds a DER TimeStampResp carrying a TSTInfo. It is
// unsigned, which is exactly what the code under test tolerates: DefendSec
// checks the imprint and nonce and leaves the signature to other tooling.
func fakeTimestampResponse(t *testing.T, status int, digest []byte, nonce *big.Int) []byte {
	t.Helper()
	return buildTimestampResponse(t, status, digest, nonce, nil)
}

func buildTimestampResponse(t *testing.T, status int, digest []byte, nonce *big.Int, acc *accuracy) []byte {
	t.Helper()

	info := tstInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 3, 4},
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm:  oidSHA256,
				Parameters: asn1.RawValue{Tag: asn1.TagNull, Class: asn1.ClassUniversal},
			},
			HashedMessage: digest,
		},
		SerialNumber: big.NewInt(99),
		GenTime:      time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
		Nonce:        nonce,
	}
	if acc != nil {
		info.Accuracy = *acc
	}
	infoDER, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}

	type encapContentInfo struct {
		EContentType asn1.ObjectIdentifier
		EContent     []byte `asn1:"explicit,optional,tag:0"`
	}
	type signedDataDER struct {
		Version          int
		DigestAlgorithms []algorithmIdentifier `asn1:"set"`
		EncapContentInfo encapContentInfo
	}
	// asn1.Marshal only emits the [0] EXPLICIT wrapper when the field has a
	// concrete type; a RawValue carrying FullBytes is written through
	// untouched, which is how the first version of this helper produced DER
	// the parser rightly rejected.
	type contentInfoDER struct {
		ContentType asn1.ObjectIdentifier
		Content     signedDataDER `asn1:"explicit,tag:0"`
	}

	ciDER, err := asn1.Marshal(contentInfoDER{
		ContentType: oidSignedData,
		Content: signedDataDER{
			Version:          3,
			DigestAlgorithms: []algorithmIdentifier{{Algorithm: oidSHA256}},
			EncapContentInfo: encapContentInfo{
				EContentType: oidTSTInfo,
				EContent:     infoDER,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp := timeStampResp{Status: pkiStatusInfo{Status: status}}
	if status == 0 || status == 1 {
		resp.TimeStampToken = asn1.RawValue{FullBytes: ciDER}
	}
	respDER, err := asn1.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return respDER
}

func fakeTimestampResponseWithAccuracy(t *testing.T, digest []byte, nonce *big.Int) []byte {
	t.Helper()
	return buildTimestampResponse(t, 0, digest, nonce, &accuracy{Seconds: 1})
}

func TestHexDigestSanity(t *testing.T) {
	d := sha256.Sum256([]byte("x"))
	if len(hex.EncodeToString(d[:])) != 64 {
		t.Fatal("a sha-256 hex digest is not 64 characters")
	}
}

func decodeInto(r *http.Request, dst *PeerAnchorRequest) error {
	return json.NewDecoder(r.Body).Decode(dst)
}
