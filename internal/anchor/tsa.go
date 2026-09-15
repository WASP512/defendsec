// Package anchor publishes signed audit checkpoints somewhere the server
// cannot retroactively control (roadmap 1.6).
//
// The audit chain and its signed checkpoints defeat an attacker who can edit
// the database. They do not defeat one who owns the server *and* the database
// and the control signing key: such an attacker can rebuild the whole chain
// and sign a fresh checkpoint over it, and the result is internally perfect.
//
// An anchor is a copy of a checkpoint hash placed where that attacker cannot
// reach back and change it — a timestamp authority's signature, a git
// repository somebody else pulls, another DefendSec instance. They can stop
// new anchors appearing. They cannot rewrite the ones already published, so
// the rewritten history no longer matches and the forgery is visible.
//
// What that is worth depends entirely on somebody checking. An anchor nobody
// compares against is decoration, which is why VerifyAgainst exists and why
// the console shows the comparison rather than a count of anchors written.
package anchor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// RFC 3161 time-stamping.
//
// DefendSec builds the request, checks the response's status, and verifies
// that the token's message imprint and nonce match what it asked for. It then
// stores the token bytes verbatim.
//
// It deliberately does *not* validate the TSA's signature or certificate
// chain. Doing that properly means a full CMS implementation and a trust store
// of TSA roots, and a half-done version would be worse than none: it would
// report "verified" on the strength of checks it did not really make. The
// token is stored whole so a third party can do it with tooling that already
// exists — `openssl ts -verify -in <token> -data <hash file> -CAfile <roots>`.
// That limitation is reported alongside every anchor rather than left implicit.

var (
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     asn1.RawValue         `asn1:"optional,tag:0"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// accuracy is TSTInfo's optional Accuracy field.
//
// It is spelled out rather than left as an optional asn1.RawValue, which is
// what the first version did. An optional RawValue matches *anything*, so it
// silently consumed the following field — the nonce — and every token then
// looked like a replay. A field that swallows its neighbour is worse than one
// that fails to parse, because it fails quietly and in the direction of
// rejecting good tokens.
type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       accuracy      `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,tag:0"`
	Extensions     asn1.RawValue `asn1:"optional,tag:1"`
}

// TSAResult is what a successful time-stamp yields.
type TSAResult struct {
	// Token is the DER TimeStampToken, stored verbatim so someone else can
	// verify the signature DefendSec does not check.
	Token []byte
	// GenTime is the time the authority asserts. It is the authority's claim,
	// not a verified fact, until the token's signature is checked.
	GenTime time.Time
	// Serial is the authority's serial number for this token.
	Serial string
	// PolicyOID is the TSA policy the token was issued under.
	PolicyOID string
}

// TimestampHash asks a TSA to timestamp a hex-encoded SHA-256 digest.
//
// The digest is the checkpoint's entry hash: timestamping the hash rather than
// the data means the authority learns nothing about the ledger's contents,
// which matters when the ledger describes an agency's security posture.
func TimestampHash(ctx context.Context, client *http.Client, url, hexDigest string) (*TSAResult, error) {
	digest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("checkpoint hash is not hex: %w", err)
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("checkpoint hash is %d bytes, want %d", len(digest), sha256.Size)
	}

	// A nonce is what makes this a fresh signature rather than a replay of one
	// the attacker captured earlier. Without it, a compromised server could
	// present an old token for a hash it has since rewritten.
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonce := new(big.Int).SetBytes(nonceBytes)

	reqDER, err := asn1.Marshal(timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm:  oidSHA256,
				Parameters: asn1.RawValue{Tag: asn1.TagNull, Class: asn1.ClassUniversal},
			},
			HashedMessage: digest,
		},
		Nonce:   nonce,
		CertReq: true, // ask for the certificate, so offline verification is possible
	})
	if err != nil {
		return nil, fmt.Errorf("build timestamp request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")

	res, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("contact timestamp authority: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("timestamp authority returned %s", res.Status)
	}
	// Bounded: a hostile or broken authority must not be able to exhaust
	// memory on a scheduled background job.
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read timestamp response: %w", err)
	}

	return parseTimestampResponse(body, digest, nonce)
}

// parseTimestampResponse checks the response and extracts what matters.
func parseTimestampResponse(der, wantDigest []byte, wantNonce *big.Int) (*TSAResult, error) {
	var resp timeStampResp
	if _, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, fmt.Errorf("parse timestamp response: %w", err)
	}
	// 0 granted, 1 granted with modifications. Anything else is a refusal.
	if resp.Status.Status != 0 && resp.Status.Status != 1 {
		return nil, fmt.Errorf("timestamp authority refused the request (status %d)", resp.Status.Status)
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, fmt.Errorf("timestamp authority granted the request but returned no token")
	}

	info, err := extractTSTInfo(resp.TimeStampToken.FullBytes)
	if err != nil {
		return nil, err
	}

	// The two checks that make the token ours rather than one the server
	// could have produced from a replayed response.
	if !bytes.Equal(info.MessageImprint.HashedMessage, wantDigest) {
		return nil, fmt.Errorf("the token timestamps a different hash than was requested")
	}
	if info.Nonce == nil || info.Nonce.Cmp(wantNonce) != 0 {
		return nil, fmt.Errorf("the token's nonce does not match the request, so it may be a replay")
	}

	return &TSAResult{
		Token:     append([]byte(nil), resp.TimeStampToken.FullBytes...),
		GenTime:   info.GenTime.UTC(),
		Serial:    info.SerialNumber.String(),
		PolicyOID: info.Policy.String(),
	}, nil
}

// extractTSTInfo digs the TSTInfo out of a CMS SignedData token.
//
// Only the eContent is walked, not the signature: see the note at the top of
// this file for why the signature is deliberately left to other tooling.
func extractTSTInfo(tokenDER []byte) (*tstInfo, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(tokenDER, &ci); err != nil {
		return nil, fmt.Errorf("parse timestamp token: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("timestamp token is not CMS SignedData")
	}

	// SignedData ::= SEQUENCE { version, digestAlgorithms SET,
	//   encapContentInfo SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING }, ... }
	// The remaining fields are not needed here, so the tail is left as raw.
	var signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo struct {
			EContentType asn1.ObjectIdentifier
			EContent     []byte `asn1:"explicit,optional,tag:0"`
		}
		Rest asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &signedData); err != nil {
		return nil, fmt.Errorf("parse SignedData: %w", err)
	}
	if !signedData.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return nil, fmt.Errorf("timestamp token does not encapsulate TSTInfo")
	}
	if len(signedData.EncapContentInfo.EContent) == 0 {
		return nil, fmt.Errorf("timestamp token carries no TSTInfo content")
	}

	var info tstInfo
	if _, err := asn1.Unmarshal(signedData.EncapContentInfo.EContent, &info); err != nil {
		return nil, fmt.Errorf("parse TSTInfo: %w", err)
	}
	if info.SerialNumber == nil {
		return nil, fmt.Errorf("TSTInfo has no serial number")
	}
	return &info, nil
}
