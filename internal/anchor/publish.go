package anchor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"defendsec/internal/auditchain"
)

// Publishers write a checkpoint to a target.

// Target is one configured destination.
type Target struct {
	Kind Kind
	// Ref is a URL for rfc3161 and peer, a directory for file.
	Ref string
	// Token is a shared secret for a peer target. Peers authenticate each
	// other so an anchor store cannot be filled with junk by anyone who finds
	// the endpoint.
	Token string
}

// Publisher writes checkpoints to configured targets.
type Publisher struct {
	Targets []Target
	Client  *http.Client
	// Server identifies this instance in file anchors, so a shared repository
	// holding several agencies' anchors stays readable.
	Server string
}

// NewPublisher builds a publisher with a bounded HTTP client. Anchoring runs
// on a timer against third parties, so a target that stops responding must
// fail rather than pin a goroutine indefinitely.
func NewPublisher(targets []Target, server string) *Publisher {
	return &Publisher{
		Targets: targets,
		Server:  server,
		Client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// ParseTargets reads the DEFENDSEC_ANCHOR_TARGETS configuration: a
// comma-separated list of kind:ref entries, for example
//
//	rfc3161=https://freetsa.org/tsr,file=/var/lib/defendsec/anchors,peer=https://peer.example/v1/anchors/receive#sharedtoken
//
// A malformed entry is an error rather than a skip. Silently ignoring one
// would leave an operator believing they had anchoring they do not have, which
// is worse than having none — they would stop looking.
func ParseTargets(raw string) ([]Target, error) {
	var out []Target
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		kind, ref, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("anchor target %q is not in kind=ref form", entry)
		}
		t := Target{Kind: Kind(strings.ToLower(strings.TrimSpace(kind)))}
		ref = strings.TrimSpace(ref)

		if t.Kind == KindPeer {
			if url, token, hasToken := strings.Cut(ref, "#"); hasToken {
				ref, t.Token = url, token
			}
		}
		t.Ref = ref

		switch t.Kind {
		case KindTSA, KindPeer:
			if !strings.HasPrefix(t.Ref, "http://") && !strings.HasPrefix(t.Ref, "https://") {
				return nil, fmt.Errorf("anchor target %q needs an http or https url", entry)
			}
		case KindFile:
			if t.Ref == "" {
				return nil, fmt.Errorf("anchor target %q needs a directory", entry)
			}
		default:
			return nil, fmt.Errorf("unknown anchor target kind %q, want rfc3161, file or peer", kind)
		}
		out = append(out, t)
	}
	return out, nil
}

// Publish writes a checkpoint to every target, returning one record each.
//
// A failing target does not stop the others: anchoring in several places is
// the point, and one authority being down should not cost the day's anchor
// everywhere else. Failures come back as records with Error set rather than
// as an error, so they are stored and visible.
func (p *Publisher) Publish(ctx context.Context, cp auditchain.Checkpoint) []Record {
	out := make([]Record, 0, len(p.Targets))
	for _, t := range p.Targets {
		rec := Record{
			ThroughSeq: cp.ThroughSeq,
			EntryHash:  cp.EntryHash,
			Kind:       t.Kind,
			Target:     t.Ref,
			AnchoredAt: time.Now().UTC(),
		}
		var err error
		switch t.Kind {
		case KindTSA:
			err = p.publishTSA(ctx, t, &rec)
		case KindFile:
			err = p.publishFile(t, cp, &rec)
		case KindPeer:
			err = p.publishPeer(ctx, t, cp, &rec)
		default:
			err = fmt.Errorf("unknown target kind %q", t.Kind)
		}
		if err != nil {
			rec.Error = err.Error()
		}
		out = append(out, rec)
	}
	return out
}

func (p *Publisher) publishTSA(ctx context.Context, t Target, rec *Record) error {
	res, err := TimestampHash(ctx, p.Client, t.Ref, rec.EntryHash)
	if err != nil {
		return err
	}
	rec.Proof = res.Token
	rec.ExternalTime = res.GenTime
	rec.Reference = res.Serial
	return nil
}

func (p *Publisher) publishFile(t Target, cp auditchain.Checkpoint, rec *Record) error {
	if err := os.MkdirAll(t.Ref, 0o750); err != nil {
		return fmt.Errorf("create anchor directory: %w", err)
	}
	line, err := MarshalFileAnchor(FileAnchor{
		ThroughSeq: cp.ThroughSeq, EntryHash: cp.EntryHash,
		AnchoredAt: rec.AnchoredAt, Server: p.Server,
		SigningKeyID: cp.SigningKeyID,
	})
	if err != nil {
		return err
	}

	// One file per month keeps a git history readable and keeps any single
	// file from growing without bound.
	path := filepath.Join(t.Ref, "anchors-"+rec.AnchoredAt.Format("2006-01")+".jsonl")
	// Append-only by intent: the file is never rewritten, so a diff shows
	// additions and nothing else. A history that only ever grows is what makes
	// an alteration obvious to whoever reviews the repository.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open anchor file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("write anchor: %w", err)
	}
	// Flushed before returning success, so a crash cannot leave DefendSec
	// recording an anchor that was never durably written.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("flush anchor: %w", err)
	}
	rec.Reference = path
	return nil
}

// PeerAnchorRequest is what one instance sends another.
type PeerAnchorRequest struct {
	ThroughSeq   int64  `json:"throughSeq"`
	EntryHash    string `json:"entryHash"`
	SigningKeyID string `json:"signingKeyId,omitempty"`
	Signature    string `json:"signature,omitempty"`
	At           string `json:"at"`
	Server       string `json:"server,omitempty"`
}

// PeerAnchorReceipt is what it sends back.
type PeerAnchorReceipt struct {
	ID         string `json:"id"`
	ReceivedAt string `json:"receivedAt"`
}

func (p *Publisher) publishPeer(ctx context.Context, t Target, cp auditchain.Checkpoint, rec *Record) error {
	// The checkpoint's own signature travels with it, so the peer stores
	// something it can verify rather than a bare hash it has to take on faith.
	body, err := json.Marshal(PeerAnchorRequest{
		ThroughSeq: cp.ThroughSeq, EntryHash: cp.EntryHash,
		SigningKeyID: cp.SigningKeyID, Signature: cp.Signature,
		At: cp.At.UTC().Format(time.RFC3339), Server: p.Server,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Ref, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if t.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.Token)
	}
	res, err := p.Client.Do(req)
	if err != nil {
		return fmt.Errorf("contact peer: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("peer returned %s", res.Status)
	}
	var receipt PeerAnchorReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return fmt.Errorf("peer returned an unreadable receipt: %w", err)
	}
	rec.Proof = raw
	rec.Reference = receipt.ID
	if receipt.ReceivedAt != "" {
		if at, err := time.Parse(time.RFC3339, receipt.ReceivedAt); err == nil {
			rec.ExternalTime = at.UTC()
		}
	}
	return nil
}
