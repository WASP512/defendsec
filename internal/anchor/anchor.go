package anchor

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Kind names where an anchor was published.
type Kind string

const (
	// KindTSA is an RFC 3161 timestamp authority. The strongest of the three:
	// a third party signs an assertion that this hash existed at this time,
	// and DefendSec never holds the key that produced it.
	KindTSA Kind = "rfc3161"
	// KindFile writes to a directory. Worth exactly as much as what the
	// operator does with that directory — pointed at a git worktree that is
	// committed and pushed, it is strong; left on the same disk as the
	// database, it is nearly worthless, because the attacker who rewrites one
	// rewrites the other.
	KindFile Kind = "file"
	// KindPeer posts to another DefendSec instance. Useful because it is
	// mutual and costs nothing: two agencies anchoring each other both gain,
	// and compromising one does not reach the other's copy.
	KindPeer Kind = "peer"
)

// Record is one published anchor.
type Record struct {
	ID         string    `json:"id"`
	ThroughSeq int64     `json:"throughSeq"`
	EntryHash  string    `json:"entryHash"`
	Kind       Kind      `json:"kind"`
	Target     string    `json:"target"`
	AnchoredAt time.Time `json:"anchoredAt"`

	// ExternalTime is what the third party says, where it says anything. For
	// RFC 3161 that is the authority's genTime; for a peer it is the peer's
	// receive time. Zero for a file target, which has no independent clock.
	ExternalTime time.Time `json:"externalTime,omitempty"`

	// Proof is whatever the target returned, stored verbatim so it can be
	// checked by tooling that is not DefendSec.
	Proof []byte `json:"proof,omitempty"`

	// Reference identifies the anchor at the target: a TSA serial, a file
	// path, a peer's receipt id.
	Reference string `json:"reference,omitempty"`

	// Error records a failed attempt. Failures are stored rather than
	// discarded: a long run of them is the interesting signal, and an anchor
	// history with the failures silently dropped looks healthier than it is.
	Error string `json:"error,omitempty"`
}

// OK reports whether the anchor was published.
func (r Record) OK() bool { return r.Error == "" }

// Verification is the comparison that gives an anchor its value.
type Verification struct {
	Record Record `json:"record"`
	// Matches is whether the anchored hash still equals the chain's hash at
	// that sequence.
	Matches bool `json:"matches"`
	// CurrentHash is what the chain says now.
	CurrentHash string `json:"currentHash,omitempty"`
	// Detail explains the outcome in words an operator can act on.
	Detail string `json:"detail"`
}

// VerifyAgainst compares published anchors with the chain as it stands now.
//
// This is the whole point of anchoring, and the step products usually skip:
// writing anchors and never comparing them detects nothing. A mismatch means
// the chain was rebuilt after the anchor was published — which is precisely
// the attack the signed checkpoint alone cannot catch, because the attacker
// holds the signing key.
//
// currentHashes maps sequence number to the chain's entry hash now. A sequence
// absent from it means the chain no longer reaches that far, which is itself a
// finding: history that was anchored has since been truncated.
func VerifyAgainst(anchors []Record, currentHashes map[int64]string) []Verification {
	out := make([]Verification, 0, len(anchors))
	for _, a := range anchors {
		v := Verification{Record: a}
		switch {
		case !a.OK():
			v.Detail = "This anchor was never published: " + a.Error
		default:
			current, present := currentHashes[a.ThroughSeq]
			v.CurrentHash = current
			switch {
			case !present:
				v.Detail = fmt.Sprintf(
					"Sequence %d was anchored on %s but the chain no longer reaches it. Anchored history has been truncated.",
					a.ThroughSeq, a.AnchoredAt.UTC().Format("2006-01-02"))
			case current == a.EntryHash:
				v.Matches = true
				v.Detail = fmt.Sprintf("Sequence %d still matches the hash anchored on %s.",
					a.ThroughSeq, a.AnchoredAt.UTC().Format("2006-01-02"))
			default:
				v.Detail = fmt.Sprintf(
					"Sequence %d does not match the hash anchored on %s. The chain has been rebuilt since it was published — a valid signature on the current chain does not clear this.",
					a.ThroughSeq, a.AnchoredAt.UTC().Format("2006-01-02"))
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Record.ThroughSeq > out[j].Record.ThroughSeq
	})
	return out
}

// Summary condenses a set of verifications for the console.
type Summary struct {
	Total      int `json:"total"`
	Matching   int `json:"matching"`
	Mismatched int `json:"mismatched"`
	Missing    int `json:"missing"`
	Failed     int `json:"failed"`
	// Verdict is the sentence an operator reads first.
	Verdict string `json:"verdict"`
}

// Summarise produces the headline.
func Summarise(vs []Verification) Summary {
	s := Summary{Total: len(vs)}
	for _, v := range vs {
		switch {
		case !v.Record.OK():
			s.Failed++
		case v.Matches:
			s.Matching++
		case v.CurrentHash == "":
			s.Missing++
		default:
			s.Mismatched++
		}
	}
	switch {
	case s.Total == 0:
		s.Verdict = "No checkpoints have been anchored. The ledger is tamper-evident against anyone who can edit the database, but not against anyone who also holds the control signing key."
	case s.Mismatched > 0 || s.Missing > 0:
		s.Verdict = fmt.Sprintf(
			"%d anchored checkpoints no longer match the chain. This is what a rebuilt ledger looks like; investigate before trusting any recent evidence.",
			s.Mismatched+s.Missing)
	case s.Matching == 0:
		s.Verdict = "Every anchoring attempt failed, so nothing is published externally. Fix the targets — unpublished anchors protect nothing."
	case s.Failed > 0:
		s.Verdict = fmt.Sprintf(
			"%d anchors match the chain, and %d attempts failed. Check the failing target: gaps in anchoring are gaps in the protection.",
			s.Matching, s.Failed)
	default:
		s.Verdict = fmt.Sprintf(
			"All %d anchored checkpoints still match the chain.", s.Matching)
	}
	return s
}

// FileAnchor is the line written to a file target. It is plain JSON, one
// object per line, so it diffs readably in a git history — which is the point
// of pointing this at a repository somebody else pulls.
type FileAnchor struct {
	ThroughSeq int64     `json:"throughSeq"`
	EntryHash  string    `json:"entryHash"`
	AnchoredAt time.Time `json:"anchoredAt"`
	Server     string    `json:"server,omitempty"`
	// SigningKeyID identifies the control key whose checkpoint this is, so a
	// reader can tell two instances' anchors apart in a shared repository.
	SigningKeyID string `json:"signingKeyId,omitempty"`
}

// MarshalFileAnchor renders one line.
func MarshalFileAnchor(a FileAnchor) ([]byte, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParseFileAnchors reads a file target back.
func ParseFileAnchors(raw []byte) ([]FileAnchor, error) {
	var out []FileAnchor
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var a FileAnchor
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		out = append(out, a)
	}
	return out, nil
}
