package repohealth

import (
	"bufio"
	"strings"
	"time"
)

// GPGVerdict is what gpgv's --status-fd output says about one signed file.
type GPGVerdict struct {
	Sig Sig
	// KeyID is the key the verdict is about (the long id gpgv prints).
	KeyID string
	// UID is the key's user id when gpgv printed one (EXPKEYSIG, GOODSIG,
	// BADSIG): the vendor's public name for the key.
	UID string
}

// ParseGPGVStatus reads the machine-readable status lines of `gpgv
// --status-fd 1`. gpgv exits 0 on an expired key ("Good signature"), so the
// verdict has to come from the status lines, in apt's order of preference: one
// good signature makes the file good (a vendor signing with two keys while it
// rotates is fine); otherwise the most informative failure wins.
func ParseGPGVStatus(out string) GPGVerdict {
	var good, expired, revoked, bad, missing, errsig GPGVerdict
	var haveGood, haveExp, haveRev, haveBad, haveMiss, haveErr bool
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		rest, ok := strings.CutPrefix(line, "[GNUPG:] ")
		if !ok {
			continue
		}
		tag, args, _ := strings.Cut(rest, " ")
		keyID, uid, _ := strings.Cut(args, " ")
		switch tag {
		case "GOODSIG":
			good, haveGood = GPGVerdict{Sig: SigGood, KeyID: keyID, UID: uid}, true
		case "EXPKEYSIG":
			if !haveExp {
				expired, haveExp = GPGVerdict{Sig: SigExpiredKey, KeyID: keyID, UID: uid}, true
			}
		case "EXPSIG":
			// The signature itself has expired: it no longer verifies.
			if !haveBad {
				bad, haveBad = GPGVerdict{Sig: SigBad, KeyID: keyID, UID: uid}, true
			}
		case "REVKEYSIG":
			if !haveRev {
				revoked, haveRev = GPGVerdict{Sig: SigRevoked, KeyID: keyID, UID: uid}, true
			}
		case "BADSIG":
			if !haveBad {
				bad, haveBad = GPGVerdict{Sig: SigBad, KeyID: keyID, UID: uid}, true
			}
		case "NO_PUBKEY":
			if !haveMiss {
				missing, haveMiss = GPGVerdict{Sig: SigNoPubkey, KeyID: keyID}, true
			}
		case "ERRSIG":
			// ERRSIG <keyid> <pkalgo> <hashalgo> <sig_class> <time> <rc> ...: rc 9
			// is a missing key (NO_PUBKEY follows), others are unusable signatures.
			if !haveErr {
				errsig, haveErr = GPGVerdict{Sig: SigBad, KeyID: keyID}, true
			}
		}
	}
	switch {
	case haveGood:
		return good
	case haveExp:
		return expired
	case haveRev:
		return revoked
	case haveBad:
		return bad
	case haveMiss:
		return missing
	case haveErr:
		return errsig
	}
	return GPGVerdict{Sig: SigUnsigned}
}

// ReleaseHeaders are the freshness fields of an apt Release or InRelease file.
type ReleaseHeaders struct {
	Date       *time.Time
	ValidUntil *time.Time
}

// ParseRelease reads Date: and Valid-Until: from a Release file, or from the
// signed text of an InRelease (everything before the signature block counts;
// the armor header and its Hash: line are skipped).
func ParseRelease(text string) ReleaseHeaders {
	var h ReleaseHeaders
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "-----BEGIN PGP SIGNATURE") {
			break
		}
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "date":
			if t, ok := parseReleaseTime(v); ok && h.Date == nil {
				h.Date = &t
			}
		case "valid-until":
			if t, ok := parseReleaseTime(v); ok && h.ValidUntil == nil {
				h.ValidUntil = &t
			}
		}
	}
	return h
}

// parseReleaseTime reads the RFC 1123 dates of Release files, which say "UTC"
// or "GMT" or carry a numeric zone.
func parseReleaseTime(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	for _, layout := range []string{
		"Mon, 02 Jan 2006 15:04:05 MST",
		"Mon, 02 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 MST",
		"Mon, 2 Jan 2006 15:04:05 -0700",
		time.RFC1123, time.RFC1123Z,
	} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
