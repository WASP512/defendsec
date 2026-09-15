package identity

import (
	"crypto/fips140"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The claim under test is narrow and load-bearing: turning FIPS mode on must
// change which algorithm new passwords use, and must not lock out a single
// existing account.

func TestActiveKDFFollowsFIPSMode(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("process is already in FIPS mode; the non-FIPS half cannot be observed")
	}
	t.Setenv("DEFENDSEC_FIPS_MODE", "")
	if got := ActiveKDF(); got != KDFArgon2id {
		t.Errorf("default KDF = %q, want %q", got, KDFArgon2id)
	}
	for _, v := range []string{"1", "true", "YES", "on", "only"} {
		t.Setenv("DEFENDSEC_FIPS_MODE", v)
		if got := ActiveKDF(); got != KDFPBKDF2 {
			t.Errorf("DEFENDSEC_FIPS_MODE=%q: KDF = %q, want %q", v, got, KDFPBKDF2)
		}
	}
	for _, v := range []string{"0", "false", "off", "", "maybe"} {
		t.Setenv("DEFENDSEC_FIPS_MODE", v)
		if got := ActiveKDF(); got != KDFArgon2id {
			t.Errorf("DEFENDSEC_FIPS_MODE=%q: KDF = %q, want %q", v, got, KDFArgon2id)
		}
	}
}

func TestPBKDF2HashRoundTrip(t *testing.T) {
	t.Setenv("DEFENDSEC_FIPS_MODE", "1")
	const password = "correct horse battery staple"
	encoded, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$pbkdf2-sha256$") {
		t.Fatalf("hash = %q, want a pbkdf2-sha256 hash in FIPS mode", encoded)
	}
	if strings.Contains(encoded, password) {
		t.Fatal("the encoded hash contains the plaintext")
	}
	if !VerifyPassword(password, encoded) {
		t.Error("the correct password did not verify")
	}
	if VerifyPassword(password+"x", encoded) {
		t.Error("a wrong password verified")
	}
	second, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if second == encoded {
		t.Error("two hashes of the same password are identical, so the salt is not per-call")
	}
}

// Switching an existing deployment to FIPS must not turn every stored Argon2id
// credential into a failed login, and switching back must not invalidate the
// PBKDF2 hashes written while it was on.
func TestBothAlgorithmsVerifyInEitherMode(t *testing.T) {
	const password = "cross-mode-verification"

	t.Setenv("DEFENDSEC_FIPS_MODE", "")
	argonHash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENDSEC_FIPS_MODE", "1")
	pbkdf2Hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{"", "1"} {
		t.Setenv("DEFENDSEC_FIPS_MODE", mode)
		for name, encoded := range map[string]string{"argon2id": argonHash, "pbkdf2": pbkdf2Hash} {
			if !VerifyPassword(password, encoded) {
				t.Errorf("DEFENDSEC_FIPS_MODE=%q: %s hash failed to verify", mode, name)
			}
			if VerifyPassword("wrong", encoded) {
				t.Errorf("DEFENDSEC_FIPS_MODE=%q: %s hash accepted a wrong password", mode, name)
			}
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	t.Setenv("DEFENDSEC_FIPS_MODE", "")
	argonHash, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENDSEC_FIPS_MODE", "1")
	pbkdf2Hash, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		mode, hash string
		want       bool
	}{
		{"", argonHash, false},
		{"", pbkdf2Hash, true},
		{"1", pbkdf2Hash, false},
		{"1", argonHash, true},
		// Anything unrecognised is rehashed, so a legacy or corrupt format is
		// replaced rather than kept forever.
		{"", "$bcrypt$whatever", true},
		{"1", "", true},
	}
	for _, tc := range cases {
		t.Setenv("DEFENDSEC_FIPS_MODE", tc.mode)
		if got := NeedsRehash(tc.hash); got != tc.want {
			t.Errorf("mode=%q hash=%.20q: NeedsRehash = %v, want %v", tc.mode, tc.hash, got, tc.want)
		}
	}
}

// A malformed PBKDF2 hash must fail closed, exactly like a malformed Argon2id
// one. Each case below would be an authentication bypass if it returned true.
func TestVerifyPBKDF2RejectsMalformedHashes(t *testing.T) {
	t.Setenv("DEFENDSEC_FIPS_MODE", "1")
	valid, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(valid, "$")

	bad := map[string]string{
		"empty":             "",
		"prefix only":       "$pbkdf2-sha256$",
		"missing fields":    "$pbkdf2-sha256$i=600000$" + parts[3],
		"too many fields":   valid + "$extra",
		"zero iterations":   "$pbkdf2-sha256$i=0$" + parts[3] + "$" + parts[4],
		"negative iters":    "$pbkdf2-sha256$i=-1$" + parts[3] + "$" + parts[4],
		"unparseable iters": "$pbkdf2-sha256$i=lots$" + parts[3] + "$" + parts[4],
		"missing iter tag":  "$pbkdf2-sha256$600000$" + parts[3] + "$" + parts[4],
		"empty salt":        "$pbkdf2-sha256$i=600000$$" + parts[4],
		"empty digest":      "$pbkdf2-sha256$i=600000$" + parts[3] + "$",
		"bad base64 salt":   "$pbkdf2-sha256$i=600000$!!!!$" + parts[4],
		"bad base64 digest": "$pbkdf2-sha256$i=600000$" + parts[3] + "$!!!!",
	}
	for name, encoded := range bad {
		if VerifyPassword("pw", encoded) {
			t.Errorf("%s: malformed hash %q verified", name, encoded)
		}
		if VerifyPassword("", encoded) {
			t.Errorf("%s: malformed hash verified an empty password", name)
		}
	}
}

func TestBurnPasswordComparisonMatchesActiveAlgorithm(t *testing.T) {
	// The point of the per-algorithm dummy is that there is one for whatever
	// mode is active; a missing entry would make the unknown-user path free.
	for _, mode := range []string{"", "1"} {
		t.Setenv("DEFENDSEC_FIPS_MODE", mode)
		if dummyHashes[ActiveKDF()] == "" {
			t.Fatalf("DEFENDSEC_FIPS_MODE=%q: no dummy hash for %q", mode, ActiveKDF())
		}
		start := time.Now()
		BurnPasswordComparison("whatever")
		if time.Since(start) < time.Millisecond {
			t.Errorf("DEFENDSEC_FIPS_MODE=%q: comparison returned in %v, too fast to be doing the work",
				mode, time.Since(start))
		}
	}
}

func TestStatusReportsPosture(t *testing.T) {
	t.Setenv("DEFENDSEC_FIPS_MODE", "1")
	st := Status()
	if !st.ApprovedAlgorithmsRequired {
		t.Error("approvedAlgorithmsRequired = false with DEFENDSEC_FIPS_MODE=1")
	}
	if st.PasswordKDF != string(KDFPBKDF2) {
		t.Errorf("passwordKdf = %q, want %q", st.PasswordKDF, KDFPBKDF2)
	}
	if st.GoModuleEnabled != fips140.Enabled() || st.GoModuleEnforced != fips140.Enforced() {
		t.Error("the reported Go module state does not match the runtime")
	}
	// Nothing must be implied by silence: the TOTP deviation is always stated.
	var mentionsTOTP bool
	for _, n := range st.Notes {
		if strings.Contains(n, "HMAC-SHA1") {
			mentionsTOTP = true
		}
	}
	if !mentionsTOTP {
		t.Error("the status notes do not disclose the HMAC-SHA1 deviation")
	}

	t.Setenv("DEFENDSEC_FIPS_MODE", "")
	if fips140.Enabled() {
		return
	}
	st = Status()
	if st.ApprovedAlgorithmsRequired || st.PasswordKDF != string(KDFArgon2id) {
		t.Errorf("unexpected default posture: %+v", st)
	}
}

// The probe finding that drove this whole section, asserted rather than
// remembered: under GODEBUG=fips140=only, Go rejects HMAC-SHA1 by panicking.
// TOTP computes its HMAC inside fips140.WithoutEnforcement, so it must keep
// working. This re-runs the test binary in only-mode, because GODEBUG=fips140
// cannot be changed after start.
func TestCryptoSurvivesFIPSOnlyMode(t *testing.T) {
	if os.Getenv("DEFENDSEC_FIPS_ONLY_CHILD") == "1" {
		if !fips140.Enforced() {
			t.Fatal("child was not started in fips140=only mode")
		}
		// TOTP, the one call that only-mode would otherwise kill.
		code, err := TOTPCodeAt("JBSWY3DPEHPK3PXP", 59)
		if err != nil {
			t.Fatalf("totp under fips140=only: %v", err)
		}
		if len(code) != TOTPDigits {
			t.Fatalf("code = %q", code)
		}
		// And the approved surface, to confirm it needs no escape hatch.
		hash, err := HashPassword("only-mode")
		if err != nil {
			t.Fatalf("hash password under fips140=only: %v", err)
		}
		if !strings.HasPrefix(hash, "$pbkdf2-sha256$") {
			t.Fatalf("only-mode selected %q, want pbkdf2", hash)
		}
		if !VerifyPassword("only-mode", hash) {
			t.Fatal("password did not verify under fips140=only")
		}
		if _, _, err := NewSessionToken(); err != nil {
			t.Fatalf("session token under fips140=only: %v", err)
		}
		return
	}

	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate the test binary: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestCryptoSurvivesFIPSOnlyMode$", "-test.v")
	cmd.Env = append(os.Environ(),
		"DEFENDSEC_FIPS_ONLY_CHILD=1",
		"GODEBUG=fips140=only",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("GODEBUG=fips140=only run failed: %v\n%s", err, out)
	}
}
