package sign

import (
	"testing"
	"time"
)

func TestSignVerifyAndRejectTamper(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(key.PublicPEM()) != string(again.PublicPEM()) {
		t.Fatal("key should persist")
	}
	e := Envelope{
		DeviceID:    "dev-1",
		CommandID:   "cmd-1",
		Type:        "isolate",
		IssuedUnix:  time.Now().Unix(),
		ExpiresUnix: time.Now().Add(2 * time.Minute).Unix(),
		Payload:     []byte(`{}`),
	}
	sig := key.Sign(e)
	if err := Verify(key.Public, e, sig, time.Now()); err != nil {
		t.Fatal(err)
	}
	e.Type = "release"
	if err := Verify(key.Public, e, sig, time.Now()); err == nil {
		t.Fatal("expected reject after type change")
	}
	e.Type = "isolate"
	if err := Verify(key.Public, e, nil, time.Now()); err == nil {
		t.Fatal("expected reject unsigned")
	}
	expired := e
	expired.ExpiresUnix = time.Now().Add(-time.Minute).Unix()
	sig2 := key.Sign(expired)
	if err := Verify(key.Public, expired, sig2, time.Now()); err == nil {
		t.Fatal("expected reject expired")
	}
	pub, err := ParsePublicPEM(key.PublicPEM())
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, e, key.Sign(e), time.Now()); err != nil {
		t.Fatal(err)
	}
}
