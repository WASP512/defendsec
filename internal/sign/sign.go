package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	privateType = "PRIVATE KEY"
	publicType  = "PUBLIC KEY"
	domain      = "keel-cmd-v1"
)

type Key struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

type Envelope struct {
	DeviceID    string
	CommandID   string
	Type        string
	IssuedUnix  int64
	ExpiresUnix int64
	Payload     []byte
}

func Canonical(e Envelope) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s\n%s\n%s\n%s\n%d\n%d\n", domain, e.DeviceID, e.CommandID, e.Type, e.IssuedUnix, e.ExpiresUnix)
	b.Write(e.Payload)
	return b.Bytes()
}

func LoadOrCreate(dir string) (*Key, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	privPath := filepath.Join(dir, "control-ed25519.key")
	pubPath := filepath.Join(dir, "control-ed25519.pub")
	if raw, err := os.ReadFile(privPath); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("invalid control key PEM")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("control key is not Ed25519")
		}
		return &Key{Private: priv, Public: priv.Public().(ed25519.PublicKey)}, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: privateType, Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	k := &Key{Private: priv, Public: pub}
	if err := os.WriteFile(pubPath, k.PublicPEM(), 0o644); err != nil {
		return nil, err
	}
	return k, nil
}

func (k *Key) PublicPEM() []byte {
	der, err := x509.MarshalPKIXPublicKey(k.Public)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: publicType, Bytes: der})
}

func (k *Key) Sign(e Envelope) []byte {
	return ed25519.Sign(k.Private, Canonical(e))
}

func ParsePublicPEM(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an Ed25519 public key")
	}
	return pub, nil
}

func Verify(pub ed25519.PublicKey, e Envelope, sig []byte, now time.Time) error {
	if len(sig) == 0 {
		return fmt.Errorf("unsigned command")
	}
	if !ed25519.Verify(pub, Canonical(e), sig) {
		return fmt.Errorf("invalid signature")
	}
	if e.ExpiresUnix > 0 && now.Unix() > e.ExpiresUnix {
		return fmt.Errorf("command expired")
	}
	if e.IssuedUnix > 0 && now.Unix()+60 < e.IssuedUnix {
		return fmt.Errorf("command issued in the future")
	}
	if e.IssuedUnix > 0 && now.Unix()-e.IssuedUnix > 5*60 {
		return fmt.Errorf("command too old")
	}
	return nil
}
