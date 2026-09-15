package sign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strconv"
)

// Acknowledgement signing closes the other half of the loop.
//
// A command carries the server's proof that it was authorised. Without a
// signed acknowledgement the endpoint's claim to have executed it is
// authenticated only by the transport, so once the record leaves the mTLS
// channel there is nothing to distinguish "we sent this" from "this ran" —
// which is exactly the gap the white paper warns about when it says to treat
// "sent" as transport state rather than proof of effect.
//
// Agents sign with the ECDSA P-256 key from their enrolled certificate rather
// than a separate key. That key is already the identity mTLS authenticates and
// the one certificate revocation targets, so a second signing identity would
// create something revocation does not cover. It is also the friendlier
// choice under FIPS 140-3, where P-256 is approved outright (roadmap 1.8).

const ackDomain = "defendsec-ack-v1"

// AckEnvelope is the acknowledgement content covered by the signature.
type AckEnvelope struct {
	CommandID    string
	DeviceID     string
	Accepted     bool
	ResultHash   string // hex SHA-256 of the result message
	ExecutedUnix int64
}

// HashResult renders the digest that goes in an AckEnvelope, so the signature
// covers the result without growing with it.
func HashResult(message string) string {
	sum := sha256.Sum256([]byte(message))
	return hex.EncodeToString(sum[:])
}

// CanonicalAck renders the signed form. Fields are length-prefixed so no
// combination of contents can be rearranged into another.
func CanonicalAck(e AckEnvelope) []byte {
	var b bytes.Buffer
	b.WriteString(ackDomain)
	b.WriteByte('\n')
	for _, field := range []string{
		e.CommandID,
		e.DeviceID,
		strconv.FormatBool(e.Accepted),
		e.ResultHash,
		strconv.FormatInt(e.ExecutedUnix, 10),
	} {
		b.WriteString(strconv.Itoa(len(field)))
		b.WriteByte(':')
		b.WriteString(field)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// SignAck signs an acknowledgement with the agent's certificate key. The
// digest is hashed again by ecdsa.SignASN1's caller contract, so the canonical
// bytes are reduced to SHA-256 first.
func SignAck(priv *ecdsa.PrivateKey, e AckEnvelope) ([]byte, error) {
	sum := sha256.Sum256(CanonicalAck(e))
	return ecdsa.SignASN1(rand.Reader, priv, sum[:])
}

// VerifyAck checks an acknowledgement signature against the agent's public key.
func VerifyAck(pub *ecdsa.PublicKey, e AckEnvelope, signature []byte) error {
	if len(signature) == 0 {
		return fmt.Errorf("acknowledgement for %s is unsigned", e.CommandID)
	}
	sum := sha256.Sum256(CanonicalAck(e))
	if !ecdsa.VerifyASN1(pub, sum[:], signature) {
		return fmt.Errorf("acknowledgement for %s does not verify against the enrolled agent key", e.CommandID)
	}
	return nil
}

// VerifyAckStored rebuilds an acknowledgement from persisted fields and checks
// it against a PEM-encoded agent public key, so a stored row can be verified
// with nothing but the row and the key.
func VerifyAckStored(agentPubPEM, commandID, deviceID string, accepted bool, resultHash string, executedUnix int64, signatureB64 string) error {
	pub, err := ParseECDSAPublicPEM([]byte(agentPubPEM))
	if err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("acknowledgement for %s: signature is not valid base64: %w", commandID, err)
	}
	return VerifyAck(pub, AckEnvelope{
		CommandID:    commandID,
		DeviceID:     deviceID,
		Accepted:     accepted,
		ResultHash:   resultHash,
		ExecutedUnix: executedUnix,
	}, raw)
}

// ECDSAPublicPEM encodes an agent public key for storage.
func ECDSAPublicPEM(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: publicType, Bytes: der}), nil
}

// ParseECDSAPublicPEM decodes an agent public key.
func ParseECDSAPublicPEM(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid agent public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("agent key is not ECDSA")
	}
	return pub, nil
}
