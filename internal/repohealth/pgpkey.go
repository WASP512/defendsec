package repohealth

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // OpenPGP v4 key ids are SHA-1 by definition; nothing is signed or verified here.
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// KeyInfo is what a public key file says about one primary key: enough to name
// it and to say whether it has expired. Nothing is verified cryptographically:
// the agent only reads the dates a vendor's key file declares, which is what
// rpm and dnf read too.
type KeyInfo struct {
	// KeyID is the long (16 hex digit) key id, upper case; Fingerprint is the
	// full v4 fingerprint, upper case.
	KeyID       string
	Fingerprint string
	Created     time.Time
	// Expires is nil for a key that does not expire.
	Expires *time.Time
	Revoked bool
}

// ShortID is the last eight hex digits of the key id, the form rpm names an
// imported key by (gpg-pubkey-<ShortID>-<time>), lower case.
func (k KeyInfo) ShortID() string {
	if len(k.KeyID) < 8 {
		return strings.ToLower(k.KeyID)
	}
	return strings.ToLower(k.KeyID[len(k.KeyID)-8:])
}

// Expired reports whether the key's expiry is at or before t.
func (k KeyInfo) Expired(t time.Time) bool {
	return k.Expires != nil && !k.Expires.After(t)
}

// Dearmor returns the binary OpenPGP packets of every armored block in text, in
// order. Input without an armor header is returned unchanged: a key file may be
// binary.
func Dearmor(data []byte) ([]byte, error) {
	if !bytes.Contains(data, []byte("-----BEGIN PGP")) {
		return data, nil
	}
	var out []byte
	var body []string
	in, headers := false, false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "-----BEGIN PGP"):
			in, headers, body = true, true, nil
		case strings.HasPrefix(line, "-----END PGP"):
			if in {
				raw, err := base64.StdEncoding.DecodeString(strings.Join(body, ""))
				if err != nil {
					return nil, errors.New("armored key block is not valid base64")
				}
				out = append(out, raw...)
			}
			in = false
		case !in:
		case headers:
			// Armor headers ("Version: ...") end at the first blank line; an
			// armor with no headers has the blank line anyway.
			if line == "" {
				headers = false
			} else if !strings.Contains(line, ": ") && !strings.HasSuffix(line, ":") {
				headers = false
				body = append(body, line)
			}
		case strings.HasPrefix(line, "="):
			// The CRC-24 line, which no one needs here.
		default:
			body = append(body, line)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no armored key block")
	}
	return out, nil
}

// ReadKeys parses the primary keys in a key file (armored or binary).
func ReadKeys(data []byte) ([]KeyInfo, error) {
	raw, err := Dearmor(data)
	if err != nil {
		return nil, err
	}
	var keys []KeyInfo
	var cur *KeyInfo
	var curSelf time.Time // creation time of the self-signature the expiry came from
	var curBody []byte
	inSub := false
	err = walkPackets(raw, func(tag int, body []byte) {
		switch tag {
		case 6: // public key
			k, ok := parsePublicKey(body)
			if !ok {
				cur = nil
				return
			}
			keys = append(keys, k)
			cur = &keys[len(keys)-1]
			curSelf, curBody, inSub = time.Time{}, body, false
		case 14: // public subkey: signatures after it are about the subkey
			inSub = true
		case 2: // signature
			if cur == nil || inSub {
				return
			}
			applySelfSig(cur, &curSelf, curBody, body)
		}
	})
	if err != nil && len(keys) == 0 {
		return nil, err
	}
	return keys, nil
}

// walkPackets calls fn for every packet.
func walkPackets(b []byte, fn func(tag int, body []byte)) error {
	for len(b) > 0 {
		hdr := b[0]
		if hdr&0x80 == 0 {
			return errors.New("not an OpenPGP packet")
		}
		var tag, n, hl int
		if hdr&0x40 != 0 { // new format
			tag = int(hdr & 0x3f)
			if len(b) < 2 {
				return errors.New("truncated packet")
			}
			switch l := int(b[1]); {
			case l < 192:
				n, hl = l, 2
			case l < 224:
				if len(b) < 3 {
					return errors.New("truncated packet")
				}
				n, hl = (l-192)<<8+int(b[2])+192, 3
			case l == 255:
				if len(b) < 6 {
					return errors.New("truncated packet")
				}
				n, hl = int(binary.BigEndian.Uint32(b[2:6])), 6
			default:
				return errors.New("partial-length packet in a key file")
			}
		} else { // old format
			tag = int(hdr>>2) & 0xf
			switch hdr & 3 {
			case 0:
				if len(b) < 2 {
					return errors.New("truncated packet")
				}
				n, hl = int(b[1]), 2
			case 1:
				if len(b) < 3 {
					return errors.New("truncated packet")
				}
				n, hl = int(binary.BigEndian.Uint16(b[1:3])), 3
			case 2:
				if len(b) < 5 {
					return errors.New("truncated packet")
				}
				n, hl = int(binary.BigEndian.Uint32(b[1:5])), 5
			default:
				n, hl = len(b)-1, 1
			}
		}
		if hl+n > len(b) || n < 0 {
			return errors.New("truncated packet")
		}
		fn(tag, b[hl:hl+n])
		b = b[hl+n:]
	}
	return nil
}

// parsePublicKey reads the creation time and, for a v4 key, the fingerprint.
// A v3 key has a validity period in the packet itself.
func parsePublicKey(body []byte) (KeyInfo, bool) {
	if len(body) < 6 {
		return KeyInfo{}, false
	}
	created := time.Unix(int64(binary.BigEndian.Uint32(body[1:5])), 0).UTC()
	k := KeyInfo{Created: created}
	switch body[0] {
	case 3:
		if len(body) < 8 {
			return KeyInfo{}, false
		}
		if days := binary.BigEndian.Uint16(body[5:7]); days > 0 {
			e := created.Add(time.Duration(days) * 24 * time.Hour)
			k.Expires = &e
		}
		// A v3 key id is the low 64 bits of the RSA modulus: not needed here.
		return k, true
	case 4:
		h := sha1.New() //nolint:gosec
		h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
		h.Write(body)
		fp := h.Sum(nil)
		k.Fingerprint = strings.ToUpper(hex.EncodeToString(fp))
		k.KeyID = k.Fingerprint[len(k.Fingerprint)-16:]
		return k, true
	}
	return KeyInfo{}, false
}

// applySelfSig reads a signature packet that follows a primary key. Self
// signatures (certifications and direct-key signatures made by the key itself)
// carry the key's expiry; the latest one wins. A key revocation marks the key
// revoked.
func applySelfSig(k *KeyInfo, latest *time.Time, keyBody, sig []byte) {
	if len(sig) < 6 || sig[0] != 4 {
		return
	}
	typ := sig[1]
	hashedLen := int(binary.BigEndian.Uint16(sig[4:6]))
	if len(sig) < 6+hashedLen+2 {
		return
	}
	hashed := sig[6 : 6+hashedLen]
	unhashedLen := int(binary.BigEndian.Uint16(sig[6+hashedLen : 8+hashedLen]))
	var unhashed []byte
	if len(sig) >= 8+hashedLen+unhashedLen {
		unhashed = sig[8+hashedLen : 8+hashedLen+unhashedLen]
	}

	var created time.Time
	var keyExp uint32
	haveExp := false
	issuerOK, issuerSeen := false, false
	check := func(sub []byte, hashed bool) {
		walkSubpackets(sub, func(t byte, d []byte) {
			switch t {
			case 2:
				if hashed && len(d) == 4 {
					created = time.Unix(int64(binary.BigEndian.Uint32(d)), 0).UTC()
				}
			case 9:
				if hashed && len(d) == 4 {
					keyExp, haveExp = binary.BigEndian.Uint32(d), true
				}
			case 16: // issuer key id
				if len(d) == 8 {
					issuerSeen = true
					if strings.EqualFold(hex.EncodeToString(d), k.KeyID) {
						issuerOK = true
					}
				}
			case 33: // issuer fingerprint: version byte + fingerprint
				if len(d) == 21 {
					issuerSeen = true
					if strings.EqualFold(hex.EncodeToString(d[1:]), k.Fingerprint) {
						issuerOK = true
					}
				}
			}
		})
	}
	check(hashed, true)
	check(unhashed, false)
	if issuerSeen && !issuerOK {
		return // someone else's signature on this key
	}
	switch typ {
	case 0x20: // key revocation
		k.Revoked = true
	case 0x10, 0x11, 0x12, 0x13, 0x1f:
		if !created.Before(*latest) {
			*latest = created
			if haveExp && keyExp > 0 {
				e := k.Created.Add(time.Duration(keyExp) * time.Second)
				k.Expires = &e
			} else {
				k.Expires = nil
			}
		}
	}
}

func walkSubpackets(b []byte, fn func(t byte, data []byte)) {
	for len(b) > 0 {
		var n, hl int
		switch l := int(b[0]); {
		case l < 192:
			n, hl = l, 1
		case l < 255:
			if len(b) < 2 {
				return
			}
			n, hl = (l-192)<<8+int(b[1])+192, 2
		default:
			if len(b) < 5 {
				return
			}
			n, hl = int(binary.BigEndian.Uint32(b[1:5])), 5
		}
		if n < 1 || hl+n > len(b) {
			return
		}
		fn(b[hl]&0x7f, b[hl+1:hl+n])
		b = b[hl+n:]
	}
}
