package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestEncryptAndDecryptBundleRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encKey := []byte("0123456789abcdef0123456789abcdef")
	artifact := []byte("artifact-content")
	bundle, err := EncryptAndSignBundle(artifact, "key-2026-03", "0.2.0", "2026-03-06T00:00:00Z", encKey, priv)
	if err != nil {
		t.Fatalf("encrypt bundle: %v", err)
	}
	plaintext, err := DecryptBundle(bundle, encKey)
	if err != nil {
		t.Fatalf("decrypt bundle: %v", err)
	}
	if string(plaintext) != string(artifact) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestParseAES256KeyBase64(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	b64 := base64.StdEncoding.EncodeToString(key)
	parsed, err := ParseAES256KeyBase64(b64)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	if string(parsed) != string(key) {
		t.Fatalf("parsed key mismatch")
	}
}
