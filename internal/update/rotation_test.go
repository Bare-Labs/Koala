package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestRotatingVerifierAcceptsPreviousKey(t *testing.T) {
	activePub, _, _ := ed25519.GenerateKey(nil)
	previousPub, previousPriv, _ := ed25519.GenerateKey(nil)

	verifier, err := NewRotatingVerifier(
		"key-active",
		map[string]string{
			"key-active":   base64.StdEncoding.EncodeToString(activePub),
			"key-previous": base64.StdEncoding.EncodeToString(previousPub),
		},
		[]string{"key-previous"},
	)
	if err != nil {
		t.Fatalf("new rotating verifier: %v", err)
	}

	manifest := Manifest{
		KeyID:       "key-previous",
		Version:     "0.2.0",
		ArtifactURL: "http://updates.local/koala.bundle.json",
		SHA256:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CreatedAt:   "2026-03-06T00:00:00Z",
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(previousPriv, []byte(ManifestSigningPayload(manifest))))
	if err := verifier.VerifyManifest(manifest); err != nil {
		t.Fatalf("verify manifest with previous key: %v", err)
	}
}

func TestRotatingVerifierRejectsUnknownKeyID(t *testing.T) {
	activePub, _, _ := ed25519.GenerateKey(nil)
	verifier, err := NewRotatingVerifier(
		"key-active",
		map[string]string{"key-active": base64.StdEncoding.EncodeToString(activePub)},
		nil,
	)
	if err != nil {
		t.Fatalf("new rotating verifier: %v", err)
	}

	manifest := Manifest{KeyID: "key-other", Signature: base64.StdEncoding.EncodeToString([]byte("x"))}
	if err := verifier.VerifyManifest(manifest); err == nil {
		t.Fatalf("expected rejection for unknown key_id")
	}
}
