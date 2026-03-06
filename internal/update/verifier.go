package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

type Verifier interface {
	VerifyManifest(manifest Manifest) error
	VerifyBundle(bundle Bundle) error
}

type NoopVerifier struct{}

func (NoopVerifier) VerifyManifest(_ Manifest) error { return nil }
func (NoopVerifier) VerifyBundle(_ Bundle) error     { return nil }

type Ed25519Verifier struct {
	publicKey ed25519.PublicKey
}

func NewEd25519VerifierFromBase64(publicKeyB64 string) (*Ed25519Verifier, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	return &Ed25519Verifier{publicKey: ed25519.PublicKey(decoded)}, nil
}

func (v *Ed25519Verifier) VerifyManifest(manifest Manifest) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(manifest.Signature))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(v.publicKey, []byte(ManifestSigningPayload(manifest)), sig) {
		return fmt.Errorf("manifest signature verification failed")
	}
	return nil
}

func (v *Ed25519Verifier) VerifyBundle(bundle Bundle) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bundle.Signature))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(v.publicKey, []byte(BundleSigningPayload(bundle)), sig) {
		return fmt.Errorf("bundle signature verification failed")
	}
	return nil
}

type RotatingVerifier struct {
	allowed map[string]ed25519.PublicKey
}

func NewRotatingVerifier(activeKeyID string, publicKeys map[string]string, previousKeys []string) (*RotatingVerifier, error) {
	allowed := map[string]ed25519.PublicKey{}
	activeKeyID = strings.TrimSpace(activeKeyID)
	if activeKeyID == "" {
		return nil, fmt.Errorf("active_key_id is required")
	}
	if err := addKeyByID(allowed, activeKeyID, publicKeys); err != nil {
		return nil, err
	}
	for _, id := range previousKeys {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if err := addKeyByID(allowed, id, publicKeys); err != nil {
			return nil, err
		}
	}
	return &RotatingVerifier{allowed: allowed}, nil
}

func addKeyByID(allowed map[string]ed25519.PublicKey, keyID string, publicKeys map[string]string) error {
	b64, ok := publicKeys[keyID]
	if !ok {
		return fmt.Errorf("missing public key for key_id=%s", keyID)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return fmt.Errorf("decode public key for key_id=%s: %w", keyID, err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return fmt.Errorf("public key for key_id=%s must be %d bytes", keyID, ed25519.PublicKeySize)
	}
	allowed[keyID] = ed25519.PublicKey(decoded)
	return nil
}

func (v *RotatingVerifier) VerifyManifest(manifest Manifest) error {
	key, ok := v.allowed[strings.TrimSpace(manifest.KeyID)]
	if !ok {
		return fmt.Errorf("manifest key_id is not allowed")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(manifest.Signature))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(key, []byte(ManifestSigningPayload(manifest)), sig) {
		return fmt.Errorf("manifest signature verification failed")
	}
	return nil
}

func (v *RotatingVerifier) VerifyBundle(bundle Bundle) error {
	key, ok := v.allowed[strings.TrimSpace(bundle.KeyID)]
	if !ok {
		return fmt.Errorf("bundle key_id is not allowed")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bundle.Signature))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(key, []byte(BundleSigningPayload(bundle)), sig) {
		return fmt.Errorf("bundle signature verification failed")
	}
	return nil
}

func ManifestSigningPayload(m Manifest) string {
	return strings.Join([]string{
		m.KeyID,
		m.Version,
		m.ArtifactURL,
		m.SHA256,
		m.CreatedAt,
		m.MinOrchestratorVersion,
		m.MinWorkerVersion,
	}, "\n")
}

func BundleSigningPayload(b Bundle) string {
	return strings.Join([]string{
		b.KeyID,
		b.Version,
		b.CreatedAt,
		b.Cipher,
		b.NonceBase64,
		b.CiphertextSHA256,
		b.ArtifactSHA256,
		fmt.Sprintf("%d", b.PlaintextSize),
	}, "\n")
}
