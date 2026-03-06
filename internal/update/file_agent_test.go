package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type staticDownloader struct {
	payload []byte
	err     error
}

func (d staticDownloader) Download(_ context.Context, _ string) ([]byte, error) {
	return d.payload, d.err
}

func signedManifest(t *testing.T, priv ed25519.PrivateKey, payload []byte, version string, createdAt string) Manifest {
	t.Helper()
	sum := sha256.Sum256(payload)
	m := Manifest{
		KeyID:                  "key-2026-03",
		Version:                version,
		ArtifactURL:            "http://updates.local/koala.bundle.json",
		SHA256:                 hex.EncodeToString(sum[:]),
		CreatedAt:              createdAt,
		MinOrchestratorVersion: "0.1.0-dev",
		MinWorkerVersion:       "0.1.0-dev",
	}
	sig := ed25519.Sign(priv, []byte(ManifestSigningPayload(m)))
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	return m
}

func signedBundleJSON(t *testing.T, priv ed25519.PrivateKey, artifact []byte, keyID string, version string, createdAt string, encKey []byte) []byte {
	t.Helper()
	bundle, err := EncryptAndSignBundle(artifact, keyID, version, createdAt, encKey, priv)
	if err != nil {
		t.Fatalf("encrypt bundle: %v", err)
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return data
}

func TestFileAgentStageApplyRollback(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	verifier := &Ed25519Verifier{publicKey: pub}
	artifact := []byte("artifact-bytes")
	createdAt := "2026-03-06T00:00:00Z"
	manifest := signedManifest(t, priv, artifact, "0.2.0", createdAt)
	encKey := []byte("0123456789abcdef0123456789abcdef")
	bundlePayload := signedBundleJSON(t, priv, artifact, manifest.KeyID, manifest.Version, createdAt, encKey)

	agent := NewFileAgent("0.1.0", filepath.Join(dir, "staging"), filepath.Join(dir, "active"), staticDownloader{payload: bundlePayload}, verifier, encKey)
	if err := agent.Stage(context.Background(), manifest); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "staging", "0.2.0", "artifact.bin")); err != nil {
		t.Fatalf("expected staged artifact: %v", err)
	}

	if err := agent.Apply(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	currentVersion, err := os.ReadFile(filepath.Join(dir, "active", "current_version"))
	if err != nil {
		t.Fatalf("read current version: %v", err)
	}
	if string(currentVersion) != "0.2.0" {
		t.Fatalf("expected current version 0.2.0, got %s", string(currentVersion))
	}

	if err := agent.Rollback(context.Background(), "healthcheck_failed"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	currentVersion, err = os.ReadFile(filepath.Join(dir, "active", "current_version"))
	if err != nil {
		t.Fatalf("read current version after rollback: %v", err)
	}
	if string(currentVersion) != "0.1.0" {
		t.Fatalf("expected rollback version 0.1.0, got %s", string(currentVersion))
	}
}

func TestFileAgentStageChecksumMismatch(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	verifier := &Ed25519Verifier{publicKey: pub}
	createdAt := "2026-03-06T00:00:00Z"
	manifest := signedManifest(t, priv, []byte("expected"), "0.2.0", createdAt)
	encKey := []byte("0123456789abcdef0123456789abcdef")
	bundlePayload := signedBundleJSON(t, priv, []byte("wrong"), manifest.KeyID, manifest.Version, createdAt, encKey)

	agent := NewFileAgent("0.1.0", filepath.Join(dir, "staging"), filepath.Join(dir, "active"), staticDownloader{payload: bundlePayload}, verifier, encKey)
	if err := agent.Stage(context.Background(), manifest); err == nil {
		t.Fatalf("expected checksum mismatch error")
	}
}

func TestFileAgentStageSignatureFailure(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	verifier := &Ed25519Verifier{publicKey: pub}
	payload := []byte("artifact")
	createdAt := "2026-03-06T00:00:00Z"
	sum := sha256.Sum256(payload)
	manifest := Manifest{
		KeyID:       "key-2026-03",
		Version:     "0.2.0",
		ArtifactURL: "http://updates.local/koala.bundle.json",
		SHA256:      hex.EncodeToString(sum[:]),
		CreatedAt:   createdAt,
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(ManifestSigningPayload(manifest))))
	encKey := []byte("0123456789abcdef0123456789abcdef")
	bundlePayload := signedBundleJSON(t, priv, payload, manifest.KeyID, manifest.Version, createdAt, encKey)

	agent := NewFileAgent("0.1.0", filepath.Join(dir, "staging"), filepath.Join(dir, "active"), staticDownloader{payload: bundlePayload}, verifier, encKey)
	if err := agent.Stage(context.Background(), manifest); err == nil {
		t.Fatalf("expected signature verification error")
	}
}
