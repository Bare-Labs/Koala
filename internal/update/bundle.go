package update

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const bundleCipherAES256GCM = "AES-256-GCM"

type Bundle struct {
	KeyID            string `json:"key_id"`
	Version          string `json:"version"`
	CreatedAt        string `json:"created_at"`
	Cipher           string `json:"cipher"`
	NonceBase64      string `json:"nonce_base64"`
	CiphertextBase64 string `json:"ciphertext_base64"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	ArtifactSHA256   string `json:"artifact_sha256"`
	PlaintextSize    int    `json:"plaintext_size"`
	Signature        string `json:"signature"`
}

func ParseAES256KeyBase64(keyB64 string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyB64))
	if err != nil {
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes for AES-256-GCM")
	}
	return decoded, nil
}

func EncryptAndSignBundle(artifact []byte, keyID string, version string, createdAt string, encKey []byte, signer ed25519.PrivateKey) (Bundle, error) {
	if len(encKey) != 32 {
		return Bundle{}, fmt.Errorf("encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return Bundle{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Bundle{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Bundle{}, err
	}
	ciphertext := aead.Seal(nil, nonce, artifact, nil)

	artifactSum := sha256.Sum256(artifact)
	ciphertextSum := sha256.Sum256(ciphertext)
	bundle := Bundle{
		KeyID:            keyID,
		Version:          version,
		CreatedAt:        createdAt,
		Cipher:           bundleCipherAES256GCM,
		NonceBase64:      base64.StdEncoding.EncodeToString(nonce),
		CiphertextBase64: base64.StdEncoding.EncodeToString(ciphertext),
		CiphertextSHA256: hex.EncodeToString(ciphertextSum[:]),
		ArtifactSHA256:   hex.EncodeToString(artifactSum[:]),
		PlaintextSize:    len(artifact),
	}
	sig := ed25519.Sign(signer, []byte(BundleSigningPayload(bundle)))
	bundle.Signature = base64.StdEncoding.EncodeToString(sig)
	return bundle, nil
}

func DecryptBundle(bundle Bundle, encKey []byte) ([]byte, error) {
	if bundle.Cipher != bundleCipherAES256GCM {
		return nil, fmt.Errorf("unsupported cipher: %s", bundle.Cipher)
	}
	if len(encKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes")
	}
	nonce, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bundle.NonceBase64))
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bundle.CiphertextBase64))
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	ciphertextSum := sha256.Sum256(ciphertext)
	if hex.EncodeToString(ciphertextSum[:]) != strings.ToLower(strings.TrimSpace(bundle.CiphertextSHA256)) {
		return nil, fmt.Errorf("ciphertext sha256 mismatch")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt bundle: %w", err)
	}
	if bundle.PlaintextSize > 0 && len(plaintext) != bundle.PlaintextSize {
		return nil, fmt.Errorf("plaintext size mismatch")
	}
	return plaintext, nil
}
