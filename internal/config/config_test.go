package config

import "testing"

func TestValidateUpdateKeyRequiredWhenEnabled(t *testing.T) {
	cfg := Config{
		MCPToken: "token",
		Worker:   WorkerConfig{URL: "http://worker:8090"},
		Update:   UpdateConfig{Enabled: true, PublicKeyBase64: "", EncryptionKeyBase64: ""},
		Cameras:  []CameraConfig{{ID: "cam1", ZoneID: "front_door"}},
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for missing update key")
	}
}

func TestValidateUpdateEncryptionKeyRequiredWhenEnabled(t *testing.T) {
	cfg := Config{
		MCPToken: "token",
		Worker:   WorkerConfig{URL: "http://worker:8090"},
		Update:   UpdateConfig{Enabled: true, PublicKeyBase64: "abc", EncryptionKeyBase64: ""},
		Cameras:  []CameraConfig{{ID: "cam1", ZoneID: "front_door"}},
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for missing update encryption key")
	}
}

func TestValidateUpdateKeyNotRequiredWhenDisabled(t *testing.T) {
	cfg := Config{
		MCPToken: "token",
		Worker:   WorkerConfig{URL: "http://worker:8090"},
		Update:   UpdateConfig{Enabled: false},
		Cameras:  []CameraConfig{{ID: "cam1", ZoneID: "front_door"}},
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidateUpdateRotationConfig(t *testing.T) {
	cfg := Config{
		MCPToken: "token",
		Worker:   WorkerConfig{URL: "http://worker:8090"},
		Update: UpdateConfig{
			Enabled:             true,
			ActiveKeyID:         "key-2026-03",
			PreviousKeys:        []string{"key-2026-02"},
			PublicKeys:          map[string]string{"key-2026-03": "abc", "key-2026-02": "def"},
			EncryptionKeyBase64: "xyz",
		},
		Cameras: []CameraConfig{{ID: "cam1", ZoneID: "front_door"}},
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidateUpdateRotationPreviousMissingKey(t *testing.T) {
	cfg := Config{
		MCPToken: "token",
		Worker:   WorkerConfig{URL: "http://worker:8090"},
		Update: UpdateConfig{
			Enabled:             true,
			ActiveKeyID:         "key-2026-03",
			PreviousKeys:        []string{"key-2026-02"},
			PublicKeys:          map[string]string{"key-2026-03": "abc"},
			EncryptionKeyBase64: "xyz",
		},
		Cameras: []CameraConfig{{ID: "cam1", ZoneID: "front_door"}},
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for missing previous key")
	}
}
