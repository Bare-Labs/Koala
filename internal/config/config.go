package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr string         `yaml:"listen_addr"`
	MCPToken   string         `yaml:"mcp_token"`
	Service    ServiceConfig  `yaml:"service"`
	Worker     WorkerConfig   `yaml:"worker"`
	Update     UpdateConfig   `yaml:"update"`
	Runtime    RuntimeConfig  `yaml:"runtime"`
	Cameras    []CameraConfig `yaml:"cameras"`
	Zones      []ZoneConfig   `yaml:"zones"`
}

type ServiceConfig struct {
	DeviceID string `yaml:"device_id"`
	Version  string `yaml:"version"`
	Address  string `yaml:"address"`
}

type WorkerConfig struct {
	URL string `yaml:"url"`
}

type UpdateConfig struct {
	Enabled             bool              `yaml:"enabled"`
	PublicKeyBase64     string            `yaml:"public_key_base64"`
	ActiveKeyID         string            `yaml:"active_key_id"`
	PreviousKeys        []string          `yaml:"previous_keys"`
	PublicKeys          map[string]string `yaml:"public_keys"`
	EncryptionKeyBase64 string            `yaml:"encryption_key_base64"`
	StagingDir          string            `yaml:"staging_dir"`
	ActiveDir           string            `yaml:"active_dir"`
}

type RuntimeConfig struct {
	QueueSize       int `yaml:"queue_size"`
	FreshnessWindow int `yaml:"freshness_window_seconds"`
}

type CameraConfig struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	RTSPURL     string `yaml:"rtsp_url"`
	ZoneID      string `yaml:"zone_id"`
	FrontDoor   bool   `yaml:"front_door"`
	ProbeAtBoot bool   `yaml:"probe_at_boot"`
}

type ZoneConfig struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode yaml: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.Runtime.QueueSize <= 0 {
		c.Runtime.QueueSize = 64
	}
	if c.Runtime.FreshnessWindow <= 0 {
		c.Runtime.FreshnessWindow = 90
	}
	if c.Service.DeviceID == "" {
		c.Service.DeviceID = "koala-local"
	}
	if c.Service.Version == "" {
		c.Service.Version = "0.1.0-dev"
	}
	if c.Service.Address == "" {
		c.Service.Address = "http://127.0.0.1:8080"
	}
	if c.Update.StagingDir == "" {
		c.Update.StagingDir = "/tmp/koala/staging"
	}
	if c.Update.ActiveDir == "" {
		c.Update.ActiveDir = "/tmp/koala/active"
	}
}

func (c Config) Validate() error {
	if c.MCPToken == "" {
		return fmt.Errorf("mcp_token is required")
	}
	if c.Worker.URL == "" {
		return fmt.Errorf("worker.url is required")
	}
	if len(c.Cameras) == 0 {
		return fmt.Errorf("at least one camera is required")
	}
	for _, camera := range c.Cameras {
		if camera.ID == "" {
			return fmt.Errorf("camera.id is required")
		}
		if camera.ZoneID == "" {
			return fmt.Errorf("camera.zone_id is required")
		}
	}
	if c.Update.Enabled && strings.TrimSpace(c.Update.PublicKeyBase64) == "" {
		if strings.TrimSpace(c.Update.ActiveKeyID) == "" {
			return fmt.Errorf("update.active_key_id is required when using key rotation config")
		}
		if len(c.Update.PublicKeys) == 0 {
			return fmt.Errorf("update.public_keys is required when using key rotation config")
		}
		if _, ok := c.Update.PublicKeys[c.Update.ActiveKeyID]; !ok {
			return fmt.Errorf("update.public_keys must include update.active_key_id")
		}
		for _, previousKeyID := range c.Update.PreviousKeys {
			if _, ok := c.Update.PublicKeys[previousKeyID]; !ok {
				return fmt.Errorf("update.public_keys must include all update.previous_keys entries")
			}
		}
	}
	if c.Update.Enabled && strings.TrimSpace(c.Update.EncryptionKeyBase64) == "" {
		return fmt.Errorf("update.encryption_key_base64 is required when update.enabled=true")
	}
	return nil
}
