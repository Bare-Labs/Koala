package update

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type Executor interface {
	Stage(ctx context.Context, device Device, manifest Manifest) error
	Apply(ctx context.Context, device Device) error
	Rollback(ctx context.Context, device Device, reason string) error
}

type NoopExecutor struct{}

func (NoopExecutor) Stage(_ context.Context, _ Device, _ Manifest) error  { return nil }
func (NoopExecutor) Apply(_ context.Context, _ Device) error              { return nil }
func (NoopExecutor) Rollback(_ context.Context, _ Device, _ string) error { return nil }

type HTTPExecutor struct {
	token  string
	client *http.Client
}

func NewHTTPExecutor(token string, timeout time.Duration) *HTTPExecutor {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &HTTPExecutor{
		token:  token,
		client: &http.Client{Timeout: timeout},
	}
}

func (e *HTTPExecutor) Stage(ctx context.Context, device Device, manifest Manifest) error {
	return e.post(ctx, device.Address, "/agent/updates/stage", map[string]any{"manifest": manifest})
}

func (e *HTTPExecutor) Apply(ctx context.Context, device Device) error {
	return e.post(ctx, device.Address, "/agent/updates/apply", map[string]any{})
}

func (e *HTTPExecutor) Rollback(ctx context.Context, device Device, reason string) error {
	return e.post(ctx, device.Address, "/agent/updates/rollback", map[string]any{"reason": reason})
}

func (e *HTTPExecutor) post(ctx context.Context, base string, route string, payload any) error {
	endpoint, err := resolveEndpoint(base, route)
	if err != nil {
		return err
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.token)

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("agent call failed status=%d body=%s", resp.StatusCode, string(data))
	}
	return nil
}

func resolveEndpoint(base string, route string) (string, error) {
	trimmed := strings.TrimSpace(base)
	if trimmed == "" {
		return "", fmt.Errorf("device address is required")
	}
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		trimmed = "http://" + trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid device address: %w", err)
	}
	u.Path = path.Join(u.Path, route)
	return u.String(), nil
}
