package update

import (
	"context"
	"fmt"
	"sync"
)

type Agent interface {
	Stage(ctx context.Context, manifest Manifest) error
	Apply(ctx context.Context) error
	Rollback(ctx context.Context, reason string) error
	Health(ctx context.Context) (map[string]any, error)
}

type MemoryAgent struct {
	mu        sync.Mutex
	current   string
	previous  string
	staged    *Manifest
	status    string
	lastError string
}

func NewMemoryAgent(currentVersion string) *MemoryAgent {
	if currentVersion == "" {
		currentVersion = "0.1.0-dev"
	}
	return &MemoryAgent{current: currentVersion, status: "healthy"}
}

func (a *MemoryAgent) Stage(_ context.Context, manifest Manifest) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.staged = &manifest
	a.status = "staged"
	a.lastError = ""
	return nil
}

func (a *MemoryAgent) Apply(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.staged == nil {
		return fmt.Errorf("no staged update")
	}
	a.previous = a.current
	a.current = a.staged.Version
	a.staged = nil
	a.status = "healthy"
	a.lastError = ""
	return nil
}

func (a *MemoryAgent) Rollback(_ context.Context, reason string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.previous == "" {
		return fmt.Errorf("no previous version")
	}
	a.current = a.previous
	a.status = "rolled_back"
	a.lastError = reason
	a.staged = nil
	return nil
}

func (a *MemoryAgent) Health(_ context.Context) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	staged := ""
	if a.staged != nil {
		staged = a.staged.Version
	}
	return map[string]any{
		"status":          a.status,
		"current_version": a.current,
		"staged_version":  staged,
		"last_error":      a.lastError,
	}, nil
}
