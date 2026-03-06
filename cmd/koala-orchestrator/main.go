package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/barelabs/koala/internal/camera"
	"github.com/barelabs/koala/internal/config"
	"github.com/barelabs/koala/internal/inference"
	"github.com/barelabs/koala/internal/mcp"
	"github.com/barelabs/koala/internal/service"
	"github.com/barelabs/koala/internal/state"
	"github.com/barelabs/koala/internal/update"
)

func main() {
	cfgPath := flag.String("config", "configs/koala.yaml", "path to config")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	registry := camera.NewRegistry(toCameras(cfg))
	prober := camera.Prober{Timeout: 2 * time.Second}
	for _, c := range registry.List() {
		if c.RTSPURL == "" {
			registry.SetStatus(c.ID, camera.StatusUnavailable)
			continue
		}
		result := prober.Probe(context.Background(), c)
		registry.SetStatus(c.ID, result.Status)
		if result.Error != "" {
			log.Printf("camera probe failed camera=%s err=%s", c.ID, result.Error)
		}
	}

	aggregator := state.NewAggregator(time.Duration(cfg.Runtime.FreshnessWindow) * time.Second)
	client := inference.NewHTTPClient(cfg.Worker.URL)
	svc := service.New(registry, aggregator, client, cfg.Runtime.QueueSize)
	var updater *update.Manager
	var agent update.Agent
	if cfg.Update.Enabled {
		executor := update.NewHTTPExecutor(cfg.MCPToken, 3*time.Second)
		updater = update.NewManager(cfg.Service.Version, "0.1.0-dev", cfg.Service.DeviceID, cfg.Service.Address, cfg.Service.Version, executor)
		var verifier update.Verifier
		if cfg.Update.PublicKeyBase64 != "" {
			edVerifier, verr := update.NewEd25519VerifierFromBase64(cfg.Update.PublicKeyBase64)
			if verr != nil {
				log.Fatalf("invalid update public key: %v", verr)
			}
			verifier = edVerifier
		} else {
			rotatingVerifier, verr := update.NewRotatingVerifier(cfg.Update.ActiveKeyID, cfg.Update.PublicKeys, cfg.Update.PreviousKeys)
			if verr != nil {
				log.Fatalf("invalid rotating update key configuration: %v", verr)
			}
			verifier = rotatingVerifier
		}
		encryptionKey, kerr := update.ParseAES256KeyBase64(cfg.Update.EncryptionKeyBase64)
		if kerr != nil {
			log.Fatalf("invalid update encryption key: %v", kerr)
		}
		agent = update.NewFileAgent(cfg.Service.Version, cfg.Update.StagingDir, cfg.Update.ActiveDir, update.NewHTTPDownloader(10*time.Second), verifier, encryptionKey)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)

	go func() {
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				healthy := svc.WorkerHealthy(ctx)
				if !healthy {
					log.Printf("worker health degraded")
				}
			}
		}
	}()

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mcp.NewServer(cfg.MCPToken, svc, updater, agent).Routes(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("koala orchestrator listening on %s", cfg.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
	<-sigch

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

func toCameras(cfg config.Config) []camera.Camera {
	cameras := make([]camera.Camera, 0, len(cfg.Cameras))
	for _, c := range cfg.Cameras {
		cameras = append(cameras, camera.Camera{
			ID:        c.ID,
			Name:      c.Name,
			RTSPURL:   c.RTSPURL,
			ZoneID:    c.ZoneID,
			FrontDoor: c.FrontDoor,
			Status:    camera.StatusUnknown,
		})
	}
	return cameras
}
