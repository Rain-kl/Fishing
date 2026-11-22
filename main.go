package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"Fishing/internal/api"
	"Fishing/internal/manager"
	"Fishing/internal/sshpot"
	"Fishing/internal/store"
	"Fishing/web"
)

var version = "dev"

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	addr := flag.String("addr", envOrDefault("FISHING_ADDR", ":8080"), "HTTP console listen address")
	dataDir := flag.String("data-dir", envOrDefault("FISHING_DATA_DIR", "./data"), "persistent data directory")
	bindHost := flag.String("bind-host", envOrDefault("FISHING_BIND_HOST", "0.0.0.0"), "honeypot bind host address")
	flag.Parse()

	st, err := store.New(*dataDir)
	if err != nil {
		log.Fatalf("initialize store: %v", err)
	}

	hostKey, err := sshpot.LoadOrCreateHostKey(*dataDir)
	if err != nil {
		log.Fatalf("initialize SSH host key: %v", err)
	}

	webPort := manager.ParsePortFromAddr(*addr)
	mgr := manager.New(st, *bindHost, webPort, hostKey)
	mgr.Restore()

	staticFS, err := web.StaticFS()
	if err != nil {
		log.Fatalf("load embedded static assets: %v", err)
	}

	apiServer := api.NewServer(mgr, staticFS, version)
	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("Fishing console listening on %s (data-dir=%s, bind-host=%s, version=%s)", *addr, *dataDir, *bindHost, version)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		if err != nil {
			mgr.CloseAll()
			log.Fatalf("http server error: %v", err)
		}
	case <-sigCtx.Done():
		log.Println("Shutting down Fishing platform...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		mgr.CloseAll()
	}
}
