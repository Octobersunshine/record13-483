package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"image-safety-detector/detector"
	"image-safety-detector/handler"
)

func main() {
	port := flag.Int("port", 8080, "server port")
	workers := flag.Int("workers", runtime.NumCPU(), "number of worker goroutines in detector pool")
	queue := flag.Int("queue", 128, "detector pool task queue size")
	flag.Parse()

	pool := detector.NewPool(
		detector.WithWorkerCount(*workers),
		detector.WithQueueSize(*queue),
	)
	log.Printf("detector pool initialized: workers=%d, queue_size=%d", *workers, *queue)

	h := handler.NewHandler(pool)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/detect", h.HandleDetect)
	mux.HandleFunc("POST /api/detect/form", h.HandleDetectForm)
	mux.HandleFunc("POST /api/detect/batch", h.HandleBatchDetect)
	mux.HandleFunc("GET /api/health", h.HandleHealth)
	mux.HandleFunc("GET /api/pool/stats", h.HandlePoolStats)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", *port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("image safety detector server starting on %s", addr)
	log.Printf("endpoints:")
	log.Printf("  POST /api/detect        - JSON body: {\"image_path\": \"<local_path>\"}")
	log.Printf("  POST /api/detect/form   - Form body: image_path=<local_path>")
	log.Printf("  POST /api/detect/batch  - JSON body: {\"image_paths\": [\"<path1>\", \"<path2>\", ...]}")
	log.Printf("  GET  /api/health        - health check with pool info")
	log.Printf("  GET  /api/pool/stats    - detector pool statistics")

	serverErrCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
		} else {
			serverErrCh <- nil
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	select {
	case sig := <-sigCh:
		log.Printf("received signal: %v, initiating graceful shutdown...", sig)
	case err := <-serverErrCh:
		if err != nil {
			log.Fatalf("server error: %v", err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown warning: %v", err)
	}
	log.Printf("http server stopped")

	if err := pool.Shutdown(10 * time.Second); err != nil {
		log.Printf("pool shutdown warning: %v", err)
	}
	wc, qs, pending, processed := pool.Stats()
	log.Printf("detector pool shutdown final stats: workers=%d, queue_size=%d, pending=%d, total_processed=%d",
		wc, qs, pending, processed)

	log.Printf("shutdown complete")
}
