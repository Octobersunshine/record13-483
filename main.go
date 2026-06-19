package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"image-safety-detector/handler"
)

func main() {
	port := flag.Int("port", 8080, "server port")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/detect", handler.HandleDetect)
	mux.HandleFunc("POST /api/detect/form", handler.HandleDetectForm)
	mux.HandleFunc("GET /api/health", handler.HandleHealth)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("image safety detector server starting on %s", addr)
	log.Printf("endpoints:")
	log.Printf("  POST /api/detect       - JSON body: {\"image_path\": \"<local_path>\"}")
	log.Printf("  POST /api/detect/form  - Form body: image_path=<local_path>")
	log.Printf("  GET  /api/health       - health check")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
