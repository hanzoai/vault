// Vault is the PCI-compliant card tokenization service.
// It runs as a standalone binary in a separate security zone (CDE).
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/hanzoai/vault/api"
	"github.com/hanzoai/vault/audit"
	"github.com/hanzoai/vault/crypto"
	"github.com/hanzoai/vault/store"
)

func main() {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = ":8443"
	}

	// Initialize key manager (in production: HSM-backed)
	km, err := crypto.NewKeyManager()
	if err != nil {
		log.Fatalf("Failed to initialize key manager: %v", err)
	}

	// Initialize storage (in production: PostgreSQL with encryption at rest)
	cardStore := store.NewMemoryStore()

	// Initialize audit logger (in production: append-only database)
	auditLogger := audit.NewMemoryLogger()

	// Initialize vault service
	v := store.NewVault(cardStore, km)

	// Initialize HTTP handler
	handler := api.NewHandler(v, auditLogger)

	mux := http.NewServeMux()

	// Card endpoints
	mux.HandleFunc("POST /vault/cards", handler.Tokenize)
	mux.HandleFunc("POST /vault/cards/{token}/detokenize", func(w http.ResponseWriter, r *http.Request) {
		handler.Detokenize(w, r, r.PathValue("token"))
	})
	mux.HandleFunc("GET /vault/cards/{token}", func(w http.ResponseWriter, r *http.Request) {
		handler.GetMetadata(w, r, r.PathValue("token"))
	})
	mux.HandleFunc("DELETE /vault/cards/{token}", func(w http.ResponseWriter, r *http.Request) {
		handler.Delete(w, r, r.PathValue("token"))
	})
	mux.HandleFunc("POST /vault/cards/{token}/rotate", func(w http.ResponseWriter, r *http.Request) {
		handler.Rotate(w, r, r.PathValue("token"))
	})

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	log.Printf("Vault service starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
