// Package api provides HTTP handlers for the vault service.
package api

import (
	"encoding/json"
	"net/http"

	"github.com/hanzoai/vault/audit"
	"github.com/hanzoai/vault/auth"
	"github.com/hanzoai/vault/store"
)

// Handler wraps the vault service for HTTP.
type Handler struct {
	vault  *store.Vault
	audit  audit.Logger
}

// NewHandler creates a new API handler.
func NewHandler(vault *store.Vault, logger audit.Logger) *Handler {
	return &Handler{
		vault: vault,
		audit: logger,
	}
}

// Tokenize handles POST /vault/cards — tokenize a card.
func (h *Handler) Tokenize(w http.ResponseWriter, r *http.Request) {
	identity := identityFromContext(r)

	if err := auth.Authorize(identity.Role, auth.OpTokenize); err != nil {
		h.audit.Log(audit.Event{
			Type:     audit.EventTokenize,
			Actor:    identity.Subject,
			TenantId: identity.TenantId,
			Success:  false,
			Error:    err.Error(),
			IP:       r.RemoteAddr,
		})
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var req store.TokenizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Enforce tenant isolation
	req.TenantId = identity.TenantId

	resp, err := h.vault.Tokenize(&req)
	if err != nil {
		h.audit.Log(audit.Event{
			Type:     audit.EventTokenize,
			Actor:    identity.Subject,
			TenantId: identity.TenantId,
			Success:  false,
			Error:    err.Error(),
			IP:       r.RemoteAddr,
		})
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.audit.Log(audit.Event{
		Type:     audit.EventTokenize,
		Actor:    identity.Subject,
		TenantId: identity.TenantId,
		Token:    resp.Token,
		Success:  true,
		IP:       r.RemoteAddr,
	})

	writeJSON(w, http.StatusCreated, resp)
}

// Detokenize handles POST /vault/cards/:token/detokenize.
func (h *Handler) Detokenize(w http.ResponseWriter, r *http.Request, token string) {
	identity := identityFromContext(r)

	if err := auth.Authorize(identity.Role, auth.OpDetokenize); err != nil {
		h.audit.Log(audit.Event{
			Type:     audit.EventDetokenize,
			Actor:    identity.Subject,
			TenantId: identity.TenantId,
			Token:    token,
			Success:  false,
			Error:    err.Error(),
			IP:       r.RemoteAddr,
		})
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	pan, err := h.vault.Detokenize(token)
	if err != nil {
		h.audit.Log(audit.Event{
			Type:     audit.EventDetokenize,
			Actor:    identity.Subject,
			TenantId: identity.TenantId,
			Token:    token,
			Success:  false,
			Error:    err.Error(),
			IP:       r.RemoteAddr,
		})
		writeError(w, http.StatusNotFound, "card not found")
		return
	}

	h.audit.Log(audit.Event{
		Type:     audit.EventDetokenize,
		Actor:    identity.Subject,
		TenantId: identity.TenantId,
		Token:    token,
		Success:  true,
		IP:       r.RemoteAddr,
	})

	writeJSON(w, http.StatusOK, map[string]string{"pan": pan})
}

// GetMetadata handles GET /vault/cards/:token.
func (h *Handler) GetMetadata(w http.ResponseWriter, r *http.Request, token string) {
	identity := identityFromContext(r)

	if err := auth.Authorize(identity.Role, auth.OpMetadata); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	meta, err := h.vault.GetMetadata(token)
	if err != nil {
		writeError(w, http.StatusNotFound, "card not found")
		return
	}

	h.audit.Log(audit.Event{
		Type:     audit.EventMetadata,
		Actor:    identity.Subject,
		TenantId: identity.TenantId,
		Token:    token,
		Success:  true,
		IP:       r.RemoteAddr,
	})

	writeJSON(w, http.StatusOK, meta)
}

// Delete handles DELETE /vault/cards/:token.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request, token string) {
	identity := identityFromContext(r)

	if err := auth.Authorize(identity.Role, auth.OpDelete); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	if err := h.vault.DeleteCard(token); err != nil {
		writeError(w, http.StatusNotFound, "card not found")
		return
	}

	h.audit.Log(audit.Event{
		Type:     audit.EventDelete,
		Actor:    identity.Subject,
		TenantId: identity.TenantId,
		Token:    token,
		Success:  true,
		IP:       r.RemoteAddr,
	})

	w.WriteHeader(http.StatusNoContent)
}

// Rotate handles POST /vault/cards/:token/rotate.
func (h *Handler) Rotate(w http.ResponseWriter, r *http.Request, token string) {
	identity := identityFromContext(r)

	if err := auth.Authorize(identity.Role, auth.OpRotate); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	newToken, err := h.vault.RotateToken(token)
	if err != nil {
		writeError(w, http.StatusNotFound, "card not found")
		return
	}

	h.audit.Log(audit.Event{
		Type:     audit.EventRotate,
		Actor:    identity.Subject,
		TenantId: identity.TenantId,
		Token:    newToken,
		Success:  true,
		IP:       r.RemoteAddr,
		Details:  "rotated from " + token,
	})

	writeJSON(w, http.StatusOK, map[string]string{"token": newToken})
}

// helpers

func identityFromContext(r *http.Request) *auth.Identity {
	// In production this extracts from mTLS cert or JWT.
	// For now, use headers.
	return &auth.Identity{
		Subject:  r.Header.Get("X-Vault-Subject"),
		TenantId: r.Header.Get("X-Vault-Tenant"),
		Role:     auth.Role(r.Header.Get("X-Vault-Role")),
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
