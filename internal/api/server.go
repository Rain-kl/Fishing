package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"Fishing/internal/manager"
	"Fishing/internal/model"
)

// Server exposes the management HTTP API and embedded static console.
type Server struct {
	mgr     *manager.Manager
	version string
	handler http.Handler
}

// NewServer constructs an HTTP handler wiring API routes and static console assets.
func NewServer(mgr *manager.Manager, staticFS fs.FS, version string) *Server {
	if version == "" {
		version = "dev"
	}
	s := &Server{
		mgr:     mgr,
		version: version,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/overview", s.handleOverview)
	mux.HandleFunc("GET /api/honeypots", s.handleListHoneypots)
	mux.HandleFunc("POST /api/honeypots", s.handleCreateHoneypot)
	mux.HandleFunc("POST /api/honeypots/{id}/start", s.handleStartHoneypot)
	mux.HandleFunc("POST /api/honeypots/{id}/stop", s.handleStopHoneypot)
	mux.HandleFunc("DELETE /api/honeypots/{id}", s.handleDeleteHoneypot)
	mux.HandleFunc("GET /api/logs", s.handleQueryLogs)
	mux.HandleFunc("DELETE /api/logs", s.handleClearLogs)

	if staticFS != nil {
		mux.Handle("GET /", http.FileServerFS(staticFS))
	}

	s.handler = s.withSecurityHeaders(mux)
	return s
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": s.version,
	})
}

func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Overview(s.version))
}

func (s *Server) handleListHoneypots(w http.ResponseWriter, _ *http.Request) {
	list := s.mgr.List()
	writeJSON(w, http.StatusOK, map[string]any{
		"honeypots": list,
	})
}

func (s *Server) handleCreateHoneypot(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	defer r.Body.Close()

	var req model.CreateHoneypotRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload: "+err.Error())
		return
	}

	view, err := s.mgr.Create(req)
	if err != nil {
		writeManagerError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"honeypot": view,
	})
}

func (s *Server) handleStartHoneypot(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "honeypot id is required")
		return
	}
	view, err := s.mgr.Start(id)
	if err != nil {
		writeManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"honeypot": view,
	})
}

func (s *Server) handleStopHoneypot(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "honeypot id is required")
		return
	}
	view, err := s.mgr.Stop(id)
	if err != nil {
		writeManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"honeypot": view,
	})
}

func (s *Server) handleDeleteHoneypot(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "honeypot id is required")
		return
	}
	if err := s.mgr.Delete(id); err != nil {
		writeManagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"deleted": id,
	})
}

func (s *Server) handleQueryLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 200
	if rawLimit := q.Get("limit"); rawLimit != "" {
		if parsed, err := strconv.Atoi(rawLimit); err == nil {
			limit = parsed
		}
	}

	filter := model.LogFilter{
		HoneypotID: strings.TrimSpace(q.Get("honeypot_id")),
		EventType:  strings.TrimSpace(q.Get("event_type")),
		SourceIP:   strings.TrimSpace(q.Get("source_ip")),
		Query:      strings.TrimSpace(q.Get("q")),
		Limit:      limit,
	}

	logs, total := s.mgr.QueryLogs(filter)
	writeJSON(w, http.StatusOK, map[string]any{
		"logs":  logs,
		"total": total,
	})
}

func (s *Server) handleClearLogs(w http.ResponseWriter, r *http.Request) {
	honeypotID := strings.TrimSpace(r.URL.Query().Get("honeypot_id"))
	if err := s.mgr.ClearLogs(honeypotID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "cleared",
	})
}

func writeManagerError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, manager.ErrValidation):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, manager.ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, manager.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, manager.ErrBindFailed):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
