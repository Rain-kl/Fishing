package manager

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"Fishing/internal/model"
	"Fishing/internal/sshpot"
	"Fishing/internal/store"
	"golang.org/x/crypto/ssh"
)

var (
	ErrValidation = errors.New("validation failed")
	ErrConflict   = errors.New("resource conflict")
	ErrNotFound   = errors.New("honeypot not found")
	ErrBindFailed = errors.New("failed to bind honeypot listener")
)

// Manager orchestrates honeypot configurations, live SSH listeners, and log collection.
type Manager struct {
	store    *store.Store
	bindHost string
	webPort  int
	hostKey  ssh.Signer

	opMu    sync.Mutex
	stateMu sync.RWMutex
	servers map[string]*sshpot.Server
	errors  map[string]string
}

// New constructs a honeypot Manager.
func New(st *store.Store, bindHost string, webPort int, hostKey ssh.Signer) *Manager {
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	return &Manager{
		store:    st,
		bindHost: bindHost,
		webPort:  webPort,
		hostKey:  hostKey,
		servers:  make(map[string]*sshpot.Server),
		errors:   make(map[string]string),
	}
}

// Restore starts all persisted honeypots whose desired state is running.
func (m *Manager) Restore() {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	for _, hp := range m.store.ListHoneypots() {
		if hp.DesiredState != model.StatusRunning {
			continue
		}
		if err := m.startServerLocked(hp); err != nil {
			m.setError(hp.ID, err.Error())
		}
	}
}

// Create validates input, binds the SSH listener immediately, and persists the honeypot.
func (m *Manager) Create(req model.CreateHoneypotRequest) (model.HoneypotView, error) {
	hpType := strings.ToLower(strings.TrimSpace(req.Type))
	if hpType == "" {
		hpType = model.HoneypotTypeSSH
	}
	if hpType != model.HoneypotTypeSSH {
		return model.HoneypotView{}, fmt.Errorf("%w: unsupported honeypot type %q (only ssh is supported)", ErrValidation, hpType)
	}

	if req.Port < 1 || req.Port > 65535 {
		return model.HoneypotView{}, fmt.Errorf("%w: port must be between 1 and 65535", ErrValidation)
	}

	username := strings.TrimSpace(req.Username)
	if len(username) == 0 || len(username) > 64 || hasControlChars(username) {
		return model.HoneypotView{}, fmt.Errorf("%w: username must be 1-64 printable characters", ErrValidation)
	}

	if len(req.Password) == 0 || len(req.Password) > 128 || hasControlChars(req.Password) {
		return model.HoneypotView{}, fmt.Errorf("%w: password must be 1-128 printable characters", ErrValidation)
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = fmt.Sprintf("ssh-%d", req.Port)
	} else if len(name) > 64 || hasControlChars(name) {
		return model.HoneypotView{}, fmt.Errorf("%w: name must be at most 64 printable characters", ErrValidation)
	}

	m.opMu.Lock()
	defer m.opMu.Unlock()

	if m.webPort > 0 && req.Port == m.webPort {
		return model.HoneypotView{}, fmt.Errorf("%w: port %d is reserved by the management console", ErrConflict, req.Port)
	}
	for _, existing := range m.store.ListHoneypots() {
		if existing.Port == req.Port {
			return model.HoneypotView{}, fmt.Errorf("%w: port %d is already used by honeypot %s", ErrConflict, req.Port, existing.Name)
		}
	}

	hp := model.Honeypot{
		ID:           generateID(),
		Name:         name,
		Type:         hpType,
		Port:         req.Port,
		Username:     username,
		Password:     req.Password,
		DesiredState: model.StatusRunning,
		CreatedAt:    time.Now().UTC(),
	}

	srv, err := m.buildAndStartServer(hp)
	if err != nil {
		return model.HoneypotView{}, fmt.Errorf("%w: %v", ErrBindFailed, err)
	}

	if err := m.store.CreateHoneypot(hp); err != nil {
		srv.Stop()
		if errors.Is(err, store.ErrPortConflict) {
			return model.HoneypotView{}, fmt.Errorf("%w: %v", ErrConflict, err)
		}
		return model.HoneypotView{}, err
	}

	m.stateMu.Lock()
	m.servers[hp.ID] = srv
	delete(m.errors, hp.ID)
	m.stateMu.Unlock()

	return m.buildView(hp, store.HoneypotCounters{}), nil
}

// Start activates an existing honeypot listener.
func (m *Manager) Start(id string) (model.HoneypotView, error) {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	hp, ok := m.store.GetHoneypot(id)
	if !ok {
		return model.HoneypotView{}, ErrNotFound
	}

	if m.isRunning(id) {
		hp, err := m.store.UpdateDesiredState(id, model.StatusRunning)
		if err != nil {
			return model.HoneypotView{}, mapStoreErr(err)
		}
		counters, _ := m.store.ComputeStats()
		return m.buildView(hp, counters[id]), nil
	}

	if err := m.startServerLocked(hp); err != nil {
		m.setError(id, err.Error())
		return model.HoneypotView{}, fmt.Errorf("%w: %v", ErrBindFailed, err)
	}

	updated, err := m.store.UpdateDesiredState(id, model.StatusRunning)
	if err != nil {
		m.stopServerLocked(id)
		return model.HoneypotView{}, mapStoreErr(err)
	}

	counters, _ := m.store.ComputeStats()
	return m.buildView(updated, counters[id]), nil
}

// Stop halts a running honeypot listener and persists desired state as stopped.
func (m *Manager) Stop(id string) (model.HoneypotView, error) {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	if _, ok := m.store.GetHoneypot(id); !ok {
		return model.HoneypotView{}, ErrNotFound
	}

	m.stopServerLocked(id)
	m.clearError(id)

	updated, err := m.store.UpdateDesiredState(id, model.StatusStopped)
	if err != nil {
		return model.HoneypotView{}, mapStoreErr(err)
	}

	counters, _ := m.store.ComputeStats()
	return m.buildView(updated, counters[id]), nil
}

// Delete stops the honeypot if running and removes its configuration.
func (m *Manager) Delete(id string) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	if _, ok := m.store.GetHoneypot(id); !ok {
		return ErrNotFound
	}

	m.stopServerLocked(id)
	m.clearError(id)

	if err := m.store.DeleteHoneypot(id); err != nil {
		return mapStoreErr(err)
	}
	return nil
}

// List returns all honeypots enriched with runtime status and audit counters.
func (m *Manager) List() []model.HoneypotView {
	list := m.store.ListHoneypots()
	counters, _ := m.store.ComputeStats()

	views := make([]model.HoneypotView, 0, len(list))
	for _, hp := range list {
		views = append(views, m.buildView(hp, counters[hp.ID]))
	}
	return views
}

// Overview computes global telemetry counters including running instance count.
func (m *Manager) Overview(version string) model.OverviewStats {
	_, overview := m.store.ComputeStats()

	m.stateMu.RLock()
	running := len(m.servers)
	m.stateMu.RUnlock()

	overview.RunningHoneypots = running
	overview.Version = version
	return overview
}

// QueryLogs proxies filtered audit log queries to the underlying store.
func (m *Manager) QueryLogs(filter model.LogFilter) ([]model.LogEntry, int) {
	return m.store.QueryLogs(filter)
}

// ClearLogs removes persisted logs globally or for a specific honeypot.
func (m *Manager) ClearLogs(honeypotID string) error {
	return m.store.ClearLogs(honeypotID)
}

// CloseAll shuts down every active SSH honeypot listener cleanly.
func (m *Manager) CloseAll() {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	m.stateMu.Lock()
	servers := make([]*sshpot.Server, 0, len(m.servers))
	for id, srv := range m.servers {
		servers = append(servers, srv)
		delete(m.servers, id)
	}
	m.stateMu.Unlock()

	for _, srv := range servers {
		srv.Stop()
	}
}

func (m *Manager) buildAndStartServer(hp model.Honeypot) (*sshpot.Server, error) {
	srv, err := sshpot.New(hp, m.bindHost, m.hostKey, func(entry model.LogEntry) {
		_ = m.store.AppendLog(entry)
	})
	if err != nil {
		return nil, err
	}
	srv.Start()
	return srv, nil
}

func (m *Manager) startServerLocked(hp model.Honeypot) error {
	srv, err := m.buildAndStartServer(hp)
	if err != nil {
		return err
	}
	m.stateMu.Lock()
	m.servers[hp.ID] = srv
	delete(m.errors, hp.ID)
	m.stateMu.Unlock()
	return nil
}

func (m *Manager) stopServerLocked(id string) {
	m.stateMu.Lock()
	srv, ok := m.servers[id]
	if ok {
		delete(m.servers, id)
	}
	m.stateMu.Unlock()

	if ok && srv != nil {
		srv.Stop()
	}
}

func (m *Manager) isRunning(id string) bool {
	m.stateMu.RLock()
	_, ok := m.servers[id]
	m.stateMu.RUnlock()
	return ok
}

func (m *Manager) setError(id, msg string) {
	m.stateMu.Lock()
	m.errors[id] = msg
	m.stateMu.Unlock()
}

func (m *Manager) clearError(id string) {
	m.stateMu.Lock()
	delete(m.errors, id)
	m.stateMu.Unlock()
}

func (m *Manager) buildView(hp model.Honeypot, c store.HoneypotCounters) model.HoneypotView {
	m.stateMu.RLock()
	_, running := m.servers[hp.ID]
	errMsg := m.errors[hp.ID]
	m.stateMu.RUnlock()

	status := model.StatusStopped
	if running {
		status = model.StatusRunning
	} else if errMsg != "" {
		status = model.StatusError
	}

	return model.HoneypotView{
		Honeypot:         hp,
		Status:           status,
		ErrorMessage:     errMsg,
		ConnectionCount:  c.ConnectionCount,
		AuthSuccessCount: c.AuthSuccessCount,
		AuthFailureCount: c.AuthFailureCount,
		CommandCount:     c.CommandCount,
		LastSeenAt:       c.LastSeenAt,
	}
}

func mapStoreErr(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	if errors.Is(err, store.ErrPortConflict) {
		return ErrConflict
	}
	return err
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func generateID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "hp-" + strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return "hp-" + hex.EncodeToString(b[:])
}

// ParsePortFromAddr extracts TCP port from a listen address such as ":8080" or "127.0.0.1:8080".
func ParsePortFromAddr(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}
