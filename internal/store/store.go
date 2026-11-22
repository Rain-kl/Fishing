package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"Fishing/internal/model"
)

var (
	ErrNotFound     = errors.New("honeypot not found")
	ErrPortConflict = errors.New("port already allocated to another honeypot")
)

const defaultMaxInMemoryLogs = 10000

// Store provides thread-safe persistent storage for honeypot configurations and access logs.
type Store struct {
	mu           sync.RWMutex
	dataDir      string
	honeypots    map[string]model.Honeypot
	logs         []model.LogEntry
	maxMemLogs   int
	honeypotFile string
	logFile      string
}

// New initializes a persistent store under dataDir.
func New(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}

	s := &Store{
		dataDir:      dataDir,
		honeypots:    make(map[string]model.Honeypot),
		logs:         make([]model.LogEntry, 0, 256),
		maxMemLogs:   defaultMaxInMemoryLogs,
		honeypotFile: filepath.Join(dataDir, "honeypots.json"),
		logFile:      filepath.Join(dataDir, "logs.jsonl"),
	}

	if err := s.loadHoneypots(); err != nil {
		return nil, err
	}
	if err := s.loadLogs(); err != nil {
		return nil, err
	}
	return s, nil
}

// DataDir returns the configured data directory path.
func (s *Store) DataDir() string {
	return s.dataDir
}

func (s *Store) loadHoneypots() error {
	data, err := os.ReadFile(s.honeypotFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read honeypots file: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}

	var list []model.Honeypot
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("parse honeypots file: %w", err)
	}
	for _, hp := range list {
		s.honeypots[hp.ID] = hp
	}
	return nil
}

func (s *Store) saveHoneypotsLocked() error {
	list := make([]model.Honeypot, 0, len(s.honeypots))
	for _, hp := range s.honeypots {
		list = append(list, hp)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.Before(list[j].CreatedAt)
	})

	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal honeypots: %w", err)
	}

	tmpPath := s.honeypotFile + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return fmt.Errorf("write temp honeypots file: %w", err)
	}
	if err := os.Rename(tmpPath, s.honeypotFile); err != nil {
		return fmt.Errorf("replace honeypots file: %w", err)
	}
	return nil
}

func (s *Store) loadLogs() error {
	f, err := os.Open(s.logFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open logs file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry model.LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		s.logs = append(s.logs, entry)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan logs file: %w", err)
	}
	if len(s.logs) > s.maxMemLogs {
		s.logs = s.logs[len(s.logs)-s.maxMemLogs:]
	}
	return nil
}

// CreateHoneypot persists a new honeypot configuration.
func (s *Store) CreateHoneypot(hp model.Honeypot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.honeypots {
		if existing.Port == hp.Port {
			return ErrPortConflict
		}
	}
	s.honeypots[hp.ID] = hp
	return s.saveHoneypotsLocked()
}

// UpdateDesiredState updates whether a honeypot should be running or stopped.
func (s *Store) UpdateDesiredState(id, desiredState string) (model.Honeypot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hp, ok := s.honeypots[id]
	if !ok {
		return model.Honeypot{}, ErrNotFound
	}
	hp.DesiredState = desiredState
	s.honeypots[id] = hp
	if err := s.saveHoneypotsLocked(); err != nil {
		return model.Honeypot{}, err
	}
	return hp, nil
}

// DeleteHoneypot removes a honeypot configuration by ID.
func (s *Store) DeleteHoneypot(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.honeypots[id]; !ok {
		return ErrNotFound
	}
	delete(s.honeypots, id)
	return s.saveHoneypotsLocked()
}

// GetHoneypot retrieves a honeypot by ID.
func (s *Store) GetHoneypot(id string) (model.Honeypot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hp, ok := s.honeypots[id]
	return hp, ok
}

// ListHoneypots returns all configured honeypots ordered by creation time descending.
func (s *Store) ListHoneypots() []model.Honeypot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]model.Honeypot, 0, len(s.honeypots))
	for _, hp := range s.honeypots {
		list = append(list, hp)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
	return list
}

// AppendLog appends an access or command audit log entry to memory and disk.
func (s *Store) AppendLog(entry model.LogEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.logs = append(s.logs, entry)
	if len(s.logs) > s.maxMemLogs {
		s.logs = s.logs[len(s.logs)-s.maxMemLogs:]
	}

	raw, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal log entry: %w", err)
	}

	f, err := os.OpenFile(s.logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open logs file for append: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("append log entry: %w", err)
	}
	return nil
}

// QueryLogs returns matching log entries ordered newest-first alongside the total matched count.
func (s *Store) QueryLogs(filter model.LogFilter) ([]model.LogEntry, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	ipQuery := strings.ToLower(strings.TrimSpace(filter.SourceIP))
	textQuery := strings.ToLower(strings.TrimSpace(filter.Query))

	matched := make([]model.LogEntry, 0, min(limit, len(s.logs)))
	total := 0

	for i := len(s.logs) - 1; i >= 0; i-- {
		entry := s.logs[i]
		if !matchesFilter(entry, filter, ipQuery, textQuery) {
			continue
		}
		total++
		if len(matched) < limit {
			matched = append(matched, entry)
		}
	}

	return matched, total
}

// ExportLogs returns all matching log entries ordered oldest-first without pagination truncation.
func (s *Store) ExportLogs(filter model.LogFilter) []model.LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ipQuery := strings.ToLower(strings.TrimSpace(filter.SourceIP))
	textQuery := strings.ToLower(strings.TrimSpace(filter.Query))

	matched := make([]model.LogEntry, 0, len(s.logs))
	for _, entry := range s.logs {
		if !matchesFilter(entry, filter, ipQuery, textQuery) {
			continue
		}
		matched = append(matched, entry)
	}
	return matched
}

func matchesFilter(entry model.LogEntry, filter model.LogFilter, ipQuery, textQuery string) bool {
	if filter.HoneypotID != "" && entry.HoneypotID != filter.HoneypotID {
		return false
	}
	if filter.EventType != "" && entry.EventType != filter.EventType {
		return false
	}
	if ipQuery != "" && !strings.Contains(strings.ToLower(entry.SourceIP), ipQuery) {
		return false
	}
	if textQuery != "" && !matchesQuery(entry, textQuery) {
		return false
	}
	return true
}

func matchesQuery(e model.LogEntry, q string) bool {
	fields := []string{
		e.SourceIP,
		e.Username,
		e.Password,
		e.Command,
		e.Detail,
		e.ClientVersion,
		e.HoneypotName,
		e.SessionID,
	}
	for _, f := range fields {
		if f != "" && strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

// ClearLogs clears all logs, or only logs belonging to honeypotID when non-empty.
func (s *Store) ClearLogs(honeypotID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if honeypotID == "" {
		s.logs = s.logs[:0]
		return os.WriteFile(s.logFile, nil, 0o600)
	}

	kept := make([]model.LogEntry, 0, len(s.logs))
	var sb strings.Builder
	for _, entry := range s.logs {
		if entry.HoneypotID == honeypotID {
			continue
		}
		kept = append(kept, entry)
		raw, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshal kept log entry: %w", err)
		}
		sb.Write(raw)
		sb.WriteByte('\n')
	}
	s.logs = kept

	tmpPath := s.logFile + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(sb.String()), 0o600); err != nil {
		return fmt.Errorf("write temp logs file: %w", err)
	}
	if err := os.Rename(tmpPath, s.logFile); err != nil {
		return fmt.Errorf("replace logs file: %w", err)
	}
	return nil
}

// HoneypotCounters aggregates runtime telemetry per honeypot from logs.
type HoneypotCounters struct {
	ConnectionCount  int
	AuthSuccessCount int
	AuthFailureCount int
	CommandCount     int
	LastSeenAt       *time.Time
}

// ComputeStats returns per-honeypot counters and global telemetry derived from logs.
func (s *Store) ComputeStats() (map[string]HoneypotCounters, model.OverviewStats) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	perHP := make(map[string]HoneypotCounters)
	uniqueIPs := make(map[string]struct{})
	var overview model.OverviewStats
	overview.TotalHoneypots = len(s.honeypots)

	for _, e := range s.logs {
		if e.SourceIP != "" {
			uniqueIPs[e.SourceIP] = struct{}{}
		}
		c := perHP[e.HoneypotID]
		ts := e.Timestamp
		if c.LastSeenAt == nil || ts.After(*c.LastSeenAt) {
			t := ts
			c.LastSeenAt = &t
		}

		switch e.EventType {
		case model.EventAuthAttempt:
			c.ConnectionCount++
			overview.TotalConnections++
			if e.AuthSuccess != nil && *e.AuthSuccess {
				c.AuthSuccessCount++
				overview.AuthSuccessCount++
			} else {
				c.AuthFailureCount++
				overview.AuthFailureCount++
			}
		case model.EventCommand:
			c.CommandCount++
			overview.CommandCount++
		}
		perHP[e.HoneypotID] = c
	}

	overview.UniqueIPCount = len(uniqueIPs)
	return perHP, overview
}
