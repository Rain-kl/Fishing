package store

import (
	"errors"
	"testing"
	"time"

	"Fishing/internal/model"
)

func boolPtr(v bool) *bool {
	return &v
}

func TestStoreHoneypotLifecycleAndReload(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New store failed: %v", err)
	}

	hp1 := model.Honeypot{
		ID:           "hp-1",
		Name:         "ssh-2222",
		Type:         model.HoneypotTypeSSH,
		Port:         2222,
		Username:     "root",
		Password:     "toor",
		DesiredState: model.StatusRunning,
		CreatedAt:    time.Now().UTC().Add(-time.Minute),
	}
	if err := s.CreateHoneypot(hp1); err != nil {
		t.Fatalf("CreateHoneypot failed: %v", err)
	}

	// Duplicate port must fail.
	err = s.CreateHoneypot(model.Honeypot{
		ID:           "hp-dup",
		Name:         "dup",
		Type:         model.HoneypotTypeSSH,
		Port:         2222,
		Username:     "admin",
		Password:     "123456",
		DesiredState: model.StatusRunning,
		CreatedAt:    time.Now().UTC(),
	})
	if !errors.Is(err, ErrPortConflict) {
		t.Fatalf("expected ErrPortConflict, got %v", err)
	}

	hp2 := model.Honeypot{
		ID:           "hp-2",
		Name:         "ssh-2223",
		Type:         model.HoneypotTypeSSH,
		Port:         2223,
		Username:     "ubuntu",
		Password:     "ubuntu",
		DesiredState: model.StatusStopped,
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.CreateHoneypot(hp2); err != nil {
		t.Fatalf("CreateHoneypot hp2 failed: %v", err)
	}

	if _, err := s.UpdateDesiredState("hp-1", model.StatusStopped); err != nil {
		t.Fatalf("UpdateDesiredState failed: %v", err)
	}

	// Reload from disk and verify persistence.
	reloaded, err := New(dir)
	if err != nil {
		t.Fatalf("reload store failed: %v", err)
	}
	list := reloaded.ListHoneypots()
	if len(list) != 2 {
		t.Fatalf("expected 2 honeypots, got %d", len(list))
	}
	got1, ok := reloaded.GetHoneypot("hp-1")
	if !ok || got1.DesiredState != model.StatusStopped {
		t.Fatalf("expected hp-1 stopped after reload, got %+v (ok=%v)", got1, ok)
	}

	if err := reloaded.DeleteHoneypot("hp-2"); err != nil {
		t.Fatalf("DeleteHoneypot failed: %v", err)
	}
	if err := reloaded.DeleteHoneypot("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestStoreLogsQueryStatsAndClear(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New store failed: %v", err)
	}

	_ = s.CreateHoneypot(model.Honeypot{
		ID:           "hp-1",
		Name:         "ssh-2222",
		Type:         model.HoneypotTypeSSH,
		Port:         2222,
		Username:     "root",
		Password:     "toor",
		DesiredState: model.StatusRunning,
		CreatedAt:    time.Now().UTC(),
	})

	base := time.Now().UTC().Add(-10 * time.Second)
	entries := []model.LogEntry{
		{
			ID:           "log-1",
			SessionID:    "sess-1",
			HoneypotID:   "hp-1",
			HoneypotName: "ssh-2222",
			HoneypotType: model.HoneypotTypeSSH,
			HoneypotPort: 2222,
			SourceIP:     "192.0.2.10",
			EventType:    model.EventAuthAttempt,
			Username:     "root",
			Password:     "wrong",
			AuthSuccess:  boolPtr(false),
			Timestamp:    base,
		},
		{
			ID:           "log-2",
			SessionID:    "sess-2",
			HoneypotID:   "hp-1",
			HoneypotName: "ssh-2222",
			HoneypotType: model.HoneypotTypeSSH,
			HoneypotPort: 2222,
			SourceIP:     "192.0.2.11",
			EventType:    model.EventAuthAttempt,
			Username:     "root",
			Password:     "toor",
			AuthSuccess:  boolPtr(true),
			Timestamp:    base.Add(time.Second),
		},
		{
			ID:           "log-3",
			SessionID:    "sess-2",
			HoneypotID:   "hp-1",
			HoneypotName: "ssh-2222",
			HoneypotType: model.HoneypotTypeSSH,
			HoneypotPort: 2222,
			SourceIP:     "192.0.2.11",
			EventType:    model.EventCommand,
			Username:     "root",
			Command:      "uname -a",
			Timestamp:    base.Add(2 * time.Second),
		},
		{
			ID:           "log-4",
			SessionID:    "sess-3",
			HoneypotID:   "hp-2",
			HoneypotName: "ssh-2223",
			HoneypotType: model.HoneypotTypeSSH,
			HoneypotPort: 2223,
			SourceIP:     "198.51.100.5",
			EventType:    model.EventCommand,
			Username:     "admin",
			Command:      "id",
			Timestamp:    base.Add(3 * time.Second),
		},
	}

	for _, e := range entries {
		if err := s.AppendLog(e); err != nil {
			t.Fatalf("AppendLog failed: %v", err)
		}
	}

	// Reload and test queries.
	reloaded, err := New(dir)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	got, total := reloaded.QueryLogs(model.LogFilter{HoneypotID: "hp-1", EventType: model.EventCommand})
	if total != 1 || len(got) != 1 || got[0].Command != "uname -a" {
		t.Fatalf("unexpected filtered query result: total=%d got=%+v", total, got)
	}

	gotIP, totalIP := reloaded.QueryLogs(model.LogFilter{SourceIP: "192.0.2.11"})
	if totalIP != 2 || len(gotIP) != 2 || gotIP[0].ID != "log-3" {
		t.Fatalf("expected newest-first order for IP filter, got total=%d entries=%+v", totalIP, gotIP)
	}

	gotQ, totalQ := reloaded.QueryLogs(model.LogFilter{Query: "uname"})
	if totalQ != 1 || len(gotQ) != 1 || gotQ[0].ID != "log-3" {
		t.Fatalf("expected keyword query hit log-3, got %+v", gotQ)
	}

	exported := reloaded.ExportLogs(model.LogFilter{HoneypotID: "hp-1"})
	if len(exported) != 3 || exported[0].ID != "log-1" || exported[2].ID != "log-3" {
		t.Fatalf("expected oldest-first order for ExportLogs, got %+v", exported)
	}

	perHP, overview := reloaded.ComputeStats()
	if overview.TotalConnections != 2 || overview.AuthSuccessCount != 1 || overview.AuthFailureCount != 1 || overview.CommandCount != 2 || overview.UniqueIPCount != 3 {
		t.Fatalf("unexpected overview stats: %+v", overview)
	}
	if perHP["hp-1"].CommandCount != 1 || perHP["hp-1"].ConnectionCount != 2 {
		t.Fatalf("unexpected per-honeypot stats: %+v", perHP["hp-1"])
	}

	if err := reloaded.ClearLogs("hp-1"); err != nil {
		t.Fatalf("ClearLogs(hp-1) failed: %v", err)
	}
	remaining, remainingTotal := reloaded.QueryLogs(model.LogFilter{})
	if remainingTotal != 1 || len(remaining) != 1 || remaining[0].ID != "log-4" {
		t.Fatalf("expected only log-4 remaining, got %+v", remaining)
	}

	if err := reloaded.ClearLogs(""); err != nil {
		t.Fatalf("ClearLogs all failed: %v", err)
	}
	empty, emptyTotal := reloaded.QueryLogs(model.LogFilter{})
	if emptyTotal != 0 || len(empty) != 0 {
		t.Fatalf("expected 0 logs after clear all, got %+v", empty)
	}
}
