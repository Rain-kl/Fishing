package manager

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"Fishing/internal/model"
	"Fishing/internal/sshpot"
	"Fishing/internal/store"
	"golang.org/x/crypto/ssh"
)

func reserveFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port failed: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestManagerCreateLifecycleAndRestore(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}
	hostKey, err := sshpot.LoadOrCreateHostKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateHostKey failed: %v", err)
	}

	mgr := New(st, "127.0.0.1", 8080, hostKey)
	t.Cleanup(mgr.CloseAll)

	// Unsupported type must be rejected.
	if _, err := mgr.Create(model.CreateHoneypotRequest{
		Type:     "http",
		Port:     2222,
		Username: "admin",
		Password: "secret",
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for unsupported type, got %v", err)
	}

	// Web port conflict must be rejected.
	if _, err := mgr.Create(model.CreateHoneypotRequest{
		Type:     "ssh",
		Port:     8080,
		Username: "admin",
		Password: "secret",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for web port, got %v", err)
	}

	freePort := reserveFreePort(t)
	created, err := mgr.Create(model.CreateHoneypotRequest{
		Port:     freePort,
		Username: "root",
		Password: "toor-password",
	})
	if err != nil {
		t.Fatalf("Create honeypot failed: %v", err)
	}
	if created.Status != model.StatusRunning || created.Type != model.HoneypotTypeSSH {
		t.Fatalf("unexpected created view: %+v", created)
	}

	// Duplicate port conflict must be rejected.
	if _, err := mgr.Create(model.CreateHoneypotRequest{
		Port:     freePort,
		Username: "other",
		Password: "pw",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate port, got %v", err)
	}

	// Connect to live honeypot over SSH immediately after creation.
	cfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("toor-password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort)), cfg)
	if err != nil {
		t.Fatalf("ssh.Dial to newly created honeypot failed: %v", err)
	}
	sess, err := client.NewSession()
	if err == nil {
		_, _ = sess.CombinedOutput("id")
		_ = sess.Close()
	}
	_ = client.Close()

	// Stop honeypot and verify state.
	stopped, err := mgr.Stop(created.ID)
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if stopped.Status != model.StatusStopped {
		t.Fatalf("expected stopped status, got %s", stopped.Status)
	}

	// Start again and restore via a fresh manager.
	started, err := mgr.Start(created.ID)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if started.Status != model.StatusRunning {
		t.Fatalf("expected running status, got %s", started.Status)
	}
	mgr.CloseAll()

	st2, err := store.New(dir)
	if err != nil {
		t.Fatalf("reload store failed: %v", err)
	}
	mgr2 := New(st2, "127.0.0.1", 8080, hostKey)
	t.Cleanup(mgr2.CloseAll)
	mgr2.Restore()

	list := mgr2.List()
	if len(list) != 1 || list[0].Status != model.StatusRunning {
		t.Fatalf("expected restored running honeypot, got %+v", list)
	}
	if list[0].CommandCount < 1 || list[0].AuthSuccessCount < 1 {
		t.Fatalf("expected recorded stats on restored view, got %+v", list[0])
	}

	if err := mgr2.Delete(created.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if len(mgr2.List()) != 0 {
		t.Fatalf("expected empty list after delete")
	}
}
