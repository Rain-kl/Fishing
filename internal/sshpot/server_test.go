package sshpot

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"Fishing/internal/model"
	"golang.org/x/crypto/ssh"
)

func startTestServer(t *testing.T) (*Server, string, *[]model.LogEntry, *sync.Mutex) {
	t.Helper()

	signer, err := LoadOrCreateHostKey(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateHostKey failed: %v", err)
	}

	var mu sync.Mutex
	logs := make([]model.LogEntry, 0, 16)

	hp := model.Honeypot{
		ID:       "hp-test",
		Name:     "ssh-test",
		Type:     model.HoneypotTypeSSH,
		Port:     0,
		Username: "ops",
		Password: "secret-password",
	}

	srv, err := New(hp, "127.0.0.1", signer, func(entry model.LogEntry) {
		mu.Lock()
		logs = append(logs, entry)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("New sshpot server failed: %v", err)
	}
	srv.Start()
	t.Cleanup(srv.Stop)

	return srv, srv.Addr().String(), &logs, &mu
}

func TestSSHServerAuthFailureAndExec(t *testing.T) {
	_, addr, logsPtr, mu := startTestServer(t)

	// 1. Wrong password must fail and still be logged.
	badCfg := &ssh.ClientConfig{
		User:            "ops",
		Auth:            []ssh.AuthMethod{ssh.Password("wrong-pass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	if client, err := ssh.Dial("tcp", addr, badCfg); err == nil {
		_ = client.Close()
		t.Fatalf("expected auth failure for wrong password")
	}

	// 2. Correct password and exec command.
	goodCfg := &ssh.ClientConfig{
		User:            "ops",
		Auth:            []ssh.AuthMethod{ssh.Password("secret-password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, goodCfg)
	if err != nil {
		t.Fatalf("ssh.Dial with valid credentials failed: %v", err)
	}

	sess, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		t.Fatalf("NewSession failed: %v", err)
	}
	out, err := sess.CombinedOutput("whoami && uname -a")
	if err != nil {
		t.Fatalf("exec failed: %v (output=%q)", err, string(out))
	}
	if !strings.Contains(string(out), "ops") || !strings.Contains(string(out), "prod-web-01") {
		t.Fatalf("unexpected exec output: %q", string(out))
	}
	_ = sess.Close()
	_ = client.Close()

	// Wait briefly for asynchronous session close log.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(*logsPtr)
		mu.Unlock()
		if count >= 5 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	logs := *logsPtr

	var sawFail, sawSuccess, sawExec, sawOpen, sawClose bool
	for _, l := range logs {
		if l.SourceIP != "127.0.0.1" {
			t.Fatalf("expected source IP 127.0.0.1, got %q", l.SourceIP)
		}
		switch l.EventType {
		case model.EventAuthAttempt:
			if l.AuthSuccess != nil && !*l.AuthSuccess && l.Password == "wrong-pass" {
				sawFail = true
			}
			if l.AuthSuccess != nil && *l.AuthSuccess && l.Password == "secret-password" {
				sawSuccess = true
			}
		case model.EventSessionOpen:
			sawOpen = true
		case model.EventCommand:
			if l.Command == "whoami && uname -a" {
				sawExec = true
			}
		case model.EventSessionClose:
			sawClose = true
		}
	}

	if !sawFail || !sawSuccess || !sawExec || !sawOpen || !sawClose {
		t.Fatalf("missing expected logs: fail=%v success=%v exec=%v open=%v close=%v logs=%+v",
			sawFail, sawSuccess, sawExec, sawOpen, sawClose, logs)
	}
}

func TestSSHServerInteractivePTYShell(t *testing.T) {
	_, addr, logsPtr, mu := startTestServer(t)

	cfg := &ssh.ClientConfig{
		User:            "ops",
		Auth:            []ssh.AuthMethod{ssh.Password("secret-password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("ssh.Dial failed: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer sess.Close()

	if err := sess.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty failed: %v", err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe failed: %v", err)
	}
	var stdout bytes.Buffer
	sess.Stdout = &stdout

	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell failed: %v", err)
	}

	cmds := []string{"pwd\r", "ls -la\r", "exit\r"}
	for _, c := range cmds {
		if _, err := io.WriteString(stdin, c); err != nil {
			t.Fatalf("write command %q failed: %v", c, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	if err := sess.Wait(); err != nil {
		t.Fatalf("shell wait failed: %v", err)
	}

	outStr := stdout.String()
	if !strings.Contains(outStr, "/home/ops") || !strings.Contains(outStr, "notes.txt") {
		t.Fatalf("expected fake shell output in stdout, got %q", outStr)
	}

	mu.Lock()
	defer mu.Unlock()
	recorded := make(map[string]bool)
	for _, l := range *logsPtr {
		if l.EventType == model.EventCommand {
			recorded[l.Command] = true
		}
	}
	for _, expected := range []string{"pwd", "ls -la", "exit"} {
		if !recorded[expected] {
			t.Fatalf("expected command %q to be recorded, recorded=%v", expected, recorded)
		}
	}
}
