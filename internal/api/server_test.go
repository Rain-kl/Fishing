package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"Fishing/internal/manager"
	"Fishing/internal/model"
	"Fishing/internal/sshpot"
	"Fishing/internal/store"
	"Fishing/web"
	"golang.org/x/crypto/ssh"
)

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port failed: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func setupTestAPI(t *testing.T) (*Server, *manager.Manager) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}
	hostKey, err := sshpot.LoadOrCreateHostKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateHostKey failed: %v", err)
	}
	mgr := manager.New(st, "127.0.0.1", 8080, hostKey)
	t.Cleanup(mgr.CloseAll)

	staticFS, err := web.StaticFS()
	if err != nil {
		t.Fatalf("web.StaticFS failed: %v", err)
	}
	return NewServer(mgr, staticFS, "test-ver"), mgr
}

func TestAPIStaticAndHoneypotFlow(t *testing.T) {
	srv, _ := setupTestAPI(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Static console index.
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for /, got %d", resp.StatusCode)
	}

	// 2. Invalid honeypot type -> 400.
	badBody := []byte(`{"type":"telnet","port":2323,"username":"root","password":"123"}`)
	badResp, err := http.Post(ts.URL+"/api/honeypots", "application/json", bytes.NewReader(badBody))
	if err != nil {
		t.Fatalf("POST bad type failed: %v", err)
	}
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid type, got %d", badResp.StatusCode)
	}

	// 3. Create SSH honeypot -> 201.
	port := freeTCPPort(t)
	createPayload, _ := json.Marshal(model.CreateHoneypotRequest{
		Type:     "ssh",
		Port:     port,
		Username: "admin",
		Password: "honeypot-pass",
	})
	createResp, err := http.Post(ts.URL+"/api/honeypots", "application/json", bytes.NewReader(createPayload))
	if err != nil {
		t.Fatalf("POST /api/honeypots failed: %v", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createResp.StatusCode)
	}

	var createdBody struct {
		Honeypot model.HoneypotView `json:"honeypot"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&createdBody); err != nil {
		t.Fatalf("decode created response failed: %v", err)
	}
	hpID := createdBody.Honeypot.ID
	if hpID == "" || createdBody.Honeypot.Status != model.StatusRunning {
		t.Fatalf("unexpected created honeypot: %+v", createdBody.Honeypot)
	}

	// 4. Connect to the created SSH honeypot and execute a command.
	sshClient, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &ssh.ClientConfig{
		User:            "admin",
		Auth:            []ssh.AuthMethod{ssh.Password("honeypot-pass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh.Dial to created honeypot failed: %v", err)
	}
	sess, err := sshClient.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	out, err := sess.CombinedOutput("cat /etc/hostname")
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if !strings.Contains(string(out), "prod-web-01") {
		t.Fatalf("unexpected simulated output: %q", string(out))
	}
	_ = sess.Close()
	_ = sshClient.Close()

	// 5. Query logs and overview.
	logResp, err := http.Get(ts.URL + "/api/logs?event_type=command&honeypot_id=" + hpID)
	if err != nil {
		t.Fatalf("GET /api/logs failed: %v", err)
	}
	defer logResp.Body.Close()
	var logBody struct {
		Logs  []model.LogEntry `json:"logs"`
		Total int              `json:"total"`
	}
	if err := json.NewDecoder(logResp.Body).Decode(&logBody); err != nil {
		t.Fatalf("decode logs failed: %v", err)
	}
	if logBody.Total != 1 || len(logBody.Logs) != 1 || logBody.Logs[0].Command != "cat /etc/hostname" {
		t.Fatalf("unexpected command logs: %+v", logBody)
	}

	ovResp, err := http.Get(ts.URL + "/api/overview")
	if err != nil {
		t.Fatalf("GET /api/overview failed: %v", err)
	}
	defer ovResp.Body.Close()
	var ov model.OverviewStats
	if err := json.NewDecoder(ovResp.Body).Decode(&ov); err != nil {
		t.Fatalf("decode overview failed: %v", err)
	}
	if ov.RunningHoneypots != 1 || ov.CommandCount < 1 || ov.UniqueIPCount < 1 {
		t.Fatalf("unexpected overview: %+v", ov)
	}

	// 6. Stop and delete honeypot, then clear logs.
	stopResp, err := http.Post(ts.URL+"/api/honeypots/"+hpID+"/stop", "application/json", nil)
	if err != nil {
		t.Fatalf("POST stop failed: %v", err)
	}
	_ = stopResp.Body.Close()
	if stopResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on stop, got %d", stopResp.StatusCode)
	}

	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/honeypots/"+hpID, nil)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE honeypot failed: %v", err)
	}
	_ = delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on delete, got %d", delResp.StatusCode)
	}

	clearReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/logs", nil)
	clearResp, err := http.DefaultClient.Do(clearReq)
	if err != nil {
		t.Fatalf("DELETE logs failed: %v", err)
	}
	_ = clearResp.Body.Close()
	if clearResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on clear logs, got %d", clearResp.StatusCode)
	}
}
