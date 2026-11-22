package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
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

	// 5. Get single honeypot detail, query logs, export JSONL & CSV, and overview.
	getResp, err := http.Get(ts.URL + "/api/honeypots/" + hpID)
	if err != nil {
		t.Fatalf("GET /api/honeypots/{id} failed: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on get honeypot detail, got %d", getResp.StatusCode)
	}
	var detailBody struct {
		Honeypot model.HoneypotView `json:"honeypot"`
	}
	if err := json.NewDecoder(getResp.Body).Decode(&detailBody); err != nil {
		t.Fatalf("decode detail failed: %v", err)
	}
	if detailBody.Honeypot.ID != hpID || detailBody.Honeypot.CommandCount < 1 {
		t.Fatalf("unexpected honeypot detail: %+v", detailBody.Honeypot)
	}

	// Execute a formula-prefixed command to verify CSV formula neutralization on export.
	sess2, err := func() (*ssh.Session, error) {
		c, dialErr := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &ssh.ClientConfig{
			User:            "admin",
			Auth:            []ssh.AuthMethod{ssh.Password("honeypot-pass")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         3 * time.Second,
		})
		if dialErr != nil {
			return nil, dialErr
		}
		t.Cleanup(func() { _ = c.Close() })
		return c.NewSession()
	}()
	if err != nil {
		t.Fatalf("second ssh session failed: %v", err)
	}
	_, _ = sess2.CombinedOutput("=cmd|'/C calc'!A0")
	_ = sess2.Close()

	// JSONL export.
	expJSONResp, err := http.Get(ts.URL + "/api/honeypots/" + hpID + "/logs/export?format=jsonl&event_type=command")
	if err != nil {
		t.Fatalf("GET jsonl export failed: %v", err)
	}
	defer expJSONResp.Body.Close()
	if expJSONResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for jsonl export, got %d", expJSONResp.StatusCode)
	}
	if cd := expJSONResp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment;") || !strings.Contains(cd, ".jsonl") {
		t.Fatalf("unexpected Content-Disposition: %q", cd)
	}
	jsonBytes, _ := io.ReadAll(expJSONResp.Body)
	lines := strings.Split(strings.TrimSpace(string(jsonBytes)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 exported command lines, got %d (%q)", len(lines), string(jsonBytes))
	}

	// CSV export.
	expCSVResp, err := http.Get(ts.URL + "/api/honeypots/" + hpID + "/logs/export?format=csv")
	if err != nil {
		t.Fatalf("GET csv export failed: %v", err)
	}
	defer expCSVResp.Body.Close()
	if expCSVResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for csv export, got %d", expCSVResp.StatusCode)
	}
	csvRaw, _ := io.ReadAll(expCSVResp.Body)
	if !bytes.HasPrefix(csvRaw, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatalf("expected UTF-8 BOM in CSV export")
	}
	records, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(csvRaw, []byte{0xEF, 0xBB, 0xBF}))).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV export failed: %v", err)
	}
	if len(records) < 3 {
		t.Fatalf("expected header + rows in CSV export, got %d rows", len(records))
	}
	var sawSanitizedFormula bool
	for _, row := range records[1:] {
		if row[10] == "'=cmd|'/C calc'!A0" {
			sawSanitizedFormula = true
		}
	}
	if !sawSanitizedFormula {
		t.Fatalf("expected neutralized formula cell in CSV export, got %+v", records)
	}

	// Unsupported format -> 400; missing honeypot -> 404.
	badFmtResp, err := http.Get(ts.URL + "/api/honeypots/" + hpID + "/logs/export?format=xml")
	if err != nil {
		t.Fatalf("GET invalid export format failed: %v", err)
	}
	_ = badFmtResp.Body.Close()
	if badFmtResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on unsupported format, got %d", badFmtResp.StatusCode)
	}
	missingExpResp, err := http.Get(ts.URL + "/api/honeypots/missing-hp/logs/export?format=csv")
	if err != nil {
		t.Fatalf("GET missing export failed: %v", err)
	}
	_ = missingExpResp.Body.Close()
	if missingExpResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 on missing honeypot export, got %d", missingExpResp.StatusCode)
	}

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
	if logBody.Total != 2 || len(logBody.Logs) != 2 || logBody.Logs[1].Command != "cat /etc/hostname" {
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
