package sshpot

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// FakeShell emulates an isolated, stateless-to-host Linux shell purely in memory.
// It never runs external processes, reads host files, or makes network requests.
type FakeShell struct {
	username  string
	hostname  string
	homeDir   string
	cwd       string
	startedAt time.Time
	sourceIP  string
	history   []string
	dirs      map[string][]fakeEntry
	files     map[string]string
}

type fakeEntry struct {
	name  string
	isDir bool
	mode  string
	size  int
	owner string
}

// NewFakeShell initializes a simulated Linux environment for the authenticated user.
func NewFakeShell(username, sourceIP string) *FakeShell {
	homeDir := "/home/" + username
	if username == "root" {
		homeDir = "/root"
	}

	s := &FakeShell{
		username:  username,
		hostname:  "prod-web-01",
		homeDir:   homeDir,
		cwd:       homeDir,
		startedAt: time.Now().UTC(),
		sourceIP:  sourceIP,
		history:   make([]string, 0, 32),
		dirs:      make(map[string][]fakeEntry),
		files:     make(map[string]string),
	}
	s.initFilesystem()
	return s
}

func (s *FakeShell) initFilesystem() {
	userEntry := fakeEntry{name: s.username, isDir: true, mode: "drwxr-xr-x", size: 4096, owner: s.username}
	s.dirs["/"] = []fakeEntry{
		{name: "bin", isDir: true, mode: "lrwxrwxrwx", size: 7, owner: "root"},
		{name: "etc", isDir: true, mode: "drwxr-xr-x", size: 4096, owner: "root"},
		{name: "home", isDir: true, mode: "drwxr-xr-x", size: 4096, owner: "root"},
		{name: "opt", isDir: true, mode: "drwxr-xr-x", size: 4096, owner: "root"},
		{name: "proc", isDir: true, mode: "dr-xr-xr-x", size: 0, owner: "root"},
		{name: "root", isDir: true, mode: "drwx------", size: 4096, owner: "root"},
		{name: "tmp", isDir: true, mode: "drwxrwxrwt", size: 4096, owner: "root"},
		{name: "usr", isDir: true, mode: "drwxr-xr-x", size: 4096, owner: "root"},
		{name: "var", isDir: true, mode: "drwxr-xr-x", size: 4096, owner: "root"},
	}
	s.dirs["/root"] = []fakeEntry{
		{name: ".bash_history", isDir: false, mode: "-rw-------", size: 214, owner: "root"},
		{name: ".ssh", isDir: true, mode: "drwx------", size: 4096, owner: "root"},
		{name: "deploy.sh", isDir: false, mode: "-rwxr-x---", size: 412, owner: "root"},
	}
	if s.username == "root" {
		s.dirs["/home"] = []fakeEntry{
			{name: "ubuntu", isDir: true, mode: "drwxr-xr-x", size: 4096, owner: "ubuntu"},
		}
	} else {
		s.dirs["/home"] = []fakeEntry{userEntry}
		s.dirs[s.homeDir] = []fakeEntry{
			{name: ".bashrc", isDir: false, mode: "-rw-r--r--", size: 3771, owner: s.username},
			{name: ".ssh", isDir: true, mode: "drwx------", size: 4096, owner: s.username},
			{name: "notes.txt", isDir: false, mode: "-rw-r--r--", size: 128, owner: s.username},
		}
	}
	s.dirs["/etc"] = []fakeEntry{
		{name: "hostname", isDir: false, mode: "-rw-r--r--", size: 12, owner: "root"},
		{name: "hosts", isDir: false, mode: "-rw-r--r--", size: 184, owner: "root"},
		{name: "os-release", isDir: false, mode: "-rw-r--r--", size: 386, owner: "root"},
		{name: "passwd", isDir: false, mode: "-rw-r--r--", size: 1620, owner: "root"},
		{name: "ssh", isDir: true, mode: "drwxr-xr-x", size: 4096, owner: "root"},
	}
	s.dirs["/etc/ssh"] = []fakeEntry{
		{name: "sshd_config", isDir: false, mode: "-rw-r--r--", size: 3250, owner: "root"},
	}
	s.dirs["/var"] = []fakeEntry{
		{name: "log", isDir: true, mode: "drwxr-xr-x", size: 4096, owner: "root"},
		{name: "www", isDir: true, mode: "drwxr-xr-x", size: 4096, owner: "www-data"},
	}
	s.dirs["/var/log"] = []fakeEntry{
		{name: "auth.log", isDir: false, mode: "-rw-r-----", size: 24576, owner: "syslog"},
		{name: "syslog", isDir: false, mode: "-rw-r-----", size: 98304, owner: "syslog"},
	}
	s.dirs["/var/www"] = []fakeEntry{}
	s.dirs["/tmp"] = []fakeEntry{}
	s.dirs["/opt"] = []fakeEntry{
		{name: "app", isDir: true, mode: "drwxr-xr-x", size: 4096, owner: "root"},
	}
	s.dirs["/opt/app"] = []fakeEntry{}
	s.dirs["/usr"] = []fakeEntry{
		{name: "bin", isDir: true, mode: "drwxr-xr-x", size: 28672, owner: "root"},
		{name: "local", isDir: true, mode: "drwxr-xr-x", size: 4096, owner: "root"},
	}
	s.dirs["/usr/bin"] = []fakeEntry{}
	s.dirs["/usr/local"] = []fakeEntry{}
	s.dirs["/proc"] = []fakeEntry{
		{name: "cpuinfo", isDir: false, mode: "-r--r--r--", size: 0, owner: "root"},
		{name: "meminfo", isDir: false, mode: "-r--r--r--", size: 0, owner: "root"},
		{name: "version", isDir: false, mode: "-r--r--r--", size: 0, owner: "root"},
	}
	s.dirs["/bin"] = s.dirs["/usr/bin"]

	s.files["/etc/hostname"] = s.hostname + "\n"
	s.files["/etc/hosts"] = fmt.Sprintf("127.0.0.1 localhost\n127.0.1.1 %s\n", s.hostname)
	s.files["/etc/os-release"] = `PRETTY_NAME="Ubuntu 22.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.5 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
`
	s.files["/etc/passwd"] = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:108:65534::/run/sshd:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
`
	if s.username != "root" && s.username != "ubuntu" {
		s.files["/etc/passwd"] += fmt.Sprintf("%s:x:1001:1001::%s:/bin/bash\n", s.username, s.homeDir)
		s.files[s.homeDir+"/notes.txt"] = "Maintenance window: Sunday 02:00 UTC\n"
		s.files[s.homeDir+"/.bashrc"] = "# ~/.bashrc: executed by bash(1) for non-login shells.\nexport PS1='\\u@\\h:\\w\\$ '\n"
	}
	s.files["/proc/version"] = "Linux version 5.15.0-119-generic (buildd@lcy02-amd64-045) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #129-Ubuntu SMP Fri Aug 2 19:25:20 UTC 2024\n"
	s.files["/proc/cpuinfo"] = "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\ncpu MHz\t\t: 2499.998\n"
	s.files["/proc/meminfo"] = "MemTotal:        4023812 kB\nMemFree:         1482920 kB\nMemAvailable:    2891044 kB\n"
	s.files["/root/.bash_history"] = "systemctl status nginx\ndocker ps\nss -tulpn\ntail -n 50 /var/log/auth.log\n"
	s.files["/root/deploy.sh"] = "#!/bin/bash\nset -e\necho \"deploying application bundle...\"\n"
	s.files["/etc/ssh/sshd_config"] = "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nSubsystem sftp /usr/lib/openssh/sftp-server\n"
	s.files["/var/log/auth.log"] = "Nov 22 08:11:02 prod-web-01 sshd[1042]: Server listening on 0.0.0.0 port 22.\n"
	s.files["/var/log/syslog"] = "Nov 22 08:11:01 prod-web-01 systemd[1]: Started OpenBSD Secure Shell server.\n"
}

// Prompt formats the simulated shell prompt for the current working directory.
func (s *FakeShell) Prompt() string {
	displayDir := s.cwd
	if s.cwd == s.homeDir {
		displayDir = "~"
	} else if strings.HasPrefix(s.cwd, s.homeDir+"/") {
		displayDir = "~" + strings.TrimPrefix(s.cwd, s.homeDir)
	}
	symbol := "$"
	if s.username == "root" {
		symbol = "#"
	}
	return fmt.Sprintf("%s@%s:%s%s ", s.username, s.hostname, displayDir, symbol)
}

// Execute evaluates a single command line (supporting `;` and `&&` separators)
// and returns simulated output, exit status, and whether the session should terminate.
func (s *FakeShell) Execute(rawLine string) (string, int, bool) {
	trimmed := strings.TrimSpace(rawLine)
	if trimmed == "" {
		return "", 0, false
	}

	s.history = append(s.history, trimmed)
	segments := splitCommandChain(trimmed)

	var out strings.Builder
	lastExit := 0
	for _, seg := range segments {
		if seg.requireZero && lastExit != 0 {
			continue
		}
		segOut, code, exit := s.executeSingle(seg.cmd)
		if segOut != "" {
			out.WriteString(segOut)
			if !strings.HasSuffix(segOut, "\n") {
				out.WriteByte('\n')
			}
		}
		lastExit = code
		if exit {
			return out.String(), code, true
		}
	}
	return out.String(), lastExit, false
}

type commandSegment struct {
	cmd         string
	requireZero bool
}

func splitCommandChain(input string) []commandSegment {
	var segments []commandSegment
	var cur strings.Builder
	var quote rune
	nextRequireZero := false

	runes := []rune(input)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			cur.WriteRune(r)
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			cur.WriteRune(r)
			continue
		}
		if r == ';' {
			if cmd := strings.TrimSpace(cur.String()); cmd != "" {
				segments = append(segments, commandSegment{cmd: cmd, requireZero: nextRequireZero})
			}
			cur.Reset()
			nextRequireZero = false
			continue
		}
		if r == '&' && i+1 < len(runes) && runes[i+1] == '&' {
			if cmd := strings.TrimSpace(cur.String()); cmd != "" {
				segments = append(segments, commandSegment{cmd: cmd, requireZero: nextRequireZero})
			}
			cur.Reset()
			nextRequireZero = true
			i++
			continue
		}
		cur.WriteRune(r)
	}
	if cmd := strings.TrimSpace(cur.String()); cmd != "" {
		segments = append(segments, commandSegment{cmd: cmd, requireZero: nextRequireZero})
	}
	return segments
}

func tokenizeArgs(cmd string) []string {
	var args []string
	var cur strings.Builder
	var quote rune
	inToken := false

	for _, r := range cmd {
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			inToken = true
			continue
		}
		if r == ' ' || r == '\t' {
			if inToken {
				args = append(args, cur.String())
				cur.Reset()
				inToken = false
			}
			continue
		}
		cur.WriteRune(r)
		inToken = true
	}
	if inToken {
		args = append(args, cur.String())
	}
	return args
}

func (s *FakeShell) resolvePath(p string) string {
	if p == "" || p == "~" {
		return s.homeDir
	}
	if strings.HasPrefix(p, "~/") {
		p = path.Join(s.homeDir, strings.TrimPrefix(p, "~/"))
	} else if !strings.HasPrefix(p, "/") {
		p = path.Join(s.cwd, p)
	}
	return path.Clean(p)
}

func (s *FakeShell) executeSingle(cmdLine string) (string, int, bool) {
	args := tokenizeArgs(cmdLine)
	if len(args) == 0 {
		return "", 0, false
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "exit", "logout":
		return "logout\n", 0, true
	case "whoami":
		return s.username + "\n", 0, false
	case "id":
		if s.username == "root" {
			return "uid=0(root) gid=0(root) groups=0(root)\n", 0, false
		}
		return fmt.Sprintf("uid=1001(%s) gid=1001(%s) groups=1001(%s)\n", s.username, s.username, s.username), 0, false
	case "hostname":
		if len(rest) > 0 && rest[0] == "-I" {
			return "10.0.2.15 \n", 0, false
		}
		return s.hostname + "\n", 0, false
	case "uname":
		return s.handleUname(rest), 0, false
	case "pwd":
		return s.cwd + "\n", 0, false
	case "cd":
		return s.handleCD(rest)
	case "ls", "ll":
		return s.handleLS(cmd == "ll", rest)
	case "cat":
		return s.handleCat(rest)
	case "echo":
		return strings.Join(rest, " ") + "\n", 0, false
	case "ps":
		return s.handlePS(), 0, false
	case "ip", "ifconfig":
		return s.handleIP(cmd), 0, false
	case "netstat", "ss":
		return s.handleNetstat(), 0, false
	case "df":
		return "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G  6.8G   31G  19% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm\n", 0, false
	case "free":
		return "               total        used        free      shared  buff/cache   available\nMem:         4023812     1128420     1482920       12400     1412472     2891044\nSwap:              0           0           0\n", 0, false
	case "uptime":
		return fmt.Sprintf(" %s up 42 days,  3:18,  1 user,  load average: 0.08, 0.04, 0.01\n", time.Now().UTC().Format("15:04:05")), 0, false
	case "w", "who":
		ip := s.sourceIP
		if ip == "" {
			ip = "127.0.0.1"
		}
		return fmt.Sprintf("%s     pts/0        %s (%s)\n", s.username, s.startedAt.Format("2006-01-02 15:04"), ip), 0, false
	case "last":
		ip := s.sourceIP
		if ip == "" {
			ip = "127.0.0.1"
		}
		return fmt.Sprintf("%s   pts/0        %s    %s   still logged in\n", s.username, ip, s.startedAt.Format("Mon Jan _2 15:04")), 0, false
	case "date":
		return time.Now().UTC().Format("Mon Jan _2 15:04:05 UTC 2006") + "\n", 0, false
	case "env":
		return fmt.Sprintf("USER=%s\nHOME=%s\nSHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nLANG=C.UTF-8\n", s.username, s.homeDir), 0, false
	case "history":
		var sb strings.Builder
		for idx, h := range s.history {
			sb.WriteString(fmt.Sprintf("%5d  %s\n", idx+1, h))
		}
		return sb.String(), 0, false
	case "wget":
		target := "remote host"
		for _, a := range rest {
			if !strings.HasPrefix(a, "-") {
				target = a
				break
			}
		}
		return fmt.Sprintf("--%s--  %s\nResolving host... failed: Temporary failure in name resolution.\n", time.Now().UTC().Format("2006-01-02 15:04:05"), target), 4, false
	case "curl":
		return "curl: (6) Could not resolve host\n", 6, false
	case "chmod", "chown", "mkdir", "touch", "rm", "mv", "cp":
		return "", 0, false
	case "sudo":
		if len(rest) == 0 {
			return "usage: sudo -h | -K | -k | -V\n", 1, false
		}
		return fmt.Sprintf("%s is not in the sudoers file.  This incident will be reported.\n", s.username), 1, false
	case "su":
		return "su: Authentication failure\n", 1, false
	case "clear":
		return "\x1b[H\x1b[2J", 0, false
	case "help":
		return "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\nBuilt-in commands: cd, pwd, ls, cat, echo, id, whoami, uname, ps, ip, ss, df, free, uptime, env, history, exit\n", 0, false
	default:
		return fmt.Sprintf("bash: %s: command not found\n", cmd), 127, false
	}
}

func (s *FakeShell) handleUname(args []string) string {
	for _, a := range args {
		if strings.Contains(a, "a") {
			return fmt.Sprintf("Linux %s 5.15.0-119-generic #129-Ubuntu SMP Fri Aug 2 19:25:20 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n", s.hostname)
		}
		if strings.Contains(a, "r") {
			return "5.15.0-119-generic\n"
		}
		if strings.Contains(a, "m") {
			return "x86_64\n"
		}
	}
	return "Linux\n"
}

func (s *FakeShell) handleCD(args []string) (string, int, bool) {
	target := s.homeDir
	if len(args) > 0 {
		target = s.resolvePath(args[0])
	}
	if _, ok := s.dirs[target]; ok {
		s.cwd = target
		return "", 0, false
	}
	if _, ok := s.files[target]; ok {
		return fmt.Sprintf("bash: cd: %s: Not a directory\n", args[0]), 1, false
	}
	return fmt.Sprintf("bash: cd: %s: No such file or directory\n", args[0]), 1, false
}

func (s *FakeShell) handleLS(longDefault bool, args []string) (string, int, bool) {
	showLong := longDefault
	showAll := false
	targetArg := ""

	for _, a := range args {
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			if strings.Contains(a, "l") {
				showLong = true
			}
			if strings.Contains(a, "a") {
				showAll = true
			}
			continue
		}
		targetArg = a
	}

	target := s.cwd
	if targetArg != "" {
		target = s.resolvePath(targetArg)
	}

	entries, isDir := s.dirs[target]
	if !isDir {
		if content, isFile := s.files[target]; isFile {
			if showLong {
				return fmt.Sprintf("-rw-r--r-- 1 root root %5d Nov 22 08:11 %s\n", len(content), path.Base(target)), 0, false
			}
			return path.Base(target) + "\n", 0, false
		}
		return fmt.Sprintf("ls: cannot access '%s': No such file or directory\n", targetArg), 2, false
	}

	visible := make([]fakeEntry, 0, len(entries))
	for _, e := range entries {
		if !showAll && strings.HasPrefix(e.name, ".") {
			continue
		}
		visible = append(visible, e)
	}
	sort.Slice(visible, func(i, j int) bool {
		return visible[i].name < visible[j].name
	})

	if !showLong {
		names := make([]string, 0, len(visible))
		for _, e := range visible {
			names = append(names, e.name)
		}
		if len(names) == 0 {
			return "", 0, false
		}
		return strings.Join(names, "  ") + "\n", 0, false
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("total %d\n", len(visible)*4))
	for _, e := range visible {
		sb.WriteString(fmt.Sprintf("%s 1 %-8s %-8s %6d Nov 22 08:11 %s\n", e.mode, e.owner, e.owner, e.size, e.name))
	}
	return sb.String(), 0, false
}

func (s *FakeShell) handleCat(args []string) (string, int, bool) {
	if len(args) == 0 {
		return "", 0, false
	}
	var out strings.Builder
	exitCode := 0
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		target := s.resolvePath(a)
		if content, ok := s.files[target]; ok {
			out.WriteString(content)
			continue
		}
		if _, isDir := s.dirs[target]; isDir {
			out.WriteString(fmt.Sprintf("cat: %s: Is a directory\n", a))
			exitCode = 1
			continue
		}
		out.WriteString(fmt.Sprintf("cat: %s: No such file or directory\n", a))
		exitCode = 1
	}
	return out.String(), exitCode, false
}

func (s *FakeShell) handlePS() string {
	return `  PID TTY          TIME CMD
    1 ?        00:00:02 systemd
  412 ?        00:00:00 sshd
  894 ?        00:00:01 nginx
 1208 pts/0    00:00:00 bash
 1245 pts/0    00:00:00 ps
`
}

func (s *FakeShell) handleIP(cmd string) string {
	if cmd == "ifconfig" {
		return `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        ether 02:42:ac:11:00:02  txqueuelen 1000  (Ethernet)
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
`
	}
	return `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0
`
}

func (s *FakeShell) handleNetstat() string {
	return `Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port
tcp    LISTEN  0       128     0.0.0.0:22           0.0.0.0:*
tcp    LISTEN  0       511     0.0.0.0:80           0.0.0.0:*
`
}
