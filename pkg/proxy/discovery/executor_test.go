package discovery

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeSSHServer is an in-process sshd that answers the fixed set of commands
// an inventory run issues. It lets the executor's concurrency, timeout and
// partial-failure behaviour be tested without any external host.
type fakeSSHServer struct {
	t        *testing.T
	listener net.Listener
	config   *ssh.ServerConfig

	// responses maps a command to its canned stdout.
	responses map[string]string

	// stderrFor maps a command to stderr written before its stdout, used to
	// exercise concurrent pipe draining.
	stderrFor map[string]string

	// delay is applied before answering, to exercise concurrency.
	delay time.Duration

	// rejectAuth makes the server refuse authentication.
	rejectAuth bool

	activeConns int32
	maxConns    int32
	wg          sync.WaitGroup
}

func newFakeSSHServer(t *testing.T, responses map[string]string) *fakeSSHServer {
	t.Helper()

	_, hostKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	s := &fakeSSHServer{t: t, responses: responses}
	s.config = &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			if s.rejectAuth {
				return nil, fmt.Errorf("auth rejected")
			}
			return nil, nil
		},
	}
	s.config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	s.listener = ln

	go s.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *fakeSSHServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *fakeSSHServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

// trackExec records concurrency over the window where a command is actually
// running. Counting whole connections instead would overshoot: the client
// closes its connection and takes its next target while this side's handler
// is still unwinding, so the server would observe connections the client has
// already finished with.
func (s *fakeSSHServer) trackExec() func() {
	active := atomic.AddInt32(&s.activeConns, 1)
	for {
		max := atomic.LoadInt32(&s.maxConns)
		if active <= max || atomic.CompareAndSwapInt32(&s.maxConns, max, active) {
			break
		}
	}
	return func() { atomic.AddInt32(&s.activeConns, -1) }
}

func (s *fakeSSHServer) handleConn(nConn net.Conn) {
	defer func() { _ = nConn.Close() }()

	_, chans, reqs, err := ssh.NewServerConn(nConn, s.config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go s.handleSession(ch, chReqs)
	}
}

func (s *fakeSSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()

	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		// Payload: 4-byte length prefix then the command string.
		if len(req.Payload) < 4 {
			_ = req.Reply(false, nil)
			continue
		}
		_ = req.Reply(true, nil)

		done := s.trackExec()
		if s.delay > 0 {
			time.Sleep(s.delay)
		}
		defer done()

		cmd := string(req.Payload[4:])
		out, known := s.responses[cmd]
		if !known {
			_, _ = io.WriteString(ch.Stderr(), "command not found\n")
			_, _ = ch.SendRequest("exit-status", false, exitStatusPayload(127))
			return
		}
		// stderr first and unread by a sequential client: this is what makes
		// the deadlock reproducible.
		if errOut, ok := s.stderrFor[cmd]; ok {
			_, _ = io.WriteString(ch.Stderr(), errOut)
		}
		_, _ = io.WriteString(ch, out)
		_, _ = ch.SendRequest("exit-status", false, exitStatusPayload(0))
		return
	}
}

func exitStatusPayload(code uint32) []byte {
	return []byte{byte(code >> 24), byte(code >> 16), byte(code >> 8), byte(code)}
}

func testExecConfig(port, concurrency int) execConfig {
	return execConfig{
		port:           port,
		concurrency:    concurrency,
		hostTimeout:    10 * time.Second,
		commandTimeout: 5 * time.Second,
		maxOutputBytes: 1 << 20,
		dialTimeout:    2 * time.Second,
		sshClientConfig: &ssh.ClientConfig{
			User:            "nudgebee-ro",
			Auth:            []ssh.AuthMethod{ssh.Password("x")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         2 * time.Second,
		},
	}
}

const ubuntuOSRelease = `NAME="Ubuntu"
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.3 LTS"`

const rhelOSRelease = `NAME="Rocky Linux"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.3"`

func debianPack(t *testing.T) *Pack {
	t.Helper()
	pub, priv := testKeys(t)
	pack, err := ParseAndVerify([]byte(signPack(t, validBody, priv)), pub)
	if err != nil {
		t.Fatalf("building pack: %v", err)
	}
	return pack
}

// The core acceptance criterion: correct per-family collectors run and their
// output comes back verbatim.
func TestRunInventory_CollectsFromDebianHost(t *testing.T) {
	pkgOutput := "acl\t2.3.1-1\tamd64\ninstall ok installed\nbash\t5.1-6ubuntu1\tamd64\n"
	srv := newFakeSSHServer(t, map[string]string{
		factsProbe:            ubuntuOSRelease + "\n---\nx86_64",
		"dpkg-query -W":       pkgOutput,
		"cat /etc/os-release": ubuntuOSRelease,
	})

	results := runInventory(context.Background(), []string{"127.0.0.1"}, debianPack(t), testExecConfig(srv.port(), 5))

	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	r := results[0]
	if r.Status != StatusOK {
		t.Fatalf("status = %s (%s), want ok", r.Status, r.Error)
	}
	if r.Facts["os_family"] != "debian" {
		t.Errorf("os_family = %q, want debian", r.Facts["os_family"])
	}
	if r.Facts["os_major"] != "22" {
		t.Errorf("os_major = %q, want 22", r.Facts["os_major"])
	}
	if got := r.Collected["pkgs-dpkg"]; got != pkgOutput {
		t.Errorf("package output altered:\ngot  %q\nwant %q", got, pkgOutput)
	}
	if _, ran := r.Collected["pkgs-rpm"]; ran {
		t.Error("rpm collector ran on a Debian host")
	}
}

// Version strings carry epoch and release suffixes that backport-aware CVE
// matching depends on; the agent must not normalize them.
func TestRunInventory_PreservesVerbatimVersions(t *testing.T) {
	rpmOutput := "bash\t0\t5.1.8\t6.el9_1\tx86_64\nkernel\t1\t5.14.0\t362.8.1.el9_3\tx86_64\n"
	srv := newFakeSSHServer(t, map[string]string{
		factsProbe:            rhelOSRelease + "\n---\nx86_64",
		"rpm -qa":             rpmOutput,
		"cat /etc/os-release": rhelOSRelease,
	})

	results := runInventory(context.Background(), []string{"127.0.0.1"}, debianPack(t), testExecConfig(srv.port(), 5))

	r := results[0]
	if r.Status != StatusOK {
		t.Fatalf("status = %s (%s), want ok", r.Status, r.Error)
	}
	if r.Facts["os_family"] != "rhel" {
		t.Fatalf("os_family = %q, want rhel (via ID_LIKE)", r.Facts["os_family"])
	}
	if got := r.Collected["pkgs-rpm"]; got != rpmOutput {
		t.Errorf("rpm output altered:\ngot  %q\nwant %q", got, rpmOutput)
	}
}

// One unreachable host must not fail the batch — the other results are the
// coverage data the product exists to produce.
func TestRunInventory_PartialFailureDoesNotFailBatch(t *testing.T) {
	srv := newFakeSSHServer(t, map[string]string{
		factsProbe:            ubuntuOSRelease + "\n---\nx86_64",
		"dpkg-query -W":       "acl\t2.3.1-1\tamd64\n",
		"cat /etc/os-release": ubuntuOSRelease,
	})

	// A port with nothing listening: closed, so the dial is refused.
	deadPort, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	deadAddr := deadPort.Addr().(*net.TCPAddr)
	_ = deadPort.Close()

	targets := make([]string, 9)
	for i := range targets {
		targets[i] = "127.0.0.1"
	}

	cfg := testExecConfig(srv.port(), 5)
	results := runInventory(context.Background(), targets, debianPack(t), cfg)

	deadCfg := cfg
	deadCfg.port = deadAddr.Port
	deadResults := runInventory(context.Background(), []string{"127.0.0.1"}, debianPack(t), deadCfg)
	results = append(results, deadResults...)

	var ok, refused int
	for _, r := range results {
		switch r.Status {
		case StatusOK:
			ok++
		case StatusSSHRefused:
			refused++
		}
	}
	if ok != 9 {
		t.Errorf("ok results = %d, want 9", ok)
	}
	if refused != 1 {
		t.Errorf("refused results = %d, want 1", refused)
	}
}

func TestRunInventory_AuthFailureIsClassified(t *testing.T) {
	srv := newFakeSSHServer(t, map[string]string{})
	srv.rejectAuth = true

	results := runInventory(context.Background(), []string{"127.0.0.1"}, debianPack(t), testExecConfig(srv.port(), 2))

	if results[0].Status != StatusSSHAuthFailed {
		t.Errorf("status = %s, want %s", results[0].Status, StatusSSHAuthFailed)
	}
}

// Concurrency must be bounded: an unbounded fan-out over a large segment
// would exhaust file descriptors on the forager and hammer the network.
func TestRunInventory_RespectsConcurrencyLimit(t *testing.T) {
	srv := newFakeSSHServer(t, map[string]string{
		factsProbe:            ubuntuOSRelease + "\n---\nx86_64",
		"dpkg-query -W":       "acl\t2.3.1-1\tamd64\n",
		"cat /etc/os-release": ubuntuOSRelease,
	})
	srv.delay = 20 * time.Millisecond

	const limit = 4
	targets := make([]string, 40)
	for i := range targets {
		targets[i] = "127.0.0.1"
	}

	results := runInventory(context.Background(), targets, debianPack(t), testExecConfig(srv.port(), limit))

	if len(results) != len(targets) {
		t.Fatalf("results = %d, want %d", len(results), len(targets))
	}
	for i, r := range results {
		if r.Status != StatusOK {
			t.Fatalf("target %d: status = %s (%s)", i, r.Status, r.Error)
		}
	}
	if peak := atomic.LoadInt32(&srv.maxConns); peak > limit {
		t.Errorf("peak concurrent connections = %d, want <= %d", peak, limit)
	}
}

// A segment-sized batch must complete without exhausting file descriptors:
// the failure mode this guards against only appears above the default
// concurrency limit, where connection reuse and cleanup start to matter.
func TestRunInventory_HandlesSegmentSizedBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scale test in short mode")
	}

	srv := newFakeSSHServer(t, map[string]string{
		factsProbe:            ubuntuOSRelease + "\n---\nx86_64",
		"dpkg-query -W":       strings.Repeat("pkg\t1.0-1\tamd64\n", 500),
		"cat /etc/os-release": ubuntuOSRelease,
	})

	const targetCount = 100
	targets := make([]string, targetCount)
	for i := range targets {
		targets[i] = "127.0.0.1"
	}

	results := runInventory(context.Background(), targets, debianPack(t), testExecConfig(srv.port(), defaultConcurrency))

	if len(results) != targetCount {
		t.Fatalf("results = %d, want %d", len(results), targetCount)
	}
	for i, r := range results {
		if r.Status != StatusOK {
			t.Fatalf("target %d: status = %s (%s)", i, r.Status, r.Error)
		}
		if r.Collected["pkgs-dpkg"] == "" {
			t.Fatalf("target %d: no package output", i)
		}
	}
	if peak := atomic.LoadInt32(&srv.maxConns); peak > defaultConcurrency {
		t.Errorf("peak concurrency = %d, want <= %d", peak, defaultConcurrency)
	}
}

// A host that accepts connections but never answers must not hold its slot
// indefinitely.
func TestRunInventory_HostTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and stall: never complete the SSH handshake.
			_ = conn
		}
	}()

	cfg := testExecConfig(ln.Addr().(*net.TCPAddr).Port, 2)
	cfg.hostTimeout = 300 * time.Millisecond
	cfg.dialTimeout = 300 * time.Millisecond

	start := time.Now()
	results := runInventory(context.Background(), []string{"127.0.0.1"}, debianPack(t), cfg)
	elapsed := time.Since(start)

	if results[0].Status == StatusOK {
		t.Error("stalled host reported ok")
	}
	if elapsed > 3*time.Second {
		t.Errorf("stalled host took %s to time out", elapsed)
	}
}

func TestRunInventory_OutputIsCapped(t *testing.T) {
	huge := strings.Repeat("x", 100_000)
	srv := newFakeSSHServer(t, map[string]string{
		factsProbe:            ubuntuOSRelease + "\n---\nx86_64",
		"dpkg-query -W":       huge,
		"cat /etc/os-release": ubuntuOSRelease,
	})

	cfg := testExecConfig(srv.port(), 2)
	cfg.maxOutputBytes = 1000

	results := runInventory(context.Background(), []string{"127.0.0.1"}, debianPack(t), cfg)

	if got := len(results[0].Collected["pkgs-dpkg"]); got > 1000 {
		t.Errorf("collected %d bytes, want <= 1000", got)
	}
}

// Reading stdout and stderr in sequence deadlocks when the remote fills one
// pipe's buffer while we wait on the other. Pipe buffers are typically 64KB,
// so a collector writing more than that to stderr — `dnf repolist` warnings,
// for one — used to hang the whole host until its timeout.
func TestRunCommand_LargeStderrDoesNotDeadlock(t *testing.T) {
	srv := newFakeSSHServer(t, map[string]string{
		factsProbe:            ubuntuOSRelease + "\n---\nx86_64",
		"cat /etc/os-release": ubuntuOSRelease,
		"dpkg-query -W":       "acl\t2.3.1-1\tamd64\n",
	})
	// Enough stderr to exhaust the SSH channel window (~2MB) before any
	// stdout is written: below that the window absorbs it and nothing blocks.
	srv.stderrFor = map[string]string{"dpkg-query -W": strings.Repeat("warning: repo unreachable\n", 200_000)}

	cfg := testExecConfig(srv.port(), 2)
	cfg.hostTimeout = 5 * time.Second
	cfg.commandTimeout = 3 * time.Second

	done := make(chan []TargetResult, 1)
	go func() {
		done <- runInventory(context.Background(), []string{"127.0.0.1"}, debianPack(t), cfg)
	}()

	select {
	case results := <-done:
		if results[0].Status != StatusOK {
			t.Fatalf("status = %s (%s), want ok", results[0].Status, results[0].Error)
		}
		if !strings.Contains(results[0].Collected["pkgs-dpkg"], "acl") {
			t.Error("stdout lost while draining a large stderr")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("inventory deadlocked on a host writing heavily to stderr")
	}
}

func TestClassifyDialError(t *testing.T) {
	cases := map[string]string{
		"ssh: handshake failed: ssh: unable to authenticate": StatusSSHAuthFailed,
		"dial tcp 10.0.0.1:22: connect: connection refused":  StatusSSHRefused,
		"dial tcp 10.0.0.1:22: connect: no route to host":    StatusSSHRefused,
		"dial tcp 10.0.0.1:22: i/o timeout":                  StatusTimeout,
		"something else entirely":                            StatusError,
	}
	for msg, want := range cases {
		if got := classifyDialError(fmt.Errorf("%s", msg)); got != want {
			t.Errorf("classify(%q) = %s, want %s", msg, got, want)
		}
	}
}

func TestParseFacts(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   map[string]string
	}{
		{
			name:   "ubuntu",
			output: ubuntuOSRelease + "\n---\nx86_64",
			want:   map[string]string{"os_family": "debian", "os_id": "ubuntu", "os_major": "22", "arch": "x86_64"},
		},
		{
			name:   "rocky via ID_LIKE",
			output: rhelOSRelease + "\n---\naarch64",
			want:   map[string]string{"os_family": "rhel", "os_id": "rocky", "os_major": "9", "arch": "aarch64"},
		},
		{
			name:   "centos 7",
			output: "NAME=\"CentOS Linux\"\nID=\"centos\"\nVERSION_ID=\"7\"\n---\nx86_64",
			want:   map[string]string{"os_family": "rhel", "os_id": "centos", "os_major": "7", "arch": "x86_64"},
		},
		{
			name:   "alpine",
			output: "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.19.1\n---\nx86_64",
			want:   map[string]string{"os_family": "alpine", "os_id": "alpine", "os_major": "3", "arch": "x86_64"},
		},
		{
			name:   "sles",
			output: "NAME=\"SLES\"\nID=\"sles\"\nVERSION_ID=\"15.5\"\n---\nx86_64",
			want:   map[string]string{"os_family": "suse", "os_id": "sles", "os_major": "15", "arch": "x86_64"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseFacts(tc.output)
			for k, want := range tc.want {
				if got[k] != want {
					t.Errorf("facts[%q] = %q, want %q", k, got[k], want)
				}
			}
		})
	}
}

// An unrecognized OS yields no os_family rather than a guess, so package
// collectors are skipped and the host is reported as a gap.
func TestParseFacts_UnknownOSHasNoFamily(t *testing.T) {
	facts := parseFacts("NAME=\"FreeBSD\"\nID=freebsd\nVERSION_ID=\"14.0\"\n---\namd64")
	if fam, ok := facts["os_family"]; ok {
		t.Errorf("os_family = %q, want absent for unknown OS", fam)
	}
}
