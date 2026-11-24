package hostkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// testServer is an in-process sshd that only completes the handshake. Host
// key checking happens during the handshake, so that is all these tests need.
type testServer struct {
	addr    string
	ed25519 ssh.PublicKey
	ecdsa   ssh.PublicKey
}

// newTestServer starts a server offering an ed25519 key and, when withECDSA,
// an ECDSA key too — the combination that makes x/crypto pick ECDSA while
// OpenSSH's known_hosts holds ed25519.
func newTestServer(t *testing.T, withECDSA bool) *testServer {
	t.Helper()
	cfg := &ssh.ServerConfig{NoClientAuth: true}

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := ssh.NewSignerFromKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddHostKey(edSigner)
	srv := &testServer{ed25519: edSigner.PublicKey()}

	if withECDSA {
		ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ecSigner, err := ssh.NewSignerFromKey(ecPriv)
		if err != nil {
			t.Fatal(err)
		}
		cfg.AddHostKey(ecSigner)
		srv.ecdsa = ecSigner.PublicKey()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.addr = ln.Addr().String()

	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "handshake only")
				}
				_ = sc.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return srv
}

func dialWith(store *Store, addr string, pin bool) error {
	base := &ssh.ClientConfig{
		User:            "tester",
		HostKeyCallback: store.HostKeyCallback(),
		Timeout:         5 * time.Second,
	}
	cfg := base
	if pin {
		cfg = ClientConfig(base, store.HostKeyAlgorithms, addr)
	}
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	return c.Close()
}

func writeKnownHosts(t *testing.T, path string, lines ...string) {
	t.Helper()
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func otherKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParsePolicy(t *testing.T) {
	for in, want := range map[string]string{"": PolicyStrict, "strict": PolicyStrict, "accept-new": PolicyAcceptNew} {
		got, err := ParsePolicy(in)
		if err != nil || got != want {
			t.Errorf("ParsePolicy(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"yes", "Accept-New", "off", "no"} {
		if _, err := ParsePolicy(bad); err == nil {
			t.Errorf("ParsePolicy(%q) accepted", bad)
		}
	}
}

// strict keeps today's behaviour: a missing file is a configuration error.
func TestOpen_StrictRequiresExistingFile(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing"), PolicyStrict, nil); err == nil {
		t.Fatal("strict accepted a missing known_hosts file")
	}
}

// accept-new creates the file it will learn into, private to the owner.
func TestOpen_AcceptNewCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if _, err := Open(path, PolicyAcceptNew, nil); err != nil {
		t.Fatalf("open: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

func TestStrict_RefusesUnknownHostAndLeavesFileAlone(t *testing.T) {
	srv := newTestServer(t, false)
	path := filepath.Join(t.TempDir(), "known_hosts")
	writeKnownHosts(t, path)

	store, err := Open(path, PolicyStrict, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := dialWith(store, srv.addr, true); err == nil {
		t.Fatal("strict accepted a host with no known_hosts entry")
	}
	if got := readFile(t, path); got != "" {
		t.Errorf("strict wrote to known_hosts: %q", got)
	}
}

// The core of trust on first use: an unknown host is accepted once, its key
// is recorded, and a strict reader of the same file then accepts it.
func TestAcceptNew_LearnsUnknownHost(t *testing.T) {
	srv := newTestServer(t, true)
	path := filepath.Join(t.TempDir(), "known_hosts")

	store, err := Open(path, PolicyAcceptNew, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := dialWith(store, srv.addr, true); err != nil {
		t.Fatalf("accept-new refused an unknown host: %v", err)
	}

	want := knownhosts.Line([]string{srv.addr}, srv.ed25519)
	if got := strings.TrimSpace(readFile(t, path)); got != want {
		t.Errorf("known_hosts = %q, want %q (first contact should record ed25519, as OpenSSH does)", got, want)
	}

	strict, err := Open(path, PolicyStrict, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := dialWith(strict, srv.addr, true); err != nil {
		t.Fatalf("learned key not accepted on the next dial: %v", err)
	}

	// A second accept-new dial must not append the host again.
	if err := dialWith(store, srv.addr, true); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(readFile(t, path), "\n"); n != 1 {
		t.Errorf("known_hosts has %d lines, want 1", n)
	}
}

// accept-new only covers hosts with no entry. A changed key is exactly what a
// man in the middle looks like, and must still be refused.
func TestAcceptNew_RefusesChangedKey(t *testing.T) {
	srv := newTestServer(t, false)
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{srv.addr}, otherKey(t))
	writeKnownHosts(t, path, line)

	store, err := Open(path, PolicyAcceptNew, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = dialWith(store, srv.addr, true)
	if err == nil {
		t.Fatal("accept-new accepted a host whose key changed")
	}
	if !strings.Contains(err.Error(), "key mismatch") {
		t.Errorf("error = %v, want a key mismatch", err)
	}
	if got := readFile(t, path); got != line+"\n" {
		t.Errorf("known_hosts was modified on a changed key: %q", got)
	}
}

// A file that holds only the host's ed25519 key — what OpenSSH records —
// must work against a host that also offers ECDSA. Without pinning, x/crypto
// negotiates ECDSA and the check fails as a mismatch.
func TestHostKeyAlgorithms_PinsRecordedKeyType(t *testing.T) {
	srv := newTestServer(t, true)
	path := filepath.Join(t.TempDir(), "known_hosts")
	writeKnownHosts(t, path, knownhosts.Line([]string{srv.addr}, srv.ed25519))

	store, err := Open(path, PolicyStrict, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := dialWith(store, srv.addr, false); err == nil {
		t.Fatal("unpinned dial succeeded; the test no longer reproduces the ECDSA preference")
	}
	if got := store.HostKeyAlgorithms(srv.addr); len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Errorf("algorithms = %v, want [%s]", got, ssh.KeyAlgoED25519)
	}
	if err := dialWith(store, srv.addr, true); err != nil {
		t.Fatalf("pinned dial refused: %v", err)
	}
}

func TestHostKeyAlgorithms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	ed := otherKey(t)
	writeKnownHosts(t, path,
		knownhosts.Line([]string{"192.0.2.10"}, ed),
		knownhosts.Line([]string{"[192.0.2.11]:2222"}, ed),
	)

	strict, err := Open(path, PolicyStrict, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strict.HostKeyAlgorithms("192.0.2.10:22"); len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Errorf("192.0.2.10:22 = %v", got)
	}
	if got := strict.HostKeyAlgorithms("192.0.2.11:2222"); len(got) != 1 {
		t.Errorf("non-default port entry not matched: %v", got)
	}
	if got := strict.HostKeyAlgorithms("192.0.2.11:22"); got != nil {
		t.Errorf("entry for port 2222 matched port 22: %v", got)
	}
	if got := strict.HostKeyAlgorithms("198.51.100.1:22"); got != nil {
		t.Errorf("strict pinned an unknown host: %v", got)
	}

	acceptNew, err := Open(path, PolicyAcceptNew, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := acceptNew.HostKeyAlgorithms("198.51.100.1:22")
	if len(got) == 0 || got[0] != ssh.KeyAlgoED25519 {
		t.Errorf("first-contact preference = %v, want ed25519 first", got)
	}
	for _, a := range got {
		if strings.Contains(a, "cert") {
			t.Errorf("first-contact preference includes certificate algorithm %s", a)
		}
	}
}

func TestAlgorithmsForKeyType_RSA(t *testing.T) {
	got := AlgorithmsForKeyType(ssh.KeyAlgoRSA)
	want := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

// Keys added to the file after startup — by another proxy learning them, or
// by an operator — must be seen without reopening the store.
func TestStore_SeesExternallyAddedKeys(t *testing.T) {
	srv := newTestServer(t, false)
	path := filepath.Join(t.TempDir(), "known_hosts")
	writeKnownHosts(t, path, knownhosts.Line([]string{"192.0.2.10"}, otherKey(t)))

	store, err := Open(path, PolicyStrict, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := dialWith(store, srv.addr, true); err == nil {
		t.Fatal("unknown host accepted under strict")
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(knownhosts.Line([]string{srv.addr}, srv.ed25519) + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if err := dialWith(store, srv.addr, true); err != nil {
		t.Fatalf("externally added key not seen: %v", err)
	}
}

// Many dials racing to the same new host, from two stores on one file (a
// discovery datasource and its ssh sibling), record it once.
func TestAcceptNew_ConcurrentLearnAppendsOnce(t *testing.T) {
	srv := newTestServer(t, false)
	path := filepath.Join(t.TempDir(), "known_hosts")

	a, err := Open(path, PolicyAcceptNew, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(path, PolicyAcceptNew, nil)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		store := a
		if i%2 == 1 {
			store = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- dialWith(store, srv.addr, true)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("dial: %v", err)
		}
	}
	if n := strings.Count(readFile(t, path), "\n"); n != 1 {
		t.Errorf("known_hosts has %d lines after concurrent first contact, want 1:\n%s", n, readFile(t, path))
	}
}

// A file without a trailing newline (hand-edited) must not have the learned
// entry glued onto its last line.
func TestAcceptNew_AppendsOnItsOwnLine(t *testing.T) {
	srv := newTestServer(t, false)
	path := filepath.Join(t.TempDir(), "known_hosts")
	existing := knownhosts.Line([]string{"192.0.2.10"}, otherKey(t))
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path, PolicyAcceptNew, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := dialWith(store, srv.addr, true); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(readFile(t, path)), "\n")
	if len(lines) != 2 || lines[0] != existing {
		t.Errorf("known_hosts lines = %q", lines)
	}
}
