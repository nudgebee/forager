package ssh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"nudgebee/forager/pkg/proxy"
)

// hostKeyServer is an in-process sshd offering both an ed25519 and an ECDSA
// host key, accepting any password. It answers keepalives so pooled
// connections stay usable.
type hostKeyServer struct {
	host    string
	port    int
	ed25519 ssh.PublicKey
}

func newHostKeyServer(t *testing.T) *hostKeyServer {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil },
	}

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := ssh.NewSignerFromKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddHostKey(edSigner)

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecSigner, err := ssh.NewSignerFromKey(ecPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddHostKey(ecSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
				_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				go func() {
					for r := range reqs {
						if r.WantReply {
							_ = r.Reply(true, nil)
						}
					}
				}()
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "handshake only")
				}
			}()
		}
	}()

	tcp := ln.Addr().(*net.TCPAddr)
	srv := &hostKeyServer{host: tcp.IP.String(), port: tcp.Port, ed25519: edSigner.PublicKey()}
	// Close the pooled client connections first (in each test's own
	// cleanup), then the listener; wg covers handlers still unwinding.
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return srv
}

func (s *hostKeyServer) addr() string { return net.JoinHostPort(s.host, strconv.Itoa(s.port)) }

func dynamicProxy(t *testing.T, cfg map[string]any) (*Proxy, error) {
	t.Helper()
	p := New(testLogger())
	err := p.Configure(cfg, map[string]string{"username": "tester", "password": "x"})
	t.Cleanup(func() { _ = p.Close() })
	return p, err
}

func connect(p *Proxy, srv *hostKeyServer) error {
	_, err := p.getClient(&proxy.ActionRequest{Params: map[string]any{"host": srv.host, "port": float64(srv.port)}})
	return err
}

func TestConfigure_HostKeyPolicyValidation(t *testing.T) {
	if _, err := dynamicProxy(t, map[string]any{"host_key_policy": "accept-new"}); err == nil {
		t.Error("accept-new accepted without known_hosts")
	}
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if _, err := dynamicProxy(t, map[string]any{"known_hosts": kh, "host_key_policy": "sometimes"}); err == nil {
		t.Error("invalid host_key_policy accepted")
	}
	if _, err := dynamicProxy(t, map[string]any{"known_hosts": kh}); err == nil {
		t.Error("strict accepted a missing known_hosts file")
	}
}

// With accept-new an unknown host is connected to and its key recorded; the
// sibling datasource that discovery registers relies on this.
func TestDynamic_AcceptNewLearnsUnknownHost(t *testing.T) {
	srv := newHostKeyServer(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")

	p, err := dynamicProxy(t, map[string]any{"known_hosts": kh, "host_key_policy": "accept-new"})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := connect(p, srv); err != nil {
		t.Fatalf("accept-new refused an unknown host: %v", err)
	}

	data, err := os.ReadFile(kh)
	if err != nil {
		t.Fatal(err)
	}
	if want := knownhosts.Line([]string{srv.addr()}, srv.ed25519); strings.TrimSpace(string(data)) != want {
		t.Errorf("known_hosts = %q, want %q", data, want)
	}
}

func TestDynamic_AcceptNewRefusesChangedKey(t *testing.T) {
	srv := newHostKeyServer(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewPublicKey(pub)
	line := knownhosts.Line([]string{srv.addr()}, other) + "\n"
	if err := os.WriteFile(kh, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := dynamicProxy(t, map[string]any{"known_hosts": kh, "host_key_policy": "accept-new"})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := connect(p, srv); err == nil {
		t.Fatal("connected to a host whose key changed")
	}
	if data, _ := os.ReadFile(kh); string(data) != line {
		t.Errorf("known_hosts modified on a changed key: %q", data)
	}
}

// known_hosts holding only the ed25519 key (what OpenSSH records) must work
// against a host that also offers ECDSA, which x/crypto would otherwise pick.
func TestDynamic_StrictPinsRecordedKeyType(t *testing.T) {
	srv := newHostKeyServer(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, []byte(knownhosts.Line([]string{srv.addr()}, srv.ed25519)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := dynamicProxy(t, map[string]any{"known_hosts": kh})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := connect(p, srv); err != nil {
		t.Fatalf("strict refused a host recorded with its ed25519 key: %v", err)
	}
}

// The same applies to a single pinned host_key in static mode.
func TestStatic_HostKeyPinsItsType(t *testing.T) {
	srv := newHostKeyServer(t)
	p := New(testLogger())
	t.Cleanup(func() { _ = p.Close() })

	err := p.Configure(map[string]any{
		"host":     srv.host,
		"port":     srv.port,
		"host_key": string(ssh.MarshalAuthorizedKey(srv.ed25519)),
	}, map[string]string{"username": "tester", "password": "x"})
	if err != nil {
		t.Fatalf("static dial with an ed25519 host_key refused: %v", err)
	}
}
