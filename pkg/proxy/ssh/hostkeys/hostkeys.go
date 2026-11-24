// Package hostkeys verifies SSH host keys against an OpenSSH known_hosts file
// for the proxies that dial hosts over SSH (the ssh proxy and discovery).
//
// It adds two things on top of x/crypto's knownhosts:
//
//   - The file is re-read whenever it changes, so a key learned by one proxy,
//     or added by an operator, is seen by the next dial without a restart.
//     knownhosts.New alone reads the file once.
//   - An opt-in trust-on-first-use policy (accept-new): a host with no entry
//     has its key recorded; a host whose key differs from its entry is still
//     refused. This mirrors OpenSSH's StrictHostKeyChecking=accept-new.
//
// It also reports which key types the file holds for a host, so a client can
// ask the server for exactly those (see HostKeyAlgorithms). Without that,
// x/crypto prefers ECDSA, and a host recorded with only its ed25519 key —
// what OpenSSH records by default — is refused as a key mismatch.
package hostkeys

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Host key policies.
const (
	// PolicyStrict refuses any host whose key is not already in the file.
	PolicyStrict = "strict"
	// PolicyAcceptNew records the key of a host the file has no entry for,
	// and refuses a host whose key differs from its entry.
	PolicyAcceptNew = "accept-new"
)

// ParsePolicy validates a host_key_policy value. Empty means strict.
func ParsePolicy(s string) (string, error) {
	switch s {
	case "", PolicyStrict:
		return PolicyStrict, nil
	case PolicyAcceptNew:
		return PolicyAcceptNew, nil
	default:
		return "", fmt.Errorf("invalid host_key_policy %q (want %q or %q)", s, PolicyStrict, PolicyAcceptNew)
	}
}

// firstContactAlgorithms is the host key preference used when the file holds
// nothing for a host and its key is about to be learned. ed25519 first, as
// OpenSSH does, so a file learned here matches one OpenSSH would write.
// Certificates are left out: a certificate is not a key that can be pinned.
var firstContactAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
	ssh.KeyAlgoRSA,
}

// appendLocks serializes appends per file across every Store in the process.
// A discovery datasource and its ssh access sibling share one known_hosts
// file through two Stores; a per-Store lock would let both append the same
// host at once.
var appendLocks sync.Map // cleaned path → *sync.Mutex

func appendLock(path string) *sync.Mutex {
	m, _ := appendLocks.LoadOrStore(path, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// Store verifies host keys against one known_hosts file.
type Store struct {
	path   string
	policy string
	logger *slog.Logger

	mu      sync.Mutex
	cb      ssh.HostKeyCallback
	modTime time.Time
	size    int64
	hasCA   bool
}

// Open prepares host key verification against path.
//
// Under strict the file must exist and parse: a missing file is a
// misconfiguration, and failing here is better than refusing every host
// later. Under accept-new a missing file is created empty (0600), since
// starting with no known hosts is the point of the policy.
func Open(path, policy string, logger *slog.Logger) (*Store, error) {
	if path == "" {
		return nil, errors.New("known_hosts file path is empty")
	}
	policy, err := ParsePolicy(policy)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	// The path comes from the agent's local config (pushes cannot set it, see
	// pkg/ws). Refusing parent-directory segments keeps a typo or a templated
	// value from walking out of the directory the operator meant.
	path = filepath.Clean(path)
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("known_hosts path %q must not contain \"..\"", path)
	}

	if policy == PolicyAcceptNew {
		f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o600) // #nosec G304 -- operator-configured path
		if err != nil {
			return nil, fmt.Errorf("creating known_hosts %q: %w", path, err)
		}
		_ = f.Close()
	}

	s := &Store{path: path, policy: policy, logger: logger}
	if _, _, err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path is the known_hosts file this store reads.
func (s *Store) Path() string { return s.path }

// Policy is the effective host key policy.
func (s *Store) Policy() string { return s.policy }

// load returns the callback for the file's current contents, re-parsing only
// when the file's size or modification time changed since the last read.
func (s *Store) load() (ssh.HostKeyCallback, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fi, err := os.Stat(s.path)
	if err != nil {
		return nil, false, fmt.Errorf("loading known_hosts %q: %w", s.path, err)
	}
	if s.cb != nil && fi.ModTime().Equal(s.modTime) && fi.Size() == s.size {
		return s.cb, s.hasCA, nil
	}

	raw, err := os.ReadFile(s.path) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, false, fmt.Errorf("loading known_hosts %q: %w", s.path, err)
	}
	cb, err := knownhosts.New(s.path)
	if err != nil {
		return nil, false, fmt.Errorf("loading known_hosts %q: %w", s.path, err)
	}
	s.cb = cb
	s.modTime = fi.ModTime()
	s.size = fi.Size()
	s.hasCA = bytes.Contains(raw, []byte("@cert-authority"))
	return cb, s.hasCA, nil
}

// invalidate forces the next load to re-read the file.
func (s *Store) invalidate() {
	s.mu.Lock()
	s.cb = nil
	s.mu.Unlock()
}

// HostKeyCallback returns the callback for ssh.ClientConfig.
func (s *Store) HostKeyCallback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		cb, _, err := s.load()
		if err != nil {
			return err
		}
		err = cb(hostname, remote, key)
		if err == nil || s.policy != PolicyAcceptNew || !isUnknownHost(err) {
			return err
		}
		return s.learn(hostname, remote, key)
	}
}

// isUnknownHost reports whether err means "no entry for this host", as
// opposed to "an entry exists and the key differs".
func isUnknownHost(err error) bool {
	var ke *knownhosts.KeyError
	return errors.As(err, &ke) && len(ke.Want) == 0
}

// learn records key for a host the file has no entry for. The file is
// re-checked under the append lock so two dials racing to the same new host
// append it once, and so a key someone else recorded in the meantime is
// enforced rather than overwritten.
func (s *Store) learn(hostname string, remote net.Addr, key ssh.PublicKey) error {
	if _, isCert := key.(*ssh.Certificate); isCert {
		return fmt.Errorf("host %s presented a certificate; accept-new records plain host keys only", hostname)
	}

	lock := appendLock(s.path)
	lock.Lock()
	defer lock.Unlock()

	s.invalidate()
	cb, _, err := s.load()
	if err != nil {
		return err
	}
	if err := cb(hostname, remote, key); err == nil || !isUnknownHost(err) {
		return err
	}

	addr := hostname
	if addr == "" && remote != nil {
		addr = remote.String()
	}
	line := knownhosts.Line([]string{addr}, key) + "\n"

	// The path is from the agent's local config only: a server push cannot set
	// accept-new (see pkg/ws stripLocalOnlyConfig), so it cannot make the agent
	// write here.
	f, err := os.OpenFile(s.path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600) // #nosec G304 -- operator-configured path
	if err != nil {
		return fmt.Errorf("recording host key for %s: %w", addr, err)
	}
	if fi, err := f.Stat(); err == nil && fi.Size() > 0 && !endsWithNewline(f, fi.Size()) {
		line = "\n" + line
	}
	_, werr := f.WriteString(line)
	cerr := f.Close()
	s.invalidate()
	if werr != nil {
		return fmt.Errorf("recording host key for %s: %w", addr, werr)
	}
	if cerr != nil {
		return fmt.Errorf("recording host key for %s: %w", addr, cerr)
	}

	s.logger.Info("ssh host key learned (accept-new)",
		"host", knownhosts.Normalize(addr),
		"key_type", key.Type(),
		"fingerprint", ssh.FingerprintSHA256(key),
		"known_hosts", s.path,
	)
	return nil
}

func endsWithNewline(f *os.File, size int64) bool {
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, size-1); err != nil {
		return true
	}
	return b[0] == '\n'
}

// probeKey never matches a real host key: it is used only to make the
// known_hosts callback list the keys it holds for an address.
var probeKey = func() ssh.PublicKey {
	k, err := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		panic(err)
	}
	return k
}()

// HostKeyAlgorithms returns the host key algorithms to request from addr
// (host:port, as passed to ssh.Dial): those matching the key types the file
// already holds for it, in file order.
//
// With no entry, it returns nil under strict (the host is refused anyway) and
// a plain-key preference under accept-new. It also returns nil when the file
// holds a @cert-authority line, since pinning plain key types would stop a
// host from presenting the certificate that entry trusts.
func (s *Store) HostKeyAlgorithms(addr string) []string {
	cb, hasCA, err := s.load()
	if err != nil || hasCA {
		return nil
	}

	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	port, _ := strconv.Atoi(portStr)
	remote := &net.TCPAddr{IP: net.IPv4zero, Port: port}

	var ke *knownhosts.KeyError
	if err := cb(addr, remote, probeKey); !errors.As(err, &ke) {
		return nil
	}
	if len(ke.Want) == 0 {
		if s.policy == PolicyAcceptNew {
			return append([]string(nil), firstContactAlgorithms...)
		}
		return nil
	}

	var algos []string
	seen := map[string]bool{}
	for _, k := range ke.Want {
		for _, a := range AlgorithmsForKeyType(k.Key.Type()) {
			if !seen[a] {
				seen[a] = true
				algos = append(algos, a)
			}
		}
	}
	return algos
}

// AlgorithmsForKeyType maps a public key type to the host key algorithms that
// can present it. An RSA key can be presented with SHA-2 or SHA-1
// signatures; every other type has one algorithm of the same name.
func AlgorithmsForKeyType(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

// ClientConfig returns base with HostKeyAlgorithms set for addr when algosFor
// determines them, and base itself otherwise. base is never modified, so one
// shared config can serve dials to many hosts.
func ClientConfig(base *ssh.ClientConfig, algosFor func(addr string) []string, addr string) *ssh.ClientConfig {
	if base == nil || algosFor == nil {
		return base
	}
	algos := algosFor(addr)
	if len(algos) == 0 {
		return base
	}
	c := *base
	c.HostKeyAlgorithms = algos
	return &c
}
