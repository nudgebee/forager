package secrets

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// EncKeypair is this forager's X25519 keypair. Nudgebee encrypts pushed
// credentials to the public key as a NaCl sealed box, so relay-server and the
// message broker carry only a blob that nothing but this process can open.
//
// The private key is created on first start, kept beside credentials.enc and
// never sent anywhere. The public key goes up in the greeting; Nudgebee
// encrypts to it and names it by EncKeyID so a push meant for another key
// (a reinstall, a second forager) is refused with a clear reason instead of
// a decryption failure.
type EncKeypair struct {
	pub  *[32]byte
	priv *[32]byte
}

const encKeyFile = "enc_key"

// ErrEncKeyMismatch is returned when a blob names a key id that is not ours.
var ErrEncKeyMismatch = errors.New("credentials were encrypted to a different key")

// ErrSealedForOther is returned when a blob opens but was sealed for another
// datasource or host than the sync presents it for.
var ErrSealedForOther = errors.New("credentials were sealed for a different datasource or host")

// sealedCredentials is the plaintext inside a credentials_enc blob. The
// datasource id and host travel inside the seal, so a blob captured from one
// push cannot be replayed into a sync that points the same credentials at
// another datasource or host — the sealed box is anonymous and anyone with
// the public key could otherwise re-wrap it.
type sealedCredentials struct {
	V     int               `json:"v"`
	ID    string            `json:"id"`
	Host  string            `json:"host,omitempty"`
	Creds map[string]string `json:"creds"`
}

const sealedCredentialsVersion = 1

// LoadOrCreateEncKeypair reads dataDir/enc_key, or generates and writes it.
func LoadOrCreateEncKeypair(dataDir string) (*EncKeypair, error) {
	path := filepath.Join(dataDir, encKeyFile)
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(raw) != 32 {
			return nil, fmt.Errorf("%s: expected a 32-byte key, got %d bytes", path, len(raw))
		}
		var priv [32]byte
		copy(priv[:], raw)
		return keypairFromPrivate(&priv)
	case os.IsNotExist(err):
		pub, priv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating encryption key: %w", err)
		}
		if err := os.MkdirAll(dataDir, 0700); err != nil {
			return nil, fmt.Errorf("creating data dir: %w", err)
		}
		// Write-then-rename: a crash mid-write must not leave a short key file
		// that stops every later start.
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, priv[:], 0600); err != nil {
			return nil, fmt.Errorf("writing %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			return nil, fmt.Errorf("installing %s: %w", path, err)
		}
		return &EncKeypair{pub: pub, priv: priv}, nil
	default:
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
}

func keypairFromPrivate(priv *[32]byte) (*EncKeypair, error) {
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("deriving public key: %w", err)
	}
	var pub [32]byte
	copy(pub[:], pubBytes)
	return &EncKeypair{pub: &pub, priv: priv}, nil
}

// PublicKey is the base64 public key sent in the greeting.
func (k *EncKeypair) PublicKey() string {
	return base64.StdEncoding.EncodeToString(k.pub[:])
}

// KeyID names this key the way Nudgebee names it on a push.
func (k *EncKeypair) KeyID() string {
	return EncKeyID(k.pub[:])
}

// EncKeyID is the key id for a raw 32-byte public key: the first 16 hex
// characters of its SHA-256, enough to tell keys apart and short enough to
// read in a log line.
func EncKeyID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Open decrypts a credentials blob sealed to this key for datasource id and
// host. keyID, when set, must name this key; the blob is base64 of a NaCl
// sealed box over a sealedCredentials JSON document, and its id and host
// must match the ones the sync presents it for.
func (k *EncKeypair) Open(keyID, blobB64, id, host string) (map[string]string, error) {
	if keyID != "" && keyID != k.KeyID() {
		return nil, fmt.Errorf("%w (blob key %s, ours %s)", ErrEncKeyMismatch, keyID, k.KeyID())
	}
	blob, err := base64.StdEncoding.DecodeString(blobB64)
	if err != nil {
		return nil, fmt.Errorf("credentials blob is not base64: %w", err)
	}
	plain, ok := box.OpenAnonymous(nil, blob, k.pub, k.priv)
	if !ok {
		return nil, errors.New("credentials blob does not open with this key")
	}
	var sealed sealedCredentials
	if err := json.Unmarshal(plain, &sealed); err != nil || sealed.V != sealedCredentialsVersion || sealed.Creds == nil {
		return nil, errors.New("decrypted credentials are not in a format this forager understands")
	}
	if sealed.ID != id {
		return nil, fmt.Errorf("%w (sealed for datasource %s, pushed as %s)", ErrSealedForOther, sealed.ID, id)
	}
	if sealed.Host != host {
		return nil, fmt.Errorf("%w (sealed for host %q, pushed for %q)", ErrSealedForOther, sealed.Host, host)
	}
	return sealed.Creds, nil
}

// SealCredentials is the sender's half, here so tests and a local tool can
// produce blobs the forager accepts. pubB64 is the forager's PublicKey; id
// and host are the datasource the credentials are for (host as
// datasourceHost derives it from the pushed config, "" when the proxy type
// has no single host).
func SealCredentials(pubB64, id, host string, creds map[string]string) (blobB64, keyID string, err error) {
	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pubBytes) != 32 {
		return "", "", errors.New("recipient public key must be base64 of 32 bytes")
	}
	var pub [32]byte
	copy(pub[:], pubBytes)
	plain, err := json.Marshal(sealedCredentials{V: sealedCredentialsVersion, ID: id, Host: host, Creds: creds})
	if err != nil {
		return "", "", fmt.Errorf("marshaling credentials: %w", err)
	}
	sealed, err := box.SealAnonymous(nil, plain, &pub, rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("sealing credentials: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sealed), EncKeyID(pub[:]), nil
}
