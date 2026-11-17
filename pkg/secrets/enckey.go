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
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// EncKeypair is this forager's X25519 keypair. Nudgebee encrypts pushed
// credentials to the public key as a NaCl sealed box, so relay-server and the
// message broker carry only a blob that nothing but this process can open.
//
// The private key comes from configuration (shared by every replica of one
// forager identity) or, for a single instance, is created on first start and
// kept beside credentials.enc. It is never sent anywhere. The public key goes up in the greeting; Nudgebee
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

// EncKeySource says where LoadEncKeypair found the private key.
type EncKeySource string

const (
	EncKeyFromConfig  EncKeySource = "enc_private_key"
	EncKeyFromFile    EncKeySource = "enc_private_key_file"
	EncKeyFromDataDir EncKeySource = "data_dir"
	EncKeyGenerated   EncKeySource = "generated"
)

// LoadEncKeypair picks the private key in this order: the configured key
// (base64 of 32 bytes), the configured key file (base64, or the 32 raw
// bytes), dataDir/enc_key, and only then a newly generated key written to
// dataDir/enc_key. Replicas of one forager identity must all open the same
// pushes, so they share a configured key; generating is the single-instance
// fallback. A configured key that is malformed is an error, never a reason
// to fall through to another source.
func LoadEncKeypair(configuredKey, keyFile, dataDir string) (*EncKeypair, EncKeySource, error) {
	switch {
	case configuredKey != "":
		priv, err := decodeEncPrivateKey([]byte(configuredKey))
		if err != nil {
			return nil, "", fmt.Errorf("enc_private_key: %w", err)
		}
		k, err := keypairFromPrivate(priv)
		return k, EncKeyFromConfig, err
	case keyFile != "":
		if err := refuseLooseKeyMode(keyFile); err != nil {
			return nil, "", fmt.Errorf("enc_private_key_file: %w", err)
		}
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, "", fmt.Errorf("enc_private_key_file: %w", err)
		}
		var priv *[32]byte
		if len(raw) == 32 {
			priv = new([32]byte)
			copy(priv[:], raw)
		} else if priv, err = decodeEncPrivateKey(raw); err != nil {
			return nil, "", fmt.Errorf("enc_private_key_file %s: %w", keyFile, err)
		}
		k, err := keypairFromPrivate(priv)
		return k, EncKeyFromFile, err
	}
	k, generated, err := loadOrCreateEncKeypair(dataDir)
	if generated {
		return k, EncKeyGenerated, err
	}
	return k, EncKeyFromDataDir, err
}

// decodeEncPrivateKey reads base64 of a 32-byte X25519 private key.
func decodeEncPrivateKey(b64 []byte) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64)))
	if err != nil {
		return nil, errors.New("expected base64 of a 32-byte key")
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("expected a 32-byte key, got %d bytes", len(raw))
	}
	var priv [32]byte
	copy(priv[:], raw)
	return &priv, nil
}

// LoadOrCreateEncKeypair reads dataDir/enc_key, or generates and writes it.
func LoadOrCreateEncKeypair(dataDir string) (*EncKeypair, error) {
	k, _, err := loadOrCreateEncKeypair(dataDir)
	return k, err
}

func loadOrCreateEncKeypair(dataDir string) (k *EncKeypair, generated bool, err error) {
	path := filepath.Join(dataDir, encKeyFile)
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(raw) != 32 {
			return nil, false, fmt.Errorf("%s: expected a 32-byte key, got %d bytes", path, len(raw))
		}
		if err := refuseLooseKeyMode(path); err != nil {
			return nil, false, err
		}
		var priv [32]byte
		copy(priv[:], raw)
		k, err := keypairFromPrivate(&priv)
		return k, false, err
	case os.IsNotExist(err):
		pub, priv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, false, fmt.Errorf("generating encryption key: %w", err)
		}
		if err := os.MkdirAll(dataDir, 0700); err != nil {
			return nil, false, fmt.Errorf("creating data dir: %w", err)
		}
		// Write-then-rename: a crash mid-write must not leave a short key file
		// that stops every later start.
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, priv[:], 0600); err != nil {
			return nil, false, fmt.Errorf("writing %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			return nil, false, fmt.Errorf("installing %s: %w", path, err)
		}
		return &EncKeypair{pub: pub, priv: priv}, true, nil
	default:
		return nil, false, fmt.Errorf("reading %s: %w", path, err)
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
	if !strings.EqualFold(strings.TrimSpace(sealed.Host), strings.TrimSpace(host)) {
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
	// Hosts are compared case-insensitively; store the canonical form.
	host = strings.ToLower(strings.TrimSpace(host))
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

// refuseLooseKeyMode refuses a private key file group or others can read: the
// key opens every sealed credential, so a copy restored from a backup, written
// with a loose umask, or mounted from a Secret with the default mode must not
// be used silently. os.Stat follows the symlinks a Kubernetes Secret volume
// uses, so the mode checked is the mounted file's.
func refuseLooseKeyMode(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is readable by group or others (mode %#o); chmod 600 it (for a Kubernetes Secret volume, set defaultMode: 0400)",
			path, info.Mode().Perm())
	}
	return nil
}
