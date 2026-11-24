package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"nudgebee/forager/pkg/config"
)

// provisionEnvDiscovery prepares the discovery datasource built from
// NB_DISCOVERY_CIDR: it reports dropped CIDR entries, creates the SSH key the
// datasource points to when there is none, and logs the public key to
// authorize on the VMs. On other platforms the install scripts do this; in a
// container nothing else would.
//
// Nothing here is fatal. A failure is logged and the datasource is still
// configured, which then reports its own error.
func provisionEnvDiscovery(logger *slog.Logger, cfg *config.Config) {
	if cfg.EnvDiscoveryIgnored() {
		logger.Info("NB_DISCOVERY_CIDR is set but the config defines a discovery datasource; using the config")
	}
	ds, envErrs := cfg.EnvDiscovery()
	for _, err := range envErrs {
		logger.Error("discovery environment setting rejected", "err", err)
	}
	if ds == nil {
		return
	}

	keyPath := ds.Credentials["private_key_file"]
	user := ds.Credentials["username"]
	logger.Info("discovery datasource from environment",
		"name", ds.Name,
		"allowed_hosts", ds.AllowedHosts,
		"ssh_user", user,
		"pack_dir", ds.Discovery.PackDir,
		"ssh_access", ds.Discovery.SSHAccess,
	)

	pubLine, generated, err := ensureSSHKey(keyPath, "nudgebee-forager@"+ds.Name)
	if err != nil {
		logger.Error("discovery SSH key unavailable", "name", ds.Name, "err", err)
		return
	}
	if generated {
		logger.Warn("generated an SSH key for discovery; the key and known_hosts live in the data dir, so it must be a persistent volume or the key is lost when the container is recreated",
			"private_key_file", keyPath,
			"known_hosts_file", ds.Discovery.KnownHostsFile,
		)
	}
	// The key lives inside the container, so ssh-copy-id needs the .pub copied
	// out first (docker cp); pasting the line is the alternative.
	logger.Info("discovery SSH public key: append public_key to ~"+user+"/.ssh/authorized_keys on each VM, or copy the .pub file out of the container and run ssh_copy_id",
		"public_key", pubLine,
		"ssh_copy_id", fmt.Sprintf("ssh-copy-id -f -i %s.pub %s@<vm-ip>", keyPath, user),
	)
}

// ensureSSHKey returns the authorized_keys line for the ed25519 key at path,
// generating the key (0600, directory 0700) when the file does not exist. The
// .pub file is (re)written when missing. generated reports whether a new key
// was created.
func ensureSSHKey(path, comment string) (pubLine string, generated bool, err error) {
	pemBytes, err := os.ReadFile(path)
	if err == nil && len(pemBytes) == 0 {
		// An empty file is a key that was never written; replace it.
		if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			return "", false, fmt.Errorf("removing empty %s: %w", path, rmErr)
		}
		err = fs.ErrNotExist
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		pemBytes, err = writeNewSSHKey(path, comment)
		if err != nil {
			return "", false, err
		}
		generated = true
	case err != nil:
		return "", false, fmt.Errorf("reading %s: %w", path, err)
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return "", false, fmt.Errorf("parsing %s: %w", path, err)
	}
	pubLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " " + comment

	pubPath := path + ".pub"
	if _, err := os.Stat(pubPath); errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(pubPath, []byte(pubLine+"\n"), 0o644); err != nil {
			return "", false, fmt.Errorf("writing %s: %w", pubPath, err)
		}
	}
	return pubLine, generated, nil
}

// writeNewSSHKey creates an ed25519 key at path in OpenSSH format. The key is
// written to a temporary file and hard-linked into place, so path never holds
// a partial key, and a key another process created in between is kept (the
// link fails and that key is read instead).
func writeNewSSHKey(path, comment string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("encoding key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	tmp, err := os.CreateTemp(filepath.Dir(path), ".id_ed25519-*")
	if err != nil {
		return nil, fmt.Errorf("creating key in %s: %w", filepath.Dir(path), err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	if _, err := tmp.Write(pemBytes); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	if err := linkFile(tmpPath, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return readExistingKey(path)
		}
		// Some volumes (host bind mounts on Docker Desktop, FAT/exFAT) have
		// no hard links. Create the file exclusively and write it directly.
		return writeKeyExclusive(path, pemBytes)
	}
	return pemBytes, nil
}

// linkFile is os.Link; a variable so tests can simulate a filesystem
// without hard links.
var linkFile = os.Link

func readExistingKey(path string) ([]byte, error) {
	existing, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return existing, nil
}

// writeKeyExclusive creates path with O_EXCL and writes the key; if another
// process created it first, that key is used.
func writeKeyExclusive(path string, pemBytes []byte) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return readExistingKey(path)
		}
		return nil, fmt.Errorf("creating %s: %w", path, err)
	}
	if _, err := f.Write(pemBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	return pemBytes, nil
}
