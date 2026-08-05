package main

// Pack key management. Verification is mandatory everywhere, including
// standalone runs, so these exist to make that practical rather than
// offering a flag to skip it — an --insecure-skip-verification option would
// end up in someone's production config eventually.

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	proxydiscovery "nudgebee/forager/pkg/proxy/discovery"
)

// splitPositional pulls non-flag arguments out before parsing.
//
// Go's flag package stops at the first non-flag argument, so
// `pack sign <file> --key X` would silently never see --key and fail with a
// usage error that points at the wrong thing. Extracting positionals first
// lets the file appear before or after the flags, which is what anyone will
// type.
func splitPositional(args []string) (positional []string, flags []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]

		// "--" ends flag parsing by convention; everything after it is
		// positional, including things that look like flags.
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}

		// A bare "-" conventionally means stdin or stdout, so it is a value
		// rather than a flag. Treating it as one would also make it swallow
		// the next argument.
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			// A flag written as "--key X" consumes the next argument, unless
			// it was written as "--key=X".
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	return positional, flags
}

func cmdPack(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pack keygen | pack sign <file> --key <base64 private key>")
	}
	switch args[0] {
	case "keygen":
		return cmdPackKeygen(args[1:])
	case "sign":
		return cmdPackSign(args[1:])
	case "verify":
		return cmdPackVerify(args[1:])
	default:
		return fmt.Errorf("unknown pack subcommand %q", args[0])
	}
}

func cmdPackKeygen(args []string) error {
	fs := flag.NewFlagSet("pack keygen", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	// Private key to stdout, public to stderr, so redirecting stdout captures
	// only the secret and the public key stays visible to the operator.
	fmt.Fprintf(os.Stderr, "public key  (set as pack_public_key): %s\n",
		base64.StdEncoding.EncodeToString(pub))
	fmt.Fprintln(os.Stderr, "private key (keep secret, printed on stdout):")
	fmt.Println(base64.StdEncoding.EncodeToString(priv))
	return nil
}

func cmdPackSign(args []string) error {
	fs := flag.NewFlagSet("pack sign", flag.ExitOnError)
	keyB64 := fs.String("key", "", "base64 Ed25519 private key (required)")
	keyEnv := fs.String("key-env", "", "environment variable holding the key, preferred over --key")
	out := fs.String("out", "", "write here instead of overwriting the input")

	positional, flags := splitPositional(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("usage: pack sign <file> --key <base64 private key>")
	}
	path := positional[0]

	// Prefer the environment: a key on the command line lands in shell history
	// and in the process list.
	material := *keyB64
	if *keyEnv != "" {
		material = os.Getenv(*keyEnv)
		if material == "" {
			return fmt.Errorf("environment variable %s is empty", *keyEnv)
		}
	}
	if material == "" {
		return fmt.Errorf("one of --key or --key-env is required")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(material)
	if err != nil {
		return fmt.Errorf("private key is not valid base64: %w", err)
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key is %d bytes, expected %d", len(keyBytes), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(keyBytes)

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading pack: %w", err)
	}

	// SignedBytes strips any existing signature line, so re-signing an already
	// signed pack works rather than nesting signatures.
	body := proxydiscovery.SignedBytes(raw)
	sig := ed25519.Sign(priv, body)
	signed := string(body) + "\nsignature: " + base64.StdEncoding.EncodeToString(sig) + "\n"

	dest := path
	if *out != "" {
		dest = *out
	}
	if err := os.WriteFile(dest, []byte(signed), 0o600); err != nil {
		return err
	}

	pub := priv.Public().(ed25519.PublicKey)
	fmt.Fprintf(os.Stderr, "signed %s\npack_public_key: %s\n",
		dest, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func cmdPackVerify(args []string) error {
	fs := flag.NewFlagSet("pack verify", flag.ExitOnError)
	pubB64 := fs.String("key", "", "base64 Ed25519 public key (required)")

	positional, flags := splitPositional(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(positional) != 1 || *pubB64 == "" {
		return fmt.Errorf("usage: pack verify <file> --key <base64 public key>")
	}

	pubBytes, err := base64.StdEncoding.DecodeString(*pubB64)
	if err != nil {
		return fmt.Errorf("public key is not valid base64: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("public key is %d bytes, expected %d", len(pubBytes), ed25519.PublicKeySize)
	}

	raw, err := os.ReadFile(positional[0])
	if err != nil {
		return err
	}

	pack, err := proxydiscovery.ParseAndVerify(raw, ed25519.PublicKey(pubBytes))
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "ok: version %d, kind %s, %d collectors\n",
		pack.Version, pack.Kind, len(pack.Collectors))
	return nil
}
