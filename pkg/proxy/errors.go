package proxy

import (
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Error classes surfaced on the Proxy Agent tab of the Agent Health page.
const (
	ErrorClassDatasource = "datasource_integration_failure"
	ErrorClassSSH        = "ssh_integration_failure"

	maxReportedErrorLen = 512
)

// ErrorClass maps a proxy type to the error class reported upstream.
func ErrorClass(proxyType string) string {
	if proxyType == "ssh-proxy" {
		return ErrorClassSSH
	}
	return ErrorClassDatasource
}

// integrationErrorMarkers are substrings (lowercase) of errors that mean the
// datasource itself is unreachable or rejecting our credentials, as opposed to
// the caller sending a bad query or hitting a policy rule.
var integrationErrorMarkers = []string{
	"connection refused", "connection reset", "broken pipe", "no such host",
	"i/o timeout", "network is unreachable", "no route to host",
	"handshake failed", "unable to authenticate", "authentication failed",
	"password authentication", "access denied for user", "permission denied (publickey",
	"host key", "x509:", "tls:", "sasl", "noauth", "wrongpass",
}

// IsIntegrationError reports whether err looks like a connectivity or
// authentication failure of the integration, rather than a caller mistake
// (invalid input, disallowed command, SQL error) which must not mark a
// healthy datasource as broken.
func IsIntegrationError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, m := range integrationErrorMarkers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

const secretKeys = `password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization|credentials?`

var (
	// scheme://user:pass@host → scheme://[redacted]@host
	urlUserinfoRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@]+@`)
	// password=..., "password":"...", token: ... (key may be followed by a closing quote)
	secretKVRe = regexp.MustCompile(`(?i)\b(` + secretKeys + `)("?\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)`)
	// Authorization header schemes with an inline credential.
	bearerRe   = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}`)
	pemBlockRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)`)

	// [fd00::5]:5432 and bare IPv6 with at least five groups.
	ipv6BracketRe = regexp.MustCompile(`\[[0-9a-fA-F:.]*:[0-9a-fA-F:.]*\]`)
	ipv6BareRe    = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b`)
	ipv4Re        = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	// host.domain:port pairs such as db.internal.example.com:5432
	hostPortRe = regexp.MustCompile(`\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+:\d{1,5}\b`)
	// Go's resolver and dialer name the host right after these words, with or
	// without dots: "lookup db.internal: no such host", "dial tcp postgres:5432".
	lookupHostRe = regexp.MustCompile(`(?i)(\blookup\s+)[^\s:]+`)
	dialHostRe   = regexp.MustCompile(`(?i)(\bdial\s+(?:tcp|udp)\d?\s+)[^\s:]+`)
)

// RedactError strips credentials and hostnames/IPs from an error message
// before it leaves the host, and bounds its length.
//
// It is best-effort: a bare hostname or a username in free-form error text
// that follows none of the patterns above is not detected.
func RedactError(msg string) string {
	msg = strings.ToValidUTF8(msg, "")
	msg = pemBlockRe.ReplaceAllString(msg, "[redacted-key]")
	msg = urlUserinfoRe.ReplaceAllString(msg, "${1}[redacted]@")
	msg = bearerRe.ReplaceAllString(msg, "${1} [redacted]")
	msg = secretKVRe.ReplaceAllString(msg, "${1}${2}[redacted]")
	msg = ipv6BracketRe.ReplaceAllString(msg, "[redacted-host]")
	msg = ipv6BareRe.ReplaceAllString(msg, "[redacted-host]")
	msg = ipv4Re.ReplaceAllString(msg, "[redacted-host]")
	msg = hostPortRe.ReplaceAllString(msg, "[redacted-host]")
	msg = lookupHostRe.ReplaceAllString(msg, "${1}[redacted-host]")
	msg = dialHostRe.ReplaceAllString(msg, "${1}[redacted-host]")
	msg = strings.Join(strings.Fields(msg), " ")
	if len(msg) > maxReportedErrorLen {
		i := maxReportedErrorLen
		for i > 0 && !utf8.RuneStart(msg[i]) {
			i--
		}
		msg = msg[:i] + "…"
	}
	return msg
}
