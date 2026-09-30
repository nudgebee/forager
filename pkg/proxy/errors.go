package proxy

import (
	"regexp"
	"strings"
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

var (
	// scheme://user:pass@host → scheme://[redacted]@host
	urlUserinfoRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@]+@`)
	// password=..., token: ..., secret=... etc.
	secretKVRe = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)(\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)`)
	pemBlockRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)`)
	ipv4Re     = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	// host:port pairs such as db.internal.example.com:5432
	hostPortRe = regexp.MustCompile(`\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+:\d{1,5}\b`)
)

// RedactError strips credentials and hostnames/IPs from an error message
// before it leaves the host, and bounds its length.
func RedactError(msg string) string {
	msg = pemBlockRe.ReplaceAllString(msg, "[redacted-key]")
	msg = urlUserinfoRe.ReplaceAllString(msg, "${1}[redacted]@")
	msg = secretKVRe.ReplaceAllString(msg, "${1}${2}[redacted]")
	msg = ipv4Re.ReplaceAllString(msg, "[redacted-host]")
	msg = hostPortRe.ReplaceAllString(msg, "[redacted-host]")
	msg = strings.Join(strings.Fields(msg), " ")
	if len(msg) > maxReportedErrorLen {
		msg = msg[:maxReportedErrorLen] + "…"
	}
	return msg
}
