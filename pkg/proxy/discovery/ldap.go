package discovery

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	defaultLDAPPort       = 389
	defaultLDAPSPort      = 636
	defaultActiveWithinD  = 90
	defaultLDAPPageSize   = 500
	defaultLDAPTimeoutS   = 30
	maxLDAPComputers      = 50000
	windowsEpochToUnixSec = 11644473600 // seconds between 1601-01-01 and 1970-01-01
)

// LDAPComputer is one computer object from the directory. AD knows machines
// exist without them being reachable, which is why this source matters: it
// contributes to the denominator a sweep alone cannot establish.
type LDAPComputer struct {
	Name       string `json:"name"`
	DNSName    string `json:"dns_name,omitempty"`
	OS         string `json:"os,omitempty"`
	OSVersion  string `json:"os_version,omitempty"`
	ObjectGUID string `json:"object_guid,omitempty"`
	LastLogon  string `json:"last_logon,omitempty"` // RFC3339, empty if never
	Enabled    bool   `json:"enabled"`
}

// LDAPResult is the response to a discovery_ldap action.
type LDAPResult struct {
	BaseDN       string         `json:"base_dn"`
	ActiveWithin int            `json:"active_within_days"`
	Returned     int            `json:"returned"`
	SkippedStale int            `json:"skipped_stale"`
	Computers    []LDAPComputer `json:"computers"`
	DurationS    float64        `json:"duration_seconds"`
}

// ldapConfig is the connection and query configuration for a directory
// datasource, pushed from the server with a read-only bind credential.
type ldapConfig struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	TLS       bool   `json:"tls"`
	StartTLS  bool   `json:"start_tls"`
	SkipVer   bool   `json:"insecure_skip_verify"`
	BaseDN    string `json:"base_dn"`
	TimeoutS  int    `json:"timeout_seconds"`
	PageSize  uint32 `json:"page_size"`
	BindDN    string `json:"-"`
	BindPass  string `json:"-"`
	MaxResult int    `json:"max_results"`
}

// runLDAPDiscovery queries computer objects, skipping ones whose last logon is
// older than activeWithin days.
//
// The staleness filter is not an optimization. AD accumulates tombstones of
// machines decommissioned years ago; importing them would inflate the asset
// count with hosts that will never be inventoried, and the coverage report —
// the deliverable this all feeds — would report permanent phantom gaps.
func runLDAPDiscovery(ctx context.Context, cfg ldapConfig, activeWithinDays int) (*LDAPResult, error) {
	start := time.Now()

	conn, err := dialLDAP(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Bind(cfg.BindDN, cfg.BindPass); err != nil {
		return nil, fmt.Errorf("ldap bind failed: %w", redactLDAPError(err))
	}

	pageSize := cfg.PageSize
	if pageSize == 0 {
		pageSize = defaultLDAPPageSize
	}
	maxResults := cfg.MaxResult
	if maxResults <= 0 || maxResults > maxLDAPComputers {
		maxResults = maxLDAPComputers
	}

	req := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, cfg.timeoutSeconds(), false,
		"(objectCategory=computer)",
		[]string{
			"name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
			"objectGUID", "lastLogonTimestamp", "userAccountControl",
		},
		nil,
	)

	res, err := conn.SearchWithPaging(req, pageSize)
	if err != nil {
		return nil, fmt.Errorf("ldap search failed: %w", redactLDAPError(err))
	}

	cutoff := time.Now().AddDate(0, 0, -activeWithinDays)
	out := make([]LDAPComputer, 0, len(res.Entries))
	skipped := 0

	for _, entry := range res.Entries {
		lastLogon := parseADTimestamp(entry.GetAttributeValue("lastLogonTimestamp"))

		// A zero timestamp means "never logged on", which is not the same as
		// stale — a freshly joined machine looks identical. Keep it and let
		// the server decide; dropping it here would hide a real host.
		if !lastLogon.IsZero() && lastLogon.Before(cutoff) {
			skipped++
			continue
		}

		computer := LDAPComputer{
			Name:       entry.GetAttributeValue("name"),
			DNSName:    strings.ToLower(entry.GetAttributeValue("dNSHostName")),
			OS:         entry.GetAttributeValue("operatingSystem"),
			OSVersion:  entry.GetAttributeValue("operatingSystemVersion"),
			ObjectGUID: formatObjectGUID(entry.GetRawAttributeValue("objectGUID")),
			Enabled:    isAccountEnabled(entry.GetAttributeValue("userAccountControl")),
		}
		if !lastLogon.IsZero() {
			computer.LastLogon = lastLogon.UTC().Format(time.RFC3339)
		}

		out = append(out, computer)
		if len(out) >= maxResults {
			break
		}
	}

	return &LDAPResult{
		BaseDN:       cfg.BaseDN,
		ActiveWithin: activeWithinDays,
		Returned:     len(out),
		SkippedStale: skipped,
		Computers:    out,
		DurationS:    time.Since(start).Seconds(),
	}, nil
}

func (c ldapConfig) timeoutSeconds() int {
	if c.TimeoutS > 0 {
		return c.TimeoutS
	}
	return defaultLDAPTimeoutS
}

func dialLDAP(ctx context.Context, cfg ldapConfig) (*ldap.Conn, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("ldap host is required")
	}

	port := cfg.Port
	if port == 0 {
		if cfg.TLS {
			port = defaultLDAPSPort
		} else {
			port = defaultLDAPPort
		}
	}

	scheme := "ldap"
	if cfg.TLS {
		scheme = "ldaps"
	}
	url := fmt.Sprintf("%s://%s:%d", scheme, cfg.Host, port)

	dialer := &net.Dialer{Timeout: time.Duration(cfg.timeoutSeconds()) * time.Second}
	opts := []ldap.DialOpt{ldap.DialWithDialer(dialer)}
	if cfg.TLS {
		opts = append(opts, ldap.DialWithTLSConfig(tlsConfigFor(cfg)))
	}

	conn, err := ldap.DialURL(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("ldap dial %s: %w", url, err)
	}

	if cfg.StartTLS && !cfg.TLS {
		if err := conn.StartTLS(tlsConfigFor(cfg)); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("ldap starttls: %w", err)
		}
	}

	conn.SetTimeout(time.Duration(cfg.timeoutSeconds()) * time.Second)
	return conn, nil
}

// tlsConfigFor builds the TLS settings for a directory connection.
// insecure_skip_verify exists because internal AD deployments commonly use a
// private CA the forager has no copy of; it must be an explicit choice in
// config rather than a silent default.
func tlsConfigFor(cfg ldapConfig) *tls.Config {
	return &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.SkipVer, // #nosec G402 -- opt-in, see doc comment
		MinVersion:         tls.VersionTLS12,
	}
}

// parseADTimestamp converts an Active Directory FILETIME (100-nanosecond
// intervals since 1601) to a time. Zero and the "never" sentinel both yield a
// zero time.
func parseADTimestamp(raw string) time.Time {
	if raw == "" || raw == "0" || raw == "9223372036854775807" {
		return time.Time{}
	}
	var ticks int64
	if _, err := fmt.Sscanf(raw, "%d", &ticks); err != nil || ticks <= 0 {
		return time.Time{}
	}
	return time.Unix(ticks/10_000_000-windowsEpochToUnixSec, 0)
}

// formatObjectGUID renders AD's little-endian mixed-endian GUID in the
// canonical string form, so it matches what other tools report for the same
// machine — this is a STRONG merge identifier and must be byte-accurate.
func formatObjectGUID(raw []byte) string {
	if len(raw) != 16 {
		if len(raw) == 0 {
			return ""
		}
		return hex.EncodeToString(raw)
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%s-%s",
		raw[3], raw[2], raw[1], raw[0],
		raw[5], raw[4],
		raw[7], raw[6],
		hex.EncodeToString(raw[8:10]),
		hex.EncodeToString(raw[10:16]),
	)
}

// isAccountEnabled reads the ACCOUNTDISABLE bit (0x2) of userAccountControl.
func isAccountEnabled(uac string) bool {
	if uac == "" {
		return true
	}
	var flags int64
	if _, err := fmt.Sscanf(uac, "%d", &flags); err != nil {
		return true
	}
	return flags&0x2 == 0
}

// redactLDAPError strips the bind DN from LDAP errors, which echo it back on
// authentication failure and would otherwise put a directory account name in
// logs and action responses.
func redactLDAPError(err error) error {
	msg := err.Error()
	if i := strings.Index(strings.ToLower(msg), "dn:"); i >= 0 {
		return fmt.Errorf("%s(dn redacted)", msg[:i])
	}
	return err
}
