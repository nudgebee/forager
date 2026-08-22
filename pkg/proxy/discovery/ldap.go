package discovery

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
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

	// go-ldap has no context-aware operations, so cancellation is wired up by
	// closing the connection: an in-flight bind or search then fails
	// immediately instead of running to its own timeout. Without this, a
	// cancelled action would keep a directory query alive for up to
	// timeout_seconds after nobody is waiting for it.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	if err := conn.Bind(cfg.BindDN, cfg.BindPass); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("ldap discovery cancelled: %w", ctxErr)
		}
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
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("ldap discovery cancelled: %w", ctxErr)
		}
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
	ticks, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ticks <= 0 {
		return time.Time{}
	}
	return time.Unix(ticks/10_000_000-windowsEpochToUnixSec, 0)
}

const hexTable = "0123456789abcdef"

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

	// AD GUID is a 16-byte structure formatted as 8-4-4-4-12 hex string (36 bytes).
	// Stack-allocated buffer avoids fmt.Sprintf reflection and intermediate slice allocations.
	var buf [36]byte
	// Data1 (4 bytes, little-endian: 3, 2, 1, 0)
	buf[0] = hexTable[raw[3]>>4]
	buf[1] = hexTable[raw[3]&0x0f]
	buf[2] = hexTable[raw[2]>>4]
	buf[3] = hexTable[raw[2]&0x0f]
	buf[4] = hexTable[raw[1]>>4]
	buf[5] = hexTable[raw[1]&0x0f]
	buf[6] = hexTable[raw[0]>>4]
	buf[7] = hexTable[raw[0]&0x0f]
	buf[8] = '-'
	// Data2 (2 bytes, little-endian: 5, 4)
	buf[9] = hexTable[raw[5]>>4]
	buf[10] = hexTable[raw[5]&0x0f]
	buf[11] = hexTable[raw[4]>>4]
	buf[12] = hexTable[raw[4]&0x0f]
	buf[13] = '-'
	// Data3 (2 bytes, little-endian: 7, 6)
	buf[14] = hexTable[raw[7]>>4]
	buf[15] = hexTable[raw[7]&0x0f]
	buf[16] = hexTable[raw[6]>>4]
	buf[17] = hexTable[raw[6]&0x0f]
	buf[18] = '-'
	// Data4 (2 bytes, big-endian: 8, 9)
	buf[19] = hexTable[raw[8]>>4]
	buf[20] = hexTable[raw[8]&0x0f]
	buf[21] = hexTable[raw[9]>>4]
	buf[22] = hexTable[raw[9]&0x0f]
	buf[23] = '-'
	// Data5 (6 bytes, big-endian: 10..15)
	buf[24] = hexTable[raw[10]>>4]
	buf[25] = hexTable[raw[10]&0x0f]
	buf[26] = hexTable[raw[11]>>4]
	buf[27] = hexTable[raw[11]&0x0f]
	buf[28] = hexTable[raw[12]>>4]
	buf[29] = hexTable[raw[12]&0x0f]
	buf[30] = hexTable[raw[13]>>4]
	buf[31] = hexTable[raw[13]&0x0f]
	buf[32] = hexTable[raw[14]>>4]
	buf[33] = hexTable[raw[14]&0x0f]
	buf[34] = hexTable[raw[15]>>4]
	buf[35] = hexTable[raw[15]&0x0f]

	return string(buf[:])
}

// isAccountEnabled reads the ACCOUNTDISABLE bit (0x2) of userAccountControl.
func isAccountEnabled(uac string) bool {
	if uac == "" {
		return true
	}
	flags, err := strconv.ParseInt(uac, 10, 64)
	if err != nil {
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
