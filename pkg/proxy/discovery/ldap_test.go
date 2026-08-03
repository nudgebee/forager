package discovery

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// objectGUID is a STRONG merge identifier: get the byte order wrong and the
// same machine seen via AD and via another source becomes two assets. AD
// stores the first three fields little-endian and the rest big-endian.
func TestFormatObjectGUID(t *testing.T) {
	raw := []byte{
		0x78, 0x56, 0x34, 0x12, // Data1, little-endian -> 12345678
		0xbc, 0x9a, // Data2, little-endian -> 9abc
		0xf0, 0xde, // Data3, little-endian -> def0
		0x12, 0x34, // Data4, big-endian
		0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	}

	got := formatObjectGUID(raw)
	want := "12345678-9abc-def0-1234-56789abcdef0"
	if got != want {
		t.Errorf("objectGUID = %s, want %s", got, want)
	}
}

func TestFormatObjectGUID_EdgeCases(t *testing.T) {
	if got := formatObjectGUID(nil); got != "" {
		t.Errorf("nil GUID = %q, want empty", got)
	}
	// A wrong-length value is returned as hex rather than silently mangled:
	// a malformed identifier must be visibly malformed, not plausible.
	if got := formatObjectGUID([]byte{0x01, 0x02}); got != "0102" {
		t.Errorf("short GUID = %q, want hex fallback", got)
	}
}

func TestParseADTimestamp(t *testing.T) {
	// 2024-01-15T10:30:00Z as a Windows FILETIME.
	want := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	ticks := (want.Unix() + windowsEpochToUnixSec) * 10_000_000

	got := parseADTimestamp(fmt.Sprintf("%d", ticks))
	if !got.UTC().Equal(want) {
		t.Errorf("timestamp = %s, want %s", got.UTC(), want)
	}
}

// "Never logged on" must be distinguishable from "logged on long ago":
// treating a never-logged-on machine as stale would hide freshly joined hosts.
func TestParseADTimestamp_NeverIsZero(t *testing.T) {
	for _, raw := range []string{"", "0", "9223372036854775807", "garbage", "-5"} {
		if got := parseADTimestamp(raw); !got.IsZero() {
			t.Errorf("parseADTimestamp(%q) = %s, want zero time", raw, got)
		}
	}
}

func TestIsAccountEnabled(t *testing.T) {
	cases := map[string]bool{
		"4096":  true,  // WORKSTATION_TRUST_ACCOUNT
		"4098":  false, // + ACCOUNTDISABLE (0x2)
		"512":   true,
		"514":   false,
		"":      true, // attribute absent: assume enabled rather than invent a disable
		"junk":  true,
		"66048": true,
	}
	for uac, want := range cases {
		if got := isAccountEnabled(uac); got != want {
			t.Errorf("isAccountEnabled(%q) = %v, want %v", uac, got, want)
		}
	}
}

// Bind failures echo the DN back; it must not reach logs or action responses.
func TestRedactLDAPError(t *testing.T) {
	err := fmt.Errorf("LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, dn: CN=svc-nudgebee,OU=Service Accounts,DC=corp,DC=local")

	got := redactLDAPError(err).Error()
	if strings.Contains(got, "svc-nudgebee") {
		t.Errorf("bind DN survived redaction: %s", got)
	}
	if !strings.Contains(got, "Invalid Credentials") {
		t.Errorf("redaction removed the useful part of the error: %s", got)
	}
}

func TestLDAPConfig_TimeoutDefault(t *testing.T) {
	if got := (ldapConfig{}).timeoutSeconds(); got != defaultLDAPTimeoutS {
		t.Errorf("default timeout = %d, want %d", got, defaultLDAPTimeoutS)
	}
	if got := (ldapConfig{TimeoutS: 5}).timeoutSeconds(); got != 5 {
		t.Errorf("timeout = %d, want 5", got)
	}
}

func TestDialLDAP_RequiresHost(t *testing.T) {
	if _, err := dialLDAP(t.Context(), ldapConfig{}); err == nil {
		t.Fatal("dialled a directory with no host configured")
	}
}

// Credentials live outside Config so they cannot be serialized back out with
// the rest of the configuration.
func TestLDAPCredentialsAreNotSerialized(t *testing.T) {
	cfg := ldapConfig{Host: "dc.corp.local", BindDN: "CN=svc", BindPass: "secret"}

	data, err := jsonMarshal(cfg)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(data, "secret") || strings.Contains(data, "CN=svc") {
		t.Errorf("credentials appear in serialized config: %s", data)
	}
}

func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
