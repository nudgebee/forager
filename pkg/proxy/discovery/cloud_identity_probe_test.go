package discovery

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAzureCurl stands in for curl on an Azure VM. Azure's IMDS shares the
// 169.254.169.254 address with AWS's and answers AWS paths with a 404 HTML
// page; metadata.google.internal does not resolve. With -f an HTTP error
// prints nothing and exits 22, like real curl. When JUNK_200 is set, the AWS
// and GCP paths instead answer 200 with an HTML body, exercising the
// ID-shape validation independently of -f.
const fakeAzureCurl = `#!/bin/sh
fail=0; url=""
for a in "$@"; do
  case "$a" in
    -sf|-fs|-f) fail=1 ;;
    http://*) url="$a" ;;
  esac
done
page='<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"><html><body>Not Found</body></html>'
case "$url" in
  *metadata.google.internal*)
    if [ -n "$JUNK_200" ]; then echo "$page"; exit 0; fi
    exit 6 ;;
  */latest/*)
    if [ -n "$JUNK_200" ]; then echo "$page"; exit 0; fi
    if [ "$fail" = 1 ]; then exit 22; fi
    echo "$page"; exit 0 ;;
  */compute/name*) printf 'vm-azure-01' ;;
  */compute/subscriptionId*) printf '00000000-1111-2222-3333-444444444444' ;;
  */compute/resourceGroupName*) printf 'rg-test' ;;
  */compute/location*) printf 'eastus' ;;
  */publicIpAddress*) printf '20.1.2.3' ;;
  *) exit 22 ;;
esac
`

func runProbeWithFakeCurl(t *testing.T, env ...string) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "curl"), []byte(fakeAzureCurl), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, "-c", cloudIdentityProbeCmd)
	// Keep the parent environment; os/exec uses the last value for a
	// duplicated key, so the fake curl's PATH entry still takes precedence.
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("probe failed: %v\n%s", err, out)
	}
	return string(out)
}

func assertAzureIdentity(t *testing.T, out string) {
	t.Helper()
	for _, want := range []string{
		"provider=azure",
		"name=vm-azure-01",
		"resource_group=rg-test",
		"subscription_id=00000000-1111-2222-3333-444444444444",
		"location=eastus",
		"public_ip=20.1.2.3",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("expected %q in probe output, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "provider=aws") || strings.Contains(out, "provider=gcp") || strings.Contains(out, "DOCTYPE") {
		t.Errorf("probe misidentified the host or leaked an error page:\n%s", out)
	}
}

func TestCloudIdentityProbe_AzureNotMistakenForAWS(t *testing.T) {
	assertAzureIdentity(t, runProbeWithFakeCurl(t))
}

func TestCloudIdentityProbe_RejectsMalformedIDs(t *testing.T) {
	// AWS and GCP paths answer 200 with HTML, so -f alone would not help;
	// the ID-shape checks must reject both and fall through to Azure.
	assertAzureIdentity(t, runProbeWithFakeCurl(t, "JUNK_200=1"))
}
