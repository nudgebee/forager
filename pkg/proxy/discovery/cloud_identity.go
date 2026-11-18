package discovery

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"
)

// Deliberately short relative to inventory's timeouts: this runs against
// every host a sweep finds (a much larger set than a filtered inventory
// batch typically is), and a slow/unreachable host must not meaningfully
// delay the sweep response.
const (
	cloudIdentityDialTimeout    = 5 * time.Second
	cloudIdentityHostTimeout    = 10 * time.Second
	cloudIdentityCommandTimeout = 8 * time.Second
	cloudIdentityMaxOutputBytes = 4096 // a handful of key=value lines
)

// cloudIdentityProbeCmd detects which cloud (if any) a host runs on by
// querying each provider's instance metadata service in turn, and prints the
// bare facts needed to identify the instance — never a full document. IMDS
// endpoints are link-local and only answer requests originating from the
// instance itself, so this has to run over SSH on the host, the same as
// every other command this package issues; there is no way to query it
// remotely from the forager's own process.
//
// Every field is fetched as plain text (Azure via format=text, including on
// indexed array leaves) so no JSON parser is required on the target host.
// Each attempt is capped at 1s and short-circuits on the first cloud that
// answers, so a non-cloud host pays at most ~3s total before this prints
// nothing.
//
// Every curl uses -f so an HTTP error yields empty output rather than the
// error page body: Azure's IMDS listens on the same 169.254.169.254 address as
// AWS's and answers the AWS paths with a 404 HTML page, which without -f was
// captured as an "instance ID" and reported as provider=aws. As a second
// guard, an ID is only accepted when it has the provider's shape (AWS
// i-<hex>, GCP all digits), so an unexpected 200 with junk falls through to
// the next provider instead of identifying the host wrongly.
//
// Output is unparsed key=value lines, one block for whichever
// provider matched; parsing lives server-side (see resolveOneTarget in
// nudgebee-enterprise's vmpackage/resource_match.go) so a parser fix never
// requires an agent release.
const cloudIdentityProbeCmd = `
TOKEN=$(curl -sf -m 1 -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null)
AWS_ID=$(curl -sf -m 1 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)
case "$AWS_ID" in
  i-?*) case "${AWS_ID#i-}" in *[!0-9a-f]*) AWS_ID="" ;; esac ;;
  *) AWS_ID="" ;;
esac
if [ -n "$AWS_ID" ]; then
  echo "provider=aws"
  echo "instance_id=$AWS_ID"
  echo "region=$(curl -sf -m 1 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null)"
  echo "public_ip=$(curl -sf -m 1 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)"
  exit 0
fi
GCP_ID=$(curl -sf -m 1 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/id 2>/dev/null)
case "$GCP_ID" in
  *[!0-9]*) GCP_ID="" ;;
esac
if [ -n "$GCP_ID" ]; then
  ZONE_PATH=$(curl -sf -m 1 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/zone 2>/dev/null)
  echo "provider=gcp"
  echo "instance_id=$GCP_ID"
  echo "zone=${ZONE_PATH##*/}"
  echo "public_ip=$(curl -sf -m 1 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip 2>/dev/null)"
  exit 0
fi
AZ_NAME=$(curl -sf -m 1 -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute/name?api-version=2021-02-01&format=text" 2>/dev/null)
if [ -n "$AZ_NAME" ]; then
  echo "provider=azure"
  echo "subscription_id=$(curl -sf -m 1 -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01&format=text" 2>/dev/null)"
  echo "resource_group=$(curl -sf -m 1 -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text" 2>/dev/null)"
  echo "name=$AZ_NAME"
  echo "location=$(curl -sf -m 1 -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text" 2>/dev/null)"
  echo "public_ip=$(curl -sf -m 1 -H "Metadata: true" "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text" 2>/dev/null)"
fi
`

// enrichCloudIdentity fills in CloudIdentity on every host in hosts that has
// the SSH port open, using cfg.sshClientConfig. A no-op when no SSH
// credentials are configured on this datasource (cfg.sshClientConfig == nil)
// — sweep-only datasources keep behaving exactly as before. One host's
// dial/auth/command failure never affects another's, and never fails the
// sweep as a whole: an unreachable or non-SSH host simply keeps an empty
// CloudIdentity, same tolerance enrichFromARP/enrichRDNS already have for
// hosts they cannot enrich.
func enrichCloudIdentity(ctx context.Context, hosts []SweepHost, cfg execConfig) {
	if cfg.sshClientConfig == nil {
		return
	}

	concurrency := cfg.concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for i := range hosts {
		if !slices.Contains(hosts[i].OpenPorts, cfg.port) {
			continue
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			hostCtx, cancel := context.WithTimeout(ctx, cfg.hostTimeout)
			defer cancel()

			client, err := dial(hostCtx, hosts[idx].IP, cfg)
			if err != nil {
				return
			}
			defer func() { _ = client.Close() }()

			out, _, _, _, err := runCommand(hostCtx, client, cloudIdentityProbeCmd, cfg)
			if err != nil || strings.TrimSpace(out) == "" {
				return
			}
			hosts[idx].CloudIdentity = out
		}(i)
	}
	wg.Wait()
}
