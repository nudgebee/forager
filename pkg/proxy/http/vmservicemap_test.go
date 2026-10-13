package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nudgebee/forager/pkg/proxy"
)

// The label shapes below are copied from a live store holding node-agent series
// from three AWS VMs: instance is the agent's machine id, container_id is a
// systemd cgroup path.
const (
	web = "ec295478e2447a9a93731ed651865ed2" // 172.31.0.12
	api = "ec283bd092af8543dcc41e8076aaffe1" // 172.31.0.10

	webSvc = "/system.slice/orders-web.service"
	apiSvc = "/system.slice/orders-api.service"
	sshSvc = "/system.slice/sshd.service"
	dbSvc  = "/docker/orders-db"
)

func sample(v float64, kv ...string) promSample {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return promSample{Metric: m, Value: v}
}

// fakeStore answers by the metric the query names, like a store would.
func fakeStore(answers map[string][]promSample) promQuerier {
	return func(_ context.Context, promql string, _ time.Time) ([]promSample, error) {
		for needle, out := range answers {
			if strings.Contains(promql, needle) {
				return out, nil
			}
		}
		return nil, nil
	}
}

var fleet = map[string][]promSample{
	"node_cloud_info[": {
		sample(1, "instance", web, "instance_id", "i-004f2d9072e506e1e"),
		sample(1, "instance", api, "instance_id", "i-053da8d1122d144bc"),
	},
	"node_info[": {
		sample(1, "instance", web, "hostname", "orders-web-host"),
		sample(1, "instance", api, "hostname", "orders-api-host"),
	},
	"node_net_interface_ip[": {
		sample(1, "instance", web, "interface", "ens5", "ip", "172.31.0.12"),
		sample(1, "instance", api, "interface", "ens5", "ip", "172.31.0.10"),
	},
	"container_info[": {
		sample(1, "instance", web, "container_id", webSvc, "systemd_type", "simple"),
		sample(1, "instance", api, "container_id", apiSvc, "systemd_type", "simple"),
		sample(1, "instance", api, "container_id", sshSvc, "systemd_type", "simple"),
		sample(1, "instance", api, "container_id", dbSvc, "image", "postgres:16"),
		sample(1, "instance", api, "container_id", "/user.slice/user-1000.slice/session-3.scope"),
		sample(1, "instance", api, "container_id", "/system.slice"),
	},
	"container_application_type[": {
		sample(1, "instance", api, "container_id", dbSvc, "application_type", "postgres"),
	},
	"container_net_tcp_listen_info[": {
		sample(1, "instance", api, "container_id", apiSvc, "listen_addr", "0.0.0.0:8080"),
		sample(1, "instance", api, "container_id", sshSvc, "listen_addr", "172.31.0.10:22"),
		sample(1, "instance", api, "container_id", dbSvc, "listen_addr", "127.0.0.1:5432"),
	},
}

func merge(parts ...map[string][]promSample) map[string][]promSample {
	out := map[string][]promSample{}
	for _, p := range parts {
		for k, v := range p {
			out[k] = v
		}
	}
	return out
}

func run(t *testing.T, answers map[string][]promSample) serviceMapResult {
	t.Helper()
	end := time.Date(2026, 10, 13, 10, 15, 0, 0, time.UTC)
	res, err := buildServiceMap(context.Background(), fakeStore(merge(fleet, answers)), end.Add(-15*time.Minute), end)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func edgeTo(t *testing.T, res serviceMapResult, source, dest string) serviceMapEdge {
	t.Helper()
	for _, e := range res.Edges {
		if e.SourceService == source && e.Destination == dest {
			return e
		}
	}
	t.Fatalf("no edge %s -> %s in %+v", source, dest, res.Edges)
	return serviceMapEdge{}
}

func TestServicesAreTheActiveUnitsAndContainersOnEachHost(t *testing.T) {
	res := run(t, nil)

	byName := map[string]serviceMapService{}
	for _, s := range res.Services {
		byName[s.Hostname+"/"+s.Name] = s
	}
	if len(res.Services) != 4 {
		t.Fatalf("services = %d, want 4 (login scopes and slices are not services): %+v", len(res.Services), res.Services)
	}
	db := byName["orders-api-host/orders-db"]
	if db.Kind != "docker" || db.Image != "postgres:16" || len(db.ApplicationTypes) != 1 || db.ApplicationTypes[0] != "postgres" {
		t.Errorf("docker service = %+v", db)
	}
	if got := byName["orders-api-host/orders-api.service"]; got.Kind != "systemd" || got.InstanceID != "i-053da8d1122d144bc" || len(got.Listeners) != 1 || got.Listeners[0].Port != 8080 {
		t.Errorf("systemd service = %+v", got)
	}
}

func TestEdgeIsFromAServiceToTheServiceListeningOnTheDestination(t *testing.T) {
	d := []string{"instance", web, "container_id", webSvc, "destination", "172.31.0.10:8080", "destination_workload_kind", "private", "destination_workload_name", "172.31.0.10"}
	res := run(t, map[string][]promSample{
		"increase(container_http_requests_total{status=~":                {sample(4, d...)},
		"increase(container_http_requests_total[":                        {sample(400, d...)},
		"increase(container_http_requests_duration_seconds_total_sum[":   {sample(20, d...)},
		"increase(container_http_requests_duration_seconds_total_count[": {sample(400, d...)},
		"container_net_tcp_bytes_sent_total":                             {sample(1000, "instance", web, "container_id", webSvc, "destination", "172.31.0.10:8080")},
		"container_net_tcp_bytes_received_total":                         {sample(9000, "instance", web, "container_id", webSvc, "destination", "172.31.0.10:8080")},
	})

	e := edgeTo(t, res, "orders-web.service", "172.31.0.10:8080")
	if e.SourceHost != "orders-web-host" || e.SourceInstanceID != "i-004f2d9072e506e1e" {
		t.Errorf("source host = %q/%q", e.SourceHost, e.SourceInstanceID)
	}
	if e.DestinationService != "orders-api.service" || e.DestinationHost != "orders-api-host" || e.DestinationInstanceID != "i-053da8d1122d144bc" {
		t.Errorf("destination = %q @ %q (%q), want orders-api.service @ orders-api-host", e.DestinationService, e.DestinationHost, e.DestinationInstanceID)
	}
	if e.Protocol != "http" || e.Requests != 400 || e.Errors != 4 || e.LatencyMs != 50 {
		t.Errorf("edge = %+v, want http 400 requests 4 errors 50ms", e)
	}
	if e.BytesSent != 1000 || e.BytesReceived != 9000 {
		t.Errorf("bytes = %v/%v", e.BytesSent, e.BytesReceived)
	}
}

func TestDestinationOnAKnownHostWithNoMatchingListenerKeepsTheHost(t *testing.T) {
	d := []string{"instance", web, "container_id", webSvc, "destination", "172.31.0.10:9090", "destination_workload_kind", "private", "destination_workload_name", "172.31.0.10"}
	res := run(t, map[string][]promSample{"increase(container_http_requests_total[": {sample(10, d...)}})

	e := edgeTo(t, res, "orders-web.service", "172.31.0.10:9090")
	if e.DestinationHost != "orders-api-host" || e.DestinationService != "" {
		t.Errorf("destination = %q @ %q, want the host and no service", e.DestinationService, e.DestinationHost)
	}
}

func TestLoopbackCallsResolveToTheLocalServiceAndSelfCallsAreDropped(t *testing.T) {
	toDB := []string{"instance", api, "container_id", apiSvc, "destination", "127.0.0.1:5432", "destination_workload_kind", "private", "destination_workload_name", "127.0.0.1"}
	toSelf := []string{"instance", api, "container_id", apiSvc, "destination", "127.0.0.1:8080", "destination_workload_kind", "private", "destination_workload_name", "127.0.0.1"}
	toNothing := []string{"instance", api, "container_id", apiSvc, "destination", "127.0.0.1:6379", "destination_workload_kind", "private", "destination_workload_name", "127.0.0.1"}
	toName := []string{"instance", api, "container_id", apiSvc, "destination", "localhost/localhost", "destination_workload_kind", "external", "destination_workload_name", "localhost"}
	res := run(t, map[string][]promSample{
		"increase(container_postgres_queries_total[": {sample(30, toDB...), sample(5, toSelf...), sample(3, toNothing...), sample(2, toName...)},
	})

	if len(res.Edges) != 1 {
		t.Fatalf("edges = %+v, want only api -> db", res.Edges)
	}
	e := edgeTo(t, res, "orders-api.service", "127.0.0.1:5432")
	if e.DestinationService != "orders-db" || e.DestinationHost != "orders-api-host" {
		t.Errorf("destination = %q @ %q, want the docker container on the same host", e.DestinationService, e.DestinationHost)
	}
}

func TestTCPFallbackOnlyWhereNoProtocolWasSeen(t *testing.T) {
	httpD := []string{"instance", web, "container_id", webSvc, "destination", "172.31.0.10:8080", "destination_workload_kind", "private", "destination_workload_name", "172.31.0.10"}
	sshD := []string{"instance", web, "container_id", webSvc, "destination", "172.31.0.10:22", "destination_workload_kind", "private", "destination_workload_name", "172.31.0.10"}
	res := run(t, map[string][]promSample{
		"increase(container_http_requests_total[":                   {sample(10, httpD...)},
		"increase(container_net_tcp_successful_connects_total[":     {sample(10, httpD...), sample(7, sshD...)},
		"increase(container_net_tcp_failed_connects_total[":         {sample(3, sshD...)},
		"increase(container_net_tcp_connection_time_seconds_total[": {sample(0.7, sshD...)},
	})

	for _, e := range res.Edges {
		if e.Protocol == "tcp" && e.Destination == "172.31.0.10:8080" {
			t.Error("tcp edge repeated a destination an application protocol already covers")
		}
	}
	tcp := edgeTo(t, res, "orders-web.service", "172.31.0.10:22")
	if tcp.Protocol != "tcp" || tcp.Requests != 7 || tcp.Errors != 3 || tcp.DestinationService != "sshd.service" {
		t.Errorf("tcp edge = %+v", tcp)
	}
	if tcp.LatencyMs < 99 || tcp.LatencyMs > 101 {
		t.Errorf("tcp latency = %v ms, want 100", tcp.LatencyMs)
	}
}

func TestNonServiceCgroupsAndZeroTrafficAreNotEdges(t *testing.T) {
	scope := []string{"instance", web, "container_id", "/user.slice/user-1000.slice/session-3.scope", "destination", "172.31.0.10:22", "destination_workload_kind", "private", "destination_workload_name", "172.31.0.10"}
	idle := []string{"instance", web, "container_id", webSvc, "destination", "172.31.0.10:22", "destination_workload_kind", "private", "destination_workload_name", "172.31.0.10"}
	res := run(t, map[string][]promSample{"increase(container_http_requests_total[": {sample(50, scope...), sample(0, idle...)}})
	if len(res.Edges) != 0 {
		t.Errorf("edges = %+v, want none", res.Edges)
	}
}

func TestDNSDestinationIsNamedAndCountsAreWhole(t *testing.T) {
	rds := []string{"instance", web, "container_id", webSvc, "destination", "orders-db.abc.us-east-1.rds.amazonaws.com:5432", "destination_workload_kind", "external", "destination_workload_name", ""}
	res := run(t, map[string][]promSample{"increase(container_postgres_queries_total[": {sample(61.6, rds...)}})

	e := edgeTo(t, res, "orders-web.service", "orders-db.abc.us-east-1.rds.amazonaws.com:5432")
	if e.DestinationName != "orders-db.abc.us-east-1.rds.amazonaws.com" || e.DestinationService != "" || e.DestinationHost != "" {
		t.Errorf("destination = %+v, want a named external destination", e)
	}
	if e.Requests != 62 {
		t.Errorf("requests = %v, want 61.6 rounded to 62", e.Requests)
	}
}

func TestDestinationName(t *testing.T) {
	cases := []struct{ dest, workload, want string }{
		{"172.31.0.10:9090", "172.31.0.10", ""},
		{"172.31.0.10:22", "ip-172-31-0-10.ec2.internal", "ip-172-31-0-10.ec2.internal"},
		{"api.stripe.com:443", "", "api.stripe.com"},
		{"10.0.0.5:80", "", ""},
	}
	for _, c := range cases {
		if got := destinationName(c.dest, c.workload); got != c.want {
			t.Errorf("destinationName(%q, %q) = %q, want %q", c.dest, c.workload, got, c.want)
		}
	}
}

func TestWholeCountKeepsATrickleVisible(t *testing.T) {
	for in, want := range map[float64]float64{0: 0, -1: 0, 0.2: 1, 1.4: 1, 61.6: 62} {
		if got := wholeCount(in); got != want {
			t.Errorf("wholeCount(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestServiceNameAndKind(t *testing.T) {
	cases := []struct{ id, name, kind string }{
		{"/system.slice/sshd.service", "sshd.service", "systemd"},
		{"/docker/orders-db", "orders-db", "docker"},
		{"/swarm/ns/svc/task", "task", "other"},
	}
	for _, c := range cases {
		if serviceName(c.id) != c.name || serviceKind(c.id) != c.kind {
			t.Errorf("%s -> %s/%s, want %s/%s", c.id, serviceName(c.id), serviceKind(c.id), c.name, c.kind)
		}
	}
}

func TestParsePromVectorRejectsStoreErrorAndDropsNaN(t *testing.T) {
	if _, err := parsePromVector([]byte(`{"status":"error","errorType":"bad_data","error":"parse error"}`)); err == nil || !strings.Contains(err.Error(), "parse error") {
		t.Errorf("err = %v, want the store's reason", err)
	}
	out, err := parsePromVector([]byte(`{"status":"success","data":{"resultType":"vector","result":[
		{"metric":{"a":"1"},"value":[1,"2"]},{"metric":{"a":"2"},"value":[1,"NaN"]}]}}`))
	if err != nil || len(out) != 1 || out[0].Value != 2 {
		t.Errorf("out = %+v err = %v, want only the finite sample", out, err)
	}
}

func TestServiceMapRange(t *testing.T) {
	now := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	s, e, err := serviceMapRange(nil, now)
	if err != nil || !e.Equal(now) || e.Sub(s) != 15*time.Minute {
		t.Errorf("default = %v..%v err=%v", s, e, err)
	}
	if _, _, err := serviceMapRange(map[string]any{"start": "2026-10-11T00:00:00Z", "end": "2026-10-13T00:00:00Z"}, now); err == nil {
		t.Error("a 48h window should be refused")
	}
	if _, _, err := serviceMapRange(map[string]any{"start": "nope"}, now); err == nil {
		t.Error("a malformed start should be refused")
	}
}

// End to end through HandleRequest against an HTTP store, so the query string,
// auth header and base path all take the same route http_request does.
func TestHandleRequestVMServiceMapAgainstAnHTTPStore(t *testing.T) {
	var (
		mu      sync.Mutex
		queries []string
		gotAuth string
	)
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prom/api/v1/query" {
			t.Errorf("path = %s, want the base path kept", r.URL.Path)
		}
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		queries = append(queries, r.URL.Query().Get("query"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer store.Close()

	p := New(testLogger())
	if err := p.Configure(map[string]any{"base_url": store.URL + "/prom", "auth_type": "bearer"}, map[string]string{"bearer_token": "tok"}); err != nil {
		t.Fatal(err)
	}
	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{Action: ActionVMServiceMap})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth = %q", gotAuth)
	}
	if len(queries) == 0 {
		t.Fatal("no queries reached the store")
	}
	var out serviceMapResult
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Hosts) != 0 || len(out.Services) != 0 || len(out.Edges) != 0 {
		t.Errorf("empty store should give an empty map, got %+v", out)
	}
	for _, q := range queries {
		if strings.Contains(q, "{__name__") || strings.Contains(q, "up{") {
			t.Errorf("unexpected query %q", q)
		}
	}
}
