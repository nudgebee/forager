package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nudgebee/forager/pkg/proxy"
)

// ActionVMServiceMap builds the call graph of a VM fleet from the node-agent
// series held in the datasource's Prometheus-compatible store.
//
// It lives in the http proxy because it reaches the store the same way
// http_request does — same base_url, TLS and auth — but, unlike http_request,
// it only ever sends the fixed queries below, so the control plane cannot use
// it to read anything else from that store.
const ActionVMServiceMap = "vm_service_map"

const (
	defaultServiceMapWindow = 15 * time.Minute
	maxServiceMapWindow     = 24 * time.Hour
	maxServiceMapEdges      = 5000
	serviceMapConcurrency   = 8
)

// l7Protocols maps a protocol to the node-agent counter of its requests and
// the histogram of their duration. DNS is left out: every host talks to its
// resolver, which would draw an edge from each VM to the same address.
var l7Protocols = []struct{ name, requests, duration string }{
	{"http", "container_http_requests_total", "container_http_requests_duration_seconds_total"},
	{"postgres", "container_postgres_queries_total", "container_postgres_queries_duration_seconds_total"},
	{"mysql", "container_mysql_queries_total", "container_mysql_queries_duration_seconds_total"},
	{"redis", "container_redis_queries_total", "container_redis_queries_duration_seconds_total"},
	{"memcached", "container_memcached_queries_total", "container_memcached_queries_duration_seconds_total"},
	{"mongo", "container_mongo_queries_total", "container_mongo_queries_duration_seconds_total"},
	{"kafka", "container_kafka_requests_total", "container_kafka_requests_duration_seconds_total"},
	{"cassandra", "container_cassandra_queries_total", "container_cassandra_queries_duration_seconds_total"},
	{"clickhouse", "container_clickhouse_queries_total", "container_clickhouse_queries_duration_seconds_total"},
	{"zookeeper", "container_zookeeper_requests_total", "container_zookeeper_requests_duration_seconds_total"},
	{"foundationdb", "container_foundationdb_requests_total", "container_foundationdb_requests_duration_seconds_total"},
	{"dubbo", "container_dubbo_requests_total", "container_dubbo_requests_duration_seconds_total"},
}

// failedStatus matches what the node-agent records for a failed request: an HTTP
// 5xx code, or "failed" for every other protocol (ebpftracer/l7 Status.String).
const failedStatus = `status=~"5[0-9][0-9]|failed"`

// grpcFailedStatus matches a gRPC status recorded on an HTTP/2 call: the
// node-agent writes it as status="grpc:<CODE>" on container_http_requests_total
// (containers/container.go, Status.GRPC()), so it never matches failedStatus's
// HTTP-code pattern and gRPC failures would otherwise count as zero errors.
// PromQL has no negative lookahead, so this is a second, separate query.
const grpcFailedStatus = `status=~"grpc:.*",status!="grpc:OK"`

type serviceMapListener struct {
	Addr string `json:"addr"`
	Port int    `json:"port"`
}

type serviceMapHost struct {
	InstanceID string               `json:"instance_id"`
	Hostname   string               `json:"hostname"`
	IPs        []string             `json:"ips"`
	Listeners  []serviceMapListener `json:"listeners"`
}

// serviceMapService is one active systemd unit or container on a host.
type serviceMapService struct {
	instance         string               // the store's instance label, not part of the answer
	InstanceID       string               `json:"instance_id"`
	Hostname         string               `json:"hostname"`
	ContainerID      string               `json:"container_id"`
	Name             string               `json:"name"`
	Kind             string               `json:"kind"` // systemd, docker, other
	Image            string               `json:"image,omitempty"`
	ApplicationTypes []string             `json:"application_types"`
	Listeners        []serviceMapListener `json:"listeners"`
}

type serviceMapEdge struct {
	SourceHost       string `json:"source_host"`
	SourceInstanceID string `json:"source_instance_id"`
	SourceService    string `json:"source_service"`
	SourceContainer  string `json:"source_container_id"`
	Destination      string `json:"destination"`
	DestinationKind  string `json:"destination_kind"`
	DestinationName  string `json:"destination_name"`
	// Set when the destination is a service this store knows: the host owning the
	// address and the service listening on that port there.
	DestinationHost       string  `json:"destination_host,omitempty"`
	DestinationInstanceID string  `json:"destination_instance_id,omitempty"`
	DestinationService    string  `json:"destination_service,omitempty"`
	DestinationContainer  string  `json:"destination_container_id,omitempty"`
	Protocol              string  `json:"protocol"`
	Requests              float64 `json:"requests"`
	Errors                float64 `json:"errors"`
	LatencyMs             float64 `json:"latency_ms"`
	BytesSent             float64 `json:"bytes_sent"`
	BytesReceived         float64 `json:"bytes_received"`
}

type serviceMapWindow struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type serviceMapResult struct {
	Window    serviceMapWindow    `json:"window"`
	Hosts     []serviceMapHost    `json:"hosts"`
	Services  []serviceMapService `json:"services"`
	Edges     []serviceMapEdge    `json:"edges"`
	Truncated bool                `json:"truncated,omitempty"`
}

type promSample struct {
	Metric map[string]string
	Value  float64
}

// promQuerier runs one instant query. It is a func so tests need no store.
type promQuerier func(ctx context.Context, promql string, at time.Time) ([]promSample, error)

func (p *Proxy) handleVMServiceMap(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	start, end, err := serviceMapRange(req.Params, time.Now())
	if err != nil {
		return nil, err
	}

	result, err := buildServiceMap(ctx, p.instantQuerier(), start, end)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encoding service map: %w", err)
	}
	return &proxy.ActionResponse{StatusCode: 200, Action: req.Action, Result: data}, nil
}

// serviceMapRange reads the optional start/end (RFC3339) params; no params means
// the default window ending now.
func serviceMapRange(params map[string]any, now time.Time) (time.Time, time.Time, error) {
	end := now
	if s, _ := params["end"].(string); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid end %q: %w", s, err)
		}
		end = t
	}
	start := end.Add(-defaultServiceMapWindow)
	if s, _ := params["start"].(string); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid start %q: %w", s, err)
		}
		start = t
	}
	if !start.Before(end) {
		return time.Time{}, time.Time{}, fmt.Errorf("start must be before end")
	}
	if end.Sub(start) > maxServiceMapWindow {
		return time.Time{}, time.Time{}, fmt.Errorf("window is longer than %s", maxServiceMapWindow)
	}
	return start, end, nil
}

// instantQuerier returns a querier bound to this proxy's store, auth and TLS.
func (p *Proxy) instantQuerier() promQuerier {
	p.mu.RLock()
	baseParsed, authType, creds, client, maxResp := p.baseParsed, p.authType, p.creds, p.client, p.maxRespBytes
	p.mu.RUnlock()

	return func(ctx context.Context, promql string, at time.Time) ([]promSample, error) {
		if client == nil || baseParsed == nil {
			return nil, fmt.Errorf("http proxy not configured")
		}
		q := url.Values{}
		q.Set("query", promql)
		q.Set("time", strconv.FormatFloat(float64(at.UnixMilli())/1000, 'f', 3, 64))
		target, err := p.resolveTargetURL(baseParsed, "/api/v1/query?"+q.Encode())
		if err != nil {
			return nil, err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		p.injectAuthWith(httpReq, authType, creds)

		resp, err := client.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("querying store: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		readLimit := maxResp
		if readLimit < math.MaxInt64 {
			readLimit++
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
		if err != nil {
			return nil, fmt.Errorf("reading store response: %w", err)
		}
		if int64(len(body)) > maxResp {
			return nil, fmt.Errorf("store response is larger than %d bytes", maxResp)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("store answered %d: %s", resp.StatusCode, truncate(string(body), 200))
		}
		return parsePromVector(body)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func parsePromVector(body []byte) ([]promSample, error) {
	var env struct {
		Status    string `json:"status"`
		Error     string `json:"error"`
		ErrorType string `json:"errorType"`
		Data      struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decoding store response: %w", err)
	}
	if env.Status != "success" {
		return nil, fmt.Errorf("store query failed: %s: %s", env.ErrorType, env.Error)
	}
	out := make([]promSample, 0, len(env.Data.Result))
	for _, r := range env.Data.Result {
		s, ok := r.Value[1].(string)
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		out = append(out, promSample{Metric: r.Metric, Value: v})
	}
	return out, nil
}

// queryAll runs the queries with bounded concurrency and returns the results
// by index. The first error wins and cancels the rest.
func queryAll(ctx context.Context, q promQuerier, at time.Time, queries []string) ([][]promSample, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([][]promSample, len(queries))
	errs := make([]error, len(queries))
	sem := make(chan struct{}, serviceMapConcurrency)
	var wg sync.WaitGroup
	for i, promql := range queries {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, promql string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i], errs[i] = q(ctx, promql, at)
			if errs[i] != nil {
				cancel()
			}
		}(i, promql)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

type edgeKey struct{ instance, container, destination, kind, name, protocol string }

// containerKey identifies a service across series: the store's instance label
// plus the node-agent's container id.
type containerKey struct{ instance, container string }

func buildServiceMap(ctx context.Context, q promQuerier, start, end time.Time) (serviceMapResult, error) {
	w := fmt.Sprintf("%ds", int(math.Ceil(end.Sub(start).Seconds())))
	const group = "instance, container_id, destination, destination_workload_kind, destination_workload_name"

	queries := []string{
		fmt.Sprintf("last_over_time(node_cloud_info[%s])", w),
		fmt.Sprintf("last_over_time(node_info[%s])", w),
		fmt.Sprintf("last_over_time(node_net_interface_ip[%s])", w),
		fmt.Sprintf("last_over_time(container_net_tcp_listen_info[%s])", w),
		fmt.Sprintf("last_over_time(container_info[%s])", w),
		fmt.Sprintf("last_over_time(container_application_type[%s])", w),
		fmt.Sprintf("sum by (instance, container_id, destination) (increase(container_net_tcp_bytes_sent_total[%s]))", w),
		fmt.Sprintf("sum by (instance, container_id, destination) (increase(container_net_tcp_bytes_received_total[%s]))", w),
		fmt.Sprintf("sum by (%s) (increase(container_net_tcp_successful_connects_total[%s]))", group, w),
		fmt.Sprintf("sum by (%s) (increase(container_net_tcp_failed_connects_total[%s]))", group, w),
		fmt.Sprintf("sum by (%s) (increase(container_net_tcp_connection_time_seconds_total[%s]))", group, w),
	}
	const fixed = 11
	for _, pr := range l7Protocols {
		queries = append(queries,
			fmt.Sprintf("sum by (%s) (increase(%s[%s]))", group, pr.requests, w),
			fmt.Sprintf("sum by (%s) (increase(%s{%s}[%s]))", group, pr.requests, failedStatus, w),
			fmt.Sprintf("sum by (%s) (increase(%s_sum[%s]))", group, pr.duration, w),
			fmt.Sprintf("sum by (%s) (increase(%s_count[%s]))", group, pr.duration, w),
		)
	}
	grpcErrIdx := len(queries)
	queries = append(queries,
		fmt.Sprintf("sum by (%s) (increase(container_http_requests_total{%s}[%s]))", group, grpcFailedStatus, w))

	res, err := queryAll(ctx, q, end, queries)
	if err != nil {
		return serviceMapResult{}, err
	}

	hosts, byInstance := collectHosts(res[0], res[1], res[2], res[3])
	services, svcByKey := collectServices(res[4], res[5], res[3], byInstance)
	resolver := newDestinationResolver(byInstance, services)
	bytesSent := sumByContainerPair(res[6])
	bytesRecv := sumByContainerPair(res[7])

	edges := map[edgeKey]*serviceMapEdge{}
	touch := func(s promSample, protocol string) *serviceMapEdge {
		instance, container := s.Metric["instance"], s.Metric["container_id"]
		dest := s.Metric["destination"]
		src := containerKey{instance, container}
		if !isServiceContainer(container) {
			return nil
		}
		target := resolver.resolve(instance, dest)
		if target.skip(src) {
			return nil
		}
		k := edgeKey{instance, container, dest, s.Metric["destination_workload_kind"], s.Metric["destination_workload_name"], protocol}
		e := edges[k]
		if e == nil {
			h := byInstance[instance]
			svc := svcByKey[src]
			name := svc.Name
			if name == "" {
				name = serviceName(container)
			}
			e = &serviceMapEdge{
				SourceHost: h.Hostname, SourceInstanceID: h.InstanceID,
				SourceService: name, SourceContainer: container,
				Destination: dest, DestinationKind: normalizeKind(k.kind),
				DestinationName: destinationName(dest, k.name), Protocol: protocol,
				DestinationHost: target.hostname, DestinationInstanceID: target.instanceID,
				DestinationService: target.service, DestinationContainer: target.container,
			}
			if e.SourceHost == "" {
				e.SourceHost = instance
			}
			edges[k] = e
		}
		return e
	}

	// Application protocols first: they carry real requests, errors and latency.
	covered := map[[3]string]bool{}
	for i, pr := range l7Protocols {
		base := fixed + i*4
		for _, s := range res[base] {
			if s.Value <= 0 {
				continue
			}
			if e := touch(s, pr.name); e != nil {
				e.Requests += s.Value
				covered[[3]string{s.Metric["instance"], s.Metric["container_id"], s.Metric["destination"]}] = true
			}
		}
		for _, s := range res[base+1] {
			if e := touch(s, pr.name); e != nil {
				e.Errors += s.Value
			}
		}
		sums := indexByEdge(res[base+2])
		for _, s := range res[base+3] {
			if s.Value <= 0 {
				continue
			}
			if e := touch(s, pr.name); e != nil {
				e.LatencyMs = sums[edgeIdentity(s)] / s.Value * 1000
			}
		}
	}

	// gRPC failures ride on container_http_requests_total with a grpc: status
	// that failedStatus's HTTP-code pattern cannot match; count them separately.
	for _, s := range res[grpcErrIdx] {
		if e := touch(s, "http"); e != nil {
			e.Errors += s.Value
		}
	}

	// Plain TCP for destinations no application protocol was seen on.
	tcpTime := indexByEdge(res[10])
	for _, s := range res[8] {
		if s.Value <= 0 || covered[[3]string{s.Metric["instance"], s.Metric["container_id"], s.Metric["destination"]}] {
			continue
		}
		if e := touch(s, "tcp"); e != nil {
			e.Requests += s.Value
			e.LatencyMs = tcpTime[edgeIdentity(s)] / s.Value * 1000
		}
	}
	for _, s := range res[9] {
		if s.Value <= 0 || covered[[3]string{s.Metric["instance"], s.Metric["container_id"], s.Metric["destination"]}] {
			continue
		}
		if e := touch(s, "tcp"); e != nil {
			e.Errors += s.Value
		}
	}

	// Byte counters are per destination, not per protocol: put them on the edge
	// that carried the most requests so they are not counted twice.
	best := map[[3]string]*serviceMapEdge{}
	for k, e := range edges {
		pair := [3]string{k.instance, k.container, k.destination}
		if cur := best[pair]; cur == nil || e.Requests > cur.Requests {
			best[pair] = e
		}
	}
	for pair, e := range best {
		e.BytesSent = bytesSent[pair]
		e.BytesReceived = bytesRecv[pair]
	}

	out := make([]serviceMapEdge, 0, len(edges))
	for _, e := range edges {
		// increase() extrapolates to the window edges, so counts come back
		// fractional; whole requests are what a reader can reason about.
		e.Requests, e.Errors = wholeCount(e.Requests), wholeCount(e.Errors)
		e.BytesSent, e.BytesReceived = math.Round(e.BytesSent), math.Round(e.BytesReceived)
		if e.Requests > 0 || e.Errors > 0 {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		if out[i].SourceService != out[j].SourceService {
			return out[i].SourceService < out[j].SourceService
		}
		return out[i].Destination < out[j].Destination
	})
	truncated := false
	if len(out) > maxServiceMapEdges {
		out, truncated = out[:maxServiceMapEdges], true
	}

	return serviceMapResult{
		Window:    serviceMapWindow{Start: start.UTC().Format(time.RFC3339), End: end.UTC().Format(time.RFC3339)},
		Hosts:     hosts,
		Services:  services,
		Edges:     out,
		Truncated: truncated,
	}, nil
}

// isServiceContainer keeps units and containers a reader would call a service
// and drops cgroups that are not: login sessions, slices and scopes.
func isServiceContainer(containerID string) bool {
	if containerID == "" {
		return false
	}
	if strings.HasSuffix(containerID, ".scope") || strings.HasSuffix(containerID, ".slice") {
		return false
	}
	return containerID != "/init.scope"
}

// serviceName and serviceKind read the node-agent's container id:
// /system.slice/<unit>.service, /docker/<name>, or an orchestrator path whose
// last element is the workload.
func serviceName(containerID string) string {
	id := strings.TrimRight(containerID, "/")
	if i := strings.LastIndex(id, "/"); i >= 0 {
		id = id[i+1:]
	}
	return id
}

func serviceKind(containerID string) string {
	switch {
	case strings.HasPrefix(containerID, "/docker/"):
		return "docker"
	case strings.HasSuffix(containerID, ".service"):
		return "systemd"
	default:
		return "other"
	}
}

// collectServices lists the containers that were active in the window — present
// in container_info — with their image, application types and listen addresses.
func collectServices(info, appType, listen []promSample, hosts map[string]serviceMapHost) ([]serviceMapService, map[containerKey]serviceMapService) {
	by := map[containerKey]*serviceMapService{}
	get := func(instance, container string) *serviceMapService {
		k := containerKey{instance, container}
		sv := by[k]
		if sv == nil {
			h := hosts[instance]
			sv = &serviceMapService{
				instance: instance, InstanceID: h.InstanceID, Hostname: h.Hostname, ContainerID: container,
				Name: serviceName(container), Kind: serviceKind(container),
				ApplicationTypes: []string{}, Listeners: []serviceMapListener{},
			}
			if sv.Hostname == "" {
				sv.Hostname = instance
			}
			by[k] = sv
		}
		return sv
	}
	for _, s := range info {
		if !isServiceContainer(s.Metric["container_id"]) {
			continue
		}
		sv := get(s.Metric["instance"], s.Metric["container_id"])
		if img := s.Metric["image"]; img != "" {
			sv.Image = img
		}
	}
	for _, s := range appType {
		if !isServiceContainer(s.Metric["container_id"]) {
			continue
		}
		k := containerKey{s.Metric["instance"], s.Metric["container_id"]}
		if sv := by[k]; sv != nil && s.Metric["application_type"] != "" && !contains(sv.ApplicationTypes, s.Metric["application_type"]) {
			sv.ApplicationTypes = append(sv.ApplicationTypes, s.Metric["application_type"])
		}
	}
	for _, s := range listen {
		k := containerKey{s.Metric["instance"], s.Metric["container_id"]}
		sv := by[k]
		if sv == nil {
			continue
		}
		if l, ok := parseListener(s.Metric["listen_addr"]); ok && !containsListener(sv.Listeners, l) {
			sv.Listeners = append(sv.Listeners, l)
		}
	}

	out := make([]serviceMapService, 0, len(by))
	idx := make(map[containerKey]serviceMapService, len(by))
	for k, sv := range by {
		sort.Strings(sv.ApplicationTypes)
		sort.Slice(sv.Listeners, func(i, j int) bool { return sv.Listeners[i].Addr < sv.Listeners[j].Addr })
		out = append(out, *sv)
		idx[k] = *sv
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].Name < out[j].Name
	})
	return out, idx
}

func parseListener(addr string) (serviceMapListener, bool) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return serviceMapListener{}, false
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return serviceMapListener{}, false
	}
	return serviceMapListener{Addr: addr, Port: n}, true
}

// resolvedDestination names where a destination address lands inside the store.
type resolvedDestination struct {
	hostname, instanceID, service, container string
	ownerInstance                            string // store instance the address belongs to
}

// skip is true for a service calling itself.
func (r resolvedDestination) skip(src containerKey) bool {
	return r.container != "" && r.ownerInstance == src.instance && r.container == src.container
}

type destinationResolver struct {
	instancesByIP map[string][]string
	hosts         map[string]serviceMapHost
	services      map[string][]serviceMapService // by store instance
}

func newDestinationResolver(byInstance map[string]serviceMapHost, services []serviceMapService) *destinationResolver {
	r := &destinationResolver{
		instancesByIP: map[string][]string{},
		hosts:         byInstance,
		services:      map[string][]serviceMapService{},
	}
	for instance, h := range byInstance {
		for _, ip := range h.IPs {
			r.instancesByIP[ip] = append(r.instancesByIP[ip], instance)
		}
	}
	for _, sv := range services {
		r.services[sv.instance] = append(r.services[sv.instance], sv)
	}
	return r
}

// resolve finds the host that owns dest's address and the service listening on
// its port there. An address shared by several hosts, or a port several
// services listen on, is left unresolved rather than guessed.
//
// There is no loopback case here: with the agent's default config, a same-host
// call is already reported by the store as the name "localhost/localhost"
// (kind "localhost"), not as a loopback IP, and carries no port to resolve
// against a listener — it stays an edge to "localhost", left unresolved.
func (r *destinationResolver) resolve(srcInstance, dest string) resolvedDestination {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return resolvedDestination{}
	}
	host = strings.Trim(host, "[]")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return resolvedDestination{}
	}

	owner := ""
	if owners := r.instancesByIP[host]; len(owners) == 1 {
		owner = owners[0]
	}
	h, known := r.hosts[owner]
	if owner == "" || !known {
		return resolvedDestination{}
	}

	out := resolvedDestination{hostname: h.Hostname, instanceID: h.InstanceID, ownerInstance: owner}
	var exact, wildcard []serviceMapService
	for _, sv := range r.services[owner] {
		for _, l := range sv.Listeners {
			if l.Port != port {
				continue
			}
			lh, _, _ := net.SplitHostPort(l.Addr)
			lh = strings.Trim(lh, "[]")
			switch {
			case lh == host:
				exact = append(exact, sv)
			case net.ParseIP(lh) != nil && net.ParseIP(lh).IsUnspecified():
				wildcard = append(wildcard, sv)
			default:
				continue
			}
			break
		}
	}
	pick := uniqueByContainer(exact)
	if len(pick) == 0 {
		pick = uniqueByContainer(wildcard)
	}
	if len(pick) == 1 {
		out.service, out.container = pick[0].Name, pick[0].ContainerID
	}
	return out
}

func uniqueByContainer(in []serviceMapService) []serviceMapService {
	seen := map[string]bool{}
	var out []serviceMapService
	for _, s := range in {
		if !seen[s.ContainerID] {
			seen[s.ContainerID] = true
			out = append(out, s)
		}
	}
	return out
}

// collectHosts folds the four per-node series into one record per reporting
// node, keyed by the store's `instance` label: the node-agent's machine id, or
// md5(machine_id + system_uuid) when a system UUID is present. Joins are
// unaffected either way since every series for a host carries the same value.
func collectHosts(cloud, info, ips, listen []promSample) ([]serviceMapHost, map[string]serviceMapHost) {
	by := map[string]*serviceMapHost{}
	get := func(instance string) *serviceMapHost {
		h := by[instance]
		if h == nil {
			h = &serviceMapHost{IPs: []string{}, Listeners: []serviceMapListener{}}
			by[instance] = h
		}
		return h
	}
	for _, s := range cloud {
		get(s.Metric["instance"]).InstanceID = s.Metric["instance_id"]
	}
	for _, s := range info {
		get(s.Metric["instance"]).Hostname = s.Metric["hostname"]
	}
	for _, s := range ips {
		h := get(s.Metric["instance"])
		if ip := s.Metric["ip"]; ip != "" && !contains(h.IPs, ip) {
			h.IPs = append(h.IPs, ip)
		}
	}
	for _, s := range listen {
		h := get(s.Metric["instance"])
		addr := s.Metric["listen_addr"]
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		n, err := strconv.Atoi(port)
		if err != nil {
			continue
		}
		l := serviceMapListener{Addr: addr, Port: n}
		if !containsListener(h.Listeners, l) {
			h.Listeners = append(h.Listeners, l)
		}
	}

	instances := make([]string, 0, len(by))
	for k := range by {
		instances = append(instances, k)
	}
	sort.Strings(instances)
	hosts := make([]serviceMapHost, 0, len(instances))
	byInstance := make(map[string]serviceMapHost, len(instances))
	for _, k := range instances {
		h := *by[k]
		sort.Strings(h.IPs)
		if h.Hostname == "" {
			h.Hostname = k
		}
		hosts = append(hosts, h)
		byInstance[k] = h
	}
	return hosts, byInstance
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func containsListener(list []serviceMapListener, v serviceMapListener) bool {
	for _, l := range list {
		if l == v {
			return true
		}
	}
	return false
}

func sumByContainerPair(samples []promSample) map[[3]string]float64 {
	out := map[[3]string]float64{}
	for _, s := range samples {
		out[[3]string{s.Metric["instance"], s.Metric["container_id"], s.Metric["destination"]}] += s.Value
	}
	return out
}

func edgeIdentity(s promSample) string {
	return strings.Join([]string{
		s.Metric["instance"], s.Metric["container_id"], s.Metric["destination"],
		s.Metric["destination_workload_kind"], s.Metric["destination_workload_name"],
	}, "\x00")
}

func indexByEdge(samples []promSample) map[string]float64 {
	out := make(map[string]float64, len(samples))
	for _, s := range samples {
		out[edgeIdentity(s)] += s.Value
	}
	return out
}

func normalizeKind(kind string) string {
	switch kind {
	case "vm", "private", "external", "localhost":
		return kind
	default:
		return "external"
	}
}

// destinationName is the name for a destination, or empty when there is only an
// address. The agent names an unresolved destination by its IP, so that is not a
// name; a destination that is itself a DNS name (an RDS endpoint, a SaaS host) is.
func destinationName(dest, workloadName string) string {
	host := dest
	if h, _, err := net.SplitHostPort(dest); err == nil {
		host = h
	}
	if workloadName != "" && workloadName != host && workloadName != dest {
		return workloadName
	}
	if net.ParseIP(strings.Trim(host, "[]")) == nil && host != "" {
		return host
	}
	return ""
}

// wholeCount rounds a counter delta to a whole number but never turns a call
// that happened into none: a trickle of traffic extrapolates to under one.
func wholeCount(v float64) float64 {
	if v <= 0 {
		return 0
	}
	if r := math.Round(v); r >= 1 {
		return r
	}
	return 1
}
