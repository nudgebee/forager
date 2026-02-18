package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/IBM/sarama"

	"nudgebee/forager/pkg/proxy"
)

// Proxy implements the proxy.Proxy interface for Kafka.
type Proxy struct {
	mu     sync.RWMutex
	client sarama.Client
	admin  sarama.ClusterAdmin
	config Config
	logger *slog.Logger
}

// Config holds Kafka connection parameters.
type Config struct {
	Brokers       string `json:"brokers"` // comma-separated
	SASLMechanism string `json:"sasl_mechanism"`
	TLSEnabled    bool   `json:"tls_enabled"`
}

// New creates a new Kafka proxy.
func New(logger *slog.Logger) *Proxy {
	return &Proxy{logger: logger}
}

func (p *Proxy) Type() string { return "kafka-proxy" }

func (p *Proxy) Configure(config map[string]any, creds map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	_ = p.closeInternal()

	configJSON, _ := json.Marshal(config)
	var cfg Config
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("parsing kafka config: %w", err)
	}
	if cfg.Brokers == "" {
		return fmt.Errorf("missing brokers configuration")
	}
	p.config = cfg

	brokers := strings.Split(cfg.Brokers, ",")
	for i := range brokers {
		brokers[i] = strings.TrimSpace(brokers[i])
	}

	saramaCfg := sarama.NewConfig()
	saramaCfg.Version = sarama.V2_6_0_0

	if cfg.TLSEnabled {
		saramaCfg.Net.TLS.Enable = true
	}

	// SASL authentication
	if mechanism := cfg.SASLMechanism; mechanism != "" {
		saramaCfg.Net.SASL.Enable = true
		saramaCfg.Net.SASL.User = creds["sasl_username"]
		saramaCfg.Net.SASL.Password = creds["sasl_password"]

		switch strings.ToLower(mechanism) {
		case "plain":
			saramaCfg.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		case "scram-sha-256":
			saramaCfg.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
			saramaCfg.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
				return &scramClient{mechanism: "SHA-256"}
			}
		case "scram-sha-512":
			saramaCfg.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
			saramaCfg.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
				return &scramClient{mechanism: "SHA-512"}
			}
		}
	}

	client, err := sarama.NewClient(brokers, saramaCfg)
	if err != nil {
		return fmt.Errorf("kafka client connect failed: %w", err)
	}

	admin, err := sarama.NewClusterAdminFromClient(client)
	if err != nil {
		_ = client.Close()
		return fmt.Errorf("kafka admin client failed: %w", err)
	}

	p.client = client
	p.admin = admin
	p.logger.Info("kafka connection established", "brokers", cfg.Brokers)
	return nil
}

func (p *Proxy) HandleRequest(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	p.mu.RLock()
	client := p.client
	admin := p.admin
	p.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("kafka not configured")
	}

	switch req.Action {
	case "kafka_consumer_lag":
		return p.handleConsumerLag(client, admin, req)
	case "kafka_consumer_groups":
		return p.handleConsumerGroups(admin)
	case "kafka_consumer_group_describe":
		return p.handleConsumerGroupDescribe(admin, req)
	case "kafka_topics":
		return p.handleTopics(admin)
	case "kafka_topic_describe":
		return p.handleTopicDescribe(admin, req)
	case "kafka_brokers":
		return p.handleBrokers(client)
	case "kafka_topic_offsets":
		return p.handleTopicOffsets(client, req)
	default:
		return nil, fmt.Errorf("unknown kafka action: %s", req.Action)
	}
}

func (p *Proxy) HealthCheck(_ context.Context) error {
	p.mu.RLock()
	client := p.client
	p.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("kafka not configured")
	}

	brokers := client.Brokers()
	if len(brokers) == 0 {
		return fmt.Errorf("no brokers available")
	}
	return nil
}

func (p *Proxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeInternal()
}

func (p *Proxy) closeInternal() error {
	var firstErr error
	if p.admin != nil {
		if err := p.admin.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		p.admin = nil
	}
	if p.client != nil {
		if err := p.client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		p.client = nil
	}
	return firstErr
}

// handleConsumerLag returns per-group, per-topic, per-partition lag.
func (p *Proxy) handleConsumerLag(client sarama.Client, admin sarama.ClusterAdmin, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	group, _ := req.Params["group"].(string)
	if group == "" {
		return nil, fmt.Errorf("missing group parameter")
	}

	// Get group's committed offsets
	offsets, err := admin.ListConsumerGroupOffsets(group, nil)
	if err != nil {
		return nil, fmt.Errorf("listing consumer group offsets: %w", err)
	}

	type partitionLag struct {
		Partition     int32 `json:"partition"`
		CurrentOffset int64 `json:"current_offset"`
		LogEndOffset  int64 `json:"log_end_offset"`
		Lag           int64 `json:"lag"`
	}

	type topicLag struct {
		Topic      string         `json:"topic"`
		Partitions []partitionLag `json:"partitions"`
		TotalLag   int64          `json:"total_lag"`
	}

	var topics []topicLag
	for topic, partitions := range offsets.Blocks {
		tl := topicLag{Topic: topic}
		for partition, block := range partitions {
			if block.Offset == -1 {
				continue
			}
			logEnd, err := client.GetOffset(topic, partition, sarama.OffsetNewest)
			if err != nil {
				continue
			}
			lag := logEnd - block.Offset
			if lag < 0 {
				lag = 0
			}
			tl.Partitions = append(tl.Partitions, partitionLag{
				Partition:     partition,
				CurrentOffset: block.Offset,
				LogEndOffset:  logEnd,
				Lag:           lag,
			})
			tl.TotalLag += lag
		}
		topics = append(topics, tl)
	}

	return jsonResponse(map[string]any{"group": group, "topics": topics})
}

// handleConsumerGroups lists all consumer groups.
func (p *Proxy) handleConsumerGroups(admin sarama.ClusterAdmin) (*proxy.ActionResponse, error) {
	groups, err := admin.ListConsumerGroups()
	if err != nil {
		return nil, fmt.Errorf("listing consumer groups: %w", err)
	}

	type groupInfo struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
	}

	result := make([]groupInfo, 0, len(groups))
	for name, proto := range groups {
		result = append(result, groupInfo{Name: name, Protocol: proto})
	}

	return jsonResponse(map[string]any{"groups": result, "count": len(result)})
}

// handleConsumerGroupDescribe returns detailed group info.
func (p *Proxy) handleConsumerGroupDescribe(admin sarama.ClusterAdmin, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	group, _ := req.Params["group"].(string)
	if group == "" {
		return nil, fmt.Errorf("missing group parameter")
	}

	descriptions, err := admin.DescribeConsumerGroups([]string{group})
	if err != nil {
		return nil, fmt.Errorf("describing consumer group: %w", err)
	}

	if len(descriptions) == 0 {
		return nil, fmt.Errorf("consumer group %q not found", group)
	}

	desc := descriptions[0]

	members := make([]map[string]any, 0, len(desc.Members))
	for _, m := range desc.Members {
		assignment, _ := m.GetMemberAssignment()
		var topics []string
		if assignment != nil {
			for topic := range assignment.Topics {
				topics = append(topics, topic)
			}
		}
		members = append(members, map[string]any{
			"client_id":   m.ClientId,
			"client_host": m.ClientHost,
			"topics":      topics,
		})
	}

	return jsonResponse(map[string]any{
		"group":        desc.GroupId,
		"state":        desc.State,
		"protocol":     desc.ProtocolType,
		"members":      members,
		"member_count": len(members),
	})
}

// handleTopics lists all topics.
func (p *Proxy) handleTopics(admin sarama.ClusterAdmin) (*proxy.ActionResponse, error) {
	topics, err := admin.ListTopics()
	if err != nil {
		return nil, fmt.Errorf("listing topics: %w", err)
	}

	type topicInfo struct {
		Name              string `json:"name"`
		Partitions        int32  `json:"partitions"`
		ReplicationFactor int16  `json:"replication_factor"`
	}

	result := make([]topicInfo, 0, len(topics))
	for name, detail := range topics {
		result = append(result, topicInfo{
			Name:              name,
			Partitions:        detail.NumPartitions,
			ReplicationFactor: detail.ReplicationFactor,
		})
	}

	return jsonResponse(map[string]any{"topics": result, "count": len(result)})
}

// handleTopicDescribe returns per-partition info including leader, replicas, ISR.
func (p *Proxy) handleTopicDescribe(admin sarama.ClusterAdmin, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	topic, _ := req.Params["topic"].(string)
	if topic == "" {
		return nil, fmt.Errorf("missing topic parameter")
	}

	metadata, err := admin.DescribeTopics([]string{topic})
	if err != nil {
		return nil, fmt.Errorf("describing topic: %w", err)
	}

	if len(metadata) == 0 {
		return nil, fmt.Errorf("topic %q not found", topic)
	}

	tm := metadata[0]

	partitions := make([]map[string]any, len(tm.Partitions))
	for i, pm := range tm.Partitions {
		partitions[i] = map[string]any{
			"id":               pm.ID,
			"leader":           pm.Leader,
			"replicas":         pm.Replicas,
			"isr":              pm.Isr,
			"offline_replicas": pm.OfflineReplicas,
		}
	}

	return jsonResponse(map[string]any{
		"topic":           tm.Name,
		"partitions":      partitions,
		"partition_count": len(partitions),
		"is_internal":     tm.IsInternal,
	})
}

// handleBrokers lists all brokers.
func (p *Proxy) handleBrokers(client sarama.Client) (*proxy.ActionResponse, error) {
	brokers := client.Brokers()

	controller, _ := client.Controller()
	var controllerID int32 = -1
	if controller != nil {
		controllerID = controller.ID()
	}

	result := make([]map[string]any, len(brokers))
	for i, b := range brokers {
		result[i] = map[string]any{
			"id":            b.ID(),
			"addr":          b.Addr(),
			"is_controller": b.ID() == controllerID,
		}
	}

	return jsonResponse(map[string]any{"brokers": result, "count": len(result), "controller_id": controllerID})
}

// handleTopicOffsets returns earliest and latest offsets per partition.
func (p *Proxy) handleTopicOffsets(client sarama.Client, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	topic, _ := req.Params["topic"].(string)
	if topic == "" {
		return nil, fmt.Errorf("missing topic parameter")
	}

	partitions, err := client.Partitions(topic)
	if err != nil {
		return nil, fmt.Errorf("getting partitions: %w", err)
	}

	type partitionOffset struct {
		Partition int32 `json:"partition"`
		Earliest  int64 `json:"earliest"`
		Latest    int64 `json:"latest"`
		Messages  int64 `json:"messages"`
	}

	results := make([]partitionOffset, 0, len(partitions))
	for _, part := range partitions {
		earliest, err := client.GetOffset(topic, part, sarama.OffsetOldest)
		if err != nil {
			continue
		}
		latest, err := client.GetOffset(topic, part, sarama.OffsetNewest)
		if err != nil {
			continue
		}
		results = append(results, partitionOffset{
			Partition: part,
			Earliest:  earliest,
			Latest:    latest,
			Messages:  latest - earliest,
		})
	}

	return jsonResponse(map[string]any{"topic": topic, "partitions": results})
}

// CollectMetadata returns cluster info for the Kafka brokers.
func (p *Proxy) CollectMetadata(_ context.Context) (map[string]any, error) {
	p.mu.RLock()
	client := p.client
	cfg := p.config
	p.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("kafka not configured")
	}

	meta := map[string]any{
		"brokers": cfg.Brokers,
	}

	brokers := client.Brokers()
	meta["broker_count"] = len(brokers)

	if controller, err := client.Controller(); err == nil && controller != nil {
		meta["controller_id"] = controller.ID()
	}

	return meta, nil
}

func jsonResponse(data any) (*proxy.ActionResponse, error) {
	b, _ := json.Marshal(data)
	return &proxy.ActionResponse{
		StatusCode: 200,
		Data:       string(b),
	}, nil
}
