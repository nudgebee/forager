package mongodb

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"nudgebee/forager/pkg/proxy"
)

// Proxy implements the proxy.Proxy interface for MongoDB.
type Proxy struct {
	mu     sync.RWMutex
	client *mongo.Client
	config Config
	logger *slog.Logger
}

// Config holds MongoDB connection parameters.
type Config struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Database   string `json:"database"`
	ReplicaSet string `json:"replica_set"`
	AuthSource string `json:"auth_source"`
	TLSEnabled bool   `json:"tls_enabled"`
}

// New creates a new MongoDB proxy.
func New(logger *slog.Logger) *Proxy {
	return &Proxy{logger: logger}
}

func (p *Proxy) Type() string { return "mongo-proxy" }

func (p *Proxy) Configure(config map[string]any, creds map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil {
		_ = p.client.Disconnect(context.Background())
		p.client = nil
	}

	configJSON, _ := json.Marshal(config)
	var cfg Config
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("parsing mongo config: %w", err)
	}
	if cfg.Port == 0 {
		cfg.Port = 27017
	}
	if cfg.AuthSource == "" {
		cfg.AuthSource = "admin"
	}

	p.config = cfg

	uri := p.buildURI(creds)
	opts := options.Client().ApplyURI(uri)

	client, err := mongo.Connect(opts)
	if err != nil {
		return fmt.Errorf("connecting to mongodb: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return fmt.Errorf("mongodb ping failed: %w", err)
	}

	p.client = client
	p.logger.Info("mongodb connection established",
		"host", cfg.Host, "port", cfg.Port, "database", cfg.Database)
	return nil
}

func (p *Proxy) buildURI(creds map[string]string) string {
	username := creds["username"]
	password := creds["password"]

	var userInfo string
	if username != "" {
		userInfo = fmt.Sprintf("%s:%s@", username, password)
	}

	uri := fmt.Sprintf("mongodb://%s%s:%d/%s?authSource=%s",
		userInfo, p.config.Host, p.config.Port, p.config.Database, p.config.AuthSource)

	if p.config.ReplicaSet != "" {
		uri += "&replicaSet=" + p.config.ReplicaSet
	}
	if p.config.TLSEnabled {
		uri += "&tls=true"
	}
	return uri
}

func (p *Proxy) HandleRequest(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	p.mu.RLock()
	client := p.client
	p.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("mongodb not configured")
	}

	switch req.Action {
	case "mongo_query":
		return p.handleQuery(ctx, client, req)
	case "mongo_aggregate":
		return p.handleAggregate(ctx, client, req)
	case "mongo_server_status":
		return p.handleServerStatus(ctx, client)
	case "mongo_repl_status":
		return p.handleReplStatus(ctx, client)
	case "mongo_collection_stats":
		return p.handleCollectionStats(ctx, client, req)
	case "mongo_current_ops":
		return p.handleCurrentOps(ctx, client)
	case "mongo_db_stats":
		return p.handleDBStats(ctx, client, req)
	case "mongo_list_databases":
		return p.handleListDatabases(ctx, client)
	case "mongo_list_collections":
		return p.handleListCollections(ctx, client, req)
	default:
		return nil, fmt.Errorf("unknown mongo action: %s", req.Action)
	}
}

func (p *Proxy) HealthCheck(ctx context.Context) error {
	p.mu.RLock()
	client := p.client
	p.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("mongodb not configured")
	}
	return client.Ping(ctx, nil)
}

func (p *Proxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil {
		err := p.client.Disconnect(context.Background())
		p.client = nil
		return err
	}
	return nil
}

// handleQuery executes a find operation.
func (p *Proxy) handleQuery(ctx context.Context, client *mongo.Client, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	start := time.Now()

	dbName := p.getDatabase(req)
	collection, _ := req.Params["collection"].(string)
	if collection == "" {
		return nil, fmt.Errorf("missing collection parameter")
	}

	// Parse filter
	filter := bson.D{}
	if f, ok := req.Params["filter"].(map[string]any); ok {
		filter = mapToBsonD(f)
	}

	maxRows := 1000
	if v, ok := req.Params["max_rows"].(float64); ok && v > 0 {
		maxRows = int(v)
	}

	coll := client.Database(dbName).Collection(collection)
	opts := options.Find().SetLimit(int64(maxRows))

	if sort, ok := req.Params["sort"].(map[string]any); ok {
		opts.SetSort(mapToBsonD(sort))
	}

	cursor, err := coll.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("mongo find failed: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("reading cursor: %w", err)
	}

	return p.jsonResponse(map[string]any{
		"documents":   results,
		"count":       len(results),
		"duration_ms": time.Since(start).Milliseconds(),
	})
}

// handleAggregate runs an aggregation pipeline.
func (p *Proxy) handleAggregate(ctx context.Context, client *mongo.Client, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	start := time.Now()

	dbName := p.getDatabase(req)
	collection, _ := req.Params["collection"].(string)
	if collection == "" {
		return nil, fmt.Errorf("missing collection parameter")
	}

	pipelineRaw, ok := req.Params["pipeline"].([]any)
	if !ok || len(pipelineRaw) == 0 {
		return nil, fmt.Errorf("missing or empty pipeline parameter")
	}

	pipeline := make(bson.A, len(pipelineRaw))
	for i, stage := range pipelineRaw {
		if m, ok := stage.(map[string]any); ok {
			pipeline[i] = mapToBsonD(m)
		} else {
			pipeline[i] = stage
		}
	}

	coll := client.Database(dbName).Collection(collection)
	cursor, err := coll.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("mongo aggregate failed: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("reading aggregate cursor: %w", err)
	}

	return p.jsonResponse(map[string]any{
		"documents":   results,
		"count":       len(results),
		"duration_ms": time.Since(start).Milliseconds(),
	})
}

// handleServerStatus returns db.serverStatus() — connections, opcounters, memory, replication.
func (p *Proxy) handleServerStatus(ctx context.Context, client *mongo.Client) (*proxy.ActionResponse, error) {
	var result bson.M
	err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("serverStatus failed: %w", err)
	}
	return p.jsonResponse(result)
}

// handleReplStatus returns rs.status() — member states, optimes, lag.
func (p *Proxy) handleReplStatus(ctx context.Context, client *mongo.Client) (*proxy.ActionResponse, error) {
	var result bson.M
	err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "replSetGetStatus", Value: 1}}).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("replSetGetStatus failed: %w", err)
	}
	return p.jsonResponse(result)
}

// handleCollectionStats returns collection.stats() — doc count, sizes, indexes.
func (p *Proxy) handleCollectionStats(ctx context.Context, client *mongo.Client, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	dbName := p.getDatabase(req)
	collection, _ := req.Params["collection"].(string)
	if collection == "" {
		return nil, fmt.Errorf("missing collection parameter")
	}

	var result bson.M
	err := client.Database(dbName).RunCommand(ctx, bson.D{{Key: "collStats", Value: collection}}).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("collStats failed: %w", err)
	}
	return p.jsonResponse(result)
}

// handleCurrentOps returns db.currentOp() — running operations, lock waits.
func (p *Proxy) handleCurrentOps(ctx context.Context, client *mongo.Client) (*proxy.ActionResponse, error) {
	var result bson.M
	err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "currentOp", Value: 1}}).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("currentOp failed: %w", err)
	}
	return p.jsonResponse(result)
}

// handleDBStats returns db.stats() — storage size, index size, object count.
func (p *Proxy) handleDBStats(ctx context.Context, client *mongo.Client, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	dbName := p.getDatabase(req)
	var result bson.M
	err := client.Database(dbName).RunCommand(ctx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("dbStats failed: %w", err)
	}
	return p.jsonResponse(result)
}

// handleListDatabases lists all databases with sizes.
func (p *Proxy) handleListDatabases(ctx context.Context, client *mongo.Client) (*proxy.ActionResponse, error) {
	result, err := client.ListDatabases(ctx, bson.D{})
	if err != nil {
		return nil, fmt.Errorf("listDatabases failed: %w", err)
	}
	return p.jsonResponse(map[string]any{
		"databases":  result.Databases,
		"total_size": result.TotalSize,
	})
}

// handleListCollections lists collections in a database.
func (p *Proxy) handleListCollections(ctx context.Context, client *mongo.Client, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	dbName := p.getDatabase(req)
	collections, err := client.Database(dbName).ListCollectionNames(ctx, bson.D{})
	if err != nil {
		return nil, fmt.Errorf("listCollections failed: %w", err)
	}
	return p.jsonResponse(map[string]any{
		"database":    dbName,
		"collections": collections,
		"count":       len(collections),
	})
}

func (p *Proxy) getDatabase(req *proxy.ActionRequest) string {
	if db, ok := req.Params["database"].(string); ok && db != "" {
		return db
	}
	return p.config.Database
}

func (p *Proxy) jsonResponse(data any) (*proxy.ActionResponse, error) {
	b, _ := json.Marshal(data)
	return &proxy.ActionResponse{
		StatusCode: 200,
		Data:       string(b),
	}, nil
}

// CollectMetadata returns version and connection info for the MongoDB server.
func (p *Proxy) CollectMetadata(ctx context.Context) (map[string]any, error) {
	p.mu.RLock()
	client := p.client
	cfg := p.config
	p.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("mongodb not configured")
	}

	meta := map[string]any{
		"host": cfg.Host,
		"port": cfg.Port,
	}
	if cfg.ReplicaSet != "" {
		meta["replica_set"] = cfg.ReplicaSet
	}

	var buildInfo bson.M
	if err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&buildInfo); err == nil {
		if v, ok := buildInfo["version"].(string); ok {
			meta["version"] = v
		}
	}

	return meta, nil
}

// mapToBsonD converts a map[string]any to bson.D preserving key order where possible.
func mapToBsonD(m map[string]any) bson.D {
	d := make(bson.D, 0, len(m))
	for k, v := range m {
		if nested, ok := v.(map[string]any); ok {
			d = append(d, bson.E{Key: k, Value: mapToBsonD(nested)})
		} else {
			d = append(d, bson.E{Key: k, Value: v})
		}
	}
	return d
}
