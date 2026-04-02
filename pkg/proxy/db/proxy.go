package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/microsoft/go-mssqldb"
	_ "github.com/sijms/go-ora/v2"

	"nudgebee/forager/pkg/proxy"
)

// Proxy is a generic database proxy supporting PostgreSQL, MySQL, MSSQL, ClickHouse, and Oracle.
type Proxy struct {
	mu        sync.RWMutex
	pool      *sql.DB
	dbType    string
	config    Config
	configRaw map[string]any
	creds     map[string]string
	readOnly  bool
	logger    *slog.Logger
}

// Config holds database connection parameters.
type Config struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Database    string `json:"database"`
	SSLMode     string `json:"ssl_mode"`
	TLSEnabled  bool   `json:"tls_enabled"`
	MaxOpen     int    `json:"max_open_connections"`
	MaxIdle     int    `json:"max_idle_connections"`
	MaxLifetime int    `json:"max_lifetime_sec"`
}

// New creates a new DB proxy.
func New(dbType string, logger *slog.Logger) *Proxy {
	return &Proxy{
		dbType: dbType,
		logger: logger,
	}
}

func (p *Proxy) Type() string { return "db-proxy" }

func (p *Proxy) Configure(config map[string]any, creds map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Close existing pool
	if p.pool != nil {
		_ = p.pool.Close()
		p.pool = nil
	}

	// Parse config
	configJSON, _ := json.Marshal(config)
	var cfg Config
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("parsing db config: %w", err)
	}

	// Apply default port based on db type
	if cfg.Port == 0 {
		switch p.dbType {
		case "postgresql":
			cfg.Port = 5432
		case "mysql":
			cfg.Port = 3306
		case "mssql":
			cfg.Port = 1433
		case "clickhouse":
			cfg.Port = 9000
		case "oracle":
			cfg.Port = 1521
		}
	}

	// Apply defaults
	if cfg.MaxOpen == 0 {
		cfg.MaxOpen = 5
	}
	if cfg.MaxIdle == 0 {
		cfg.MaxIdle = 2
	}
	if cfg.MaxLifetime == 0 {
		cfg.MaxLifetime = 300
	}

	p.config = cfg
	p.configRaw = config
	p.creds = creds

	if v, ok := config["read_only"].(bool); ok {
		p.readOnly = v
	}

	// Build DSN and open connection
	dsn, driverName, err := p.buildDSN()
	if err != nil {
		return fmt.Errorf("building DSN: %w", err)
	}

	pool, err := sql.Open(driverName, dsn)
	if err != nil {
		return fmt.Errorf("opening db: %w", err)
	}

	pool.SetMaxOpenConns(cfg.MaxOpen)
	pool.SetMaxIdleConns(cfg.MaxIdle)
	pool.SetConnMaxLifetime(time.Duration(cfg.MaxLifetime) * time.Second)

	// Test connection using a lightweight query instead of PingContext.
	// go-ora's Ping sends a TNS-level operation (0x93) that some network
	// middleboxes (transit gateways, load balancers) mishandle, causing
	// nil-pointer panics in the driver. A simple query validates the full
	// path without relying on the TNS ping operation.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := safeProbe(ctx, pool, p.dbType); err != nil {
		_ = pool.Close()
		return fmt.Errorf("connection test failed: %w", err)
	}

	p.pool = pool
	p.logger.Info("database connection established",
		"type", p.dbType,
		"host", cfg.Host,
		"port", cfg.Port,
		"database", cfg.Database,
	)
	return nil
}

func (p *Proxy) HandleRequest(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	p.mu.RLock()
	pool := p.pool
	p.mu.RUnlock()

	if pool == nil {
		return nil, fmt.Errorf("database not configured")
	}

	switch req.Action {
	case "db_query":
		return p.handleQuery(ctx, pool, req)
	case "db_execute":
		return p.handleExecute(ctx, pool, req)
	case "db_metadata":
		return p.handleMetadata(ctx, pool, req)
	default:
		return nil, fmt.Errorf("unknown db action: %s", req.Action)
	}
}

func (p *Proxy) HealthCheck(ctx context.Context) error {
	p.mu.RLock()
	pool := p.pool
	p.mu.RUnlock()

	if pool == nil {
		return fmt.Errorf("database not configured")
	}
	return pool.PingContext(ctx)
}

func (p *Proxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.pool != nil {
		err := p.pool.Close()
		p.pool = nil
		return err
	}
	return nil
}

// probeQuery returns a no-op SELECT suitable for the database type.
func probeQuery(dbType string) string {
	switch dbType {
	case "oracle":
		return "SELECT 1 FROM dual"
	case "mssql":
		return "SELECT 1"
	default:
		return "SELECT 1"
	}
}

// safeProbe validates the connection by running a lightweight query,
// recovering from any driver panics (e.g. go-ora nil-pointer dereference).
func safeProbe(ctx context.Context, pool *sql.DB, dbType string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("driver panic: %v", r)
		}
	}()
	row := pool.QueryRowContext(ctx, probeQuery(dbType))
	var n int
	return row.Scan(&n)
}

func (p *Proxy) buildDSN() (string, string, error) {
	username := p.creds["username"]
	password := p.creds["password"]

	switch p.dbType {
	case "postgresql":
		sslMode := p.config.SSLMode
		if sslMode == "" {
			sslMode = "disable"
		}
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			p.config.Host, p.config.Port, username, password, p.config.Database, sslMode)
		return dsn, "pgx", nil

	case "mysql":
		tls := ""
		if p.config.TLSEnabled {
			tls = "?tls=true"
		}
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s%s",
			username, password, p.config.Host, p.config.Port, p.config.Database, tls)
		return dsn, "mysql", nil

	case "mssql":
		q := url.Values{}
		q.Set("database", p.config.Database)
		if p.config.TLSEnabled {
			q.Set("encrypt", "true")
		} else {
			q.Set("encrypt", "disable")
		}
		u := &url.URL{
			Scheme:   "sqlserver",
			User:     url.UserPassword(username, password),
			Host:     fmt.Sprintf("%s:%d", p.config.Host, p.config.Port),
			RawQuery: q.Encode(),
		}
		return u.String(), "sqlserver", nil

	case "clickhouse":
		q := url.Values{}
		if username != "" {
			q.Set("username", username)
		}
		if password != "" {
			q.Set("password", password)
		}
		if p.config.Database != "" {
			q.Set("database", p.config.Database)
		}
		if p.config.TLSEnabled {
			q.Set("secure", "true")
		}
		u := &url.URL{
			Scheme:   "clickhouse",
			Host:     fmt.Sprintf("%s:%d", p.config.Host, p.config.Port),
			RawQuery: q.Encode(),
		}
		return u.String(), "clickhouse", nil

	case "oracle":
		serviceName := p.config.Database
		if sn, ok := p.configRaw["service_name"].(string); ok && sn != "" {
			serviceName = sn
		}
		dsn := fmt.Sprintf("oracle://%s:%s@%s:%d/%s",
			url.PathEscape(username), url.PathEscape(password),
			p.config.Host, p.config.Port, serviceName)
		return dsn, "oracle", nil

	default:
		return "", "", fmt.Errorf("unsupported database type: %s", p.dbType)
	}
}

// sanitizeQuery strips CLI tool wrapping that callers may send.
// Known formats (produced by llm-server/runbook-server):
//   - psql [flags] -c "\copy (SQL) TO stdout WITH CSV HEADER"
//   - psql [flags] -c "SQL"
//   - mariadb [flags] -e "SQL"
//   - sqlcmd [flags] -Q "SQL"
//   - echo "SQL" | sqlplus [flags]
//   - sqlplus [flags] <<< "SQL"
//
// If the query doesn't match these patterns it is returned unchanged.
func sanitizeQuery(query string) string {
	q := strings.TrimSpace(query)
	lower := strings.ToLower(q)

	// Detect psql wrapping
	if strings.HasPrefix(lower, "psql") {
		arg := extractFlagArg(q, lower, " -c ")
		if arg == "" {
			return q
		}

		// \copy (SQL) TO stdout ...
		lowerArg := strings.ToLower(arg)
		if strings.HasPrefix(lowerArg, "\\copy") {
			open := strings.Index(arg, "(")
			if open < 0 {
				return q
			}
			// Find matching closing paren — scan from end for ") TO"
			closeMark := strings.LastIndex(strings.ToUpper(arg), ") TO")
			if closeMark <= open {
				return q
			}
			return strings.TrimSpace(arg[open+1 : closeMark])
		}

		// Plain: psql -c "SELECT ..."
		return arg
	}

	// Detect mariadb/mysql wrapping
	if strings.HasPrefix(lower, "mariadb") || strings.HasPrefix(lower, "mysql") {
		arg := extractFlagArg(q, lower, " -e ")
		if arg == "" {
			return q
		}
		return arg
	}

	// Detect sqlcmd wrapping: sqlcmd [flags] -Q "SQL"
	if strings.HasPrefix(lower, "sqlcmd") {
		arg := extractFlagArg(q, lower, " -q ")
		if arg == "" {
			return q
		}
		return arg
	}

	// Detect pipe to sqlplus: echo "SQL" | sqlplus [flags]
	if pipeIdx := strings.Index(lower, "| sqlplus"); pipeIdx >= 0 {
		prefix := strings.TrimSpace(q[:pipeIdx])
		lowerPrefix := strings.ToLower(prefix)
		if strings.HasPrefix(lowerPrefix, "echo ") {
			return stripQuotes(strings.TrimSpace(prefix[5:]))
		}
		return q
	}

	// Detect sqlplus wrapping: sqlplus [flags] <<< "SQL"
	if strings.HasPrefix(lower, "sqlplus") {
		if hereIdx := strings.Index(q, "<<<"); hereIdx >= 0 {
			return stripQuotes(strings.TrimSpace(q[hereIdx+3:]))
		}
		return q
	}

	return q
}

// extractFlagArg extracts the quoted or unquoted argument following a CLI flag
// (e.g. -c or -e). It properly handles single/double-quoted arguments without
// greedily consuming subsequent flags. Returns "" if the flag is not found.
func extractFlagArg(original, lowered, flag string) string {
	idx := strings.Index(lowered, flag)
	if idx < 0 {
		return ""
	}
	argPart := strings.TrimSpace(original[idx+len(flag):])
	if len(argPart) == 0 {
		return ""
	}

	// Quoted argument: find the matching closing quote
	if argPart[0] == '"' {
		end := strings.Index(argPart[1:], "\"")
		if end < 0 {
			return "" // unclosed quote
		}
		return argPart[1 : end+1]
	}
	if argPart[0] == '\'' {
		// Handle shell-escaped single quotes: 'arg with '\''embedded'\'' quotes'
		// The pattern '\'' means: end quote, literal ', start new quote.
		// We reassemble by joining segments split on '\'' until we find a
		// closing single quote that isn't followed by \'.
		inner := argPart[1:] // skip leading '
		var result strings.Builder
		for {
			end := strings.Index(inner, "'")
			if end < 0 {
				return "" // unclosed quote
			}
			result.WriteString(inner[:end])
			rest := inner[end+1:]
			// Check if this is a shell-escaped quote: '\'' (the rest starts with \')
			if strings.HasPrefix(rest, "\\''") {
				result.WriteByte('\'')
				inner = rest[3:] // skip \\'
				continue
			}
			// Real closing quote
			return result.String()
		}
	}

	// Unquoted: take the first space-delimited token
	fields := strings.Fields(argPart)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// stripQuotes removes a matching pair of surrounding single or double quotes.
func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func (p *Proxy) handleQuery(ctx context.Context, pool *sql.DB, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	start := time.Now()

	query, _ := req.Params["query"].(string)
	if query == "" {
		return nil, fmt.Errorf("missing query parameter")
	}

	query = sanitizeQuery(query)

	// Apply timeout
	timeoutMs := 30000
	if v, ok := req.Params["timeout_ms"].(float64); ok && v > 0 {
		timeoutMs = int(v)
		if timeoutMs > 120000 {
			timeoutMs = 120000
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	// Max rows
	maxRows := 10000
	if v, ok := req.Params["max_rows"].(float64); ok && v > 0 {
		maxRows = int(v)
	}

	// Extract positional params
	var args []any
	if params, ok := req.Params["params"].([]any); ok {
		args = params
	}

	rows, err := pool.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Get column info
	colTypes, err := rows.ColumnTypes()
	if err != nil {
		return nil, fmt.Errorf("getting column types: %w", err)
	}

	columns := make([]map[string]any, len(colTypes))
	for i, ct := range colTypes {
		nullable, _ := ct.Nullable()
		columns[i] = map[string]any{
			"name":     ct.Name(),
			"type":     ct.DatabaseTypeName(),
			"nullable": nullable,
		}
	}

	// Scan rows
	var resultRows [][]any
	scanBuf := make([]any, len(colTypes))
	scanPtrs := make([]any, len(colTypes))
	for i := range scanBuf {
		scanPtrs[i] = &scanBuf[i]
	}

	rowCount := 0
	for rows.Next() {
		if rowCount >= maxRows {
			break
		}
		if err := rows.Scan(scanPtrs...); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		row := make([]any, len(scanBuf))
		copy(row, scanBuf)
		resultRows = append(resultRows, row)
		rowCount++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	result := map[string]any{
		"columns":     columns,
		"rows":        resultRows,
		"row_count":   rowCount,
		"duration_ms": time.Since(start).Milliseconds(),
	}

	data, _ := json.Marshal(result)
	return &proxy.ActionResponse{
		StatusCode: 200,
		Data:       string(data),
	}, nil
}

func (p *Proxy) handleExecute(ctx context.Context, pool *sql.DB, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	if p.readOnly {
		return nil, fmt.Errorf("datasource is read-only, execute not allowed")
	}

	start := time.Now()

	statement, _ := req.Params["statement"].(string)
	if statement == "" {
		return nil, fmt.Errorf("missing statement parameter")
	}

	var args []any
	if params, ok := req.Params["params"].([]any); ok {
		args = params
	}

	result, err := pool.ExecContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("execute failed: %w", err)
	}

	affected, _ := result.RowsAffected()
	data, _ := json.Marshal(map[string]any{
		"affected_rows": affected,
		"duration_ms":   time.Since(start).Milliseconds(),
	})

	return &proxy.ActionResponse{
		StatusCode: 200,
		Data:       string(data),
	}, nil
}

func (p *Proxy) handleMetadata(ctx context.Context, pool *sql.DB, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	metadataType, _ := req.Params["metadata_type"].(string)

	var query string
	var args []any

	// ph returns the placeholder for the nth parameter (1-indexed) for the current DB driver.
	ph := func(n int) string {
		switch p.dbType {
		case "postgresql":
			return fmt.Sprintf("$%d", n)
		case "oracle":
			return fmt.Sprintf(":%d", n)
		case "mssql":
			return fmt.Sprintf("@p%d", n)
		default: // mysql, clickhouse
			return "?"
		}
	}

	switch p.dbType {
	case "postgresql":
		switch metadataType {
		case "schemas":
			query = "SELECT schema_name FROM information_schema.schemata ORDER BY schema_name"
		case "tables":
			schemaFilter := "public"
			if v, ok := req.Params["schema_filter"].(string); ok && v != "" {
				schemaFilter = v
			}
			query = fmt.Sprintf("SELECT table_name, table_type FROM information_schema.tables WHERE table_schema = %s ORDER BY table_name", ph(1))
			args = []any{schemaFilter}
		case "columns":
			tableName, _ := req.Params["table_name"].(string)
			schemaFilter := "public"
			if v, ok := req.Params["schema_filter"].(string); ok && v != "" {
				schemaFilter = v
			}
			query = fmt.Sprintf("SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position", ph(1), ph(2))
			args = []any{schemaFilter, tableName}
		default:
			return nil, fmt.Errorf("unknown metadata_type: %s", metadataType)
		}
	case "mysql":
		switch metadataType {
		case "schemas":
			query = "SELECT SCHEMA_NAME as schema_name FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME"
		case "tables":
			query = fmt.Sprintf("SELECT TABLE_NAME as table_name, TABLE_TYPE as table_type FROM information_schema.TABLES WHERE TABLE_SCHEMA = %s ORDER BY TABLE_NAME", ph(1))
			args = []any{p.config.Database}
		case "columns":
			tableName, _ := req.Params["table_name"].(string)
			query = fmt.Sprintf("SELECT COLUMN_NAME as column_name, DATA_TYPE as data_type, IS_NULLABLE as is_nullable, COLUMN_DEFAULT as column_default FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION", ph(1), ph(2))
			args = []any{p.config.Database, tableName}
		default:
			return nil, fmt.Errorf("unknown metadata_type: %s", metadataType)
		}
	case "mssql":
		switch metadataType {
		case "schemas":
			query = "SELECT name AS schema_name FROM sys.schemas ORDER BY name"
		case "tables":
			schemaFilter := "dbo"
			if v, ok := req.Params["schema_filter"].(string); ok && v != "" {
				schemaFilter = v
			}
			query = fmt.Sprintf("SELECT t.name AS table_name, CASE WHEN t.type = 'U' THEN 'BASE TABLE' ELSE 'VIEW' END AS table_type FROM sys.tables t INNER JOIN sys.schemas s ON t.schema_id = s.schema_id WHERE s.name = %s ORDER BY t.name", ph(1))
			args = []any{schemaFilter}
		case "columns":
			tableName, _ := req.Params["table_name"].(string)
			schemaFilter := "dbo"
			if v, ok := req.Params["schema_filter"].(string); ok && v != "" {
				schemaFilter = v
			}
			query = fmt.Sprintf("SELECT c.name AS column_name, TYPE_NAME(c.user_type_id) AS data_type, CASE c.is_nullable WHEN 1 THEN 'YES' ELSE 'NO' END AS is_nullable, dc.definition AS column_default FROM sys.columns c INNER JOIN sys.tables t ON c.object_id = t.object_id INNER JOIN sys.schemas s ON t.schema_id = s.schema_id LEFT JOIN sys.default_constraints dc ON c.default_object_id = dc.object_id WHERE s.name = %s AND t.name = %s ORDER BY c.column_id", ph(1), ph(2))
			args = []any{schemaFilter, tableName}
		default:
			return nil, fmt.Errorf("unknown metadata_type: %s", metadataType)
		}
	case "clickhouse":
		switch metadataType {
		case "schemas":
			query = "SELECT name AS schema_name FROM system.databases ORDER BY name"
		case "tables":
			dbFilter := p.config.Database
			if v, ok := req.Params["schema_filter"].(string); ok && v != "" {
				dbFilter = v
			}
			query = fmt.Sprintf("SELECT name AS table_name, engine AS table_type FROM system.tables WHERE database = %s ORDER BY name", ph(1))
			args = []any{dbFilter}
		case "columns":
			tableName, _ := req.Params["table_name"].(string)
			dbFilter := p.config.Database
			if v, ok := req.Params["schema_filter"].(string); ok && v != "" {
				dbFilter = v
			}
			query = fmt.Sprintf("SELECT name AS column_name, type AS data_type, '' AS is_nullable, default_expression AS column_default FROM system.columns WHERE database = %s AND table = %s ORDER BY position", ph(1), ph(2))
			args = []any{dbFilter, tableName}
		default:
			return nil, fmt.Errorf("unknown metadata_type: %s", metadataType)
		}
	case "oracle":
		switch metadataType {
		case "schemas":
			query = "SELECT username AS schema_name FROM all_users ORDER BY username"
		case "tables":
			schemaFilter := ""
			if v, ok := req.Params["schema_filter"].(string); ok && v != "" {
				schemaFilter = v
			}
			if schemaFilter != "" {
				query = fmt.Sprintf("SELECT table_name, 'BASE TABLE' AS table_type FROM all_tables WHERE owner = %s ORDER BY table_name", ph(1))
				args = []any{schemaFilter}
			} else {
				query = "SELECT table_name, 'BASE TABLE' AS table_type FROM user_tables ORDER BY table_name"
			}
		case "columns":
			tableName, _ := req.Params["table_name"].(string)
			schemaFilter := ""
			if v, ok := req.Params["schema_filter"].(string); ok && v != "" {
				schemaFilter = v
			}
			if schemaFilter != "" {
				query = fmt.Sprintf("SELECT column_name, data_type, nullable AS is_nullable, data_default AS column_default FROM all_tab_columns WHERE owner = %s AND table_name = %s ORDER BY column_id", ph(1), ph(2))
				args = []any{schemaFilter, tableName}
			} else {
				query = fmt.Sprintf("SELECT column_name, data_type, nullable AS is_nullable, data_default AS column_default FROM user_tab_columns WHERE table_name = %s ORDER BY column_id", ph(1))
				args = []any{tableName}
			}
		default:
			return nil, fmt.Errorf("unknown metadata_type: %s", metadataType)
		}
	default:
		return nil, fmt.Errorf("unsupported db type for metadata: %s", p.dbType)
	}

	// Execute the metadata query using the same query handler
	params := map[string]any{
		"query":    query,
		"max_rows": float64(10000),
	}
	if len(args) > 0 {
		params["params"] = args
	}
	metaReq := &proxy.ActionRequest{
		Action: "db_query",
		Params: params,
	}
	return p.handleQuery(ctx, pool, metaReq)
}

// CollectMetadata returns version and connection info for the underlying database.
func (p *Proxy) CollectMetadata(ctx context.Context) (map[string]any, error) {
	p.mu.RLock()
	pool := p.pool
	cfg := p.config
	p.mu.RUnlock()

	if pool == nil {
		return nil, fmt.Errorf("not connected")
	}

	meta := map[string]any{
		"db_type":  p.dbType,
		"host":     cfg.Host,
		"port":     cfg.Port,
		"database": cfg.Database,
	}

	var versionQuery string
	switch p.dbType {
	case "postgresql":
		versionQuery = "SELECT version()"
	case "mysql":
		versionQuery = "SELECT VERSION()"
	case "mssql":
		versionQuery = "SELECT @@VERSION"
	case "clickhouse":
		versionQuery = "SELECT version()"
	case "oracle":
		versionQuery = "SELECT banner FROM v$version WHERE ROWNUM = 1"
	}

	if versionQuery != "" {
		var version string
		if err := pool.QueryRowContext(ctx, versionQuery).Scan(&version); err == nil {
			meta["version"] = version
		}
	}

	if p.dbType == "mssql" {
		var serverName string
		if err := pool.QueryRowContext(ctx, "SELECT @@SERVERNAME").Scan(&serverName); err == nil {
			meta["server_name"] = serverName
		}
	}

	return meta, nil
}
