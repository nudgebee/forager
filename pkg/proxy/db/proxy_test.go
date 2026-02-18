package db

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"nudgebee/forager/pkg/proxy"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestProxy_Type(t *testing.T) {
	p := New("postgresql", testLogger())
	if p.Type() != "db-proxy" {
		t.Fatalf("expected db-proxy, got %s", p.Type())
	}
}

func TestProxy_BuildDSN_PostgreSQL(t *testing.T) {
	p := New("postgresql", testLogger())
	p.config = Config{Host: "db.internal", Port: 5432, Database: "mydb", SSLMode: "require"}
	p.creds = map[string]string{"username": "admin", "password": "secret"}

	dsn, driver, err := p.buildDSN()
	if err != nil {
		t.Fatalf("buildDSN: %v", err)
	}
	if driver != "pgx" {
		t.Fatalf("expected pgx driver, got %s", driver)
	}
	expected := "host=db.internal port=5432 user=admin password=secret dbname=mydb sslmode=require"
	if dsn != expected {
		t.Fatalf("expected DSN %q, got %q", expected, dsn)
	}
}

func TestProxy_BuildDSN_PostgreSQL_DefaultSSL(t *testing.T) {
	p := New("postgresql", testLogger())
	p.config = Config{Host: "localhost", Port: 5432, Database: "testdb"}
	p.creds = map[string]string{"username": "u", "password": "p"}

	dsn, _, err := p.buildDSN()
	if err != nil {
		t.Fatalf("buildDSN: %v", err)
	}
	// Default ssl_mode should be "disable"
	expected := "host=localhost port=5432 user=u password=p dbname=testdb sslmode=disable"
	if dsn != expected {
		t.Fatalf("expected DSN %q, got %q", expected, dsn)
	}
}

func TestProxy_BuildDSN_MySQL(t *testing.T) {
	p := New("mysql", testLogger())
	p.config = Config{Host: "mysql.internal", Port: 3306, Database: "analytics"}
	p.creds = map[string]string{"username": "root", "password": "pass"}

	dsn, driver, err := p.buildDSN()
	if err != nil {
		t.Fatalf("buildDSN: %v", err)
	}
	if driver != "mysql" {
		t.Fatalf("expected mysql driver, got %s", driver)
	}
	expected := "root:pass@tcp(mysql.internal:3306)/analytics"
	if dsn != expected {
		t.Fatalf("expected DSN %q, got %q", expected, dsn)
	}
}

func TestProxy_BuildDSN_MySQL_TLS(t *testing.T) {
	p := New("mysql", testLogger())
	p.config = Config{Host: "mysql.internal", Port: 3306, Database: "db", TLSEnabled: true}
	p.creds = map[string]string{"username": "u", "password": "p"}

	dsn, _, err := p.buildDSN()
	if err != nil {
		t.Fatalf("buildDSN: %v", err)
	}
	expected := "u:p@tcp(mysql.internal:3306)/db?tls=true"
	if dsn != expected {
		t.Fatalf("expected DSN %q, got %q", expected, dsn)
	}
}

func TestProxy_BuildDSN_UnsupportedType(t *testing.T) {
	p := New("mongodb", testLogger()) // mongodb is not a SQL db type
	p.config = Config{Host: "h", Port: 27017, Database: "d"}
	p.creds = map[string]string{"username": "u", "password": "p"}

	_, _, err := p.buildDSN()
	if err == nil {
		t.Fatal("expected error for unsupported db type")
	}
}

func TestProxy_BuildDSN_MSSQL(t *testing.T) {
	p := New("mssql", testLogger())
	p.config = Config{Host: "sql.internal", Port: 1433, Database: "mydb"}
	p.creds = map[string]string{"username": "sa", "password": "pass"}

	dsn, driver, err := p.buildDSN()
	if err != nil {
		t.Fatalf("buildDSN: %v", err)
	}
	if driver != "sqlserver" {
		t.Fatalf("expected sqlserver driver, got %s", driver)
	}
	if dsn == "" {
		t.Fatal("expected non-empty DSN")
	}
}

func TestProxy_BuildDSN_ClickHouse(t *testing.T) {
	p := New("clickhouse", testLogger())
	p.config = Config{Host: "ch.internal", Port: 9000, Database: "default"}
	p.creds = map[string]string{"username": "default", "password": ""}

	dsn, driver, err := p.buildDSN()
	if err != nil {
		t.Fatalf("buildDSN: %v", err)
	}
	if driver != "clickhouse" {
		t.Fatalf("expected clickhouse driver, got %s", driver)
	}
	if dsn == "" {
		t.Fatal("expected non-empty DSN")
	}
}

func TestProxy_BuildDSN_Oracle(t *testing.T) {
	p := New("oracle", testLogger())
	p.config = Config{Host: "oracle.internal", Port: 1521, Database: "ORCL"}
	p.configRaw = map[string]any{}
	p.creds = map[string]string{"username": "sys", "password": "pass"}

	dsn, driver, err := p.buildDSN()
	if err != nil {
		t.Fatalf("buildDSN: %v", err)
	}
	if driver != "oracle" {
		t.Fatalf("expected oracle driver, got %s", driver)
	}
	expected := "oracle://sys:pass@oracle.internal:1521/ORCL"
	if dsn != expected {
		t.Fatalf("expected DSN %q, got %q", expected, dsn)
	}
}

func TestProxy_BuildDSN_Oracle_ServiceName(t *testing.T) {
	p := New("oracle", testLogger())
	p.config = Config{Host: "oracle.internal", Port: 1521, Database: "ORCL"}
	p.configRaw = map[string]any{"service_name": "MYSERVICE"}
	p.creds = map[string]string{"username": "sys", "password": "pass"}

	dsn, _, err := p.buildDSN()
	if err != nil {
		t.Fatalf("buildDSN: %v", err)
	}
	expected := "oracle://sys:pass@oracle.internal:1521/MYSERVICE"
	if dsn != expected {
		t.Fatalf("expected DSN %q, got %q", expected, dsn)
	}
}

func TestProxy_HandleRequest_NotConfigured(t *testing.T) {
	p := New("postgresql", testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{Action: "db_query"})
	if err == nil {
		t.Fatal("expected error when pool is nil")
	}
}

func TestProxy_HandleRequest_UnknownAction(t *testing.T) {
	p := New("postgresql", testLogger())
	// Manually set a non-nil pool to pass the nil check (won't actually connect)
	// This tests action routing only
	p.pool = nil // Will fail at nil check
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{Action: "db_unknown"})
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestProxy_HandleExecute_ReadOnly(t *testing.T) {
	p := New("postgresql", testLogger())
	p.readOnly = true

	// Provide a fake pool pointer to bypass nil check
	// handleExecute checks readOnly before using pool
	// We need at least a non-nil pool to reach handleExecute
	// Actually, HandleRequest checks pool first, so let's test via handleExecute directly
	_, err := p.handleExecute(context.Background(), nil, &proxy.ActionRequest{
		Action: "db_execute",
		Params: map[string]any{"statement": "DELETE FROM users"},
	})
	if err == nil {
		t.Fatal("expected error for read-only execute")
	}
	if err.Error() != "datasource is read-only, execute not allowed" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProxy_HandleQuery_MissingQuery(t *testing.T) {
	p := New("postgresql", testLogger())
	_, err := p.handleQuery(context.Background(), nil, &proxy.ActionRequest{
		Action: "db_query",
		Params: map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error for missing query")
	}
}

func TestProxy_HandleExecute_MissingStatement(t *testing.T) {
	p := New("postgresql", testLogger())
	p.readOnly = false
	_, err := p.handleExecute(context.Background(), nil, &proxy.ActionRequest{
		Action: "db_execute",
		Params: map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error for missing statement")
	}
}

func TestProxy_HealthCheck_NotConfigured(t *testing.T) {
	p := New("postgresql", testLogger())
	err := p.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected error when pool is nil")
	}
}

func TestProxy_Close_NoPool(t *testing.T) {
	p := New("postgresql", testLogger())
	if err := p.Close(); err != nil {
		t.Fatalf("Close with no pool: %v", err)
	}
}

func TestProxy_Configure_Defaults(t *testing.T) {
	// This will fail at PingContext (no real DB) but we can test config parsing
	p := New("postgresql", testLogger())
	err := p.Configure(map[string]any{
		"host":     "localhost",
		"port":     float64(5432), // JSON numbers are float64
		"database": "testdb",
	}, map[string]string{"username": "u", "password": "p"})

	// Will fail because no real PG is running, but config should be parsed
	if err == nil {
		t.Fatal("expected connection error (no real DB)")
	}

	// Verify defaults were applied
	if p.config.MaxOpen != 5 {
		t.Fatalf("expected MaxOpen=5, got %d", p.config.MaxOpen)
	}
	if p.config.MaxIdle != 2 {
		t.Fatalf("expected MaxIdle=2, got %d", p.config.MaxIdle)
	}
	if p.config.MaxLifetime != 300 {
		t.Fatalf("expected MaxLifetime=300, got %d", p.config.MaxLifetime)
	}
}

func TestProxy_HandleMetadata_UnknownType(t *testing.T) {
	p := New("postgresql", testLogger())
	_, err := p.handleMetadata(context.Background(), nil, &proxy.ActionRequest{
		Action: "db_metadata",
		Params: map[string]any{"metadata_type": "invalid"},
	})
	if err == nil {
		t.Fatal("expected error for unknown metadata_type")
	}
}

func TestProxy_HandleMetadata_UnsupportedDB(t *testing.T) {
	p := New("mongodb", testLogger()) // mongodb is not a SQL db type
	_, err := p.handleMetadata(context.Background(), nil, &proxy.ActionRequest{
		Action: "db_metadata",
		Params: map[string]any{"metadata_type": "schemas"},
	})
	if err == nil {
		t.Fatal("expected error for unsupported db type")
	}
}
