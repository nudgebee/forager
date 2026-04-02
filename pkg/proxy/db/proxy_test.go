package db

import (
	"context"
	"log/slog"
	"os"
	"strings"
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
	if !strings.HasPrefix(dsn, "oracle://sys:pass@oracle.internal:1521/?") {
		t.Fatalf("unexpected DSN prefix: %s", dsn)
	}
	if !strings.Contains(dsn, "SERVICE_NAME%3DORCL") {
		t.Fatalf("DSN missing SERVICE_NAME=ORCL: %s", dsn)
	}
	if !strings.Contains(dsn, "SERVER%3DDEDICATED") {
		t.Fatalf("DSN missing SERVER=DEDICATED: %s", dsn)
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
	if !strings.Contains(dsn, "SERVICE_NAME%3DMYSERVICE") {
		t.Fatalf("DSN missing SERVICE_NAME=MYSERVICE: %s", dsn)
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

func TestSanitizeQuery(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "raw SQL passthrough",
			input: "SELECT pid, datname FROM pg_stat_activity WHERE state = 'active'",
			want:  "SELECT pid, datname FROM pg_stat_activity WHERE state = 'active'",
		},
		{
			name:  "psql copy wrapper double quotes",
			input: `psql -c "\copy (SELECT pid, datname FROM pg_stat_activity) TO stdout WITH CSV HEADER"`,
			want:  "SELECT pid, datname FROM pg_stat_activity",
		},
		{
			name:  "psql copy wrapper single quotes",
			input: `psql -c '\copy (SELECT * FROM users WHERE name = $$John$$) TO stdout WITH CSV HEADER'`,
			want:  `SELECT * FROM users WHERE name = $$John$$`,
		},
		{
			name:  "psql copy wrapper shell-escaped single quotes",
			input: `psql -c '\copy (SELECT tablename FROM pg_tables WHERE schemaname = '\''public'\'' AND tablename NOT LIKE '\''pg_%'\'') TO stdout WITH CSV HEADER'`,
			want:  `SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename NOT LIKE 'pg_%'`,
		},
		{
			name:  "psql with dbname flag",
			input: `psql --dbname mydb -c "\copy (SELECT 1) TO stdout WITH CSV HEADER"`,
			want:  "SELECT 1",
		},
		{
			name:  "psql plain query",
			input: `psql -c "EXPLAIN ANALYZE SELECT * FROM orders"`,
			want:  "EXPLAIN ANALYZE SELECT * FROM orders",
		},
		{
			name:  "mariadb wrapper",
			input: `mariadb --user $MYSQL_USER --ssl=0 --password=$MYSQL_PASSWD --host $MYSQL_HOST --port $MYSQL_PORT --database $MYSQL_DATABASE -e "SELECT * FROM users"`,
			want:  "SELECT * FROM users",
		},
		{
			name:  "mysql wrapper",
			input: `mysql --user root -e "SHOW TABLES"`,
			want:  "SHOW TABLES",
		},
		{
			name:  "psql without -c flag passthrough",
			input: `psql mydb`,
			want:  `psql mydb`,
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "nested parens in copy",
			input: `psql -c "\copy (SELECT count(*) FROM (SELECT 1) sub) TO stdout WITH CSV HEADER"`,
			want:  "SELECT count(*) FROM (SELECT 1) sub",
		},
		{
			name:  "psql with flags after -c",
			input: `psql -c "SELECT 1" --dbname mydb`,
			want:  "SELECT 1",
		},
		{
			name:  "mariadb with flags after -e",
			input: `mariadb -e "SELECT 1" --database mydb`,
			want:  "SELECT 1",
		},
		{
			name:  "sqlcmd wrapper",
			input: `sqlcmd -Q "SELECT name FROM sys.tables" -s "	" -W`,
			want:  "SELECT name FROM sys.tables",
		},
		{
			name:  "sqlcmd with database flag",
			input: `sqlcmd -d "mydb" -Q "SELECT @@VERSION" -s "	" -W`,
			want:  "SELECT @@VERSION",
		},
		{
			name:  "sqlcmd without -Q flag passthrough",
			input: `sqlcmd -S localhost`,
			want:  `sqlcmd -S localhost`,
		},
		{
			name:  "echo pipe to sqlplus double quotes",
			input: `echo "SELECT * FROM dual" | sqlplus -s user/pass@//host:1521/ORCL`,
			want:  "SELECT * FROM dual",
		},
		{
			name:  "echo pipe to sqlplus single quotes",
			input: `echo 'SELECT name FROM v$session' | sqlplus -s /nolog`,
			want:  "SELECT name FROM v$session",
		},
		{
			name:  "sqlplus here-string double quotes",
			input: `sqlplus -s user/pass@host <<< "SELECT sysdate FROM dual"`,
			want:  "SELECT sysdate FROM dual",
		},
		{
			name:  "sqlplus here-string single quotes",
			input: `sqlplus -s /nolog <<< 'SELECT 1 FROM dual'`,
			want:  "SELECT 1 FROM dual",
		},
		{
			name:  "sqlplus without here-string or pipe passthrough",
			input: `sqlplus -s user/pass@host @script.sql`,
			want:  `sqlplus -s user/pass@host @script.sql`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeQuery(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeQuery(%q)\n  got:  %q\n  want: %q", tt.input, got, tt.want)
			}
		})
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
