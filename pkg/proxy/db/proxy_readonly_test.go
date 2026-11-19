package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"nudgebee/forager/pkg/proxy"
)

func TestProxy_HandleQuery_ReadOnlyUnsupportedType(t *testing.T) {
	for _, dbType := range []string{"mssql", "clickhouse", "oracle"} {
		t.Run(dbType, func(t *testing.T) {
			p := New(dbType, testLogger())
			// A nil pool: the refusal must come before anything is sent.
			_, err := p.handleQuery(context.Background(), nil, &proxy.ActionRequest{
				Action: "db_query",
				Params: map[string]any{"query": "SELECT 1", "read_only": true},
			})
			if err == nil || !strings.Contains(err.Error(), "read_only is not supported") {
				t.Fatalf("expected read_only refusal for %s, got %v", dbType, err)
			}
		})
	}
}

// TestProxy_HandleQuery_ReadOnly_Postgres needs a real server, because the
// point is that Postgres itself refuses the write. Set
// FORAGER_TEST_POSTGRES_DSN (e.g. "host=localhost port=5432 user=postgres
// dbname=postgres sslmode=disable") to run it.
func TestProxy_HandleQuery_ReadOnly_Postgres(t *testing.T) {
	dsn := os.Getenv("FORAGER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("FORAGER_TEST_POSTGRES_DSN not set")
	}
	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pool.Close() }()
	// One connection, so a read-only setting that outlived its query would be
	// visible to the next one.
	pool.SetMaxOpenConns(1)

	ctx := context.Background()
	table := fmt.Sprintf("forager_read_only_%d", time.Now().UnixNano())
	if _, err := pool.ExecContext(ctx, "CREATE TABLE "+table+" (id int)"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = pool.ExecContext(ctx, "DROP TABLE IF EXISTS "+table) }()
	if _, err := pool.ExecContext(ctx, "INSERT INTO "+table+" VALUES (1)"); err != nil {
		t.Fatal(err)
	}

	p := New("postgresql", testLogger())
	// SELECT-shaped, so a prefix filter would pass it; only the server stops it.
	deleting := "WITH d AS (DELETE FROM " + table + " RETURNING id) SELECT count(*) FROM d"
	query := func(sqlText string, readOnly bool) (map[string]any, error) {
		params := map[string]any{"query": sqlText}
		if readOnly {
			params["read_only"] = true
		}
		resp, err := p.handleQuery(ctx, pool, &proxy.ActionRequest{Action: "db_query", Params: params})
		if err != nil {
			return nil, err
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(resp.Data), &out); err != nil {
			t.Fatal(err)
		}
		return out, nil
	}
	count := func() int {
		var n int
		if err := pool.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if _, err := query(deleting, true); err == nil || !strings.Contains(err.Error(), "read-only transaction") {
		t.Fatalf("expected the server to refuse the write, got %v", err)
	}
	if n := count(); n != 1 {
		t.Fatalf("row was deleted under read_only: count=%d", n)
	}

	out, err := query("SELECT id FROM "+table, true)
	if err != nil {
		t.Fatal(err)
	}
	if out["read_only"] != true {
		t.Fatalf("expected read_only echoed in the response, got %v", out["read_only"])
	}

	// The same (only) connection still writes: nothing leaked past the query.
	if _, err := pool.ExecContext(ctx, "INSERT INTO "+table+" VALUES (2)"); err != nil {
		t.Fatalf("connection stayed read-only after the query: %v", err)
	}
	// And without the flag the statement does delete — the refusal above was
	// the flag's doing, not the statement's.
	if _, err := query(deleting, false); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 0 {
		t.Fatalf("expected rows deleted without read_only, count=%d", n)
	}
}
