package db

import (
	"encoding/json"
	"testing"
)

func TestTextifyRow(t *testing.T) {
	row := []any{
		[]byte("shop"),         // VARCHAR
		[]byte("96129"),        // BIGINT reported as text by SHOW STATUS
		[]byte("12.50"),        // DECIMAL
		[]byte{0xde, 0xad},     // BLOB, not UTF-8
		[]byte("abc"),          // VARBINARY: bytes even though printable
		int64(7),               // INT
		nil,                    // NULL
		"already text",         // pgx / go-mssqldb
		[]byte("beyond types"), // more values than type names
	}
	textifyRow(row, []string{"VARCHAR", "VARCHAR", "DECIMAL", "BLOB", "VARBINARY", "INT", "VARCHAR", "TEXT"})

	out, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	want := `["shop","96129","12.50","3q0=","YWJj",7,null,"already text","YmV5b25kIHR5cGVz"]`
	if string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}
