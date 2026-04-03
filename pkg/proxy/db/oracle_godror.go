//go:build oracle

package db

import (
	"fmt"
	"strings"

	_ "github.com/godror/godror"
)

const oracleDriverName = "godror"

func buildOracleDSN(host string, port int, database, username, password string, configRaw map[string]any) (string, string, error) {
	serviceName := database
	if sn, ok := configRaw["service_name"].(string); ok && sn != "" {
		serviceName = sn
	}
	// Use godror's parameter format to avoid URL-encoding issues with
	// special characters in passwords.
	dsn := fmt.Sprintf(`user="%s" password="%s" connectString="%s:%d/%s"`,
		escapeGodrorParam(username),
		escapeGodrorParam(password),
		host, port, serviceName,
	)
	return dsn, oracleDriverName, nil
}

// escapeGodrorParam escapes double quotes inside a godror DSN parameter value.
func escapeGodrorParam(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}
