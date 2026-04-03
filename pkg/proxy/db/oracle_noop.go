//go:build !oracle

package db

import (
	"fmt"
	"net/url"

	_ "github.com/sijms/go-ora/v2"
)

const oracleDriverName = "oracle"

func buildOracleDSN(host string, port int, database, username, password string, configRaw map[string]any) (string, string, error) {
	serviceName := database
	if sn, ok := configRaw["service_name"].(string); ok && sn != "" {
		serviceName = sn
	}
	dsn := fmt.Sprintf("oracle://%s:%s@%s:%d/%s?ENABLE_OOB=FALSE",
		url.PathEscape(username), url.PathEscape(password),
		host, port, serviceName)
	return dsn, oracleDriverName, nil
}
