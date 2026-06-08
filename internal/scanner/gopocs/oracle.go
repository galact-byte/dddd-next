package gopocs

import (
	"context"
	"database/sql"
	"strings"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
)

type oracleCracker struct{}

func (oracleCracker) Service() string { return "oracle" }

// oracleServices are the default service names tried per credential, since the
// dict carries no service name (orcl=11g, XE=Express Edition, ORCL=common).
var oracleServices = []string{"orcl", "XE", "ORCL"}

func (oracleCracker) Try(ctx context.Context, host string, port int, cred Credential, timeout time.Duration) (bool, error) {
	var lastErr error
	for _, svc := range oracleServices {
		dsn := go_ora.BuildUrl(host, port, svc, cred.User, cred.Pass, nil)
		db, err := sql.Open("oracle", dsn)
		if err != nil {
			lastErr = err
			continue
		}

		ctx2, cancel := context.WithTimeout(ctx, timeout)
		err = db.PingContext(ctx2)
		cancel()
		_ = db.Close()

		switch {
		case err == nil:
			return true, nil
		case isOracleAuthFailure(err):
			return false, nil // service reached, wrong password → next credential
		case isOracleServiceMissing(err):
			lastErr = err // wrong service name → try the next default
			continue
		default:
			return false, err // connection-level failure, other services won't help
		}
	}
	return false, lastErr
}

// isOracleAuthFailure matches ORA-01017 (invalid username/password).
func isOracleAuthFailure(err error) bool {
	return strings.Contains(err.Error(), "ORA-01017")
}

// isOracleServiceMissing matches listener errors for an unknown service/SID, so
// we try the next default service name rather than the next credential.
func isOracleServiceMissing(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "ORA-12514") || strings.Contains(msg, "ORA-12505")
}
