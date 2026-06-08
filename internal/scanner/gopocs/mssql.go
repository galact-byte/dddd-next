package gopocs

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb"
)

type mssqlCracker struct{}

func (mssqlCracker) Service() string { return "mssql" }

func (mssqlCracker) Try(ctx context.Context, host string, port int, cred Credential, timeout time.Duration) (bool, error) {
	sec := int(timeout.Seconds())
	if sec < 1 {
		sec = 1
	}
	// ADO-style DSN avoids URL-escaping passwords with @ # ! that the
	// sqlserver:// form would mangle; encrypt=disable matches legacy servers.
	dsn := fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s;encrypt=disable;dial timeout=%d;connection timeout=%d",
		host, port, cred.User, cred.Pass, sec, sec)

	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()

	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := db.PingContext(ctx2); err != nil {
		if isMSSQLAuthFailure(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isMSSQLAuthFailure matches SQL Server error 18456 (login failed) so a wrong
// password moves to the next credential instead of abandoning the endpoint.
func isMSSQLAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "Login failed for user") || strings.Contains(msg, "18456")
}
