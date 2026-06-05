package gopocs

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

type postgresCracker struct{}

func (postgresCracker) Service() string { return "postgresql" }

func (postgresCracker) Try(ctx context.Context, host string, port int, cred Credential, timeout time.Duration) (bool, error) {
	connTimeout := int(timeout.Seconds())
	if connTimeout < 1 {
		connTimeout = 1
	}
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=%d",
		host, port, cred.User, cred.Pass, connTimeout)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()

	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := db.PingContext(ctx2); err != nil {
		if isPostgresAuthFailure(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isPostgresAuthFailure matches SQLSTATE 28P01/28000 (invalid password).
func isPostgresAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "28P01") ||
		strings.Contains(msg, "password authentication failed") ||
		strings.Contains(msg, "28000")
}
