package gopocs

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type mysqlCracker struct{}

func (mysqlCracker) Service() string { return "mysql" }

func (mysqlCracker) Try(ctx context.Context, host string, port int, cred Credential, timeout time.Duration) (bool, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/?timeout=%s&readTimeout=%s&writeTimeout=%s",
		cred.User, cred.Pass, addr, timeout, timeout, timeout)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()

	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := db.PingContext(ctx2); err != nil {
		if isMySQLAuthFailure(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isMySQLAuthFailure matches error 1045 (access denied) so a wrong password
// doesn't abort the rest of the dict.
func isMySQLAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "Error 1045") || strings.Contains(msg, "Access denied")
}
