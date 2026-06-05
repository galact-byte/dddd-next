package gopocs

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type redisCracker struct{}

func (redisCracker) Service() string { return "redis" }

func (redisCracker) Try(ctx context.Context, host string, port int, cred Credential, timeout time.Duration) (bool, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         net.JoinHostPort(host, strconv.Itoa(port)),
		Username:     cred.User, // empty for classic password-only redis
		Password:     cred.Pass,
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		MaxRetries:   -1,
	})
	defer rdb.Close()

	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := rdb.Ping(ctx2).Err(); err != nil {
		if isRedisAuthFailure(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isRedisAuthFailure matches wrong-password rejections. A no-auth server that
// refuses our AUTH ("no password is set") is also treated as a non-match here —
// unauthenticated redis is nuclei's job, not the brute forcer's.
func isRedisAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "WRONGPASS") ||
		strings.Contains(msg, "invalid username-password") ||
		strings.Contains(msg, "NOAUTH") ||
		strings.Contains(msg, "without any password") ||
		strings.Contains(msg, "no password is set")
}
