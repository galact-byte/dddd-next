package gopocs

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type mongodbCracker struct{}

func (mongodbCracker) Service() string { return "mongodb" }

func (mongodbCracker) Try(ctx context.Context, host string, port int, cred Credential, timeout time.Duration) (bool, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	opts := options.Client().
		SetHosts([]string{addr}).
		SetConnectTimeout(timeout).
		SetServerSelectionTimeout(timeout).
		SetAuth(options.Credential{
			AuthSource: "admin",
			Username:   cred.User,
			Password:   cred.Pass,
		})

	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := mongo.Connect(ctx2, opts)
	if err != nil {
		return false, err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	if err := client.Ping(ctx2, nil); err != nil {
		if isMongoAuthFailure(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isMongoAuthFailure matches server error code 18 (AuthenticationFailed). A
// no-auth server has no user table, so guessed creds fail here too — meaning an
// unauthenticated mongodb is left to nuclei, never reported as a weak credential.
func isMongoAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "AuthenticationFailed") ||
		strings.Contains(msg, "Authentication failed") ||
		strings.Contains(msg, "auth error")
}
