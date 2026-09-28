package hunter

import (
	"context"
	"errors"
	"testing"
)

func TestRequestRedactionPreservesCancellation(t *testing.T) {
	c, err := New(Options{APIKey: "dummy-key", Timeout: 1})
	if err != nil {
		t.Fatal(err)
	}
	c.baseURL = "http://127.0.0.1:1"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.Search(ctx, "test")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation cause lost: %v", err)
	}
}
