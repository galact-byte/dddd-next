package hunter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuditHunterTransportErrorRedactsAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	endpoint := srv.URL
	srv.Close()
	const dummyKey = "audit-dummy-key-DO-NOT-LOG"
	client, err := New(Options{APIKey: dummyKey, MaxPages: 1, Timeout: 1})
	if err != nil {
		t.Fatal(err)
	}
	client.baseURL = endpoint
	_, err = client.Search(context.Background(), "ip=127.0.0.1")
	if err == nil {
		t.Fatal("连接关闭的本地服务应该失败")
	}
	if strings.Contains(err.Error(), dummyKey) {
		t.Fatalf("错误消息包含测试 API Key：%v", err)
	}
}
