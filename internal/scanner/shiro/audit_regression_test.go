package shiro

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuditShiroBlockedResponseIsNotValidKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("rememberMe")
		if cookie != nil && cookie.Value == "123" {
			http.SetCookie(w, &http.Cookie{Name: "rememberMe", Value: "deleteMe", Path: "/"})
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("blocked by WAF; no key has been accepted"))
	}))
	defer srv.Close()
	scanner := New([]string{"kPH+bIxk5D2deZiIxcaaaA=="}, time.Second, "")
	finding, err := scanner.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if finding != nil {
		t.Fatalf("服务器只返回 403 却产生漏洞: id=%s detail=%s", finding.ID, finding.Detail)
	}
}
