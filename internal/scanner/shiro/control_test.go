package shiro

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestScanRequiresEncryptedNegativeControl(t *testing.T) {
	for _, status := range []int{200, 302, 403, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cookie, _ := r.Cookie("rememberMe")
				if cookie != nil && cookie.Value == "123" {
					w.Header().Set("Set-Cookie", "rememberMe=deleteMe")
					return
				}
				w.WriteHeader(status)
			}))
			defer srv.Close()
			f, err := New([]string{testKey}, time.Second, "").Scan(context.Background(), srv.URL)
			if err != nil || f != nil {
				t.Fatalf("challenge HTTP %d: finding=%v err=%v", status, f, err)
			}
		})
	}
}

func TestScanRecognizesDeleteMeWithoutAttributes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Set-Cookie", "rememberMe=deleteMe") }))
	defer srv.Close()
	f, err := New([]string{testKey}, time.Second, "").Scan(context.Background(), srv.URL)
	if err != nil || f != nil {
		t.Fatalf("rejected cookie: finding=%v err=%v", f, err)
	}
}
