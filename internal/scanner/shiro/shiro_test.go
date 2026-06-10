package shiro

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dddd-next/internal/types"
)

// kPH+bIxk5D2deZiIxcaaaA== is Shiro's most infamous default key.
const testKey = "kPH+bIxk5D2deZiIxcaaaA=="

// fakeShiro emulates a Shiro target: it answers "rememberMe=deleteMe" unless the
// rememberMe cookie decrypts cleanly with key (the correct-key path). nonShiro
// makes it never emit deleteMe (a plain web app).
func fakeShiro(t *testing.T, key string, nonShiro bool) *httptest.Server {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(key)
	want, _ := base64.StdEncoding.DecodeString(checkContent)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if nonShiro {
			return // no Set-Cookie at all
		}
		rememberMe := rememberMeFromCookie(r.Header.Get("Cookie"))
		if rememberMe != "" && rememberMe != "123" && cbcDecryptsTo(rememberMe, raw, want) {
			w.Header().Set("Set-Cookie", "JSESSIONID=ok; Path=/")
			return
		}
		w.Header().Set("Set-Cookie", "rememberMe=deleteMe; Path=/; Max-Age=0")
	}))
}

func TestScanFindsWeakKey(t *testing.T) {
	srv := fakeShiro(t, testKey, false)
	defer srv.Close()

	s := New([]string{"AAAAAAAAAAAAAAAAAAAAAA==", testKey}, 5*time.Second, "")
	f, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if f == nil {
		t.Fatal("expected a finding for the weak key")
	}
	if f.Severity != types.SeverityCritical || !strings.Contains(f.Description, testKey) {
		t.Errorf("finding = %+v, want critical mentioning %s", f, testKey)
	}
}

func TestScanSkipsNonShiro(t *testing.T) {
	srv := fakeShiro(t, testKey, true)
	defer srv.Close()

	s := New([]string{testKey}, 5*time.Second, "")
	f, err := s.Scan(context.Background(), srv.URL)
	if err != nil || f != nil {
		t.Fatalf("non-Shiro target: got %v err %v, want nil/nil (gated out)", f, err)
	}
}

func TestScanWrongKeyNoFalsePositive(t *testing.T) {
	srv := fakeShiro(t, testKey, false) // shiro, but accepts only testKey
	defer srv.Close()

	s := New([]string{"AAAAAAAAAAAAAAAAAAAAAA=="}, 5*time.Second, "") // testKey not in list
	f, err := s.Scan(context.Background(), srv.URL)
	if err != nil || f != nil {
		t.Fatalf("wrong key only: got %v err %v, want nil/nil (no false positive)", f, err)
	}
}

func rememberMeFromCookie(cookie string) string {
	for _, part := range strings.Split(cookie, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "rememberMe=") {
			return strings.TrimPrefix(part, "rememberMe=")
		}
	}
	return ""
}

func cbcDecryptsTo(rememberMe string, key, want []byte) bool {
	data, err := base64.StdEncoding.DecodeString(rememberMe)
	if err != nil || len(data) < aes.BlockSize {
		return false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	iv, ct := data[:aes.BlockSize], data[aes.BlockSize:]
	if len(ct)%aes.BlockSize != 0 || len(ct) == 0 {
		return false
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	if n := int(out[len(out)-1]); n > 0 && n <= aes.BlockSize && n <= len(out) {
		out = out[:len(out)-n] // strip PKCS7 padding
	}
	return string(out) == string(want)
}
