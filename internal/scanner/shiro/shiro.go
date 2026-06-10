// Package shiro detects Apache Shiro-550 rememberMe deserialization by
// brute-forcing the AES key. A wrong key makes Shiro answer with a
// "rememberMe=deleteMe" Set-Cookie; the correct key decrypts cleanly and that
// marker disappears — that inversion is the whole detection.
package shiro

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"dddd-next/internal/types"
)

// checkContent is a harmless serialized SimplePrincipalCollection — enough to
// exercise decryption without carrying a gadget chain.
const checkContent = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="

const userAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"

type Scanner struct {
	keys   []string
	client *http.Client
}

func New(keys []string, timeout time.Duration, proxy string) *Scanner {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	if proxy != "" {
		if u, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &Scanner{
		keys: keys,
		client: &http.Client{
			Timeout:       timeout,
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// LoadKeys reads base64 AES keys, one per line (blanks and # comments skipped).
func LoadKeys(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("shiro: open keys %s: %w", path, err)
	}
	defer f.Close()

	var keys []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keys = append(keys, line)
	}
	return keys, sc.Err()
}

// Scan gates on the deleteMe behaviour, then brute-forces the key list. Returns
// nil when the target is not Shiro or no key matches.
func (s *Scanner) Scan(ctx context.Context, url string) (*types.Finding, error) {
	// A non-Shiro app won't emit deleteMe for a garbage rememberMe — skip it
	// rather than fire the whole key list at every web root.
	if ok, err := s.sendRememberMe(ctx, url, "123"); err != nil || ok {
		return nil, err
	}

	content, err := base64.StdEncoding.DecodeString(checkContent)
	if err != nil {
		return nil, err
	}
	for _, key := range s.keys {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if mode, ok := s.tryKey(ctx, url, key, content); ok {
			return &types.Finding{
				ID:           "shiro-weak-key",
				Name:         "Apache Shiro Weak Key (rememberMe)",
				Severity:     types.SeverityCritical,
				Target:       url,
				Description:  fmt.Sprintf("Shiro rememberMe decryptable with known key %q (%s)", key, mode),
				Tags:         []string{"shiro", "deserialization", "rce"},
				DiscoveredAt: time.Now(),
			}, nil
		}
	}
	return nil, nil
}

// tryKey checks one key in CBC then GCM mode, confirming a hit twice to cut
// false positives.
func (s *Scanner) tryKey(ctx context.Context, url, key string, content []byte) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", false
	}
	for mode, enc := range map[string]func([]byte, []byte) (string, error){"cbc": aesCBCEncrypt, "gcm": aesGCMEncrypt} {
		payload, err := enc(raw, content)
		if err != nil {
			continue
		}
		if ok, _ := s.sendRememberMe(ctx, url, payload); !ok {
			continue
		}
		if ok, _ := s.sendRememberMe(ctx, url, payload); ok {
			return mode, true
		}
	}
	return "", false
}

// sendRememberMe returns true when the response lacks the deleteMe marker —
// i.e. the rememberMe value decrypted successfully.
func (s *Scanner) sendRememberMe(ctx context.Context, url, data string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Cookie", "JSESSIONID="+randID()+";rememberMe="+data)

	resp, err := s.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	return !strings.Contains(strings.Join(resp.Header["Set-Cookie"], ""), "rememberMe=deleteMe;"), nil
}

func aesCBCEncrypt(key, content []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	content = pkcs7Pad(content, block.BlockSize())
	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	out := make([]byte, len(content))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, content)
	return base64.StdEncoding.EncodeToString(append(iv, out...)), nil
}

func aesGCMEncrypt(key, content []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 16) // Shiro uses a 16-byte GCM nonce, not Go's default 12
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(append(nonce, gcm.Seal(nil, nonce, content, nil)...)), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(n)}, n)...)
}

func randID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
