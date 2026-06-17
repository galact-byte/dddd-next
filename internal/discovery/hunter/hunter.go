// Package hunter is a dedicated client for Qianxin Hunter used by low-perception
// mode (-lpm). It bypasses projectdiscovery/uncover, which drops the `banner`
// field that -lpm fingerprints locally instead of probing the target.
package hunter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultBaseURL = "https://hunter.qianxin.com/openApi/search"

type Asset struct {
	IP         string
	Port       int
	Domain     string
	Protocol   string
	Title      string
	URL        string
	Banner     string // raw HTTP response for web assets
	StatusCode int
	IsWeb      bool
}

type Options struct {
	APIKey   string
	PageSize int
	MaxPages int
	Proxy    string
	Timeout  int
}

type Client struct {
	apiKey   string
	pageSize int
	maxPages int
	baseURL  string
	http     *http.Client
}

func New(opts Options) (*Client, error) {
	if opts.APIKey == "" {
		return nil, errors.New("hunter: HUNTER_API_KEY not set (put it in .env)")
	}
	if opts.PageSize <= 0 {
		opts.PageSize = 100
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30
	}

	transport := &http.Transport{}
	if opts.Proxy != "" {
		pu, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("hunter: bad proxy %q: %w", opts.Proxy, err)
		}
		transport.Proxy = http.ProxyURL(pu)
	}

	return &Client{
		apiKey:   opts.APIKey,
		pageSize: opts.PageSize,
		maxPages: opts.MaxPages,
		baseURL:  defaultBaseURL,
		http:     &http.Client{Timeout: time.Duration(opts.Timeout) * time.Second, Transport: transport},
	}, nil
}

// Search pages through results, sleeping between requests for the rate limit.
func (c *Client) Search(ctx context.Context, query string) ([]Asset, error) {
	var out []Asset
	got := 0
	for page := 1; page <= c.maxPages; page++ {
		items, total, err := c.queryPage(ctx, query, page)
		if err != nil {
			return out, err
		}
		for _, it := range items {
			out = append(out, toAsset(it))
		}
		got += len(items)
		if len(items) == 0 || got >= total {
			break
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return out, nil
}

type apiItem struct {
	URL        string `json:"url"`
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Domain     string `json:"domain"`
	Protocol   string `json:"protocol"`
	IsWeb      string `json:"is_web"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"web_title"`
	Banner     string `json:"banner"`
}

type apiResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int       `json:"total"`
		Arr   []apiItem `json:"arr"`
	} `json:"data"`
}

func (c *Client) queryPage(ctx context.Context, query string, page int) ([]apiItem, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL, nil)
	if err != nil {
		return nil, 0, err
	}
	q := req.URL.Query()
	q.Set("api-key", c.apiKey)
	q.Set("search", base64.URLEncoding.EncodeToString([]byte(query)))
	q.Set("page", strconv.Itoa(page))
	q.Set("page_size", strconv.Itoa(c.pageSize))
	q.Set("is_web", "3") // banner only returns with is_web set
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("hunter: request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("hunter: read body: %w", err)
	}

	var parsed apiResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, 0, fmt.Errorf("hunter: decode: %w", err)
	}
	if parsed.Code != 200 {
		return nil, 0, fmt.Errorf("hunter: api code %d: %s", parsed.Code, parsed.Message)
	}
	return parsed.Data.Arr, parsed.Data.Total, nil
}

func toAsset(it apiItem) Asset {
	return Asset{
		IP:         it.IP,
		Port:       it.Port,
		Domain:     it.Domain,
		Protocol:   it.Protocol,
		Title:      it.Title,
		URL:        it.URL,
		Banner:     it.Banner,
		StatusCode: it.StatusCode,
		IsWeb:      isWebTrue(it.IsWeb),
	}
}

func isWebTrue(s string) bool {
	switch strings.TrimSpace(s) {
	case "是", "1", "true", "yes":
		return true
	}
	return false
}

type Banner struct {
	StatusCode  int
	Header      string
	Body        string
	Server      string
	ContentType string
}

// ParseBanner splits a raw HTTP response into status code, headers and body.
func ParseBanner(raw string) Banner {
	sep := "\r\n\r\n"
	idx := strings.Index(raw, sep)
	if idx < 0 {
		sep = "\n\n"
		idx = strings.Index(raw, sep)
	}
	head, body := raw, ""
	if idx >= 0 {
		head = raw[:idx]
		body = raw[idx+len(sep):]
	}

	b := Banner{Header: head, Body: body}
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	if len(lines) > 0 {
		if parts := strings.Fields(lines[0]); len(parts) >= 2 {
			b.StatusCode, _ = strconv.Atoi(parts[1])
		}
	}
	for _, ln := range lines[1:] {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "server":
			b.Server = strings.TrimSpace(v)
		case "content-type":
			b.ContentType = strings.TrimSpace(v)
		}
	}
	return b
}
