package config

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func TestProxy(ctx context.Context, proxyURL, testURL string) error {
	if proxyURL == "" {
		return errors.New("config: proxy test requested but -proxy is empty")
	}
	if testURL == "" {
		return errors.New("config: proxy test URL is empty")
	}
	parsedProxy, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("config: parse proxy URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return fmt.Errorf("config: create proxy test request: %w", err)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(parsedProxy),
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("config: proxy test failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("config: proxy test returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func RedactURLCredentials(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	username := u.User.Username()
	if username == "" {
		u.User = url.UserPassword("xxxxx", "xxxxx")
	} else {
		u.User = url.UserPassword(username, "xxxxx")
	}
	return u.String()
}
