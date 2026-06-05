// Package uncover wraps projectdiscovery/uncover for internet asset discovery
// via fofa/hunter/quake search queries. API keys are read from environment
// variables (FOFA_EMAIL/FOFA_KEY, HUNTER_API_KEY, QUAKE_TOKEN) by uncover
// itself; this wrapper only projects sources.Result onto types.Asset.
//
// Unlike the other discovery modules this needs internet egress (the engines
// are public databases), so it is only reached for search-query targets — the
// intranet path never calls it.
package uncover

import (
	"context"
	"errors"
	"fmt"

	pduncover "github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/sources"

	"dddd-next/internal/types"
)

type Options struct {
	Agents  []string // fofa / hunter / quake / ...
	Limit   int
	Timeout int
	Proxy   string
}

func DefaultOptions() Options {
	return Options{
		Agents:  []string{"fofa", "hunter", "quake"},
		Limit:   100,
		Timeout: 30,
	}
}

type Source struct {
	opts Options
}

func New(opts Options) *Source {
	if len(opts.Agents) == 0 {
		opts.Agents = []string{"fofa", "hunter", "quake"}
	}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30
	}
	return &Source{opts: opts}
}

// Query runs the search expression across the configured engines and returns
// discovered assets. It errors if uncover has no usable API keys — set
// FOFA_EMAIL/FOFA_KEY, HUNTER_API_KEY or QUAKE_TOKEN in the environment.
func (s *Source) Query(ctx context.Context, query string, limit int) ([]types.Asset, error) {
	if query == "" {
		return nil, errors.New("uncover: empty query")
	}
	if limit <= 0 {
		limit = s.opts.Limit
	}
	if ctx == nil {
		ctx = context.Background()
	}

	u, err := pduncover.New(&pduncover.Options{
		Agents:   s.opts.Agents,
		Queries:  []string{query},
		Limit:    limit,
		MaxRetry: 2,
		Timeout:  s.opts.Timeout,
		Proxy:    s.opts.Proxy,
	})
	if err != nil {
		return nil, fmt.Errorf("uncover: init: %w", err)
	}

	ch, err := u.Execute(ctx)
	if err != nil {
		return nil, fmt.Errorf("uncover: execute: %w", err)
	}

	var assets []types.Asset
	for r := range ch {
		if r.Error != nil {
			continue
		}
		assets = append(assets, toAsset(r))
	}
	return assets, nil
}

func toAsset(r sources.Result) types.Asset {
	return types.Asset{
		Source: r.Source,
		Host:   r.Host,
		Port:   r.Port,
		URL:    r.Url,
		IP:     r.IP,
	}
}
