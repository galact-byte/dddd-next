// Package uncover combines internet asset search engines and a configurable
// FOFA adapter. API credentials come from environment variables or uncover's
// provider configuration. Only search-query targets enter this module.
package uncover

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	pduncover "github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/sources"

	"dddd-next/internal/types"
)

type Options struct {
	Agents     []string // fofa / hunter / quake / ...
	Limit      int
	Timeout    int
	Proxy      string
	FofaServer string // empty uses the official FOFA server
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

// Query runs the search expression across the configured engines. Partial
// assets are returned alongside errors; callers should retain those assets.
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
	if err := ctx.Err(); err != nil {
		return nil, err
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

	defer u.Session.RateLimits.Stop()
	defer u.Session.Client.HTTPClient.CloseIdleConnections()
	if u.Session.Client.HTTPClient2 != nil {
		defer u.Session.Client.HTTPClient2.CloseIdleConnections()
	}

	// Explicit environment credentials take precedence over uncover's random
	// provider-file selection, especially when using a different FOFA server.
	if email, ok := os.LookupEnv("FOFA_EMAIL"); ok {
		u.Session.Keys.FofaEmail = email
	}
	if key, ok := os.LookupEnv("FOFA_KEY"); ok {
		u.Session.Keys.FofaKey = key
	}
	for i, agent := range u.Agents {
		if agent.Name() == "fofa" {
			u.Agents[i] = &fofaAgent{server: s.opts.FofaServer}
		}
	}
	if len(u.Agents) == 0 {
		return nil, errors.New("uncover: no supported agents selected")
	}

	// Consume agents directly: Execute logs and drops initialization errors.
	ch := make(chan sources.Result)
	var wg sync.WaitGroup
	for _, agent := range u.Agents {
		wg.Add(1)
		go func(agent sources.Agent) {
			defer wg.Done()
			results, err := agent.Query(ctx, u.Session, &sources.Query{Query: query, Limit: limit})
			if err != nil {
				sources.SendResult(ctx, ch, sources.Result{Source: agent.Name(), Error: err})
				return
			}
			for result := range results {
				sources.SendResult(ctx, ch, result)
			}
		}(agent)
	}
	go func() {
		wg.Wait()
		close(ch)
	}()

	var assets []types.Asset
	var queryErrors []error
	for r := range ch {
		if r.Error != nil {
			queryErrors = append(queryErrors, fmt.Errorf("%s: %s", r.Source, reconMessage(r.Error.Error(), u.Session.Keys)))
			continue
		}
		assets = append(assets, toAsset(r))
	}
	if ctx.Err() != nil {
		queryErrors = append(queryErrors, ctx.Err())
	}
	return assets, errors.Join(queryErrors...)
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
