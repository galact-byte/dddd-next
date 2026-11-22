package uncover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"dddd-next/internal/types"
)

// queryHunterFofa keeps the seeds when enrichment fails. Each unique seed IP
// gets one bounded FOFA query; expressions are never copied between engines.
func queryHunterFofa(ctx context.Context, query string, limit int, extra []string, run func(context.Context, string, string, int) ([]types.Asset, error)) ([]types.Asset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	seeds, err := run(ctx, "hunter", query, limit)
	if len(seeds) > limit {
		seeds = seeds[:limit]
	}
	assets := append([]types.Asset(nil), seeds...)
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	seen := make(map[string]bool)
	for _, seed := range seeds {
		if ctx.Err() != nil {
			break
		}
		ip := net.ParseIP(strings.TrimSpace(seed.IP))
		if ip == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		found, e := run(ctx, "fofa", fmt.Sprintf(`ip="%s"`, ip.String()), limit)
		if len(found) > limit {
			found = found[:limit]
		}
		assets = append(assets, found...)
		if e != nil {
			errs = append(errs, e)
		}
	}
	for _, agent := range extra {
		if ctx.Err() != nil {
			break
		}
		found, e := run(ctx, agent, query, limit)
		if len(found) > limit {
			found = found[:limit]
		}
		assets = append(assets, found...)
		if e != nil {
			errs = append(errs, e)
		}
	}
	if ctx.Err() != nil {
		errs = append(errs, ctx.Err())
	}
	return assets, errors.Join(errs...)
}
