package uncover

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"dddd-next/internal/types"
)

// Removing IP-derived FOFA queries must lose the additional port in this fixture.
func TestHunterFofaUsesDiscoveredIPsAndPreservesSeeds(t *testing.T) {
	var calls []string
	run := func(ctx context.Context, agent, query string, limit int) ([]types.Asset, error) {
		calls = append(calls, agent+":"+query)
		switch agent + ":" + query {
		case `hunter:icp.name="公司"`:
			return []types.Asset{{Source: "hunter", IP: "192.0.2.1", Port: 80}, {Source: "hunter", IP: "192.0.2.1", Port: 443}, {Source: "hunter", IP: "not-an-ip", Port: 80}}, nil
		case `fofa:ip="192.0.2.1"`:
			return []types.Asset{{Source: "fofa", IP: "192.0.2.1", Port: 8443}}, nil
		default:
			t.Fatalf("unexpected external query: %s %s", agent, query)
			return nil, nil
		}
	}
	assets, err := queryHunterFofa(context.Background(), `icp.name="公司"`, 100, nil, run)
	if err != nil || len(assets) != 4 || assets[3].Port != 8443 {
		t.Fatalf("assets=%+v err=%v", assets, err)
	}
	if want := []string{`hunter:icp.name="公司"`, `fofa:ip="192.0.2.1"`}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v", calls)
	}
}

func TestHunterFofaKeepsPartialResultsAndOtherEngines(t *testing.T) {
	failed := errors.New("page unavailable")
	run := func(ctx context.Context, agent, query string, limit int) ([]types.Asset, error) {
		switch agent {
		case "hunter":
			return []types.Asset{{IP: "192.0.2.5", Port: 80}}, failed
		case "fofa":
			return []types.Asset{{IP: "192.0.2.5", Port: 443}}, failed
		case "quake":
			if query != `icp.name="公司"` {
				t.Fatalf("extra engine query=%q", query)
			}
			return []types.Asset{{IP: "192.0.2.6", Port: 22}}, nil
		}
		t.Fatalf("unexpected agent %s", agent)
		return nil, nil
	}
	assets, err := queryHunterFofa(context.Background(), `icp.name="公司"`, 10, []string{"quake"}, run)
	if len(assets) != 3 || !errors.Is(err, failed) {
		t.Fatalf("assets=%+v err=%v", assets, err)
	}
}

func TestHunterFofaDoesNotQueryFofaWithoutSeedIPs(t *testing.T) {
	calls := 0
	assets, err := queryHunterFofa(context.Background(), "query", 10, nil, func(context.Context, string, string, int) ([]types.Asset, error) { calls++; return nil, nil })
	if calls != 1 || len(assets) != 0 || err != nil {
		t.Fatalf("calls=%d assets=%v err=%v", calls, assets, err)
	}
}

func TestHunterFofaStopsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	assets, err := queryHunterFofa(ctx, "query", 1, nil, func(context.Context, string, string, int) ([]types.Asset, error) {
		calls++
		cancel()
		return []types.Asset{{IP: "192.0.2.1", Port: 80}}, nil
	})
	if calls != 1 || len(assets) != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("calls=%d assets=%v err=%v", calls, assets, err)
	}
}
