package reporter

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"dddd-next/internal/types"
)

// AssetCSV keeps endpoint metadata until Close so later HTTP results enrich
// earlier port discoveries without producing duplicate endpoint-only rows.
type AssetCSV struct {
	mu       sync.Mutex
	writer   *csv.Writer
	closer   io.Closer
	assets   map[string]types.Asset
	closed   bool
	closeErr error
}

func NewAssetCSVFile(path string) (*AssetCSV, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return nil, err
	}
	r, err := NewAssetCSVWriter(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	r.closer = f
	return r, nil
}

func NewAssetCSVWriter(w io.Writer) (*AssetCSV, error) {
	// BOM lets Excel recognize UTF-8 when opening the CSV directly.
	if _, err := io.WriteString(w, "\ufeff"); err != nil {
		return nil, err
	}
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"host", "ip", "port", "service", "url", "title", "fingerprints", "source", "status"}); err != nil {
		return nil, err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return &AssetCSV{writer: writer, assets: make(map[string]types.Asset)}, nil
}

func (r *AssetCSV) WriteAsset(a types.Asset) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("asset CSV is closed")
	}
	key := assetEndpoint(a) + "|" + a.URL
	r.assets[key] = mergeAsset(r.assets[key], a)
	return nil
}

func (r *AssetCSV) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.closeErr
	}
	r.closed = true
	webEndpoints := make(map[string]bool)
	var keys []string
	for key, a := range r.assets {
		keys = append(keys, key)
		if a.URL != "" {
			webEndpoints[assetEndpoint(a)] = true
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		a := r.assets[key]
		endpoint := assetEndpoint(a)
		if a.URL == "" && webEndpoints[endpoint] {
			continue
		}
		if a.URL != "" {
			a = mergeAsset(r.assets[endpoint+"|"], a)
		}
		port := ""
		if a.Port > 0 {
			port = strconv.Itoa(a.Port)
		}
		row := []string{a.Host, a.IP, port, a.Service, a.URL, a.Title, strings.Join(a.Fingerprints, ";"), a.Source, a.Status}
		for i, value := range row {
			row[i] = csvSafeCell(value)
		}
		if err := r.writer.Write(row); err != nil {
			r.closeErr = err
			break
		}
	}
	r.writer.Flush()
	r.closeErr = errors.Join(r.closeErr, r.writer.Error())
	if r.closer != nil {
		r.closeErr = errors.Join(r.closeErr, r.closer.Close())
	}
	return r.closeErr
}

func assetEndpoint(a types.Asset) string { return net.JoinHostPort(a.Host, strconv.Itoa(a.Port)) }

func mergeAsset(old, next types.Asset) types.Asset {
	if next.Host != "" {
		old.Host = next.Host
	}
	if next.IP != "" {
		old.IP = next.IP
	}
	if next.Port != 0 {
		old.Port = next.Port
	}
	if next.Service != "" {
		old.Service = next.Service
	}
	if next.URL != "" {
		old.URL = next.URL
	}
	if next.Title != "" {
		old.Title = next.Title
	}
	if next.Status != "" && (next.Status != "imported" || old.Status == "") {
		old.Status = next.Status
	}
	old.Source = strings.Join(assetUnique(append(strings.Split(old.Source, ";"), strings.Split(next.Source, ";")...)), ";")
	old.Fingerprints = assetUnique(append(append([]string(nil), old.Fingerprints...), next.Fingerprints...))
	return old
}

func assetUnique(values []string) []string {
	seen := make(map[string]bool)
	for _, v := range values {
		if v != "" {
			seen[v] = true
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func csvSafeCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}
