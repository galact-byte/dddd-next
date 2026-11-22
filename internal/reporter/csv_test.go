package reporter

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"dddd-next/internal/types"
)

func TestAssetCSVDoesNotTruncateExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(path, []byte("original report"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := NewAssetCSVFile(path)
	if err == nil {
		_ = r.Close()
		t.Error("existing report opened for CSV")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "original report" {
		t.Fatalf("existing report changed: %q, %v", data, err)
	}
}

func TestAssetCSVIncludesUnidentifiedPortsAndMergesWebMetadata(t *testing.T) {
	var out bytes.Buffer
	r, err := NewAssetCSVWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []types.Asset{
		{Host: "192.0.2.1", Port: 22, Status: "open", Source: "portscan"},
		{Host: "192.0.2.2", Port: 80, Service: "http", Status: "open", Source: "portscan"},
		{Host: "192.0.2.2", Port: 80, URL: "http://192.0.2.2/", Title: "中文,\"标题\"\n第二行", Fingerprints: []string{"Demo"}, Status: "http:200", Source: "http"},
		{Host: "192.0.2.2", Port: 80, URL: "http://192.0.2.2/", Source: "import", Status: "imported", Fingerprints: []string{"History"}},
	} {
		if err := r.WriteAsset(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(out.String(), "\ufeff"))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows=%v", rows)
	}
	if !reflect.DeepEqual(rows[1], []string{"192.0.2.1", "", "22", "", "", "", "", "portscan", "open"}) {
		t.Fatalf("unknown port=%v", rows[1])
	}
	if want := []string{"192.0.2.2", "", "80", "http", "http://192.0.2.2/", "中文,\"标题\"\n第二行", "Demo;History", "http;import;portscan", "http:200"}; !reflect.DeepEqual(rows[2], want) {
		t.Fatalf("web row=%v", rows[2])
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteAsset(types.Asset{Host: "later"}); err == nil {
		t.Fatal("write after close accepted")
	}
}

func TestAssetCSVNeutralizesSpreadsheetFormulas(t *testing.T) {
	for _, value := range []string{"=1+1", "+SUM(A1)", "-2+3", "@SUM(A1)", " \t=1+1", "\r=1+1", "\n=1+1"} {
		var out bytes.Buffer
		r, err := NewAssetCSVWriter(&out)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.WriteAsset(types.Asset{Host: "host", Title: value}); err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(out.String(), "\ufeff"))).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if rows[1][5] != "'"+value {
			t.Fatalf("unsafe cell=%q", rows[1][5])
		}
	}
}

type assetFailWriter struct{ fail bool }

func (w *assetFailWriter) Write(p []byte) (int, error) {
	if w.fail {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}
func TestAssetCSVReportsFlushFailure(t *testing.T) {
	w := &assetFailWriter{}
	r, err := NewAssetCSVWriter(w)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WriteAsset(types.Asset{Host: "host"}); err != nil {
		t.Fatal(err)
	}
	w.fail = true
	if err := r.Close(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("close error=%v", err)
	}
}
