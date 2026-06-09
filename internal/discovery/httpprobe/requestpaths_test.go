package httpprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRequestPathsProbesEachPath verifies the RequestPaths option makes httpx
// probe every path on the target (httpx -path), not just the root — the
// mechanism the product-path fingerprint stage depends on.
func TestRequestPathsProbesEachPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the path so the test can confirm each was actually requested.
		_, _ = w.Write([]byte("PATH:" + r.URL.Path))
	}))
	defer srv.Close()

	paths := []string{
		"/nacos/", "/api/nacos/", "/druid/index.html", "/wui/index.html",
		"/error", "/gateway/error/", "/api/error/", "/?a=WKtwuea&c=2RVM&m=fv3C&s=ba5a",
		"/WebReport/ReportServer", "/ReportServer", "/webroot/decision/login",
		"/xxl-job-admin/toLogin", "/xxl-job/toLogin", "/xxl/toLogin", "/geoserver/web/",
		"/ueditor/ueditor.all.js", "/zentao/", "/phpmyadmin/", "/pma/", "/arcgis/",
		"/smartbi/vision/index.jsp", "/harbor/", "/minio/", "/manager/html", "/jenkins/login",
	}
	p := New(Options{Targets: []string{srv.URL}, RequestPaths: paths, TimeoutSeconds: 5})

	ch, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got := 0
	for resp := range ch {
		if resp.StatusCode != 200 || !strings.Contains(resp.Body, "PATH:") {
			t.Errorf("probe %q: status=%d body=%q", resp.URL, resp.StatusCode, resp.Body)
		}
		got++
	}
	// Every path must be probed — the product-path stage relies on full coverage,
	// and the query-string path must survive the comma-joined RequestURIs.
	if got != len(paths) {
		t.Fatalf("probed %d path(s), want all %d", got, len(paths))
	}
}
