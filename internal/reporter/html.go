package reporter

import (
	"fmt"
	"html/template"
	"os"
	"sync"
	"time"

	"dddd-next/internal/types"
)

// HTMLReporter buffers findings and fingerprints in memory, then renders a
// self-contained HTML report on Close.
//
// We do not stream HTML because the page needs aggregate sections
// (counts by severity, table of contents). For "incremental persistence"
// purposes, scans should pair HTML with TextReporter — the latter is the
// crash-safe sink, HTML is the human deliverable.
type HTMLReporter struct {
	mu       sync.Mutex
	path     string
	findings []types.Finding
	fps      map[string][]types.Fingerprint
}

// NewHTML returns a reporter that writes to path on Close.
func NewHTML(path string) *HTMLReporter {
	return &HTMLReporter{path: path, fps: make(map[string][]types.Fingerprint)}
}

func (r *HTMLReporter) WriteFingerprint(target string, fp types.Fingerprint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fps[target] = append(r.fps[target], fp)
	return nil
}

func (r *HTMLReporter) WriteFinding(f types.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findings = append(r.findings, f)
	return nil
}

type htmlPayload struct {
	GeneratedAt   time.Time
	Findings      []types.Finding
	Fingerprints  map[string][]types.Fingerprint
	SeverityCount map[string]int
}

func (r *HTMLReporter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	payload := htmlPayload{
		GeneratedAt:   time.Now(),
		Findings:      r.findings,
		Fingerprints:  r.fps,
		SeverityCount: map[string]int{},
	}
	for _, f := range r.findings {
		payload.SeverityCount[string(f.Severity)]++
	}

	t, err := template.New("report").Parse(htmlTpl)
	if err != nil {
		return fmt.Errorf("reporter: parse template: %w", err)
	}

	out, err := os.Create(r.path)
	if err != nil {
		return fmt.Errorf("reporter: create %s: %w", r.path, err)
	}
	defer out.Close()

	if err := t.Execute(out, payload); err != nil {
		return fmt.Errorf("reporter: execute template: %w", err)
	}
	return nil
}

const htmlTpl = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dddd-next 扫描报告</title>
<style>
  :root {
    --bg: #0f0f0f; --surface: #1a1a1a; --text: #f5f5f5;
    --muted: #888; --primary: #00d4aa; --accent: #ff6b9d;
    --critical: #ff4444; --high: #ff8800; --medium: #ffcc00;
    --low: #66cc66; --info: #66aaff;
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 32px; background: var(--bg); color: var(--text);
         font-family: "DM Sans", "PingFang SC", -apple-system, system-ui, sans-serif; }
  h1 { font-family: "DM Serif Display", "Source Han Serif SC", serif; font-weight: 400; margin: 0 0 8px; font-size: 32px; }
  .meta { color: var(--muted); font-size: 14px; margin-bottom: 32px; }
  .grid { display: grid; gap: 24px; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); margin-bottom: 32px; }
  .card { background: var(--surface); border-radius: 10px; padding: 20px; }
  .card .num { font-size: 28px; font-weight: 600; }
  .card .lbl { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
  .sev-critical { color: var(--critical); }
  .sev-high     { color: var(--high); }
  .sev-medium   { color: var(--medium); }
  .sev-low      { color: var(--low); }
  .sev-info     { color: var(--info); }
  section { background: var(--surface); border-radius: 10px; padding: 20px 24px; margin-bottom: 24px; }
  section h2 { margin: 0 0 16px; font-size: 18px; font-weight: 600; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #2a2a2a; }
  th { color: var(--muted); font-weight: 500; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
  .badge.critical { background: var(--critical); color: #fff; }
  .badge.high     { background: var(--high); color: #fff; }
  .badge.medium   { background: var(--medium); color: #000; }
  .badge.low      { background: var(--low); color: #000; }
  .badge.info     { background: var(--info); color: #fff; }
  details { background: #131313; border-radius: 6px; padding: 8px 12px; margin-top: 8px; }
  summary { cursor: pointer; color: var(--muted); font-size: 12px; }
  pre { background: #0a0a0a; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
</style>
</head>
<body>
<h1>dddd-next 扫描报告</h1>
<div class="meta">生成时间 {{.GeneratedAt.Format "2006-01-02 15:04:05"}} · 漏洞 {{len .Findings}} · 命中指纹的目标 {{len .Fingerprints}}</div>

<div class="grid">
{{range $sev, $n := .SeverityCount}}
  <div class="card"><div class="num sev-{{$sev}}">{{$n}}</div><div class="lbl">{{$sev}}</div></div>
{{end}}
</div>

{{if .Findings}}
<section>
  <h2>漏洞清单</h2>
  <table>
    <thead><tr><th>等级</th><th>目标</th><th>名称</th><th>模板</th></tr></thead>
    <tbody>
    {{range .Findings}}
      <tr>
        <td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
        <td>{{.Target}}</td>
        <td>{{.Name}}</td>
        <td><code>{{.Template}}</code></td>
      </tr>
      {{if or .Request .Response}}
      <tr><td colspan="4">
        <details>
          <summary>请求 / 响应</summary>
          {{if .Request}}<pre>{{.Request}}</pre>{{end}}
          {{if .Response}}<pre>{{.Response}}</pre>{{end}}
        </details>
      </td></tr>
      {{end}}
    {{end}}
    </tbody>
  </table>
</section>
{{end}}

{{if .Fingerprints}}
<section>
  <h2>指纹命中</h2>
  <table>
    <thead><tr><th>目标</th><th>指纹</th></tr></thead>
    <tbody>
    {{range $target, $fps := .Fingerprints}}
      <tr><td>{{$target}}</td><td>{{range $fps}}<span style="margin-right:8px">{{.Name}}</span>{{end}}</td></tr>
    {{end}}
    </tbody>
  </table>
</section>
{{end}}

</body>
</html>
`
