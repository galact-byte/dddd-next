package reporter

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
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
	GeneratedAt        time.Time
	GeneratedAtText    string
	Findings           []htmlFinding
	FingerprintTargets []htmlFingerprintTarget
	SeverityStats      []htmlSeverityStat
	TotalFindings      int
	TotalFingerprints  int
	TotalTargets       int
}

type htmlSeverityStat struct {
	Severity string
	Label    string
	Count    int
}

type htmlFinding struct {
	Index         int
	ID            string
	Name          string
	Title         string
	Severity      string
	SeverityLabel string
	Target        string
	Template      string
	Description   string
	References    []string
	Request       string
	Response      string
	RequestID     string
	ResponseID    string
	HasHTTP       bool
	CVSS          string
	Tags          string
	DiscoveredAt  string
}

type htmlFingerprintTarget struct {
	Target       string
	Fingerprints []htmlFingerprint
}

type htmlFingerprint struct {
	Name       string
	Source     string
	Confidence int
	Evidence   string
}

func (r *HTMLReporter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	generatedAt := time.Now()
	payload := buildHTMLPayload(generatedAt, r.findings, r.fps)

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

func buildHTMLPayload(generatedAt time.Time, findings []types.Finding, fps map[string][]types.Fingerprint) htmlPayload {
	counts := make(map[string]int)
	outFindings := make([]htmlFinding, 0, len(findings))
	for i, f := range findings {
		sev := string(f.Severity)
		if sev == "" {
			sev = string(types.SeverityInfo)
		}
		counts[sev]++
		hf := htmlFinding{
			Index:         i + 1,
			ID:            f.ID,
			Name:          f.Name,
			Title:         findingTitle(f),
			Severity:      sev,
			SeverityLabel: severityLabel(sev),
			Target:        f.Target,
			Template:      f.Template,
			Description:   f.Description,
			References:    append([]string(nil), f.References...),
			Request:       f.Request,
			Response:      f.Response,
			RequestID:     fmt.Sprintf("request-%d", i+1),
			ResponseID:    fmt.Sprintf("response-%d", i+1),
			HasHTTP:       f.Request != "" || f.Response != "",
			Tags:          strings.Join(f.Tags, ", "),
		}
		if f.CVSS > 0 {
			hf.CVSS = fmt.Sprintf("%.1f", f.CVSS)
		}
		if !f.DiscoveredAt.IsZero() {
			hf.DiscoveredAt = f.DiscoveredAt.Format("2006-01-02 15:04:05")
		}
		outFindings = append(outFindings, hf)
	}

	totalFP := 0
	targets := make([]string, 0, len(fps))
	for target := range fps {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	fpTargets := make([]htmlFingerprintTarget, 0, len(targets))
	for _, target := range targets {
		items := make([]htmlFingerprint, 0, len(fps[target]))
		for _, fp := range fps[target] {
			items = append(items, htmlFingerprint{
				Name:       fp.Name,
				Source:     fp.Source,
				Confidence: fp.Confidence,
				Evidence:   fp.Evidence,
			})
			totalFP++
		}
		fpTargets = append(fpTargets, htmlFingerprintTarget{Target: target, Fingerprints: items})
	}

	stats := make([]htmlSeverityStat, 0, 6)
	stats = append(stats, htmlSeverityStat{Severity: "all", Label: "全部", Count: len(findings)})
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		stats = append(stats, htmlSeverityStat{Severity: sev, Label: severityLabel(sev), Count: counts[sev]})
	}

	return htmlPayload{
		GeneratedAt:        generatedAt,
		GeneratedAtText:    generatedAt.Format("2006-01-02 15:04:05"),
		Findings:           outFindings,
		FingerprintTargets: fpTargets,
		SeverityStats:      stats,
		TotalFindings:      len(findings),
		TotalFingerprints:  totalFP,
		TotalTargets:       len(fpTargets),
	}
}

func findingTitle(f types.Finding) string {
	if f.Name != "" {
		return f.Name
	}
	if f.ID != "" {
		return f.ID
	}
	return "未命名漏洞"
}

func severityLabel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	case "info":
		return "信息"
	default:
		return sev
	}
}

const htmlTpl = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>dddd-next 扫描报告</title>
<style>
  :root {
    --bg: #090b0f;
    --panel: #10141b;
    --panel-2: #151a23;
    --panel-3: #0c1016;
    --line: #293140;
    --line-soft: #1e2633;
    --text: #eef2f7;
    --muted: #9aa5b5;
    --muted-2: #6f7b8d;
    --brand: #3b82f6;
    --brand-2: #22c55e;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #f59e0b;
    --low: #22c55e;
    --info: #38bdf8;
    --code: #9ef99e;
  }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font: 14px/1.6 "PingFang SC", "Microsoft YaHei", "Noto Sans CJK SC", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  a { color: #8ab4ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  button { font: inherit; }
  .report-shell {
    width: min(1280px, calc(100vw - 32px));
    margin: 0 auto;
    padding: 24px 0 40px;
  }
  .report-header {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 24px;
    align-items: end;
    padding: 18px 0 20px;
    border-bottom: 1px solid var(--line);
  }
  .eyebrow {
    color: var(--brand);
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0;
    margin-bottom: 6px;
  }
  h1 {
    margin: 0;
    font-size: clamp(24px, 3vw, 34px);
    line-height: 1.2;
    letter-spacing: 0;
  }
  .meta {
    color: var(--muted);
    margin-top: 8px;
  }
  .summary-strip {
    display: grid;
    grid-template-columns: repeat(3, minmax(120px, 1fr));
    gap: 10px;
    min-width: 360px;
  }
  .summary-box {
    border: 1px solid var(--line);
    background: var(--panel);
    border-radius: 6px;
    padding: 12px 14px;
  }
  .summary-box strong {
    display: block;
    font-size: 22px;
    line-height: 1.1;
  }
  .summary-box span {
    display: block;
    color: var(--muted);
    font-size: 12px;
    margin-top: 5px;
  }
  .stats-bar {
    position: sticky;
    top: 0;
    z-index: 5;
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 8px;
    padding: 12px 0;
    background: rgba(9, 11, 15, 0.95);
    border-bottom: 1px solid var(--line-soft);
    backdrop-filter: blur(10px);
  }
  .stat-filter {
    min-height: 48px;
    border: 1px solid var(--line);
    background: var(--panel);
    color: var(--text);
    border-radius: 6px;
    cursor: pointer;
    text-align: left;
    padding: 8px 10px;
    transition: border-color 160ms ease, background 160ms ease;
  }
  .stat-filter:hover,
  .stat-filter.active {
    border-color: var(--brand);
    background: var(--panel-2);
  }
  .stat-filter .label {
    color: var(--muted);
    font-size: 12px;
  }
  .stat-filter .count {
    display: block;
    font-size: 20px;
    font-weight: 750;
    line-height: 1.15;
  }
  .section-head {
    display: flex;
    justify-content: space-between;
    gap: 16px;
    align-items: center;
    margin: 24px 0 12px;
  }
  .section-head h2 {
    margin: 0;
    font-size: 18px;
    line-height: 1.3;
  }
  .section-note {
    color: var(--muted);
    font-size: 13px;
  }
  .finding-list {
    display: grid;
    gap: 10px;
  }
  .finding-card {
    border: 1px solid var(--line);
    border-radius: 6px;
    background: var(--panel);
    overflow: hidden;
  }
  .finding-card[hidden] { display: none; }
  .finding-critical { border-left: 4px solid var(--critical); }
  .finding-high { border-left: 4px solid var(--high); }
  .finding-medium { border-left: 4px solid var(--medium); }
  .finding-low { border-left: 4px solid var(--low); }
  .finding-info { border-left: 4px solid var(--info); }
  .finding-summary {
    width: 100%;
    display: grid;
    grid-template-columns: auto minmax(0, 1fr) auto;
    gap: 12px;
    align-items: center;
    border: 0;
    color: var(--text);
    background: var(--panel-2);
    cursor: pointer;
    text-align: left;
    padding: 12px 14px;
  }
  .finding-index {
    min-width: 30px;
    height: 28px;
    display: inline-grid;
    place-items: center;
    border-radius: 5px;
    background: #202838;
    color: #c8d3e3;
    font-size: 12px;
    font-weight: 800;
  }
  .finding-title {
    min-width: 0;
  }
  .finding-title strong {
    display: block;
    overflow-wrap: anywhere;
  }
  .finding-target {
    color: var(--muted);
    margin-top: 3px;
    overflow-wrap: anywhere;
    font-size: 13px;
  }
  .finding-meta {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    justify-content: flex-end;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    min-height: 24px;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 800;
    white-space: nowrap;
  }
  .badge-critical { color: #fff; background: rgba(239, 68, 68, 0.84); }
  .badge-high { color: #fff; background: rgba(249, 115, 22, 0.84); }
  .badge-medium { color: #111827; background: rgba(245, 158, 11, 0.9); }
  .badge-low { color: #06130a; background: rgba(34, 197, 94, 0.86); }
  .badge-info { color: #06121f; background: rgba(56, 189, 248, 0.9); }
  .finding-body {
    display: none;
    padding: 14px;
    border-top: 1px solid var(--line-soft);
  }
  .finding-card.expanded .finding-body {
    display: block;
  }
  .detail-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }
  .detail-block {
    border: 1px solid var(--line-soft);
    background: var(--panel-3);
    border-radius: 6px;
    padding: 12px;
    min-width: 0;
  }
  .detail-block.full {
    grid-column: 1 / -1;
  }
  .detail-label {
    color: var(--muted);
    font-size: 12px;
    margin-bottom: 8px;
  }
  .description {
    margin: 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .kv {
    display: grid;
    grid-template-columns: 96px minmax(0, 1fr);
    gap: 6px 10px;
    font-size: 13px;
  }
  .kv dt {
    color: var(--muted);
  }
  .kv dd {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .http-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }
  .http-box {
    position: relative;
    border: 1px solid var(--line);
    background: #05070a;
    border-radius: 6px;
    min-width: 0;
  }
  .http-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    padding: 8px 10px;
    border-bottom: 1px solid var(--line-soft);
    color: var(--muted);
    font-size: 12px;
  }
  .copy-btn {
    min-height: 32px;
    border: 1px solid var(--line);
    background: #172033;
    color: var(--text);
    border-radius: 5px;
    padding: 4px 10px;
    cursor: pointer;
  }
  .copy-btn:hover {
    border-color: var(--brand);
  }
  pre {
    margin: 0;
    padding: 12px;
    color: var(--code);
    font: 12px/1.55 "Cascadia Mono", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    overflow: auto;
    max-height: 360px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .fingerprint-panel {
    border: 1px solid var(--line);
    border-radius: 6px;
    background: var(--panel);
    overflow: hidden;
  }
  .fp-row {
    display: grid;
    grid-template-columns: minmax(220px, 36%) minmax(0, 1fr);
    gap: 12px;
    padding: 12px 14px;
    border-top: 1px solid var(--line-soft);
  }
  .fp-row:first-child {
    border-top: 0;
  }
  .fp-target {
    color: #dbeafe;
    overflow-wrap: anywhere;
  }
  .fp-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .fp-tag {
    border: 1px solid var(--line);
    background: #111827;
    border-radius: 4px;
    padding: 3px 7px;
    color: #d6dee9;
    font-size: 12px;
  }
  .empty-state {
    border: 1px dashed var(--line);
    color: var(--muted);
    background: var(--panel);
    border-radius: 6px;
    padding: 20px;
  }
  .toast {
    position: fixed;
    left: 50%;
    bottom: 24px;
    transform: translateX(-50%);
    background: #111827;
    color: var(--text);
    border: 1px solid var(--line);
    border-radius: 6px;
    padding: 10px 14px;
    opacity: 0;
    pointer-events: none;
    transition: opacity 180ms ease;
    z-index: 20;
  }
  .toast.show { opacity: 1; }
  @media (max-width: 900px) {
    .report-header,
    .detail-grid,
    .http-grid,
    .fp-row {
      grid-template-columns: 1fr;
    }
    .summary-strip {
      min-width: 0;
      grid-template-columns: repeat(3, 1fr);
    }
    .stats-bar {
      grid-template-columns: repeat(3, 1fr);
    }
    .finding-summary {
      grid-template-columns: auto minmax(0, 1fr);
    }
    .finding-meta {
      grid-column: 1 / -1;
      justify-content: flex-start;
    }
  }
  @media (max-width: 560px) {
    .report-shell {
      width: min(100vw - 20px, 1280px);
      padding-top: 12px;
    }
    .summary-strip,
    .stats-bar {
      grid-template-columns: repeat(2, 1fr);
    }
    .kv {
      grid-template-columns: 1fr;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    * { scroll-behavior: auto !important; transition: none !important; }
  }
</style>
<script>
document.addEventListener('DOMContentLoaded', function () {
  const buttons = Array.from(document.querySelectorAll('[data-filter]'));
  const cards = Array.from(document.querySelectorAll('.finding-card'));
  const visibleCount = document.getElementById('visible-count');

  function setActive(level) {
    buttons.forEach(function (btn) {
      btn.classList.toggle('active', btn.dataset.filter === level);
    });
  }

  function filter(level) {
    let count = 0;
    cards.forEach(function (card) {
      const show = level === 'all' || card.dataset.severity === level;
      card.hidden = !show;
      if (show) count += 1;
    });
    if (visibleCount) visibleCount.textContent = String(count);
    setActive(level);
  }

  buttons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      filter(btn.dataset.filter);
    });
  });

  document.querySelectorAll('.finding-summary').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const card = btn.closest('.finding-card');
      if (!card) return;
      card.classList.toggle('expanded');
      btn.setAttribute('aria-expanded', card.classList.contains('expanded') ? 'true' : 'false');
    });
  });

  window.copyText = function (id) {
    const el = document.getElementById(id);
    if (!el) return;
    const text = el.textContent || '';
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { showToast('已复制'); }, function () { fallbackCopy(text); });
      return;
    }
    fallbackCopy(text);
  };

  function fallbackCopy(text) {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', 'readonly');
    area.style.position = 'fixed';
    area.style.left = '-9999px';
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand('copy');
      showToast('已复制');
    } catch (e) {
      showToast('复制失败');
    }
    document.body.removeChild(area);
  }

  function showToast(message) {
    let toast = document.querySelector('.toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.className = 'toast';
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add('show');
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(function () { toast.classList.remove('show'); }, 1600);
  }

  filter('all');
});
</script>
</head>
<body>
<main class="report-shell">
  <header class="report-header">
    <div>
      <div class="eyebrow">dddd-next / security scan report</div>
      <h1>dddd-next 扫描报告</h1>
      <div class="meta">生成时间 {{.GeneratedAtText}} · 当前显示 <span id="visible-count">{{.TotalFindings}}</span> / {{.TotalFindings}} 个漏洞</div>
    </div>
    <div class="summary-strip" aria-label="报告摘要">
      <div class="summary-box"><strong>{{.TotalFindings}}</strong><span>漏洞结果</span></div>
      <div class="summary-box"><strong>{{.TotalTargets}}</strong><span>指纹资产</span></div>
      <div class="summary-box"><strong>{{.TotalFingerprints}}</strong><span>指纹命中</span></div>
    </div>
  </header>

  <nav class="stats-bar" aria-label="漏洞等级筛选">
    {{range .SeverityStats}}
      <button type="button" class="stat-filter" data-filter="{{.Severity}}">
        <span class="count">{{.Count}}</span>
        <span class="label">{{.Label}}</span>
      </button>
    {{end}}
  </nav>

  <section aria-labelledby="findings-title">
    <div class="section-head">
      <h2 id="findings-title">漏洞清单</h2>
      <div class="section-note">点击条目展开详情；请求和响应可单独复制。</div>
    </div>
    {{if .Findings}}
    <div class="finding-list">
      {{range .Findings}}
      <article class="finding-card finding-{{.Severity}}" data-severity="{{.Severity}}">
        <button type="button" class="finding-summary" aria-expanded="false">
          <span class="finding-index">{{.Index}}</span>
          <span class="finding-title">
            <strong>{{.Title}}</strong>
            <span class="finding-target">{{.Target}}</span>
          </span>
          <span class="finding-meta">
            <span class="badge badge-{{.Severity}}">{{.SeverityLabel}}</span>
            {{if .ID}}<span>{{.ID}}</span>{{end}}
          </span>
        </button>
        <div class="finding-body">
          <div class="detail-grid">
            <div class="detail-block">
              <div class="detail-label">漏洞描述</div>
              {{if .Description}}<p class="description">{{.Description}}</p>{{else}}<p class="description">暂无描述。</p>{{end}}
            </div>
            <div class="detail-block">
              <div class="detail-label">元数据</div>
              <dl class="kv">
                <dt>目标</dt><dd>{{.Target}}</dd>
                <dt>模板</dt><dd>{{if .Template}}{{.Template}}{{else}}-{{end}}</dd>
                <dt>CVSS</dt><dd>{{if .CVSS}}{{.CVSS}}{{else}}-{{end}}</dd>
                <dt>标签</dt><dd>{{if .Tags}}{{.Tags}}{{else}}-{{end}}</dd>
                <dt>发现时间</dt><dd>{{if .DiscoveredAt}}{{.DiscoveredAt}}{{else}}-{{end}}</dd>
              </dl>
            </div>
            {{if .References}}
            <div class="detail-block full">
              <div class="detail-label">参考链接</div>
              <ul>
                {{range .References}}<li><a href="{{.}}" rel="noreferrer" target="_blank">{{.}}</a></li>{{end}}
              </ul>
            </div>
            {{end}}
            {{if .HasHTTP}}
            <div class="detail-block full">
              <div class="detail-label">请求 / 响应</div>
              <div class="http-grid">
                <div class="http-box">
                  <div class="http-toolbar"><span>Request</span><button type="button" class="copy-btn" onclick="copyText('{{.RequestID}}')">复制请求</button></div>
                  <pre id="{{.RequestID}}">{{.Request}}</pre>
                </div>
                <div class="http-box">
                  <div class="http-toolbar"><span>Response</span><button type="button" class="copy-btn" onclick="copyText('{{.ResponseID}}')">复制响应</button></div>
                  <pre id="{{.ResponseID}}">{{.Response}}</pre>
                </div>
              </div>
            </div>
            {{end}}
          </div>
        </div>
      </article>
      {{end}}
    </div>
    {{else}}
    <div class="empty-state">本次报告没有漏洞结果。</div>
    {{end}}
  </section>

  <section aria-labelledby="fingerprints-title">
    <div class="section-head">
      <h2 id="fingerprints-title">指纹资产</h2>
      <div class="section-note">{{.TotalTargets}} 个目标，{{.TotalFingerprints}} 条指纹。</div>
    </div>
    {{if .FingerprintTargets}}
    <div class="fingerprint-panel">
      {{range .FingerprintTargets}}
      <div class="fp-row">
        <div class="fp-target">{{.Target}}</div>
        <div class="fp-tags">
          {{range .Fingerprints}}
          <span class="fp-tag">{{.Name}}{{if .Source}} · {{.Source}}{{end}}{{if .Confidence}} · {{.Confidence}}{{end}}</span>
          {{end}}
        </div>
      </div>
      {{end}}
    </div>
    {{else}}
    <div class="empty-state">没有指纹命中。</div>
    {{end}}
  </section>
</main>
</body>
</html>
`
