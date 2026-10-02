// Package report generates self-contained HTML reports from analysis results.
package report

import (
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/SIH-2026/trace/internal/assess"
	"github.com/SIH-2026/trace/internal/engine"
	"github.com/SIH-2026/trace/internal/policy"
)

// GenerateExecutiveHTML writes a one-page executive HTML report.
func GenerateExecutiveHTML(w io.Writer, result *engine.Result, filename string) error {
	return executiveTpl.Execute(w, reportData{
		Result:    result,
		Filename:  filename,
		Generated: time.Now().Format("2006-01-02 15:04:05"),
	})
}

// GenerateTechnicalHTML writes a detailed technical HTML report.
func GenerateTechnicalHTML(w io.Writer, result *engine.Result, filename string) error {
	return technicalTpl.Execute(w, reportData{
		Result:    result,
		Filename:  filename,
		Generated: time.Now().Format("2006-01-02 15:04:05"),
	})
}

type reportData struct {
	Result    *engine.Result
	Filename  string
	Generated string
}

var funcMap = template.FuncMap{
	"statusColor": func(s assess.ControlStatus) string {
		switch s {
		case assess.StatusPass:
			return "#22c55e"
		case assess.StatusFail:
			return "#ef4444"
		case assess.StatusUnknown:
			return "#f59e0b"
		case assess.StatusNA:
			return "#6b7280"
		default:
			return "#6b7280"
		}
	},
	"statusIcon": func(s assess.ControlStatus) string {
		switch s {
		case assess.StatusPass:
			return "✓"
		case assess.StatusFail:
			return "✗"
		case assess.StatusUnknown:
			return "?"
		case assess.StatusNA:
			return "—"
		default:
			return "?"
		}
	},
	"sevColor": func(s policy.Severity) string {
		switch s {
		case policy.SevCritical:
			return "#dc2626"
		case policy.SevHigh:
			return "#ea580c"
		case policy.SevMedium:
			return "#ca8a04"
		case policy.SevLow:
			return "#2563eb"
		default:
			return "#6b7280"
		}
	},
	"threatColor": func(s assess.ThreatStatus) string {
		switch s {
		case assess.ThreatExposed:
			return "#ef4444"
		case assess.ThreatUnverified:
			return "#f59e0b"
		case assess.ThreatMitigated:
			return "#22c55e"
		default:
			return "#6b7280"
		}
	},
	"riskColor": func(r assess.RiskLevel) string {
		switch r {
		case assess.RiskLow:
			return "#22c55e"
		case assess.RiskModerate:
			return "#f59e0b"
		case assess.RiskHigh:
			return "#ea580c"
		case assess.RiskCritical:
			return "#dc2626"
		default:
			return "#6b7280"
		}
	},
	"joinStrings": func(ss []string) string {
		return strings.Join(ss, ", ")
	},
	"scoreWidth": func(f float64) string {
		return fmt.Sprintf("%.0f%%", f)
	},
}

var executiveTpl = template.Must(template.New("executive").Funcs(funcMap).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TRACE Executive Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--muted:#94a3b8;--accent:#3b82f6;--border:#334155}
body{font-family:'Inter','Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);padding:2rem;max-width:900px;margin:auto}
h1{font-size:1.8rem;font-weight:700;color:#f1f5f9;margin-bottom:.5rem}
h2{font-size:1.2rem;font-weight:600;color:#cbd5e1;margin:1.5rem 0 .75rem;border-bottom:1px solid var(--border);padding-bottom:.5rem}
.header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:2rem}
.badge{display:inline-block;padding:.25rem .75rem;border-radius:6px;font-weight:600;font-size:.9rem}
.card{background:var(--card);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;border:1px solid var(--border)}
.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.5rem}
.metric{text-align:center;padding:1rem;background:var(--bg);border-radius:8px}
.metric-value{font-size:2rem;font-weight:700}
.metric-label{font-size:.8rem;color:var(--muted);margin-top:.25rem}
.bar{height:8px;background:var(--border);border-radius:4px;overflow:hidden;margin-top:.5rem}
.bar-fill{height:100%;border-radius:4px;transition:width .3s}
.finding{padding:.75rem 1rem;margin:.5rem 0;border-radius:8px;border-left:4px solid}
.finding-title{font-weight:600;font-size:.9rem}
.finding-fix{font-family:monospace;font-size:.8rem;color:var(--muted);margin-top:.25rem;padding:.25rem .5rem;background:var(--bg);border-radius:4px}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th,td{padding:.5rem .75rem;text-align:left;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:500;text-transform:uppercase;font-size:.75rem;letter-spacing:.05em}
.footer{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);font-size:.75rem;color:var(--muted);text-align:center}
@media(prefers-color-scheme:light){:root{--bg:#f8fafc;--card:#fff;--text:#1e293b;--muted:#64748b;--border:#e2e8f0}}
</style>
</head>
<body>
<div class="header">
<div>
<h1>TRACE Executive Report</h1>
<p style="color:var(--muted);font-size:.9rem">{{.Filename}}</p>
</div>
{{if .Result.Assessment}}
<span class="badge" style="background:{{riskColor .Result.Assessment.Headline.RiskLevel}};color:#fff">
{{.Result.Assessment.Headline.Label}}
</span>
{{end}}
</div>

{{if .Result.Assessment}}
<div class="metrics">
<div class="metric">
<div class="metric-value" style="color:{{riskColor .Result.Assessment.Headline.RiskLevel}}">{{printf "%.0f" .Result.Assessment.Headline.Score}}</div>
<div class="metric-label">Score</div>
<div class="bar"><div class="bar-fill" style="width:{{scoreWidth .Result.Assessment.Headline.Score}};background:{{riskColor .Result.Assessment.Headline.RiskLevel}}"></div></div>
</div>
<div class="metric">
<div class="metric-value">{{printf "%.0f%%" .Result.Assessment.Headline.Coverage}}</div>
<div class="metric-label">Coverage</div>
<div class="bar"><div class="bar-fill" style="width:{{scoreWidth .Result.Assessment.Headline.Coverage}};background:var(--accent)"></div></div>
</div>
<div class="metric">
<div class="metric-value" style="color:{{riskColor .Result.Assessment.Headline.RiskLevel}}">{{.Result.Assessment.Headline.RiskLevel}}</div>
<div class="metric-label">Risk</div>
</div>
</div>

<div class="card">
<p style="color:var(--muted);font-size:.85rem">
Bounds: {{printf "%.0f" .Result.Assessment.Headline.LowerBound}} – {{printf "%.0f" .Result.Assessment.Headline.UpperBound}} · Confidence: {{printf "%.2f" .Result.Assessment.Headline.Confidence}}
</p>
</div>

{{if .Result.Assessment.Findings}}
<h2>Top Findings</h2>
{{range .Result.Assessment.Findings}}
<div class="finding" style="border-color:{{sevColor .Severity}};background:var(--card)">
<div class="finding-title" style="color:{{sevColor .Severity}}">{{.Severity}} — {{.Title}}</div>
{{if .FixConfig}}<div class="finding-fix">Fix: {{.FixConfig}}</div>{{end}}
</div>
{{end}}
{{end}}

<h2>Control Summary</h2>
<div class="card">
<table>
<tr><th>ID</th><th>Control</th><th>Status</th><th>Severity</th></tr>
{{range .Result.Assessment.Controls}}
<tr>
<td>{{.ID}}</td>
<td>{{.Name}}</td>
<td><span style="color:{{statusColor .Status}};font-weight:600">{{statusIcon .Status}} {{.Status}}</span></td>
<td>{{if .Severity}}<span style="color:{{sevColor .Severity}}">{{.Severity}}</span>{{else}}—{{end}}</td>
</tr>
{{end}}
</table>
</div>
{{end}}

<div class="footer">
TRACE v{{.Result.Version}} · Policy: {{.Result.PolicyID}} · Generated: {{.Generated}}<br>
SHA-256: {{.Result.Input.SHA256}}
</div>
</body>
</html>`))

var technicalTpl = template.Must(template.New("technical").Funcs(funcMap).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TRACE Technical Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--muted:#94a3b8;--accent:#3b82f6;--border:#334155}
body{font-family:'Inter','Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);padding:2rem;max-width:1100px;margin:auto}
h1{font-size:1.8rem;font-weight:700;color:#f1f5f9;margin-bottom:.5rem}
h2{font-size:1.2rem;font-weight:600;color:#cbd5e1;margin:1.5rem 0 .75rem;border-bottom:1px solid var(--border);padding-bottom:.5rem}
h3{font-size:1rem;font-weight:600;color:#94a3b8;margin:1rem 0 .5rem}
.card{background:var(--card);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th,td{padding:.5rem .75rem;text-align:left;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:500;text-transform:uppercase;font-size:.75rem;letter-spacing:.05em}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-weight:600;font-size:.8rem}
.kv{display:grid;grid-template-columns:auto 1fr;gap:.25rem 1rem;font-size:.85rem}
.kv dt{color:var(--muted)}
.kv dd{color:var(--text)}
code{font-family:'Fira Code','Consolas',monospace;font-size:.8rem;background:var(--bg);padding:.15rem .35rem;border-radius:3px}
.evidence-chip{display:inline-block;padding:.1rem .4rem;margin:.1rem;background:var(--bg);border-radius:3px;font-size:.75rem;font-family:monospace}
.finding{padding:.75rem 1rem;margin:.5rem 0;border-radius:8px;border-left:4px solid}
.finding-title{font-weight:600;font-size:.9rem}
.footer{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);font-size:.75rem;color:var(--muted);text-align:center}
</style>
</head>
<body>
<h1>TRACE Technical Report</h1>
<p style="color:var(--muted);margin-bottom:2rem">{{.Filename}} · Generated {{.Generated}}</p>

<h2>Input Summary</h2>
<div class="card">
<dl class="kv">
<dt>Format</dt><dd>{{.Result.Input.Format}}</dd>
<dt>Size</dt><dd>{{.Result.Input.Size}} bytes</dd>
<dt>SHA-256</dt><dd><code>{{.Result.Input.SHA256}}</code></dd>
<dt>Packets</dt><dd>{{.Result.Input.Stats.Seen}} seen, {{.Result.Input.Stats.IPsec}} IPsec</dd>
<dt>IKE SAs</dt><dd>{{len .Result.IKESAs}}</dd>
<dt>Child SA Pairs</dt><dd>{{.Result.ChildSAs}}</dd>
</dl>
</div>

{{if .Result.Assessment}}
<h2>Assessment Headline</h2>
<div class="card">
<dl class="kv">
<dt>Label</dt><dd><strong>{{.Result.Assessment.Headline.Label}}</strong></dd>
<dt>Score</dt><dd>{{printf "%.1f" .Result.Assessment.Headline.Score}}</dd>
<dt>Coverage</dt><dd>{{printf "%.1f%%" .Result.Assessment.Headline.Coverage}}</dd>
<dt>Confidence</dt><dd>{{printf "%.2f" .Result.Assessment.Headline.Confidence}}</dd>
<dt>Bounds</dt><dd>[{{printf "%.0f" .Result.Assessment.Headline.LowerBound}} – {{printf "%.0f" .Result.Assessment.Headline.UpperBound}}]</dd>
<dt>Risk</dt><dd><span style="color:{{riskColor .Result.Assessment.Headline.RiskLevel}};font-weight:700">{{.Result.Assessment.Headline.RiskLevel}}</span></dd>
</dl>
</div>

<h2>Controls</h2>
<div class="card">
<table>
<tr><th>ID</th><th>Control</th><th>Status</th><th>Severity</th><th>Weight</th><th>Explanation</th><th>Evidence</th></tr>
{{range .Result.Assessment.Controls}}
<tr>
<td><code>{{.ID}}</code></td>
<td>{{.Name}}</td>
<td><span style="color:{{statusColor .Status}};font-weight:600">{{statusIcon .Status}} {{.Status}}</span></td>
<td>{{if .Severity}}<span style="color:{{sevColor .Severity}}">{{.Severity}}</span>{{else}}—{{end}}</td>
<td>{{.Weight}}</td>
<td style="font-size:.8rem">{{.Explanation}}</td>
<td>{{range .EvidenceIDs}}<span class="evidence-chip">{{.}}</span>{{end}}</td>
</tr>
{{end}}
</table>
</div>

{{if .Result.Assessment.Findings}}
<h2>Findings</h2>
{{range .Result.Assessment.Findings}}
<div class="finding" style="border-color:{{sevColor .Severity}};background:var(--card)">
<div class="finding-title" style="color:{{sevColor .Severity}}">{{.ID}} · {{.Severity}} — {{.Title}}</div>
<p style="font-size:.8rem;color:var(--muted);margin-top:.25rem">{{.WhyMatters}}</p>
{{if .FixConfig}}<p style="margin-top:.25rem"><code>{{.FixConfig}}</code></p>{{end}}
{{if .EvidenceIDs}}<p style="font-size:.75rem;margin-top:.25rem">Evidence: {{range .EvidenceIDs}}<span class="evidence-chip">{{.}}</span>{{end}}</p>{{end}}
</div>
{{end}}
{{end}}

<h2>Threat Matrix</h2>
<div class="card">
<table>
<tr><th>Threat</th><th>Status</th><th>Likelihood</th><th>Impact</th><th>Controls</th><th>ATT&CK</th></tr>
{{range .Result.Assessment.Threats}}
<tr>
<td>{{.Name}}</td>
<td><span style="color:{{threatColor .Status}};font-weight:600">{{.Status}}</span></td>
<td>{{.Likelihood}}</td>
<td>{{.Impact}}</td>
<td>{{joinStrings .Controls}}</td>
<td>{{joinStrings .ATTACKIDs}}</td>
</tr>
{{end}}
</table>
</div>
{{end}}

<h2>Methodology and Limits</h2>
<div class="card" style="font-size:.85rem">
<p>TRACE analyses IPsec tunnel security from packet captures. It extracts cryptographic evidence from IKE negotiations and ESP/AH traffic, evaluates it against RFC 8221/8247 baselines, and produces graded findings.</p>
<p style="margin-top:.5rem"><strong>Limits:</strong> Without gateway configuration data, TRACE cannot observe child SA suites, PFS settings, replay windows, or lifetimes. Coverage reflects what can be evaluated. No decryption is performed.</p>
</div>

<div class="footer">
TRACE v{{.Result.Version}} · Policy: {{.Result.PolicyID}} · Schema: {{.Result.Schema}}<br>
SHA-256: {{.Result.Input.SHA256}}
</div>
</body>
</html>`))
