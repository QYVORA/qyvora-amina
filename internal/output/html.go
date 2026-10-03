package output

import (
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/QYVORA/qyvora-amina/internal/config"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// HTMLRenderer writes a single self-contained HTML document.
//
// Self-contained is the requirement, not a convenience: a security report gets
// emailed, archived and opened months later from a directory that no longer
// exists, and a report that renders blank without its stylesheet is a report
// nobody reads. So the stylesheet is inline and there are no external assets.
//
// Rendering goes through html/template, never string concatenation. Every string
// in this report originates on the assessed host — a package name, a hostname, a
// path, a git remote — and a host is exactly the thing an attacker controls. An
// attacker who can choose a package name can therefore choose what this document
// contains, and a report that is rendered by concatenation would let them inject
// script into the browser of whoever reads the assessment.
type HTMLRenderer struct {
	// Standalone emits the inline stylesheet. It is a field so the same
	// renderer can produce a fragment when a caller is embedding the report.
	Standalone bool
}

func (HTMLRenderer) Format() config.Format { return config.FormatHTML }

// htmlModel is the template's view of a report. Converting first means the
// template never handles a raw domain object, so a new field on Report cannot
// silently appear in the output.
type htmlModel struct {
	Report      *models.Report
	Host        string
	Standalone  bool
	Severities  []htmlSeverity
	Findings    []htmlFinding
	Limitations []string
	Identities  []htmlIdentity
	Secrets     []htmlSecret
	Modules     []htmlModule
	Sources     []htmlSource
	Config      [][2]string
}

type htmlSeverity struct {
	Name  string
	Count int
}

type htmlFinding struct {
	Finding     models.Finding
	Objects     []string
	MoreObjects int
	Description string
	Impact      string
	Recommend   string
	References  string
	Attributes  [][2]string
}

type htmlIdentity struct {
	Identity models.CorrelatedIdentity
	Domains  string
}

type htmlSecret struct {
	Record   models.SecretRecord
	Location string
}

type htmlModule struct {
	Status models.ModuleStatus
	Detail string
}

type htmlSource struct {
	Source models.PackageSource
}

// NewHTMLModel projects a report into the template's model.
func NewHTMLModel(rep *models.Report, standalone bool) htmlModel {
	m := htmlModel{Report: rep, Standalone: standalone, Host: hostLabel(rep)}
	for _, sev := range []models.Severity{
		models.SeverityCritical, models.SeverityHigh, models.SeverityMedium,
		models.SeverityLow, models.SeverityInformational,
	} {
		if n := rep.Summary.BySeverity[sev]; n > 0 {
			m.Severities = append(m.Severities, htmlSeverity{Name: severityLabel(sev), Count: n})
		}
	}
	for _, f := range rep.Findings {
		v := htmlFinding{Finding: f, Description: f.Description, Impact: f.Impact,
			Recommend: f.Recommendation}
		if len(f.Objects) > 8 {
			v.Objects = f.Objects[:8]
			v.MoreObjects = len(f.Objects) - 8
		} else {
			v.Objects = f.Objects
		}
		if len(f.References) > 0 {
			v.References = strings.Join(f.References, ", ")
		}
		// Attribute order is fixed; a map ranged directly would reshuffle the
		// document on every render.
		for _, k := range sortedKeys(f.Attributes) {
			v.Attributes = append(v.Attributes, [2]string{k, f.Attributes[k]})
		}
		m.Findings = append(m.Findings, v)
	}
	m.Limitations = rep.Limitations
	for _, id := range rep.Identities {
		m.Identities = append(m.Identities, htmlIdentity{Identity: id, Domains: strings.Join(id.Domains, ", ")})
	}
	for _, s := range rep.Secrets {
		loc := s.Location
		if s.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, s.Line)
		}
		m.Secrets = append(m.Secrets, htmlSecret{Record: s, Location: loc})
	}
	for _, mod := range rep.Modules {
		detail := mod.Reason
		if len(mod.Unavailable) > 0 {
			if detail != "" {
				detail += "; "
			}
			detail += "unavailable: " + strings.Join(mod.Unavailable, ", ")
		}
		m.Modules = append(m.Modules, htmlModule{Status: mod, Detail: detail})
	}
	m.Sources = append(m.Sources, htmlSource{Source: models.PackageSource{}})
	m.Sources = m.Sources[:0]
	for _, s := range rep.Sources {
		m.Sources = append(m.Sources, htmlSource{Source: s})
	}
	for _, k := range sortedKeys(rep.Configuration) {
		m.Config = append(m.Config, [2]string{k, rep.Configuration[k]})
	}
	return m
}

func (r HTMLRenderer) Write(w io.Writer, rep *models.Report) error {
	standalone := r.Standalone
	tmpl := htmlReportTemplate
	if !standalone {
		tmpl = htmlFragmentTemplate
	}
	// The named blocks must be parsed alongside the document that calls them.
	tmpl += htmlSubTemplates
	t, err := template.New("report").Funcs(templateFuncs).Parse(tmpl)
	if err != nil {
		return fmt.Errorf("parse html template: %w", err)
	}
	if err := t.Execute(w, NewHTMLModel(rep, standalone)); err != nil {
		return fmt.Errorf("write html report: %w", err)
	}
	return nil
}

var templateFuncs = template.FuncMap{
	"humanBytes": humanBytes,
	"time":       formatTime,
	"sevClass": func(s models.Severity) string {
		switch s {
		case models.SeverityCritical:
			return "sev-critical"
		case models.SeverityHigh:
			return "sev-high"
		case models.SeverityMedium:
			return "sev-medium"
		case models.SeverityLow:
			return "sev-low"
		}
		return "sev-info"
	},
	"statusClass": func(s models.ExposureLevel) string {
		switch s {
		case models.ExposureComplete:
			return "ok"
		case models.ExposurePartial, models.ExposureDegraded:
			return "warn"
		case models.ExposurePrivilege, models.ExposureSkipped:
			return "skip"
		}
		return "warn"
	},
}

const htmlStyles = `
:root{color-scheme:light dark;--fg:#1a1a1a;--muted:#666;--bg:#fff;--panel:#f6f7f9;--border:#d8dce2;
--crit:#b3261e;--high:#d1500f;--med:#a8760b;--low:#4a6fa5;--info:#666;--ok:#1f7a44}
@media (prefers-color-scheme:dark){:root{--fg:#e6e6e6;--muted:#9aa0a6;--bg:#14161a;--panel:#1c1f25;
--border:#2c313a;--crit:#f2777a;--high:#ff9e64;--med:#e2c08d;--low:#82aaff;--info:#9aa0a6;--ok:#6fcf97}}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1rem;font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
color:var(--fg);background:var(--bg)}
main{max-width:62rem;margin:0 auto}
h1{font-size:1.6rem;margin:0 0 .25rem}h2{font-size:1.15rem;margin:2rem 0 .75rem;padding-bottom:.3rem;
border-bottom:1px solid var(--border)}
h3{font-size:1rem;margin:1.25rem 0 .4rem}
.sub{color:var(--muted);margin:0 0 1.5rem;font-size:.9rem}
table{width:100%;border-collapse:collapse;margin:.5rem 0;font-size:.9rem}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.88em}
.cards{display:flex;flex-wrap:wrap;gap:.75rem;margin:1rem 0}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:.75rem 1rem;min-width:8rem}
.card .n{font-size:1.5rem;font-weight:600;line-height:1.2}
.card .k{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
.badge{display:inline-block;padding:.1rem .45rem;border-radius:4px;font-size:.75rem;font-weight:600;
color:#fff;background:var(--info)}
.sev-critical{background:var(--crit)}.sev-high{background:var(--high)}
.sev-medium{background:var(--med)}.sev-low{background:var(--low)}.sev-info{background:var(--info)}
.ok{color:var(--ok)}.warn{color:var(--med)}.skip{color:var(--muted)}
ul.compact{margin:.3rem 0;padding-left:1.2rem}
.note{background:var(--panel);border-left:3px solid var(--med);padding:.7rem 1rem;border-radius:0 6px 6px 0;
margin:1rem 0}
.note strong{color:var(--med)}
footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--muted);
font-size:.85rem}
details{margin:.5rem 0}
summary{cursor:pointer;color:var(--muted);font-size:.9rem}
`

// htmlReportTemplate is the standalone document.
const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Amina Assessment — {{.Host}}</title>
<style>{{stylesheet}}</style>
</head>
<body>
<main>
<h1>Amina Operational Security Assessment</h1>
<p class="sub">{{.Host}} · assessed {{time .Report.GeneratedAt}} · {{.Report.DepthName}} depth</p>
{{template "summary" .}}
{{template "limitations" .}}
{{template "identities" .}}
{{template "findings" .}}
{{template "secrets" .}}
{{template "sources" .}}
{{template "modules" .}}
{{template "footer" .}}
</main>
</body>
</html>
`

const htmlFragmentTemplate = `{{template "summary" .}}
{{template "limitations" .}}
{{template "identities" .}}
{{template "findings" .}}
{{template "secrets" .}}
{{template "sources" .}}
{{template "modules" .}}
`

const htmlSummaryTemplate = `{{define "summary"}}
<div class="cards">
  <div class="card"><div class="n">{{.Report.Summary.Total}}</div><div class="k">Findings</div></div>
  <div class="card"><div class="n">{{.Report.Summary.MaxRisk}}</div><div class="k">Highest risk</div></div>
  <div class="card"><div class="n">{{.Report.Summary.RiskBand}}</div><div class="k">Risk band</div></div>
  <div class="card"><div class="n">{{.Report.Summary.IdentityCount}}</div><div class="k">Identities</div></div>
</div>
{{if .Severities}}<table>
<tr><th>Severity</th><th>Count</th></tr>
{{range .Severities}}<tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>
{{end}}</table>{{end}}
{{end}}`

const htmlLimitationsTemplate = `{{define "limitations"}}
{{if .Limitations}}<h2>What this run did not see</h2>
<div class="note"><strong>A finding is only as good as the coverage behind it.</strong>
The following was not fully assessed:</div>
<ul class="compact">{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>
{{end}}
{{end}}`

const htmlIdentitiesTemplate = `{{define "identities"}}
{{if .Identities}}<h2>Correlated operator identities</h2>
<table><tr><th>Identity</th><th>Strength</th><th>Signals</th><th>Domains</th></tr>
{{range .Identities}}<tr><td class="mono">{{.Identity.Canonical}}</td><td>{{.Identity.Strength}}</td>
<td>{{.Identity.SignalCount}}</td><td>{{.Domains}}</td></tr>
{{end}}</table>{{end}}
{{end}}`

const htmlFindingsTemplate = `{{define "findings"}}
<h2>Findings</h2>
{{if not .Findings}}<p class="ok">No findings within the areas that were assessed.</p>{{end}}
{{range .Findings}}<section class="finding">
<h3><span class="badge {{sevClass .Finding.Severity}}">{{.Finding.Severity}}</span>
{{.Finding.Title}}</h3>
<table>
<tr><th>Rule</th><td class="mono">{{.Finding.RuleID}}</td>
    <th>Module</th><td class="mono">{{.Finding.ModuleID}}</td></tr>
<tr><th>Risk</th><td>{{.Finding.RiskScore}} ({{.Finding.RiskBand}})</td>
    <th>State</th><td>{{.Finding.State}}</td></tr>
<tr><th>Exposure</th><td>{{.Finding.Exposure}}</td>
    <th>Privilege</th><td>{{.Finding.Privilege}}</td></tr>
<tr><th>Confidence</th><td>{{.Finding.Confidence}}</td>
    <th>Sensitivity</th><td>{{.Finding.Sensitivity}}</td></tr>
</table>
{{if .Description}}<p>{{.Description}}</p>{{end}}
{{if .Objects}}<p><strong>Applies to</strong></p><ul class="compact">
{{range .Objects}}<li class="mono">{{.}}</li>{{end}}</ul>
{{if .MoreObjects}}<li>and {{.MoreObjects}} more</li>{{end}}{{end}}
{{if .Impact}}<p><strong>Impact.</strong> {{.Impact}}</p>{{end}}
{{if .Recommend}}<p><strong>Recommendation.</strong> {{.Recommend}}</p>{{end}}
{{if .References}}<p><strong>References.</strong> {{.References}}</p>{{end}}
{{if .Attributes}}<details><summary>Evidence attributes</summary><table>
{{range .Attributes}}<tr><th>{{index . 0}}</th><td class="mono">{{index . 1}}</td></tr>{{end}}
</table></details>{{end}}
</section>
{{end}}
{{end}}`

const htmlSecretsTemplate = `{{define "secrets"}}
{{if .Secrets}}<h2>Secret material on disk</h2>
<div class="note"><strong>No secret values are stored in this report.</strong>
Each is recorded as a salted fingerprint, its location and its length.</div>
<table><tr><th>Type</th><th>Location</th><th>Field</th><th>Fingerprint</th><th>Length</th></tr>
{{range .Secrets}}<tr><td>{{.Record.Type}}</td><td class="mono">{{.Location}}</td>
<td class="mono">{{.Record.Field}}</td><td class="mono">{{.Record.Fingerprint}}</td>
<td>{{.Record.Length}}</td></tr>
{{end}}</table>{{end}}
{{end}}`

const htmlSourcesTemplate = `{{define "sources"}}
{{if .Sources}}<h2>Package sources</h2>
<table><tr><th>Provider</th><th>URI</th><th>Trust</th><th>Keys</th><th>Enabled</th></tr>
{{range .Sources}}<tr><td>{{.Source.Provider}}</td><td class="mono">{{.Source.URI}}</td>
<td>{{.Source.Trust}}</td><td>{{.Source.Keys}}</td><td>{{.Source.Enabled}}</td></tr>
{{end}}</table>{{end}}
{{end}}`

const htmlModulesTemplate = `{{define "modules"}}
{{if .Modules}}<h2>Module coverage</h2>
<table><tr><th>Module</th><th>Status</th><th>Assets</th><th>Findings</th><th>Detail</th></tr>
{{range .Modules}}<tr><td>{{.Status.Name}}</td>
<td class="{{statusClass .Status.Status}}">{{.Status.Status}}</td>
<td>{{.Status.Assets}}</td><td>{{.Status.Findings}}</td><td>{{.Detail}}</td></tr>
{{end}}</table>{{end}}
{{end}}`

const htmlFooterTemplate = `{{define "footer"}}
<footer>
<p>Report <span class="mono">{{.Report.ID}}</span> · integrity <span class="mono">{{.Report.Integrity}}</span></p>
<p>Redaction: {{.Report.Redaction.Strategy}}. {{.Report.Redaction.Note}}</p>
<p>Generated by {{.Report.Framework}} {{.Report.FrameworkVersion}} on {{time .Report.GeneratedAt}}.</p>
{{if .Config}}<p>Configuration: {{range .Config}}{{index . 0}}={{index . 1}} {{end}}</p>{{end}}
</footer>
{{end}}`

// htmlSubTemplates holds every named block the documents reference. They are
// parsed together with the document because a template reference cannot resolve
// against a block that was never parsed.
var htmlSubTemplates = htmlSummaryTemplate + htmlLimitationsTemplate +
	htmlIdentitiesTemplate + htmlFindingsTemplate + htmlSecretsTemplate +
	htmlSourcesTemplate + htmlModulesTemplate + htmlFooterTemplate

// init registers the helper that supplies the inline stylesheet.
//
// The stylesheet is referenced from the standalone document only, so a fragment
// carries no styling and the caller supplies its own.
func init() {
	templateFuncs["stylesheet"] = func() string { return htmlStyles }
}
