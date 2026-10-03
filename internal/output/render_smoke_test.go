package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

func smokeReport() *models.Report {
	r := models.NewReport(models.Target{ID: "t1", Name: "workstation", Type: models.TargetHost}, 2, "standard")
	r.GeneratedAt = time.Unix(1700000000, 0).UTC()
	r.FrameworkVersion = "0.1.0"
	r.Configuration = map[string]string{"depth": "standard", "format": "terminal"}
	r.Findings = []models.Finding{{
		ID: "f1", RuleID: "NET-001", ModuleID: "network",
		Title:    `Public <script>alert(1)</script> listener on 0.0.0.0:22`,
		Category: models.CategoryNetwork, Severity: models.SeverityHigh,
		State: models.StateObserved, Confidence: models.ConfidenceObserved,
		Exposure: models.ScopePublic, Privilege: models.PrivUser,
		Sensitivity:    models.SensitivitySensitive,
		Description:    "A service binds to every interface. Pipes | and #hash and `ticks` appear.",
		Recommendation: "Bind to loopback or a specific interface.",
		Objects:        []string{"0.0.0.0:22", "/etc/ssh/sshd_config"},
		Attributes:     map[string]string{"risk_score": "72.5", "risk_band": "high", "b": "2", "a": "1"},
	}}
	r.Modules = []models.ModuleStatus{
		{ID: "network", Name: "Network Exposure", Status: models.ExposureComplete, Assets: 4, Findings: 1},
		{ID: "metadata", Name: "Metadata Exposure", Status: models.ExposureSkipped, Reason: "requires depth 3"},
	}
	r.Secrets = []models.SecretRecord{{
		Type: models.SecretToken, Location: "/home/u/.aws/credentials", Line: 3,
		Field: "aws_secret_access_key", Fingerprint: "abc123def456", Length: 40,
	}}
	r.Identities = []models.CorrelatedIdentity{{
		ID: "id-1", Canonical: "aisha@corp", Strength: 80, SignalCount: 4, Domains: []string{"git", "aws"},
	}}
	r.Sources = []models.PackageSource{{ID: "s1", Provider: "apt", URI: "http://deb.debian.org/debian", Trust: "official", Keys: 2, Enabled: true}}
	r.Finalize()
	r.Limitations = models.Limitations(r.Modules)
	return &r
}

func TestAllFormatsRender(t *testing.T) {
	for _, f := range []string{"terminal", "json", "yaml", "markdown", "html"} {
		var buf bytes.Buffer
		if err := Render(&buf, smokeReport(), mustFormat(f), false); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if buf.Len() == 0 {
			t.Errorf("%s: empty output", f)
		}
		if strings.Contains(buf.String(), "\x1b[") {
			t.Errorf("%s: emitted ANSI sequences with colour disabled", f)
		}
		t.Logf("%s -> %d bytes", f, buf.Len())
	}
}

func TestHTMLEscapesHostControlledStrings(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, smokeReport(), mustFormat("html"), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("HTML output contains an unescaped script tag from a finding title")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected the title to appear escaped")
	}
}

func TestJSONAndYAMLAgreeOnFields(t *testing.T) {
	var j, y bytes.Buffer
	rep := smokeReport()
	if err := Render(&j, rep, mustFormat("json"), false); err != nil {
		t.Fatal(err)
	}
	if err := Render(&y, rep, mustFormat("yaml"), false); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema", "integrity", "findings", "limitations", "redaction"} {
		if !strings.Contains(j.String(), `"`+key+`"`) {
			t.Errorf("json missing %q", key)
		}
		if !strings.Contains(y.String(), key+":") {
			t.Errorf("yaml missing %q", key)
		}
	}
}

func TestTerminalHonoursNoColor(t *testing.T) {
	var buf bytes.Buffer
	r := TerminalRenderer{Color: false}
	if err := r.Write(&buf, smokeReport()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Error("terminal output contains ANSI sequences when colour is disabled")
	}
	var colour bytes.Buffer
	rc := TerminalRenderer{Color: true}
	if err := rc.Write(&colour, smokeReport()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(colour.String(), "\x1b[") {
		t.Error("terminal output has no ANSI sequences when colour is enabled")
	}
}

func TestRenderRejectsUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, smokeReport(), "pdf", false); err == nil {
		t.Error("an unknown format must be an error, not a silent fallback")
	}
}
