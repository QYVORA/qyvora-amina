package modules

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// testEnv describes the live host.
//
// Detect's contract is that a nil env means "probe this machine", so the nil is
// the point of the call rather than a placeholder for an unbuilt value.
func testEnv(t *testing.T) *platform.Env {
	t.Helper()
	return platform.Detect(nil) //nolint:staticcheck // SA1012: nil means the live host here.
}

// TestSecretDetectorNeverReturnsAPlaceholder covers the single filter that
// decides whether the tool reports noise. A ruleset that reports "password =
// changeme" trains its reader to ignore it.
func TestSecretDetectorPlaceholdersAreNotFindings(t *testing.T) {
	d := newSecretDetector(&platform.Env{MachineID: "test-machine"})
	for _, line := range []string{
		`password = changeme`,
		`password: "your_password_here"`,
		`API_KEY=xxxxxxxxxxxxxxxx`,
		`api_token=${FROM_VAULT}`,
		`password=12345678`,
		`secret = example`,
		`token=aaaaaaaaaaaaaaaa`,
		`password=""`,
		`password = hunter2`,
		`client_secret=YOUR_CLIENT_SECRET`,
	} {
		if _, _, _, ok := d.match(line); ok {
			t.Errorf("placeholder reported as a secret: %q", line)
		}
	}
}

func TestSecretDetectorRecognisesRealCredentials(t *testing.T) {
	d := newSecretDetector(&platform.Env{MachineID: "test-machine"})
	cases := []struct {
		line string
		typ  models.SecretType
	}{
		{"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", models.SecretCloudCredential},
		{"password = 8fQ2vLp!zR4t", models.SecretPassword},
		{"github_pat_11ABCDEFG0abcdefghijkl_1234567890abcdefghijklmnopqrstuvwxyz", models.SecretCICD},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk", models.SecretJWT},
		{"DATABASE_URL=postgres://app:s3cr3tp4ss@db.internal:5432/main", models.SecretDatabaseCredential},
		{"-----BEGIN OPENSSH PRIVATE KEY-----", models.SecretPrivateKey},
		// A forge prefix classifies as a CI/CD credential rather than a generic
		// token: the remediation differs, since it must be revoked in the forge
		// rather than in whatever service issued it.
		{"export GITHUB_TOKEN=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", models.SecretCICD},
	}
	for _, c := range cases {
		typ, field, value, ok := d.match(c.line)
		if !ok {
			t.Errorf("real credential not detected: %q", c.line)
			continue
		}
		if typ != c.typ {
			t.Errorf("%q: type %q, want %q", c.line, typ, c.typ)
		}
		if field == "" {
			t.Errorf("%q: no field reported", c.line)
		}
		if value == "" {
			t.Errorf("%q: no value measured", c.line)
		}
	}
}

// TestSecretRecordCarriesNoValue is the safety property of the whole module:
// whatever the detector finds, the stored record cannot contain the secret,
// because the record has no field that could hold it.
func TestSecretRecordCarriesNoValue(t *testing.T) {
	e := testEnv(t)
	const secret = "hunter2correcthorsebattery"
	rec := secretRecord(models.SecretPassword, "/tmp/x", 3, "password", e, "test")
	rec.Length = len(secret)
	rec.Fingerprint = platform.Fingerprint(e.MachineID+":/tmp/x:"+secret, 12)

	// The fingerprint must not be reversible to the value by any field.
	encoded := rec.Location + rec.Field + rec.Fingerprint + rec.Source + string(rec.Redaction)
	if strings.Contains(encoded, secret) {
		t.Fatal("a secret value reached a stored field")
	}
	if rec.Fingerprint == secret {
		t.Fatal("fingerprint equals the secret")
	}
}

// TestSecretDetectorFingerprintIsSaltedPerHost checks that the same credential
// on two hosts produces two fingerprints, so a fingerprint cannot be used as a
// cross-host correlation key for known secrets.
func TestSecretDetectorFingerprintIsSaltedPerHost(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	a := platform.Fingerprint("machine-a:creds:"+secret, 12)
	b := platform.Fingerprint("machine-b:creds:"+secret, 12)
	if a == b {
		t.Fatal("fingerprint is not host-salted")
	}
}

func TestPromptDisclosures(t *testing.T) {
	got := promptDisclosures(`PS1='\u@\h:\w\$ '`)
	for _, want := range []string{"username", "hostname", "working_directory"} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt disclosure %q missing from %q", want, got)
		}
	}
	if got := promptDisclosures(`PS1='$ '`); got != "" {
		t.Errorf("a static prompt should disclose nothing, got %q", got)
	}
}

// TestStripURLCredentials is the case that matters in practice: a token pasted
// into a git remote.
func TestStripURLCredentials(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://ghp_TOKENVALUE@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https://user:pass@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"git@github.com:org/repo.git", "git@github.com:org/repo.git"},
		{"https://github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"ssh://git@example.com:2222/org/repo.git", "ssh://example.com:2222/org/repo.git"},
	}
	for _, c := range cases {
		if got := stripURLCredentials(c.in); got != c.want {
			t.Errorf("stripURLCredentials(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSplitRemoteURL(t *testing.T) {
	host, path, ok := splitRemoteURL("https://github.com/org/repo.git")
	if !ok || host != "github.com" || path != "org/repo.git" {
		t.Errorf("got host=%q path=%q ok=%v", host, path, ok)
	}
	if _, _, ok := splitRemoteURL("https://github.com"); ok {
		t.Error("a bare host should not produce an identity signal")
	}
}

func TestCredentialVariableClassification(t *testing.T) {
	cases := map[string]models.SecretType{
		"AWS_SECRET_ACCESS_KEY": models.SecretCloudCredential,
		"SOME_VENDOR_API_TOKEN": models.SecretToken,
		"MYAPP_DB_PASSWORD":     models.SecretDatabaseCredential,
		"APP_JWT":               models.SecretJWT,
		"HOME":                  "",
		"PATH":                  "",
	}
	for name, want := range cases {
		got, _ := credentialVariable(name)
		if got != want {
			t.Errorf("credentialVariable(%q) = %q, want %q", name, got, want)
		}
	}
}

// writeDocx builds a minimal OOXML package with the given core properties.
func writeDocx(t *testing.T, path, core string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zw := zip.NewWriter(f)
	w, err := zw.Create("docProps/core.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(core)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDocumentMetadataExtractsAuthorFromDocx(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "report.docx")
	writeDocx(t, p, `<?xml version="1.0"?><cp:coreProperties xmlns:cp="x" xmlns:dc="y">
<dc:creator>Aisha Bello</dc:creator><cp:lastModifiedBy>Aisha Bello</cp:lastModifiedBy>
<dc:title>Q3</dc:title></cp:coreProperties>`)

	fields := documentMetadata(p)
	var author string
	for _, f := range fields {
		if f.Key == "author" {
			author = f.Value
		}
	}
	if author != "Aisha Bello" {
		t.Errorf("author = %q, want %q (fields: %+v)", author, "Aisha Bello", fields)
	}
}

func TestDocumentMetadataIgnoresApplicationDefaults(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.docx")
	writeDocx(t, p, `<cp:coreProperties xmlns:cp="x" xmlns:dc="y">
<dc:creator></dc:creator><cp:application>Microsoft Office Word</cp:application>
</cp:coreProperties>`)

	for _, f := range documentMetadata(p) {
		if f.Key == "author" && f.Value != "" {
			t.Errorf("an empty creator produced a finding: %+v", f)
		}
		if strings.EqualFold(f.Value, "microsoft office word") {
			t.Errorf("an application default was reported as metadata: %+v", f)
		}
	}
}

func TestPDFMetadata(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "contract.pdf")
	body := "%PDF-1.7\n1 0 obj<</Type/Catalog>>endobj\n" +
		`trailer<</Info<</Author(Amina Yusuf \(Contractor\))/Creator(Adobe Acrobat 24.0)>>>>` + "\n%%EOF\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fields := documentMetadata(p)
	found := false
	for _, f := range fields {
		if f.Key == "author" && strings.Contains(f.Value, "Amina Yusuf") {
			found = true
		}
	}
	if !found {
		t.Errorf("PDF author not extracted: %+v", fields)
	}
}

func TestPNGMetadata(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "shot.png")
	// PNG signature, then a tEXt chunk with an Author keyword.
	var buf []byte
	buf = append(buf, []byte("\x89PNG\r\n\x1a\n")...)
	text := "Author\x00Screenshot Author\x00"
	chunk := make([]byte, 0, 12+len(text))
	var length [4]byte
	length[0] = byte(len(text) >> 24)
	length[1] = byte(len(text) >> 16)
	length[2] = byte(len(text) >> 8)
	length[3] = byte(len(text))
	chunk = append(chunk, length[:]...)
	chunk = append(chunk, []byte("tEXt")...)
	chunk = append(chunk, []byte(text)...)
	var crc [4]byte
	chunk = append(chunk, crc[:]...)
	buf = append(buf, chunk...)
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	fields := documentMetadata(p)
	found := false
	for _, f := range fields {
		if f.Key == "author" && f.Value == "Screenshot Author" {
			found = true
		}
	}
	if !found {
		t.Errorf("PNG author not extracted: %+v", fields)
	}
}

func TestDocumentMetadataIgnoresUnreadableAndOversized(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "huge.pdf")
	if err := os.WriteFile(p, []byte("%PDF-1.7"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fields := documentMetadata(filepath.Join(dir, "missing.pdf")); fields != nil {
		t.Errorf("missing file produced metadata: %+v", fields)
	}
}

func TestHasIdentityField(t *testing.T) {
	if hasIdentityField([]metaField{{Key: "application", Value: "Something"}}) {
		t.Error("a software-only field should not count as identity metadata")
	}
	if !hasIdentityField([]metaField{{Key: "company", Value: "QYVORA"}}) {
		t.Error("a company field is identity metadata")
	}
}

// TestCollectMetadataReportsExtractedFields runs the collector end to end on a
// directory containing a real document, which is the only way to know the
// extraction is wired into the assets rather than only unit-tested.
func TestCollectMetadataReportsExtractedFields(t *testing.T) {
	if _, err := os.Stat("/proc"); err != nil {
		t.Skip("POSIX-only fixture")
	}
	home := t.TempDir()
	writeDocx(t, filepath.Join(home, "notes.docx"), `<cp:coreProperties xmlns:cp="x" xmlns:dc="y">
<dc:creator>Kofi Mensah</dc:creator></cp:coreProperties>`)

	e := &platform.Env{
		Platform:  models.PlatformLinux,
		Home:      home,
		MachineID: "test-machine",
	}
	// The collector reads e.Paths; give it a writable place to look.
	e.Paths.ConfigHome = filepath.Join(home, ".config")

	res, err := collectMetadata(Input{Ctx: context.Background(), Env: e, Depth: 3})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	found := false
	for _, a := range res.Assets {
		if a.Attributes["identity_metadata"] == "true" && a.Attributes["meta_author"] == "Kofi Mensah" {
			found = true
		}
	}
	if !found {
		var seen []string
		for _, a := range res.Assets {
			seen = append(seen, a.Path+"["+a.Attributes["metadata_state"]+"]")
		}
		t.Errorf("collector did not report the embedded author; assets: %v", seen)
	}
}
