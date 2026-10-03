package correlation

import (
	"math/rand"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

func sig(typ, value, source, domain string) models.IdentitySignal {
	return models.IdentitySignal{
		Type:   typ,
		Value:  value,
		Source: source,
		Domain: domain,
		Module: "test",
		At:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// TestSpecWorkedExample is the example the specification gives for correlation:
// six unrelated observations of one operator, which must resolve to one
// identity rather than six findings.
func TestSpecWorkedExample(t *testing.T) {
	signals := []models.IdentitySignal{
		sig(TypeUsername, "wsuits6", "/etc/passwd", "accounts"),
		sig(TypeHostname, "wsuits6-workstation", "uname -n", "network"),
		sig(TypeHome, "/home/wsuits6", "getent passwd", "accounts"),
		sig(TypeEmail, "wsuits6@example.com", "git config user.email", "development"),
		sig(TypeKeyComment, "wsuits6@example.com", "~/.ssh/id_ed25519", "secrets"),
		sig(TypeRemote, "github.com/acmecorp/wsuits6-notes", "git remote -v", "development"),
	}

	res := Correlate(signals, Options{})
	if len(res.Identities) != 1 {
		for _, id := range res.Identities {
			t.Logf("group: canonical=%s strength=%d signals=%d", id.Canonical, id.Strength, id.SignalCount)
		}
		t.Fatalf("six observations of one operator produced %d identities, want 1", len(res.Identities))
	}

	got := res.Identities[0]
	if got.Canonical != "wsuits6" {
		t.Errorf("canonical = %q, want the username %q", got.Canonical, "wsuits6")
	}
	if got.SignalCount != 6 {
		t.Errorf("SignalCount = %d, want 6", got.SignalCount)
	}
	if got.Strength < 60 {
		t.Errorf("strength = %d; six corroborated signals should score well above a single observation", got.Strength)
	}
	if got.ID == "" {
		t.Error("identity has no ID")
	}
	if len(got.Signals) != 6 {
		t.Errorf("identity carries %d signals, want 6", len(got.Signals))
	}
	if len(got.Domains) != 4 {
		t.Errorf("identity spans domains %v, want 4 domains", got.Domains)
	}
	if got.Summary == "" {
		t.Error("identity has no summary")
	}
}

// TestGenericEmailIsNotMergedIntoAnIdentity documents the deliberate limit on
// correlation. The specification's illustrative example pairs a username with a
// git email whose local part is the word "user"; a tool that reported those as
// the same operator would be guessing. The honest behaviour is to keep them
// apart and let the weaker evidence stand on its own.
func TestGenericEmailIsNotMergedIntoAnIdentity(t *testing.T) {
	signals := []models.IdentitySignal{
		sig(TypeUsername, "wsuits6", "/etc/passwd", "accounts"),
		sig(TypeHostname, "wsuits6-workstation", "uname -n", "network"),
		sig(TypeEmail, "user@example.com", "git config user.email", "development"),
	}

	res := Correlate(signals, Options{})
	var merged bool
	for _, id := range res.Identities {
		if id.SignalCount == 3 {
			merged = true
		}
	}
	if merged {
		t.Error("an email whose local part is a generic word was merged into a named identity; that is a fabricated link")
	}
	if res.Unlinked != 0 {
		t.Errorf("Unlinked = %d, want 0; the email is a resolved singleton, not an unresolvable signal", res.Unlinked)
	}
}

func TestDistinctOperatorsAreNeverMerged(t *testing.T) {
	signals := []models.IdentitySignal{
		sig(TypeUsername, "wsuits6", "/etc/passwd", "accounts"),
		sig(TypeHostname, "wsuits6-workstation", "uname -n", "network"),
		sig(TypeHome, "/home/wsuits6", "getent passwd", "accounts"),
		sig(TypeUsername, "aisha", "/etc/passwd", "accounts"),
		sig(TypeHome, "/home/aisha", "getent passwd", "accounts"),
		sig(TypeHostname, "aisha-thinkpad", "uname -n", "network"),
	}

	res := Correlate(signals, Options{})
	if len(res.Identities) != 2 {
		for _, id := range res.Identities {
			t.Logf("group: canonical=%s signals=%d", id.Canonical, id.SignalCount)
		}
		t.Fatalf("two operators produced %d identities, want 2", len(res.Identities))
	}
	if res.Identities[0].Strength != res.Identities[1].Strength {
		t.Errorf("identical evidence produced different strengths: %d and %d",
			res.Identities[0].Strength, res.Identities[1].Strength)
	}
}

// TestUsernameAndOrganisationSharingAWordDoNotMerge guards the namespace split:
// an account called "acme" and an organisation called "acme" are not one thing.
func TestUsernameAndOrganisationSharingAWordDoNotMerge(t *testing.T) {
	signals := []models.IdentitySignal{
		sig(TypeUsername, "acme", "/etc/passwd", "accounts"),
		sig(TypeOrg, "acme", "cloud identity", "cloud"),
	}
	res := Correlate(signals, Options{})
	if len(res.Identities) != 1 {
		t.Fatalf("a username and an organisation sharing a word were merged into %d identity(ies)", len(res.Identities))
	}
	if res.Identities[0].SignalCount != 1 {
		t.Errorf("the organisation was attributed to the account; an organisation is not a person")
	}
	if res.Unlinked != 1 {
		t.Errorf("Unlinked = %d, want 1: the organisation should be recorded as observed but unattributed", res.Unlinked)
	}
}

// TestSharedMailDomainDoesNotFuseColleagues is the failure mode that a naive
// implementation falls into: the mail domain is a property of the employer, not
// of the person, so treating it as identifying merges a whole team into one
// identity.
func TestSharedMailDomainDoesNotFuseColleagues(t *testing.T) {
	var signals []models.IdentitySignal
	for _, n := range []string{"wsuits6", "aisha", "amina"} {
		signals = append(signals,
			sig(TypeUsername, n, "/etc/passwd", "accounts"),
			sig(TypeEmail, n+"@example.com", "git config", "development"),
		)
	}
	res := Correlate(signals, Options{})
	if len(res.Identities) != 3 {
		for _, id := range res.Identities {
			t.Logf("group: canonical=%s signals=%d", id.Canonical, id.SignalCount)
		}
		t.Fatalf("three colleagues at one mail domain collapsed into %d identities", len(res.Identities))
	}
	for _, id := range res.Identities {
		if id.SignalCount != 2 {
			t.Errorf("identity %q has %d signals, want its own username and email only", id.Canonical, id.SignalCount)
		}
	}
}

// TestGenericRemoteIsObservedButNotAttributed keeps the spec's literal remote
// honest: "github.com/organization/private-project" names nothing that
// identifies a person, so it is recorded rather than merged.
func TestGenericRemoteIsObservedButNotAttributed(t *testing.T) {
	res := Correlate([]models.IdentitySignal{
		sig(TypeUsername, "wsuits6", "/etc/passwd", "accounts"),
		sig(TypeRemote, "github.com/organization/private-project", "git remote", "development"),
	}, Options{})
	if len(res.Identities) != 1 {
		t.Fatalf("%d identities, want 1", len(res.Identities))
	}
	if res.Identities[0].SignalCount != 1 {
		t.Errorf("a fully generic remote was attributed to the operator")
	}
	if res.Unlinked != 1 {
		t.Errorf("Unlinked = %d, want 1", res.Unlinked)
	}
}

func TestRoleWordsDoNotMergeUnrelatedOperators(t *testing.T) {
	// Both tokens in each hostname are generic, so neither signal carries
	// identifying information and neither may bridge anything.
	signals := []models.IdentitySignal{
		sig(TypeHostname, "prod-server", "uname -n", "network"),
		sig(TypeHostname, "test-webserver", "uname -n", "network"),
		sig(TypeUsername, "prod", "/etc/passwd", "accounts"),
	}
	res := Correlate(signals, Options{})
	if len(res.Identities) != 0 {
		for _, id := range res.Identities {
			t.Errorf("generic-only signal produced an identity: %q (signals %v)", id.Canonical, id.Signals)
		}
	}
	if res.Unlinked != 3 {
		t.Errorf("Unlinked = %d, want 3", res.Unlinked)
	}
}

// TestOrderIndependence is the property the whole deterministic-output contract
// rests on: the collectors run concurrently, so signals arrive in whatever order
// the scheduler produced.
func TestOrderIndependence(t *testing.T) {
	base := []models.IdentitySignal{
		sig(TypeUsername, "wsuits6", "/etc/passwd", "accounts"),
		sig(TypeHostname, "wsuits6-workstation", "uname -n", "network"),
		sig(TypeHome, "/home/wsuits6", "getent passwd", "accounts"),
		sig(TypeEmail, "wsuits6@example.com", "git config", "development"),
		sig(TypeUsername, "aisha", "/etc/passwd", "accounts"),
		sig(TypeHostname, "aisha-thinkpad", "uname -n", "network"),
		sig(TypeRemote, "github.com/acmecorp/private-project", "git remote", "development"),
		sig(TypeOrg, "acmecorp", "cloud identity", "cloud"),
	}

	want := Correlate(base, Options{}).Identities
	if len(want) == 0 {
		t.Fatal("baseline produced no identities")
	}

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		shuffled := append([]models.IdentitySignal(nil), base...)
		rng.Shuffle(len(shuffled), func(a, b int) {
			shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
		})

		got := Correlate(shuffled, Options{}).Identities
		if len(got) != len(want) {
			t.Fatalf("shuffle %d produced %d identities, want %d", i, len(got), len(want))
		}
		for j := range got {
			if got[j].ID != want[j].ID || got[j].Canonical != want[j].Canonical || got[j].Strength != want[j].Strength {
				t.Fatalf("shuffle %d identity %d = %+v, want %s/%s/%d",
					i, j, got[j], want[j].ID, want[j].Canonical, want[j].Strength)
			}
		}
	}
}

// TestStrengthRewardsBreadthNotVolume stops the engine from degenerating into a
// duplicate counter: one name seen six times is weaker evidence than six
// different kinds of observation of one name.
func TestStrengthRewardsBreadthNotVolume(t *testing.T) {
	repeated := []models.IdentitySignal{
		sig(TypeUsername, "wsuits6", "/etc/passwd", "accounts"),
		sig(TypeUsername, "wsuits6", "id -un", "process"),
		sig(TypeUsername, "wsuits6", "loginctl", "accounts"),
		sig(TypeUsername, "wsuits6", "whoami", "process"),
		sig(TypeUsername, "wsuits6", "getent passwd", "accounts"),
		sig(TypeUsername, "wsuits6", "ps -o user", "process"),
	}

	broad := []models.IdentitySignal{
		sig(TypeUsername, "wsuits6", "/etc/passwd", "accounts"),
		sig(TypeHostname, "wsuits6-workstation", "uname -n", "network"),
		sig(TypeHome, "/home/wsuits6", "getent passwd", "accounts"),
		sig(TypeEmail, "wsuits6@example.com", "git config", "development"),
		sig(TypeKeyComment, "wsuits6@example.com", "ssh key", "secrets"),
		sig(TypeRemote, "github.com/acmecorp/wsuits6-amina", "git remote", "development"),
	}

	gotRepeated := Correlate(repeated, Options{}).Identities
	gotBroad := Correlate(broad, Options{}).Identities
	if len(gotRepeated) != 1 || len(gotBroad) != 1 {
		t.Fatalf("unexpected group counts: %d and %d", len(gotRepeated), len(gotBroad))
	}
	if gotBroad[0].Strength <= gotRepeated[0].Strength {
		t.Errorf("breadth (%d) did not beat repetition (%d); the engine is counting duplicates",
			gotBroad[0].Strength, gotRepeated[0].Strength)
	}
	if gotRepeated[0].SignalCount != gotBroad[0].SignalCount {
		t.Errorf("test is not comparing like for like: %d vs %d signals",
			gotRepeated[0].SignalCount, gotBroad[0].SignalCount)
	}
}

func TestRedactedSignalsAreExcludedAndCounted(t *testing.T) {
	signals := []models.IdentitySignal{
		sig(TypeUsername, "wsuits6", "/etc/passwd", "accounts"),
		{Type: TypeEmail, Value: "[redacted]", Source: "env", Domain: "process", Redacted: true},
		{Type: TypeKeyComment, Value: "[redacted]", Source: "ssh", Domain: "secrets", Redacted: true},
	}

	res := Correlate(signals, Options{})
	if res.Redacted != 2 {
		t.Errorf("Redacted = %d, want 2", res.Redacted)
	}
	if len(res.Identities) != 1 {
		t.Fatalf("%d identities, want 1", len(res.Identities))
	}
	if res.Identities[0].SignalCount != 1 {
		t.Errorf("redacted signals were correlated into an identity (%d signals)", res.Identities[0].SignalCount)
	}
}

func TestTwoRedactedSignalsDoNotMergeIntoOneIdentity(t *testing.T) {
	// Both placeholders share the literal string "[redacted]"; correlating on
	// them would invent an operator who does not exist.
	signals := []models.IdentitySignal{
		{Type: TypeEmail, Value: "[redacted]", Source: "env", Domain: "process", Redacted: true},
		{Type: TypeKeyComment, Value: "[redacted]", Source: "ssh", Domain: "secrets", Redacted: true},
	}
	res := Correlate(signals, Options{})
	if len(res.Identities) != 0 {
		t.Errorf("redacted placeholders produced %d identities", len(res.Identities))
	}
}

func TestCanonicalPreferenceOrder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		signals []models.IdentitySignal
		want    string
	}{
		{
			name: "username beats hostname",
			signals: []models.IdentitySignal{
				sig(TypeHostname, "wsuits6-workstation", "uname -n", "network"),
				sig(TypeUsername, "wsuits6", "/etc/passwd", "accounts"),
			},
			want: "wsuits6",
		},
		{
			name: "home beats email",
			signals: []models.IdentitySignal{
				sig(TypeEmail, "wsuits6@example.com", "git config", "development"),
				sig(TypeHome, "/home/wsuits6", "getent passwd", "accounts"),
			},
			want: "/home/wsuits6",
		},
		{
			name: "email beats key comment",
			signals: []models.IdentitySignal{
				sig(TypeKeyComment, "wsuits6@example.com", "ssh key", "secrets"),
				sig(TypeEmail, "wsuits6@example.com", "git config", "development"),
			},
			want: "wsuits6@example.com",
		},
		{
			name: "hostname used when it is all there is",
			signals: []models.IdentitySignal{
				sig(TypeHostname, "wsuits6-workstation", "uname -n", "network"),
			},
			want: "wsuits6-workstation",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := Correlate(tc.signals, Options{})
			if len(res.Identities) != 1 {
				t.Fatalf("%d identities, want 1", len(res.Identities))
			}
			if res.Identities[0].Canonical != tc.want {
				t.Errorf("canonical = %q, want %q", res.Identities[0].Canonical, tc.want)
			}
		})
	}
}

func TestIdentityIDIsStableAcrossRuns(t *testing.T) {
	signals := []models.IdentitySignal{
		sig(TypeUsername, "wsuits6", "/etc/passwd", "accounts"),
		sig(TypeHostname, "wsuits6-workstation", "uname -n", "network"),
	}
	first := Correlate(signals, Options{}).Identities[0].ID
	for i := 0; i < 20; i++ {
		if got := Correlate(signals, Options{}).Identities[0].ID; got != first {
			t.Fatalf("identity ID changed between runs: %q then %q", first, got)
		}
	}
	if len(first) != len("ident-")+12 {
		t.Errorf("identity ID %q has an unexpected shape", first)
	}
}

func TestMinimumStrengthSuppressesWeakGroups(t *testing.T) {
	signals := []models.IdentitySignal{
		sig(TypeUsername, "wsuits6", "/etc/passwd", "accounts"),
		sig(TypeHostname, "wsuits6-workstation", "uname -n", "network"),
		sig(TypeHome, "/home/wsuits6", "getent passwd", "accounts"),
		sig(TypeEmail, "wsuits6@example.com", "git config", "development"),
	}

	all := Correlate(signals, Options{}).Identities
	if len(all) != 1 {
		t.Fatalf("%d identities, want 1", len(all))
	}
	if got := Correlate(signals, Options{MinimumStrength: all[0].Strength + 1}).Identities; len(got) != 0 {
		t.Errorf("MinimumStrength did not suppress the group: %d identities survived", len(got))
	}
	if got := Correlate(signals, Options{MinimumStrength: all[0].Strength}).Identities; len(got) != 1 {
		t.Errorf("a group exactly at MinimumStrength was suppressed")
	}
}

func TestMaxGroupsBoundsOutputAndKeepsTheStrongest(t *testing.T) {
	var signals []models.IdentitySignal
	for _, n := range []string{"wsuits6", "aisha", "amina", "zainab", "kemi", "folake", "bisi", "tunde"} {
		signals = append(signals,
			sig(TypeUsername, n, "/etc/passwd", "accounts"),
			sig(TypeHostname, n+"-workstation", "uname -n", "network"),
			sig(TypeHome, "/home/"+n, "getent passwd", "accounts"),
			sig(TypeEmail, n+"@example.com", "git config", "development"),
		)
	}
	all := Correlate(signals, Options{})
	if len(all.Identities) != 8 {
		t.Fatalf("%d identities, want 8", len(all.Identities))
	}
	capped := Correlate(signals, Options{MaxGroups: 3})
	if len(capped.Identities) != 3 {
		t.Fatalf("MaxGroups=3 returned %d identities", len(capped.Identities))
	}
	// Ties here are broken on canonical value, so the cap keeps a stable subset.
	if capped.Identities[0].Canonical != all.Identities[0].Canonical {
		t.Errorf("capped output does not start with the strongest identity")
	}
}

func TestEmptyAndBlankInput(t *testing.T) {
	res := Correlate(nil, Options{})
	if len(res.Identities) != 0 || res.Unlinked != 0 || res.Redacted != 0 {
		t.Errorf("nil input produced %+v", res)
	}
	res = Correlate([]models.IdentitySignal{{Type: TypeUsername, Value: "  "}}, Options{})
	if res.Unlinked != 1 {
		t.Errorf("blank value produced Unlinked=%d, want 1", res.Unlinked)
	}
}

func TestUnknownSignalTypeIsCountedUnlinked(t *testing.T) {
	res := Correlate([]models.IdentitySignal{
		sig("quantum_flux", "whatever", "sensor", "environment"),
	}, Options{})
	if res.Unlinked != 1 {
		t.Errorf("Unlinked = %d, want 1 for a signal type the resolver does not know", res.Unlinked)
	}
	if len(res.Identities) != 0 {
		t.Error("an unknown signal type produced an identity")
	}
}

func TestTimestampDefaultIsNotWallClock(t *testing.T) {
	// Correlation runs inside a reproducible pipeline, so a wall-clock default
	// would make otherwise identical runs differ.
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	res := Correlate([]models.IdentitySignal{
		{Type: TypeUsername, Value: "wsuits6", Source: "/etc/passwd", Domain: "accounts"},
	}, Options{At: fixed})
	if res.Identities[0].Signals[0].At != fixed {
		t.Errorf("signal timestamp = %v, want the injected %v", res.Identities[0].Signals[0].At, fixed)
	}
}

func TestNoGroupContainsSignalsThatShareNoEvidence(t *testing.T) {
	// The engine's central promise: every group is justified by a shared token.
	signals := []models.IdentitySignal{
		sig(TypeUsername, "wsuits6", "/etc/passwd", "accounts"),
		sig(TypeUsername, "aisha", "/etc/passwd", "accounts"),
		sig(TypeUsername, "kemi", "/etc/passwd", "accounts"),
		sig(TypeHostname, "zainab-laptop", "uname -n", "network"),
		sig(TypeEmail, "folake@example.com", "git config", "development"),
	}
	res := Correlate(signals, Options{})

	seen := map[string]bool{}
	for _, id := range res.Identities {
		for _, s := range id.Signals {
			key := s.Type + "|" + s.Value + "|" + s.Source
			if seen[key] {
				t.Errorf("signal %q appears in two identities", key)
			}
			seen[key] = true
		}
		if id.SignalCount != len(id.Signals) {
			t.Errorf("identity %s claims %d signals but carries %d", id.ID, id.SignalCount, len(id.Signals))
		}
	}
	if len(res.Identities) != 5 {
		t.Errorf("%d identities from 5 unrelated signals, want 5 singletons", len(res.Identities))
	}
}

func TestPublicSuffixesDoNotBecomeIdentities(t *testing.T) {
	res := Correlate([]models.IdentitySignal{
		sig(TypeRemote, "github.com/org/repo", "git remote", "development"),
		sig(TypeRemote, "gitlab.com/org/other", "git remote", "development"),
	}, Options{})
	for _, id := range res.Identities {
		if id.Canonical == "github.com" || id.Canonical == "gitlab.com" || id.Canonical == "com" {
			t.Errorf("public suffix became an identity: %q", id.Canonical)
		}
	}
}
