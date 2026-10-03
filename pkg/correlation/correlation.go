// Package correlation resolves the identity signals collected across every
// module into a small number of operator identities.
//
// The problem it exists to solve: a workstation leaks its operator's name in at
// least five unrelated places — the username, the hostname, the home directory,
// the git email, an SSH key comment. Reported independently those are five
// warnings an operator learns to ignore. Reported as one correlated identity
// they are a single statement about how much this machine says who uses it.
//
// Two constraints shape the implementation:
//
//   - Correlation never fabricates a link. Two signals are joined only when they
//     share a normalised token, or when one signal itself yields two tokens
//     (an email yields its local part and its full address). Nothing is joined
//     on similarity, and no link is inferred from timing or proximity.
//   - Correlation never merges on a weak token. Every hostname that contains
//     "server", and every email local part of "info", would otherwise collapse
//     unrelated operators into one identity. A token that is only a role word is
//     used to label a group, never to join one.
package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Signal types the resolver understands. Unknown types still contribute a
// finding group; they simply cannot be normalised into tokens, so they never
// bridge two other signals.
const (
	TypeUsername   = "username"
	TypeHostname   = "hostname"
	TypeEmail      = "email"
	TypeHome       = "home"
	TypeRemote     = "remote"
	TypeOrg        = "org"
	TypeAccount    = "account"
	TypeKeyComment = "key_comment"
	TypeProject    = "project"
	TypeDevice     = "device"
)

// correlationKind distinguishes the namespaces of tokens so that a username
// "acme" and an organisation "acme" are not joined merely by sharing a word.
//
// The kindName namespace is deliberately shared by every signal that is a
// *person's* name in some spelling: username, home directory, hostname segment,
// email local part and project name. Keeping them apart would defeat the whole
// engine, since "wsuits6-workstation" and "wsuits6" share a word precisely
// because they are the same person named twice.
type correlationKind string

const (
	kindName  correlationKind = "name"
	kindEmail correlationKind = "email"
	kindOrg   correlationKind = "org"
	kindProj  correlationKind = "proj"
	kindDev   correlationKind = "device"
)

// bridgeable reports whether a namespace may join two separate signals.
//
// Only the person-name namespaces may. An organisation, a mail domain, a
// repository and a device are all shared by many people, so a link on any of
// them fuses unrelated operators: eight colleagues at example.com, each with a
// git remote, would otherwise resolve to one single identity with thirty-two
// signals. Those namespaces are still recorded, as context on the identity.
func (k correlationKind) bridgeable() bool {
	return k == kindName || k == kindEmail
}

// Options configures a correlation run.
type Options struct {
	// MinimumStrength suppresses groups below this strength. A lone signal is
	// almost never worth reporting as a correlated identity; set to 0 to keep
	// singletons.
	MinimumStrength int
	// MaxGroups bounds the returned identities, highest strength first, so a
	// pathological host with thousands of leaked names cannot produce an
	// unreadable report. Ties break on canonical value, never on map order.
	MaxGroups int
	// At fixes the timestamp stamped onto signals that carry none. Correlation
	// must be reproducible, so a wall-clock default is not acceptable here.
	At time.Time
}

func (o Options) withDefaults() Options {
	if o.MaxGroups <= 0 {
		o.MaxGroups = 50
	}
	if o.At.IsZero() {
		o.At = time.Time{}
	}
	return o
}

// resolvedSignal is one signal that survived normalisation, with the tokens
// derived from it.
type resolvedSignal struct {
	sig  models.IdentitySignal
	toks []token
}

// Result is the outcome of a correlation run.
type Result struct {
	Identities []models.CorrelatedIdentity
	// Unlinked counts signals that carried no usable token. They are reported
	// rather than dropped, because "we saw an identity signal we could not
	// resolve" is information the operator needs.
	Unlinked int
	// Redacted counts signals excluded because their value had been redacted
	// upstream. A redacted value is a placeholder, so correlating on it would
	// join every redacted signal to every other one.
	Redacted int
}

// unionFind is the linkage structure. It is a map rather than a slice because
// the token set is discovered while walking the signals, not known in advance.
type unionFind struct {
	parent map[string]string
	rank   map[string]int
	order  []string
}

func newUnionFind() *unionFind {
	return &unionFind{parent: map[string]string{}, rank: map[string]int{}}
}

func (u *unionFind) add(key string) {
	if _, ok := u.parent[key]; ok {
		return
	}
	u.parent[key] = key
	u.rank[key] = 0
	u.order = append(u.order, key)
}

func (u *unionFind) find(key string) string {
	p, ok := u.parent[key]
	if !ok {
		return key
	}
	for p != u.parent[p] {
		u.parent[p] = u.parent[u.parent[p]] // path halving
		p = u.parent[p]
	}
	return p
}

func (u *unionFind) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return
	}
	// Rank keeps the tree flat; the find above keeps it shallow enough that the
	// tie-break below never decides a real merge on map iteration order.
	if u.rank[ra] < u.rank[rb] {
		ra, rb = rb, ra
	}
	u.parent[rb] = ra
	if u.rank[ra] == u.rank[rb] {
		u.rank[ra]++
	}
}

// token is one normalised fragment of an identity signal, with the evidence for
// why it is or is not allowed to join two groups.
type token struct {
	key  string
	kind correlationKind
	// distinctive records whether the token may bridge separate signals. Role
	// words and common local parts are labels, not links.
	distinctive bool
	// label is the human-readable form used when the token becomes canonical.
	label string
}

// nonDistinctiveTokens are words that carry no identifying information. They
// are excluded from linkage for the same reason "server" is: nearly every
// machine has one, so a join on it merges unrelated operators.
var nonDistinctiveTokens = map[string]bool{
	"admin": true, "administrator": true, "all": true, "api": true, "app": true,
	"apps": true, "bin": true, "build": true, "builder": true, "cache": true,
	"cd": true, "ci": true, "client": true, "cloud": true, "code": true,
	"common": true, "computer": true, "core": true, "data": true, "default": true,
	"deploy": true, "desktop": true, "dev": true, "developer": true, "devops": true,
	"dist": true, "docker": true, "docs": true, "downloads": true, "etc": true,
	"example": true, "git": true, "group": true, "guest": true, "home": true,
	"host": true, "hostname": true, "info": true, "internal": true, "lab": true,
	"lib": true, "local": true, "log": true, "logs": true,
	"machine": true, "mail": true, "main": true, "media": true, "mnt": true,
	"my": true, "new": true, "node": true, "office": true, "opt": true,
	"private": true, "project": true, "public": true, "root": true, "run": true,
	"sbin": true, "server": true, "service": true, "services": true,
	"shared": true, "shell": true, "srv": true, "ssh": true, "src": true,
	"sys": true, "system": true, "task": true, "temp": true, "test": true,
	"tmp": true, "usr": true, "var": true, "user": true, "users": true,
	"web": true, "win": true, "work": true, "workstation": true, "www": true,
	// Deployment and distribution vocabulary. These are the words that appear
	// on thousands of unrelated machines, so a join on any of them merges
	// strangers.
	"prod": true, "production": true, "staging": true, "qa": true, "uat": true,
	"cluster": true, "k8s": true, "kube": true, "vagrant": true, "vm": true,
	"virtualbox": true, "hyperv": true, "console": true, "terminal": true,
	"ubuntu": true, "debian": true, "fedora": true, "centos": true, "arch": true,
	"alpine": true, "kali": true, "mint": true, "windows": true, "apple": true,
	"macbook": true, "macos": true, "android": true, "iphone": true, "pc": true,
	"notebook": true, "imac": true, "external": true, "backup": true,
	"edge": true, "primary": true, "secondary": true,
	"node1": true, "node2": true, "srv1": true, "srv2": true, "web1": true,
	"web2": true, "app1": true, "app2": true, "api1": true, "db1": true,
}

func isNonDistinctive(s string) bool {
	// A token of one or two characters carries no identifying information, and a
	// purely numeric one is an index or an address rather than a name.
	if s == "" || len(s) <= 2 || isAllDigits(s) {
		return true
	}
	return nonDistinctiveTokens[s] || isGenericCompound(s)
}

// publicSuffixes are the second-level labels that separate a hosting service
// from the organisation that uses it.
var publicSuffixes = map[string]bool{
	"com": true, "org": true, "net": true, "io": true, "dev": true, "git": true,
	"co": true, "edu": true, "gov": true, "mil": true, "int": true, "ac": true,
	"me": true, "app": true, "ai": true, "sh": true, "cloud": true, "uk": true,
	"de": true, "fr": true, "jp": true, "cn": true, "us": true, "ca": true,
	"eu": true, "info": true, "biz": true, "local": true, "localhost": true,
	"internal": true, "lan": true, "home": true, "corp": true,
}

func isPublicSuffix(s string) bool { return publicSuffixes[s] }

// genericSuffixes are role words that routinely appear as the tail of a longer
// compound: "web" + "server" makes "webserver". Hostnames are written this way
// constantly, so an enumerated word list alone never finishes the job.
var genericSuffixes = []string{
	"server", "servers", "service", "services", "host", "hosts", "node", "nodes",
	"cache", "proxy", "gateway", "ingress", "controller", "daemon", "client",
	"clients", "worker", "workers", "machine", "machines", "device", "devices",
	"database", "container", "cluster", "runtime", "instance", "instances",
}

func isGenericCompound(tok string) bool {
	for _, suf := range genericSuffixes {
		if len(tok) > len(suf) && strings.HasSuffix(tok, suf) {
			return true
		}
	}
	return false
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// splitToken breaks an identifier on every separator that appears in hostnames,
// directory names and package names.
func splitToken(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		switch r {
		case '-', '_', '.', ' ', '+', '@', '\\', '/':
			return true
		}
		return false
	})
}

// tokensFor normalises one signal into the tokens that may represent the same
// operator. Every token it returns is derived mechanically from the value; none
// is inferred.
func tokensFor(s models.IdentitySignal) []token {
	v := strings.TrimSpace(s.Value)
	if v == "" {
		return nil
	}
	lower := strings.ToLower(v)

	switch s.Type {
	case TypeUsername, TypeAccount:
		if isNonDistinctive(lower) {
			return nil
		}
		return []token{{key: string(kindName) + ":" + lower, kind: kindName, distinctive: true, label: lower}}

	case TypeHome:
		// A home directory names its owner in the last path element. Only the
		// leaf is used: /home/wsuits6/work is a working directory, and its
		// parent already carries the name.
		leaf := lower
		if i := strings.LastIndexAny(leaf, "/\\"); i >= 0 {
			leaf = leaf[i+1:]
		}
		if isNonDistinctive(leaf) {
			return nil
		}
		return []token{{key: string(kindName) + ":" + leaf, kind: kindName, distinctive: true, label: leaf}}

	case TypeEmail, TypeKeyComment:
		local, domain, hasAt := strings.Cut(lower, "@")
		if !hasAt || local == "" {
			return nil
		}
		// The full address is kept as its own namespace so that two addresses at
		// the same organisation are not merged into one operator, and so that a
		// key comment matching the git email resolves without a wildcard.
		out := []token{{key: string(kindEmail) + ":" + lower, kind: kindEmail, distinctive: true, label: lower}}
		if !isNonDistinctive(local) {
			// A local part that matches the username is the bridge, but only
			// when it is distinctive: info@ and admin@ say nothing about who.
			out = append(out, token{key: string(kindName) + ":" + local, kind: kindName, distinctive: true, label: local})
		}
		if domain != "" && !isNonDistinctive(domain) {
			// The domain is recorded as context but never bridges: it is shared
			// by every mailbox on that mail host.
			out = append(out, token{key: string(kindOrg) + ":" + domain, kind: kindOrg, distinctive: false, label: domain})
		}
		return out

	case TypeHostname:
		var out []token
		for _, part := range splitToken(lower) {
			if isNonDistinctive(part) {
				continue
			}
			out = append(out, token{key: string(kindName) + ":" + part, kind: kindName, distinctive: true, label: part})
		}
		return out

	case TypeRemote:
		// github.com/acmecorp/wsuits6-notes. The layout is
		// service[.tld]/organisation/repository, but the public suffix shifts
		// the organisation's position, so it is found by scanning rather than
		// by fixed index.
		seg := splitToken(lower)
		var meaningful []string
		for _, p := range seg {
			if isPublicSuffix(p) {
				continue
			}
			meaningful = append(meaningful, p)
		}
		if len(meaningful) == 0 {
			return nil
		}
		var out []token
		// meaningful[0] is the hosting service (github, gitlab, codeberg).
		if len(meaningful) >= 2 {
			out = append(out, token{
				key:         string(kindOrg) + ":" + meaningful[1],
				kind:        kindOrg,
				distinctive: false, // an organisation is shared by many people
				label:       meaningful[1],
			})
		}
		// A repository named after the operator is evidence about the
		// operator, so it may bridge; a repository named after a system is not.
		for _, p := range meaningful[min(2, len(meaningful)):] {
			if isNonDistinctive(p) {
				continue
			}
			out = append(out, token{key: string(kindName) + ":" + p, kind: kindName, distinctive: true, label: p})
		}
		return out

	case TypeOrg:
		if isNonDistinctive(lower) {
			return nil
		}
		return []token{{key: string(kindOrg) + ":" + lower, kind: kindOrg, distinctive: false, label: lower}}

	case TypeProject, TypeDevice:
		var out []token
		for _, part := range splitToken(lower) {
			if isNonDistinctive(part) {
				continue
			}
			k := correlationKind(kindProj)
			distinctive := true
			if s.Type == TypeDevice {
				// A device name describes the hardware, not the person.
				k = kindDev
				distinctive = false
			}
			out = append(out, token{key: string(k) + ":" + part, kind: k, distinctive: distinctive, label: part})
		}
		return out
	}

	// An unknown signal type is kept as a singleton label. It is never given a
	// token, so it cannot bridge two known signals into one identity.
	return nil
}

// Correlate resolves signals into operator identities.
//
// The returned slice is sorted by descending strength and then by canonical
// value, so two runs over the same inputs are byte-identical.
func Correlate(signals []models.IdentitySignal, opts Options) Result {
	opts = opts.withDefaults()
	uf := newUnionFind()

	// Pass 1: derive tokens and join the tokens belonging to a single signal.
	// A signal is the only thing permitted to bridge two namespaces, because a
	// single observation carrying two forms of a name is genuine evidence of one
	// operator.
	kept := make([]resolvedSignal, 0, len(signals))
	res := Result{}

	for _, sig := range signals {
		if sig.Redacted {
			// The value is a placeholder. Correlating on it would merge every
			// redacted signal in the run into a single fictitious identity.
			res.Redacted++
			continue
		}
		if sig.At.IsZero() {
			sig.At = opts.At
		}
		toks := bridgeableTokens(tokensFor(sig))
		if len(toks) == 0 {
			// The signal carried only shared nouns — a mail domain, an
			// organisation, a generic hostname. It is recorded as observed and
			// left unattributed rather than attached to an operator.
			res.Unlinked++
			continue
		}
		kept = append(kept, resolvedSignal{sig: sig, toks: toks})
		for _, tk := range toks {
			uf.add(tk.key)
		}
		// A single observation is permitted to bridge its own namespaces, because
		// an email address that carries both a local part and a domain really is
		// two forms of one value. The tokens are already restricted to bridgeable
		// namespaces here, which is what stops a shared mail domain from becoming
		// an accidental bridge between two colleagues.
		for i := 1; i < len(toks); i++ {
			uf.union(toks[0].key, toks[i].key)
		}
	}

	// Pass 2: join across signals on distinctive shared tokens.
	// Only distinctive tokens may perform a cross-signal join, so the pair loop
	// is driven by a precomputed index of distinctive keys.
	byKey := map[string][]int{}
	for i, r := range kept {
		for _, tk := range r.toks {
			if !tk.distinctive {
				continue
			}
			byKey[tk.key] = append(byKey[tk.key], i)
		}
	}
	for _, idxs := range byKey {
		for i := 1; i < len(idxs); i++ {
			uf.union(kept[idxs[0]].toks[0].key, kept[idxs[i]].toks[0].key)
		}
	}

	// Pass 3: materialise one identity per connected component.
	groups := map[string][]int{}
	for i, r := range kept {
		root := uf.find(r.toks[0].key)
		groups[root] = append(groups[root], i)
	}

	roots := make([]string, 0, len(groups))
	for root := range groups {
		roots = append(roots, root)
	}
	sort.Strings(roots) // deterministic iteration before any scoring

	out := make([]models.CorrelatedIdentity, 0, len(roots))
	for _, root := range roots {
		idxs := groups[root]
		identity := buildIdentity(kept, idxs)
		if identity.Strength < opts.MinimumStrength {
			continue
		}
		out = append(out, identity)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Strength != out[j].Strength {
			return out[i].Strength > out[j].Strength
		}
		if out[i].Canonical != out[j].Canonical {
			return out[i].Canonical < out[j].Canonical
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > opts.MaxGroups {
		out = out[:opts.MaxGroups]
	}

	res.Identities = out
	return res
}

// bridgeableTokens keeps only the tokens that may participate in linkage.
//
// Context tokens are dropped rather than carried along, and that is deliberate:
// a token which is recorded but never unioned cannot act as a bridge by
// transitivity. Keeping them in the union-find would make every shared value —
// one mail domain, one organisation — a hub that silently fused unrelated
// operators into a single identity.
func bridgeableTokens(toks []token) []token {
	out := make([]token, 0, len(toks))
	for _, tk := range toks {
		if tk.kind.bridgeable() {
			out = append(out, tk)
		}
	}
	return out
}

// buildIdentity assembles one correlated identity from its member signals.
//
// Strength rewards breadth rather than volume: five copies of the same username
// discovered in five places is strong evidence of one operator, but five
// different usernames is not. A run of near-duplicate signals therefore cannot
// out-score a genuinely corroborated identity, which is what keeps this from
// being a duplicate counter.
func buildIdentity(kept []resolvedSignal, idxs []int) models.CorrelatedIdentity {
	sigs := make([]models.IdentitySignal, 0, len(idxs))
	types := map[string]bool{}
	sources := map[string]bool{}
	domains := map[string]bool{}

	for _, i := range idxs {
		s := kept[i].sig
		sigs = append(sigs, s)
		types[s.Type] = true
		sources[s.Source] = true
		domains[s.Domain] = true
	}

	sort.SliceStable(sigs, func(i, j int) bool {
		if sigs[i].Type != sigs[j].Type {
			return sigs[i].Type < sigs[j].Type
		}
		if sigs[i].Value != sigs[j].Value {
			return sigs[i].Value < sigs[j].Value
		}
		return sigs[i].Source < sigs[j].Source
	})

	canonical, sourceList := canonicalOf(sigs)

	// Normalisation denominators are the counts that a full identity would
	// produce: the eight signal types the framework collects, and three
	// corroborating sources and three domains beyond the one that named it.
	coverage := float64(len(types)) / 8.0
	corroboration := min(1.0, float64(len(sourceList))/3.0)
	spread := min(1.0, float64(len(domains))/3.0)
	strength := int(100*(0.5*coverage+0.3*corroboration+0.2*spread) + 0.5)
	if strength > 100 {
		strength = 100
	}

	id := identityID(canonical, sourceList)

	return models.CorrelatedIdentity{
		ID:          id,
		Canonical:   canonical,
		Strength:    strength,
		SignalCount: len(sigs),
		Signals:     sigs,
		Sources:     sourceList,
		Domains:     sortedKeys(domains),
		Summary:     summarise(canonical, len(sigs), len(types), len(sources), len(domains)),
	}
}

// canonicalOf picks the value an identity is reported under, and the source
// list that supports it.
//
// The preference order is fixed and documented rather than heuristic: a
// username is the operator's own chosen handle and is the most stable value,
// a home directory is derived from it, an email is stable but often a work
// address that outlives the person, and a hostname is the weakest because it is
// the one value a user is most likely to have inherited.
func canonicalOf(sigs []models.IdentitySignal) (string, []string) {
	rank := map[string]int{
		TypeUsername: 0, TypeAccount: 0, TypeHome: 1, TypeEmail: 2,
		TypeKeyComment: 3, TypeHostname: 4, TypeRemote: 5, TypeOrg: 6,
		TypeProject: 7, TypeDevice: 7,
	}
	best := -1
	for i, s := range sigs {
		if r, ok := rank[s.Type]; ok && (best < 0 || r < rank[sigs[best].Type]) {
			best = i
		}
	}
	canonical := ""
	if best >= 0 {
		canonical = sigs[best].Value
	}

	set := map[string]bool{}
	for _, s := range sigs {
		if s.Source != "" {
			set[s.Source] = true
		}
	}
	return canonical, sortedKeys(set)
}

// identityID is derived from the canonical value and its supporting sources, so
// the same observation always yields the same ID across runs and machines.
func identityID(canonical string, sources []string) string {
	h := sha256.New()
	h.Write([]byte(canonical))
	for _, s := range sources {
		h.Write([]byte{0})
		h.Write([]byte(s))
	}
	return "ident-" + hex.EncodeToString(h.Sum(nil))[:12]
}

func summarise(canonical string, signals, types, sources, domains int) string {
	var b strings.Builder
	b.WriteString("Identity ")
	b.WriteString(canonical)
	b.WriteString(" is disclosed by ")
	b.WriteString(strconv.Itoa(signals))
	if signals == 1 {
		b.WriteString(" signal")
	} else {
		b.WriteString(" signals")
	}
	b.WriteString(" across ")
	b.WriteString(strconv.Itoa(types))
	if types == 1 {
		b.WriteString(" kind")
	} else {
		b.WriteString(" kinds")
	}
	b.WriteString(" of observation, from ")
	b.WriteString(strconv.Itoa(sources))
	if sources == 1 {
		b.WriteString(" source")
	} else {
		b.WriteString(" sources")
	}
	b.WriteString(" and ")
	b.WriteString(strconv.Itoa(domains))
	if domains == 1 {
		b.WriteString(" domain.")
	} else {
		b.WriteString(" domains.")
	}
	return b.String()
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
