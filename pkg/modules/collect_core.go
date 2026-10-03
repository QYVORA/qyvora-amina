package modules

import (
	"strconv"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// collectHostIdentity builds the host-identity module from what Detect already
// observed. The platform layer does the work because detecting a hostname,
// machine ID or virtualisation marker is an operating-system question, not an
// assessment one; this module decides what those values mean.
func collectHostIdentity(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapHostIdentity}}, nil
	}

	var res Result
	var assets []models.Asset

	add := func(kind models.AssetKind, name, path, val string) {
		if val == "" {
			return
		}
		a := models.Asset{
			Kind:     kind,
			Domain:   "host-identity",
			Name:     name,
			Path:     path,
			Platform: e.Platform,
			Support:  e.SupportLevel(platform.CapHostIdentity),
		}
		a.Set("value", val)
		assets = append(assets, a)
	}

	// Each of these is a value the host volunteers about itself. They are assets
	// in their own right: the rules layer decides which of them expose the
	// operator, and that decision belongs to the rules, not to the collector.
	add(models.KindHostIdentity, "hostname", "", e.Hostname)
	add(models.KindHostIdentity, "computer_name", "", e.ComputerName)
	add(models.KindHostIdentity, "machine_id", "", e.MachineID)
	add(models.KindHostIdentity, "domain", "", e.Domain)
	add(models.KindHostIdentity, "user_domain", "", e.UserDomain)
	add(models.KindHostIdentity, "kernel", "", e.Kernel)
	add(models.KindHostIdentity, "distro", "", e.Distro)
	add(models.KindHostIdentity, "cloud", "", e.Cloud)
	add(models.KindHostIdentity, "shell", e.Shell, e.Shell)
	add(models.KindHostIdentity, "terminal", "", e.Terminal)
	add(models.KindHostIdentity, "home", e.Home, e.Home)

	// The environment tells us what kind of machine this is, which changes how
	// every other finding should be read: a container's wildcard bind is not a
	// workstation's wildcard bind.
	if e.Virtual {
		a := models.Asset{Kind: models.KindHostIdentity, Domain: "host-identity", Name: "virtualization", Platform: e.Platform}
		a.Set("value", e.VirtualKind)
		assets = append(assets, a)
	}
	if e.Container {
		a := models.Asset{Kind: models.KindHostIdentity, Domain: "host-identity", Name: "container", Platform: e.Platform}
		a.Set("value", e.ContainerKind)
		assets = append(assets, a)
	}

	res.Assets = assets

	// Identity signals: the values that let the correlation engine link this
	// host to its operator. Each records the source it came from, so a
	// correlated finding can cite it.
	res.Identities = []models.IdentitySignal{
		{Type: "hostname", Value: e.Hostname, Source: "host identity", Domain: "host-identity"},
		{Type: "hostname", Value: e.ComputerName, Source: "host identity", Domain: "host-identity"},
		{Type: "username", Value: e.User, Source: "host identity", Domain: "host-identity"},
		{Type: "home", Value: e.Home, Source: "host identity", Domain: "host-identity"},
	}

	// Detect records notes when something could not be established. They are
	// passed through rather than dropped, so an incomplete host identity shows
	// up in the report as incomplete.
	if len(e.Notes) > 0 {
		res.Degraded = true
		res.Note = ReasonUnavailable
		res.Unavailable = append(res.Unavailable, e.Notes...)
	}
	return res, nil
}

// collectAccounts turns the platform account inventory into module output and
// emits one identity signal per account name.
func collectAccounts(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapAccounts}}, nil
	}

	accounts, levels := platform.Accounts(in.Ctx, e)
	// Accounts reports one level per source it consulted. A module reports a
	// single verdict, so the weakest source decides: a passwd file read in full
	// alongside a group file that could not be parsed is a partial answer, not a
	// complete one.
	support := weakestSupport(levels)
	res := Result{Accounts: accounts}

	var assets []models.Asset
	var signals []models.IdentitySignal
	for _, a := range accounts {
		asset := models.Asset{
			Kind:     models.KindAccount,
			Domain:   "accounts",
			Name:     a.Name,
			Platform: e.Platform,
			Support:  support,
		}
		asset.Set("uid", a.UID)
		asset.Set("shell", a.Shell)
		asset.Set("classification", string(a.Classification))
		asset.Set("reason", a.Reason)
		asset.Set("privileged", boolString(a.Privileged))
		asset.Set("source", a.Source)
		assets = append(assets, asset)

		// The account name is a name signal whether or not it looks personal:
		// the correlation engine decides what is distinctive.
		signals = append(signals, models.IdentitySignal{
			Type: "username", Value: a.Name, Source: a.Source, Domain: "accounts",
		})
	}
	res.Assets = assets
	res.Identities = signals

	if support == models.SupportNone || support == models.SupportPrivilege {
		res.Degraded = true
		res.Note = "account inventory is incomplete on this host"
		res.Unavailable = []string{platform.CapAccounts}
	}
	return res, nil
}

// collectNetwork records interfaces and listening sockets, and attributes each
// socket to the account that owns it where the platform exposes that mapping.
func collectNetwork(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapNetwork}}, nil
	}

	ifaces, sockets, support := platform.Network(in.Ctx, e)
	res := Result{Interfaces: ifaces, Sockets: sockets}

	assets := make([]models.Asset, 0, len(ifaces)+len(sockets))
	for _, i := range ifaces {
		a := models.Asset{
			Kind:     models.KindNetworkInterface,
			Domain:   "network",
			Name:     i.Name,
			Platform: e.Platform,
			Support:  support[0],
		}
		a.Set("kind", i.Kind)
		a.Set("scope", i.Scope)
		a.Set("up", boolString(i.Up))
		a.Set("mac", i.MAC)
		for n, addr := range i.Addrs {
			a.Set("addr_"+strconv.Itoa(n), addr)
		}
		assets = append(assets, a)
	}
	for _, sk := range sockets {
		a := models.Asset{
			Kind:     models.KindListeningSocket,
			Domain:   "network",
			Name:     sk.Proto + "/" + sk.Addr + ":" + strconv.Itoa(sk.Port),
			Platform: e.Platform,
			Support:  support[1],
		}
		a.Set("proto", sk.Proto)
		a.Set("addr", sk.Addr)
		a.Set("port", strconv.Itoa(sk.Port))
		a.Set("scope", string(sk.Scope))
		a.Set("wildcard", boolString(sk.Wildcard))
		a.Set("process", sk.Process)
		a.Set("pid", strconv.Itoa(sk.PID))
		assets = append(assets, a)
	}
	res.Assets = assets

	if support[0] == models.SupportNone || support[1] == models.SupportNone {
		res.Degraded = true
		res.Note = "listening sockets could not be fully enumerated"
		res.Unavailable = []string{platform.CapNetwork}
	}
	return res, nil
}

// supportRank orders the capability levels from least to most capable, so the
// weakest of several sources can be selected.
var supportRank = map[models.SupportLevel]int{
	models.SupportNone: 0, models.SupportPrivilege: 1, models.SupportLimited: 2,
	models.SupportPartial: 3, models.SupportFull: 4,
}

// weakestSupport returns the least capable level in the set. SupportNone is
// returned for an empty set: no source consulted is not full support.
func weakestSupport(levels []models.SupportLevel) models.SupportLevel {
	if len(levels) == 0 {
		return models.SupportNone
	}
	worst := levels[0]
	for _, l := range levels[1:] {
		if supportRank[l] < supportRank[worst] {
			worst = l
		}
	}
	return worst
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
