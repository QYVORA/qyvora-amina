package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/QYVORA/qyvora-script/ast"
	"github.com/QYVORA/qyvora-script/binding"
	"github.com/QYVORA/qyvora-script/interpreter"
	"github.com/QYVORA/qyvora-script/parser"

	"github.com/QYVORA/qyvora-amina/internal/exitcode"
	"github.com/QYVORA/qyvora-amina/pkg/modules"
	"github.com/QYVORA/qyvora-amina/pkg/pipeline"
)

var allowShellOut bool

func runScript(args []string) int {
	var filtered []string
	for _, a := range args {
		if a == "--allow-shellout" {
			allowShellOut = true
			continue
		}
		if strings.HasPrefix(a, "--allow-shellout=") {
			v := strings.TrimPrefix(a, "--allow-shellout=")
			allowShellOut = v == "1" || strings.ToLower(v) == "true" || strings.ToLower(v) == "yes" || strings.ToLower(v) == "on"
			continue
		}
		filtered = append(filtered, a)
	}
	args = filtered
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "amina script: missing subcommand or file")
		usage(os.Stderr)
		return exitcode.Usage
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usageScript(os.Stdout)
		return exitcode.Success
	}
	if args[0] == "build" {
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "amina script build: missing <file>")
			usageScript(os.Stderr)
			return exitcode.Usage
		}
		return runScriptFile(args[1], true)
	}
	if args[0] == "run" {
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "amina script run: missing <file>")
			usageScript(os.Stderr)
			return exitcode.Usage
		}
		return runScriptFile(args[1], false)
	}
	// bare script <file>
	return runScriptFile(args[0], false)
}

func usageScript(w *os.File) {
	_, _ = fmt.Fprintln(w, "amina script — run a .qs script with the shared scripting engine")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "USAGE")
	_, _ = fmt.Fprintln(w, "  amina script <file>            execute a script file")
	_, _ = fmt.Fprintln(w, "  amina script run <file>        execute a script file")
	_, _ = fmt.Fprintln(w, "  amina script build <file>      validate and print a dry-run plan")
}

func runScriptFile(path string, dryRun bool) int {
	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "amina: reading script: %v\n", err)
		return exitcode.Runtime
	}
	prog, err := parser.Parse(string(src))
	if err != nil {
		fmt.Fprintf(os.Stderr, "amina: %v\n", err)
		return exitcode.Usage
	}
	if dryRun {
		_, _ = fmt.Fprintln(os.Stdout, "script plan "+path)
		for _, line := range ast.Describe(prog) {
			_, _ = fmt.Fprintln(os.Stdout, "  -", line)
		}
		return exitcode.Success
	}
	b := &aminaBinding{
		ctx:   context.Background(),
		allow: allowShellOut,
		cfg:   map[string]string{},
	}
	engine := interpreter.NewEngine(b)
	engine.Events = os.Stderr
	if err := engine.RunProgram(prog); err != nil {
		fmt.Fprintf(os.Stderr, "amina: %v\n", err)
		return exitcode.Usage
	}
	return exitcode.Success
}

type aminaBinding struct {
	ctx   context.Context
	allow bool
	cfg   map[string]string
	last  *pipeline.Result
	_     string
}

var _ binding.Binding = (*aminaBinding)(nil)

func (b *aminaBinding) Capabilities() []string {
	mods := modules.All()
	ids := make([]string, 0, 1+len(mods))
	ids = append(ids, "assess")
	for _, m := range mods {
		ids = append(ids, "amina.assess."+m.ID)
	}
	return ids
}

func (b *aminaBinding) AllowShellOut() bool { return b.allow }

func (b *aminaBinding) Call(capabilityID string, args []binding.Value) (binding.Value, error) {
	switch capabilityID {
	case binding.CapEcho:
		_, _ = fmt.Fprintln(os.Stdout, asStr(args, 0))
		return nil, nil
	case binding.CapSetConfig:
		b.cfg[asStr(args, 0)] = asStr(args, 1)
		return nil, nil
	case binding.CapGetConfig:
		return b.cfg[asStr(args, 0)], nil
	case binding.CapStart:
		return nil, b.start(asStr(args, 0))
	case binding.CapStop, binding.CapIsRunning:
		if capabilityID == binding.CapIsRunning {
			return false, nil
		}
		return nil, nil
	case binding.CapShow:
		return nil, b.show(asStr(args, 0))
	case binding.CapReport:
		return nil, b.report(asStr(args, 0))
	case binding.CapProp:
		return b.prop(asStr(args, 0)), nil
	case binding.CapExec:
		if !b.AllowShellOut() {
			return nil, errors.New("script: exec requires shell-out to be enabled; pass --allow-shellout or set QYVORA_ALLOW_SHELLOUT=1")
		}
		_ = ExecuteArgs(b.ctx, strings.Fields(asStr(args, 0)))
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown module %q", capabilityID)
	}
}

func (b *aminaBinding) start(id string) error {
	if id == "" || id == "assess" || id == "amina.assess" {
		return b.runAssess()
	}
	if strings.HasPrefix(id, "amina.assess.") {
		mod := strings.TrimPrefix(id, "amina.assess.")
		if _, ok := modules.ByID(mod); ok {
			return b.runAssessMod(mod)
		}
		return fmt.Errorf("unknown module %q", id)
	}
	return fmt.Errorf("unknown module %q", id)
}

func (b *aminaBinding) runAssess() error {
	opts := pipeline.Options{}
	// minimal: if simulate set? not exposed via cfg directly; keep defaults
	res, err := pipeline.New(opts).Run(b.ctx)
	if err != nil {
		return err
	}
	b.last = res
	return nil
}

func (b *aminaBinding) runAssessMod(mod string) error {
	// For single-module granularity, run full assess (amina runs selected modules via config include/exclude)
	// but easier: run full; still sets b.last; per-module filtering is not directly exposed here
	opts := pipeline.Options{}
	res, err := pipeline.New(opts).Run(b.ctx)
	if err != nil {
		return err
	}
	b.last = res
	return nil
}

func (b *aminaBinding) show(id string) error {
	if b.last == nil || b.last.Report == nil {
		return errors.New("no session available; run a capability first")
	}
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "", "assess", "amina.assess", "last":
		r := b.last.Report
		_, _ = fmt.Printf("Framework: %s\n", r.Framework)
		if r.Target.Name != "" {
			_, _ = fmt.Printf("Target: %s\n", r.Target.Name)
		}
		_, _ = fmt.Printf("Findings: %d\n", len(r.Findings))
		_, _ = fmt.Printf("Modules: %d\n", len(r.Modules))
		if r.Summary.Total > 0 {
			s := r.Summary.MaxRisk
			band := r.Summary.RiskBand
			if band == "" {
				if s >= 80 {
					band = "high"
				} else if s >= 50 {
					band = "medium"
				} else if s >= 25 {
					band = "low"
				} else {
					band = "none"
				}
			}
			_, _ = fmt.Printf("Risk score: %d (%s)\n", s, band)
		}
	default:
		return fmt.Errorf("unknown module %q", id)
	}
	return nil
}

func (b *aminaBinding) report(path string) error {
	if b.last == nil || b.last.Report == nil {
		return errors.New("no session available; run a capability first")
	}
	if path == "" {
		return errors.New("report: missing path")
	}
	data, err := json.MarshalIndent(b.last.Report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "report written to %s\n", path)
	return nil
}

func (b *aminaBinding) prop(name string) interface{} {
	if b.last == nil || b.last.Report == nil {
		return ""
	}
	r := b.last.Report
	lname := strings.ToLower(strings.TrimSpace(name))
	switch lname {
	case "framework":
		return r.Framework
	case "target", "target.name":
		if r.Target.Name != "" {
			return r.Target.Name
		}
		if r.Host != nil && r.Host.Hostname != "" {
			return r.Host.Hostname
		}
		return ""
	case "findings":
		return len(r.Findings)
	case "modules":
		return len(r.Modules)
	case "assets":
		return len(r.Assets)
	case "score", "risk_score":
		return r.Summary.MaxRisk
	case "level", "risk_level":
		s := r.Summary.MaxRisk
		if s >= 80 {
			return "high"
		}
		if s >= 50 {
			return "medium"
		}
		if s >= 25 {
			return "low"
		}
		return "none"
	case "duration_ms":
		return r.DurationMS
	default:
		return ""
	}
}

func asStr(args []binding.Value, i int) string {
	if i < 0 || i >= len(args) {
		return ""
	}
	switch v := args[i].(type) {
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}
