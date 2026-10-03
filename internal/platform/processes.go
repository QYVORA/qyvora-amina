package platform

import (
	"context"
	"os"
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Process is one running process, reduced to the fields an exposure assessment
// actually uses. Full command lines are captured because a process whose
// arguments contain a token is a finding, but the ownership and parentage
// fields are what turn a process into a correlation signal.
type Process struct {
	PID     int
	PPID    int
	Name    string
	User    string
	Args    string
	Exe     string
	Cwd     string
	Started string
	State   string
}

// Processes enumerates running processes.
//
// Two strategies exist because no single one works everywhere: reading /proc is
// exact and free but Linux-only, while `ps`/`wmic`/`tasklist` are universal and
// lossy. Amina tries the exact source first and records which one answered, so
// a report never presents a lossy process list as a complete one.
func Processes(ctx context.Context, e *Env) ([]Process, []string) {
	var procs []Process
	var unavailable []string

	if procs = procfsProcesses(e); len(procs) > 0 {
		return procs, unavailable
	}
	if e.Platform == models.PlatformWindows {
		if out, err := Run(ctx, "wmic", "process", "get", "ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine", "/format:csv"); err == nil {
			procs = parseWMIProcess(out)
			// wmic is deprecated and absent on current Windows builds, so its
			// absence is expected rather than anomalous.
			unavailable = append(unavailable, "wmic")
		} else {
			unavailable = append(unavailable, "wmic")
		}
	}
	if len(procs) == 0 {
		if out, err := Run(ctx, "ps", "-eo", "pid,ppid,user,state,comm"); err == nil {
			procs = parsePS(out)
		} else {
			unavailable = append(unavailable, "ps")
		}
	}
	sort.SliceStable(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs, unavailable
}

// procfsProcesses reads /proc, which is the only source on Linux that yields
// command lines and working directories without privilege.
func procfsProcesses(e *Env) []Process {
	entries := readDirNames("/proc")
	if len(entries) == 0 {
		return nil
	}
	// Process owners are recorded as numeric uids in /proc/<pid>/status. A
	// report saying "runs as 1000" is less useful than "runs as alice", and the
	// uid table costs one small file read rather than one lookup per process.
	uids := passwdUIDTable()
	out := make([]Process, 0, len(entries))
	for _, name := range entries {
		pid, err := atoiSafe(name)
		if err != nil || !dirExists("/proc/"+name) {
			continue
		}
		p := Process{PID: pid}
		p.Name = strings.TrimSpace(readText("/proc/" + name + "/comm"))
		p.Exe = readlinkText("/proc/" + name + "/exe")
		if status, err := ReadLines("/proc/"+name+"/status", 64); err == nil {
			for _, line := range status {
				if v, ok := cutPrefix(line, "PPid:"); ok {
					p.PPID, _ = atoiSafe(strings.TrimSpace(v))
				} else if v, ok := cutPrefix(line, "Uid:"); ok {
					uid := strings.Fields(strings.TrimSpace(v))
					if len(uid) > 0 {
						p.User = uid[0]
						if name, ok := uids[p.User]; ok {
							p.User = name
						}
					}
				} else if v, ok := cutPrefix(line, "State:"); ok {
					p.State = strings.TrimSpace(v)
				}
			}
		}
		if cmdline, err := ReadFileLimited("/proc/" + name + "/cmdline"); err == nil {
			p.Args = strings.TrimSpace(strings.ReplaceAll(strings.TrimRight(string(cmdline), "\x00"), "\x00", " "))
		}
		p.Cwd = readlinkText("/proc/" + name + "/cwd")
		p.Started = procStartTime("/proc/" + name + "/stat")
		out = append(out, p)
	}
	return out
}

// passwdUIDTable maps uid to login name, keyed by the numeric uid exactly as
// /proc reports it. A uid with no passwd entry is deliberately left numeric:
// "nobody" and "999" are different facts and a missing name is not evidence of
// an anonymous process.
func passwdUIDTable() map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(readText("/etc/passwd"), "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 3 || f[2] == "" {
			continue
		}
		out[f[2]] = f[0]
	}
	return out
}

func parsePS(out string) []Process {
	var procs []Process
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !isAllDigits(f[0]) {
			continue
		}
		p := Process{PID: atoiOr(f[0], -1), PPID: atoiOr(f[1], -1), Name: f[4], State: f[3]}
		if len(f) > 2 {
			p.User = f[2]
		}
		procs = append(procs, p)
	}
	return procs
}

func parseWMIProcess(csv string) []Process {
	lines := strings.Split(csv, "\n")
	if len(lines) < 2 {
		return nil
	}
	header := strings.Split(strings.TrimSpace(lines[0]), ",")
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToUpper(strings.TrimSpace(h))] = i
	}
	get := func(fields []string, key string) string {
		if i, ok := col[key]; ok && i < len(fields) {
			return strings.TrimSpace(fields[i])
		}
		return ""
	}
	var procs []Process
	for _, line := range lines[1:] {
		fields := strings.Split(strings.TrimSpace(line), ",")
		if len(fields) < len(header) {
			continue
		}
		procs = append(procs, Process{
			PID:  atoiOr(get(fields, "PROCESSID"), -1),
			PPID: atoiOr(get(fields, "PARENTPROCESSID"), -1),
			Name: get(fields, "NAME"),
			Args: get(fields, "COMMANDLINE"),
			Exe:  get(fields, "EXECUTABLEPATH"),
		})
	}
	return procs
}

// procStartTime extracts the start tick from /proc/<pid>/stat.
func procStartTime(path string) string {
	data, err := ReadFileLimited(path)
	if err != nil {
		return ""
	}
	return procStartTimeFrom(string(data))
}

// procStartTimeFrom parses the start field out of a /proc/<pid>/stat line.
//
// The comm field can contain spaces and parentheses, so the field scan starts
// after the *last* ')' rather than splitting the whole line. A naive split
// produces a plausible but wrong parent pid for any process with a space in
// its name — including the ones an attacker most wants to misreport.
func procStartTimeFrom(statLine string) string {
	i := strings.LastIndex(statLine, ")")
	if i < 0 || i+2 >= len(statLine) {
		return ""
	}
	// After the closing parenthesis field 3 (state) comes first; starttime is
	// field 22 overall, which is index 19 of what follows.
	f := strings.Fields(statLine[i+2:])
	if len(f) < 20 {
		return ""
	}
	return f[19]
}

func readlinkText(path string) string {
	data, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return data
}
