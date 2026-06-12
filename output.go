package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"syscall"
	"unsafe"
)

// ---- TTY detection (DR-006) -----------------------------------------------
// isTerminal reports whether fd refers to a terminal. Implemented with a
// single syscall rather than a third-party isatty library (DR-001).
func isTerminal(fd uintptr) bool {
	var termios [256]byte // large enough for any termios struct on Linux/macOS
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd,
		syscall.TIOCGWINSZ, // works on both Linux and macOS to probe a TTY
		uintptr(unsafe.Pointer(&termios[0])),
	)
	return errno == 0
}

// ---- ANSI colors (DR-006) --------------------------------------------------
// colorEnabled is set once at startup by main after flag parsing.
// output.go never reads os.Args or flags directly — that is main's job.
var colorEnabled bool

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiGreen  = "\033[32m"
	ansiGray   = "\033[90m"
	ansiBold   = "\033[1m"
)

func colorize(s, ansiCode string) string {
	if !colorEnabled {
		return s
	}
	return ansiCode + s + ansiReset
}

// ---- Sorting (DR-007) ------------------------------------------------------
// SortResults sorts a Results slice in-place, alphabetically by domain name.
// Called by main after all goroutines complete — never mid-stream.
func SortResults(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		return results[i].Domain < results[j].Domain
	})
}

// ---- Human output (P3) -----------------------------------------------------
// PrintHuman writes all results to stdout in a human-readable table.
// It contains no business logic — Status thresholds were decided in checker.go.
func PrintHuman(results []Result) {
	for _, r := range results {
		printHumanResult(r)
	}
}

func printHumanResult(r Result) {
	label, code := statusLabel(r.Status)
	domain := colorize(fmt.Sprintf("%-40s", r.Domain), ansiBold)
	fmt.Printf("%s %s  %s\n", domain, code, label)
}

// statusLabel returns the coloured status badge and the message for a Result.
func statusLabel(s Status) (message string, badge string) {
	switch s {
	case StatusOK:
		return colorize("OK", ansiGreen), colorize("[  OK  ]", ansiGreen)
	case StatusWarning:
		return colorize("WARN", ansiYellow), colorize("[ WARN ]", ansiYellow)
	case StatusExpired:
		return colorize("EXPIRED", ansiRed), colorize("[EXPIRD]", ansiRed)
	case StatusError:
		return colorize("ERROR", ansiRed), colorize("[ ERR  ]", ansiRed)
	default:
		return "UNKNOWN", "[ ???? ]"
	}
}

// PrintHumanResult writes a single result line — used when streaming is
// preferred in future (not wired up now; preserved for Stage 3 completeness).
func PrintHumanResult(r Result) {
	printHumanResult(r)
}

// PrintHumanDetail writes a second line with the full message for non-OK
// results. Called by main when --verbose is set (gap: DR-gap-verbose; see
// note below).
func PrintHumanDetail(r Result) {
	if r.Status == StatusOK {
		return
	}
	fmt.Printf("  %s\n", colorize(r.Message, ansiGray))
}

// ---- JSON output (P3) ------------------------------------------------------
// jsonResult is the wire format. Exported field names become JSON keys.
// ExpiresAt is omitted (omitempty) for error results where it is zero.
type jsonResult struct {
	Domain    string `json:"domain"`
	Port      int    `json:"port"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at,omitempty"`
	DaysLeft  int    `json:"days_left,omitempty"`
	Message   string `json:"message"`
}

// PrintJSON serialises all results to stdout as a JSON array.
// An empty slice produces [] (OQ-4 / DR-011). Never mixes with fmt.Printf
// output — JSON and human paths are completely separate (P3).
func PrintJSON(results []Result) error {
	out := make([]jsonResult, len(results))
	for i, r := range results {
		out[i] = toJSONResult(r)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func toJSONResult(r Result) jsonResult {
	jr := jsonResult{
		Domain:  r.Domain,
		Port:    r.Port,
		Status:  statusString(r.Status),
		Message: r.Message,
	}
	if r.Status != StatusError {
		jr.ExpiresAt = r.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
		jr.DaysLeft = r.DaysLeft
	}
	return jr
}

func statusString(s Status) string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusWarning:
		return "warning"
	case StatusExpired:
		return "expired"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// ---- Exit code helpers (DR-005) -------------------------------------------
// ExitCode returns the appropriate process exit code for a set of results.
// Exit 0: everything healthy.
// Exit 1: any cert expired, expiring, or any domain unreachable.
// Exit 2 is reserved for usage errors and is returned directly by main.
func ExitCode(results []Result) int {
	for _, r := range results {
		if r.Status != StatusOK {
			return 1
		}
	}
	return 0
}
