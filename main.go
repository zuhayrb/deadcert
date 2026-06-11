package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// version is the single place to update for releases.
const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:]))
}

// run is separated from main so tests can call it with arbitrary args and
// capture the exit code without os.Exit terminating the test binary.
func run(args []string) int {
	fs := flag.NewFlagSet("deadcert", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage(fs)

	// ---- Flags (stdlib flag is enough for one command) -----------------
	warnDays := fs.Int("warn-days", 30,
		"warn when a cert expires within this many days (0 = expired certs only)")
	port := fs.Int("port", 443,
		"TCP port to connect on")
	timeoutStr := fs.String("timeout", "10s",
		"per-domain dial+handshake timeout (Go duration: 5s, 1m, …)")
	jsonOut := fs.Bool("json", false,
		"emit JSON array instead of human-readable output")
	noColor := fs.Bool("no-color", false,
		"disable ANSI color codes even when stdout is a TTY")
	verbose := fs.Bool("verbose", false,
		"print detail line for non-OK results (human output only)")
	filePath := fs.String("file", "",
		"read additional domains from file, one per line; # and blank lines skipped")
	showVersion := fs.Bool("version", false,
		"print version and exit")

	if err := fs.Parse(args); err != nil {
		// flag.ContinueOnError already printed the error to stderr.
		return 2
	}

	if *showVersion {
		fmt.Fprintf(os.Stderr, "deadcert %s\n", version)
		return 0
	}

	// ---- Validate --warn-days ----------------------------------------------
	// 0 is explicitly valid: "alert on already-expired certs only".
	// Negative values are a usage error.
	if *warnDays < 0 {
		fmt.Fprintln(os.Stderr, "error: --warn-days must be 0 or greater")
		return 2
	}

	// ---- Parse --timeout ---------------------------------------------------
	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil || timeout <= 0 {
		fmt.Fprintf(os.Stderr, "error: invalid --timeout %q (use a Go duration: 5s, 1m)\n", *timeoutStr)
		return 2
	}

	// ---- Collect domains ---------------------------------------------------
	// Positional arguments take priority; --file adds to the same list.
	domains := fs.Args()

	if *filePath != "" {
		fileDomains, err := domainsFromFile(*filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			return 2
		}
		domains = append(domains, fileDomains...)
	}

	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "error: no domains specified")
		fs.Usage()
		return 2
	}

	// ---- Color setup -------------------------------------------------------
	// --no-color always wins. Otherwise enable color only when stdout is a TTY.
	colorEnabled = !*noColor && isTerminal(os.Stdout.Fd())

	// ---- Concurrent checking -----------------------------------------------
	results := make([]Result, 0, len(domains))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, d := range domains {
		d := d // capture loop variable
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := CheckDomain(d, *port, timeout, *warnDays)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}()
	}

	wg.Wait()

	// ---- Sort before print -------------------------------------------------
	SortResults(results)

	// ---- Render ------------------------------------------------------------
	if *jsonOut {
		if err := PrintJSON(results); err != nil {
			fmt.Fprintf(os.Stderr, "error writing JSON: %s\n", err)
			return 2
		}
	} else {
		PrintHuman(results)
		if *verbose {
			for _, r := range results {
				PrintHumanDetail(r)
			}
		}
	}

	// ---- Exit code ---------------------------------------------------------
	return ExitCode(results)
}

// domainsFromFile reads domains from path, one per line.
// Blank lines and lines beginning with # are skipped silently (OQ-2 / DR-009).
func domainsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open --file %q: %w", path, err)
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // silent skip (OQ-2 / DR-009)
		}
		domains = append(domains, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading --file %q: %w", path, err)
	}
	return domains, nil
}

// usage returns the Usage function for the FlagSet.
func usage(fs *flag.FlagSet) func() {
	return func() {
		fmt.Fprintln(os.Stderr, `
deadcert — TLS certificate expiry checker

Usage:
  deadcert [flags] <domain> [domain …]
  deadcert [flags] --file domains.txt

Examples:
  deadcert example.com
  deadcert --warn-days 14 example.com api.example.com
  deadcert --json --no-color example.com | jq .
  deadcert --file domains.txt --timeout 5s
  deadcert --port 8443 internal.example.com

Exit codes:
  0  all certs healthy
  1  any cert expired, expiring within --warn-days, or domain unreachable
  2  usage error

Flags:`)
		fs.PrintDefaults()
	}
}
