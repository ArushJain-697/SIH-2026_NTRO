// TRACE — forensic IPsec tunnel analyzer.
//
// Commands:
//
//	trace analyze <file>    Analyze a pcap/pcapng capture
//	trace serve             Start the HTTP API server
//	trace keygen            Generate an API key
//	trace version           Print version information
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/SIH-2026/trace/internal/assess"
	"github.com/SIH-2026/trace/internal/engine"
	"github.com/SIH-2026/trace/internal/policy"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "analyze":
		cmdAnalyze(os.Args[2:])
	case "version":
		cmdVersion()
	case "keygen":
		cmdKeygen()
	case "serve":
		cmdServe(os.Args[2:])
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`TRACE — Forensic IPsec Tunnel Analyzer

Usage:
  trace analyze <file> [options]   Analyze a pcap/pcapng capture
  trace serve [options]            Start the HTTP API server
  trace keygen                     Generate an API key
  trace version                    Print version information

Analyze options:
  --gateway <file>     Gateway facts JSON file
  --profile <name>     Policy profile: trace-default (default) or strict
  --json               Output raw JSON result
  --text               Output human-readable text (default)`)
}

func cmdAnalyze(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: trace analyze <file> [--gateway facts.json] [--profile strict] [--json|--text]")
		os.Exit(1)
	}

	file := args[0]
	opts := engine.Options{}
	outputJSON := false

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--gateway":
			if i+1 < len(args) {
				opts.GatewayFile = args[i+1]
				i++
			}
		case "--profile":
			if i+1 < len(args) {
				opts.Profile = args[i+1]
				i++
			}
		case "--json":
			outputJSON = true
		case "--text":
			outputJSON = false
		}
	}

	f, err := os.Open(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	stat, _ := f.Stat()
	size := stat.Size()

	result, err := engine.Analyze(f, size, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if outputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(result)
	} else {
		printTextReport(result, file)
	}
}

func printTextReport(result *engine.Result, file string) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    TRACE — IPsec Analyzer                   ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Input summary.
	fmt.Printf("  File:     %s\n", file)
	fmt.Printf("  Format:   %s\n", result.Input.Format)
	fmt.Printf("  SHA-256:  %s\n", result.Input.SHA256)
	fmt.Printf("  Packets:  %d seen, %d IPsec\n", result.Input.Stats.Seen, result.Input.Stats.IPsec)
	fmt.Printf("  State:    %s\n", result.State)
	fmt.Println()

	if result.State == engine.StateFailed {
		fmt.Printf("  ❌ Analysis failed: %s\n\n", result.Error)
		return
	}

	if result.State == engine.StateCompletedNoIPs {
		fmt.Println("  ⚠️  No IPsec traffic found in this capture.")
		fmt.Println()
		printSkipAccounting(result)
		return
	}

	// IKE SAs.
	fmt.Printf("  IKE SAs:  %d\n", len(result.IKESAs))
	fmt.Printf("  Child SAs: %d pairs\n", result.ChildSAs)
	fmt.Println()

	// Headline.
	if result.Assessment != nil {
		h := result.Assessment.Headline
		fmt.Println("  ┌─────────────────────────────────────────────────┐")
		fmt.Printf("  │  %s\n", h.Label)
		fmt.Printf("  │  Score: %.1f    Coverage: %.1f%%    Risk: %s\n", h.Score, h.Coverage, h.RiskLevel)
		fmt.Printf("  │  Bounds: [%.0f – %.0f]    Confidence: %.2f\n", h.LowerBound, h.UpperBound, h.Confidence)
		fmt.Println("  └─────────────────────────────────────────────────┘")
		fmt.Println()

		// Control table.
		fmt.Println("  Controls:")
		fmt.Println("  ─────────")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  %-5s %-25s %-8s %-8s %s\n", "ID", "Name", "Status", "Sev", "Explanation")
		fmt.Fprintf(w, "  %-5s %-25s %-8s %-8s %s\n", "──", "────", "──────", "───", "───────────")
		for _, c := range result.Assessment.Controls {
			status := statusIcon(c.Status) + " " + string(c.Status)
			sev := string(c.Severity)
			if sev == "" {
				sev = "—"
			}
			fmt.Fprintf(w, "  %-5s %-25s %-8s %-8s %s\n", c.ID, c.Name, status, sev, truncate(c.Explanation, 50))
		}
		w.Flush()
		fmt.Println()

		// Findings.
		if len(result.Assessment.Findings) > 0 {
			fmt.Println("  Findings:")
			fmt.Println("  ─────────")
			for _, f := range result.Assessment.Findings {
				icon := severityIcon(f.Severity)
				fmt.Printf("  %s [%s] %s\n", icon, f.Severity, f.Title)
				if f.FixConfig != "" {
					fmt.Printf("     Fix: %s\n", f.FixConfig)
				}
			}
			fmt.Println()
		}

		// What could not be seen.
		var unseen []string
		for _, c := range result.Assessment.Controls {
			if c.Status == assess.StatusUnknown {
				unseen = append(unseen, fmt.Sprintf("%s (%s)", c.ID, c.Name))
			}
		}
		if len(unseen) > 0 {
			fmt.Println("  What TRACE could not see:")
			fmt.Println("  ─────────────────────────")
			for _, u := range unseen {
				fmt.Printf("    ? %s\n", u)
			}
			fmt.Println()
			fmt.Println("  To improve coverage: provide gateway facts with --gateway")
			fmt.Println("    trace analyze capture.pcap --gateway facts.json")
			fmt.Println()
		}

		// Threat matrix.
		if len(result.Assessment.Threats) > 0 {
			fmt.Println("  Threat Matrix:")
			fmt.Println("  ──────────────")
			w2 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w2, "  %-25s %-12s %-10s %-10s %s\n", "Threat", "Status", "Likely", "Impact", "Controls")
			fmt.Fprintf(w2, "  %-25s %-12s %-10s %-10s %s\n", "──────", "──────", "──────", "──────", "────────")
			for _, t := range result.Assessment.Threats {
				statusStr := threatIcon(t.Status) + " " + string(t.Status)
				fmt.Fprintf(w2, "  %-25s %-12s %-10s %-10s %s\n", t.Name, statusStr, t.Likelihood, t.Impact, strings.Join(t.Controls, ","))
			}
			w2.Flush()
			fmt.Println()
		}
	}

	fmt.Printf("  Policy: %s    IANA: %s    Generated: %s\n",
		result.PolicyID, engine.IANAVersion, result.Generated.Format("2006-01-02 15:04:05"))
	fmt.Println()
}

func printSkipAccounting(result *engine.Result) {
	if len(result.Input.Stats.Skipped) > 0 {
		fmt.Println("  Packet accounting:")
		for reason, count := range result.Input.Stats.Skipped {
			fmt.Printf("    %-25s %d\n", reason, count)
		}
		fmt.Println()
	}
}

func statusIcon(s assess.ControlStatus) string {
	switch s {
	case assess.StatusPass:
		return "✅"
	case assess.StatusFail:
		return "❌"
	case assess.StatusUnknown:
		return "❓"
	case assess.StatusNA:
		return "➖"
	default:
		return "?"
	}
}

func severityIcon(s policy.Severity) string {
	switch s {
	case policy.SevCritical:
		return "🔴"
	case policy.SevHigh:
		return "🟠"
	case policy.SevMedium:
		return "🟡"
	case policy.SevLow:
		return "🔵"
	default:
		return "ℹ️"
	}
}

func threatIcon(s assess.ThreatStatus) string {
	switch s {
	case assess.ThreatExposed:
		return "🔴"
	case assess.ThreatUnverified:
		return "🟡"
	case assess.ThreatMitigated:
		return "🟢"
	default:
		return "?"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func cmdVersion() {
	fmt.Printf("TRACE %s\n", version)
	fmt.Printf("  IANA Registry: %s\n", engine.IANAVersion)
	fmt.Printf("  Policy: %s\n", policy.PolicyVersion)
}

func cmdKeygen() {
	// Simple key generation.
	fmt.Println("Generate an API key using: openssl rand -hex 32")
	fmt.Println("Set it in the environment: TRACE_API_KEYS=<key>")
}

func cmdServe(args []string) {
	addr := ":8443"
	for i := 0; i < len(args); i++ {
		if args[i] == "--addr" && i+1 < len(args) {
			addr = args[i+1]
			i++
		}
	}
	fmt.Printf("TRACE API server — not yet implemented. Would listen on %s\n", addr)
}
