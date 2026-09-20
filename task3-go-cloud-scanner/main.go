// cloudscan finds firewall and security group rules that are open to the whole
// internet across AWS, GCP and Azure, and prints them as JSON.
//
//	cloudscan                                  # every configured provider
//	cloudscan -providers aws,gcp               # a subset
//	cloudscan -fixture testdata/fixture.json   # offline demo, no credentials
//	cloudscan -fail-on-findings -out report.json
//
// Exit codes:
//
//	0  scan completed, nothing to report (or findings without -fail-on-findings)
//	1  insecure rules found and -fail-on-findings was set
//	2  the scan could not run or the report could not be written
//	3  at least one provider failed; the report contains partial results
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"cloudscan/internal/providers"
	"cloudscan/internal/scanner"
)

const version = "1.0.0"

type config struct {
	providers       []string
	awsRegions      []string
	gcpProjects     []string
	azureSubs       []string
	azureDefaults   bool
	fixture         string
	out             string
	compact         bool
	includeMetadata bool
	failOnFindings  bool
	timeout         time.Duration
}

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cloudscan: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	started := time.Now()
	report, meta := scan(ctx, cfg)

	if cfg.includeMetadata {
		meta.StartedAt = started.UTC().Format(time.RFC3339)
		meta.DurationMS = time.Since(started).Milliseconds()
		meta.FindingsTotal = report.Findings()
		meta.ResourcesOpen = report.ResourcesWithFindings()
		meta.ToolVersion = version
		meta.IncludesIPv6Any = true
		report.Metadata = meta
	}

	if err := write(cfg, report); err != nil {
		fmt.Fprintf(os.Stderr, "cloudscan: %v\n", err)
		return 2
	}

	// Errors always reach stderr, even when metadata is suppressed, so a failed
	// provider can never be mistaken for a clean result.
	for _, e := range meta.Errors {
		scope := e.Provider
		if e.Scope != "" {
			scope = e.Provider + "/" + e.Scope
		}
		fmt.Fprintf(os.Stderr, "cloudscan: %s: %s\n", scope, e.Message)
	}

	switch {
	case len(meta.Errors) > 0:
		return 3
	case cfg.failOnFindings && report.Findings() > 0:
		return 1
	default:
		return 0
	}
}

// scan runs the selected providers concurrently. One slow or failing provider
// never blocks or fails the others.
func scan(ctx context.Context, cfg config) (*scanner.Report, *scanner.Metadata) {
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		report = &scanner.Report{}
		meta   = &scanner.Metadata{}
	)

	var fixture *providers.Fixture
	if cfg.fixture != "" {
		f, err := providers.LoadFixture(cfg.fixture)
		if err != nil {
			meta.Errors = append(meta.Errors, scanner.ScanError{Provider: "fixture", Message: err.Error()})
			return report, meta
		}
		fixture = f
	}

	record := func(name string, out providers.Outcome) {
		meta.ResourcesTotal += out.Examined
		meta.Errors = append(meta.Errors, out.Errors...)
		if len(out.Errors) == 0 {
			meta.ProvidersOK = append(meta.ProvidersOK, name)
		}
	}

	for _, name := range cfg.providers {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()

			switch name {
			case "aws":
				var (
					section *scanner.AWSSection
					outcome providers.Outcome
				)
				if fixture != nil {
					section, outcome = providers.ScanFixtureAWS(fixture)
				} else {
					section, outcome = providers.ScanAWS(ctx, cfg.awsRegions)
				}
				mu.Lock()
				report.AWS = section
				record(name, outcome)
				mu.Unlock()

			case "gcp":
				var (
					section *scanner.GCPSection
					outcome providers.Outcome
				)
				if fixture != nil {
					section, outcome = providers.ScanFixtureGCP(fixture)
				} else {
					section, outcome = providers.ScanGCP(ctx, cfg.gcpProjects)
				}
				mu.Lock()
				report.GCP = section
				record(name, outcome)
				mu.Unlock()

			case "azure":
				var (
					section *scanner.AzureSection
					outcome providers.Outcome
				)
				if fixture != nil {
					section, outcome = providers.ScanFixtureAzure(fixture)
				} else {
					section, outcome = providers.ScanAzure(ctx, cfg.azureSubs, cfg.azureDefaults)
				}
				mu.Lock()
				report.Azure = section
				record(name, outcome)
				mu.Unlock()
			}
		}(name)
	}

	wg.Wait()
	sort.Strings(meta.ProvidersOK)
	return report, meta
}

func write(cfg config, report *scanner.Report) error {
	out := os.Stdout
	if cfg.out != "" {
		// 0600: a findings report is a map of where the account is weakest.
		f, err := os.OpenFile(cfg.out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("open output: %w", err)
		}
		defer f.Close()
		out = f
	}

	enc := json.NewEncoder(out)
	if !cfg.compact {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func parseFlags() (config, error) {
	var (
		cfg         config
		provList    = flag.String("providers", "aws,gcp,azure", "comma-separated providers to scan: aws, gcp, azure")
		awsRegions  = flag.String("aws-regions", "", "comma-separated AWS regions (default: every region the account has enabled)")
		gcpProjects = flag.String("gcp-projects", "", "comma-separated GCP project IDs (default: $GOOGLE_CLOUD_PROJECT)")
		azureSubs   = flag.String("azure-subscriptions", "", "comma-separated Azure subscription IDs (default: $AZURE_SUBSCRIPTION_ID)")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.BoolVar(&cfg.azureDefaults, "azure-default-rules", false, "also evaluate Azure's built-in default NSG rules")
	flag.StringVar(&cfg.fixture, "fixture", "", "scan a recorded fixture file instead of live APIs (no credentials needed)")
	flag.StringVar(&cfg.out, "out", "", "write the report to this file instead of stdout (created with mode 0600)")
	flag.BoolVar(&cfg.compact, "compact", false, "emit single-line JSON instead of indented")
	flag.BoolVar(&cfg.includeMetadata, "include-metadata", false, "add a scan_metadata object with counts, timings and provider errors")
	flag.BoolVar(&cfg.failOnFindings, "fail-on-findings", false, "exit 1 when any insecure rule is found (for CI gates)")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Minute, "overall deadline for the scan")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"cloudscan %s - find firewall rules open to 0.0.0.0/0 across AWS, GCP and Azure.\n\nUsage:\n  cloudscan [flags]\n\nFlags:\n", version)
		flag.PrintDefaults()
		fmt.Fprint(flag.CommandLine.Output(), `
Exit codes:
  0  completed, nothing to report
  1  insecure rules found (only with -fail-on-findings)
  2  the scan could not run
  3  a provider failed; the report holds partial results

Credentials are read from each SDK's default chain and are never accepted as
flags. See README.md for the required read-only permissions.
`)
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("cloudscan %s\n", version)
		os.Exit(0)
	}

	cfg.providers = splitList(*provList)
	if len(cfg.providers) == 0 {
		return cfg, errors.New("-providers must name at least one of: aws, gcp, azure")
	}
	for _, p := range cfg.providers {
		switch p {
		case "aws", "gcp", "azure":
		default:
			return cfg, fmt.Errorf("unknown provider %q (want aws, gcp or azure)", p)
		}
	}
	if cfg.timeout <= 0 {
		return cfg, errors.New("-timeout must be positive")
	}

	cfg.awsRegions = splitList(*awsRegions)
	cfg.gcpProjects = splitList(*gcpProjects)
	cfg.azureSubs = splitList(*azureSubs)
	return cfg, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, strings.ToLower(p))
		}
	}
	return out
}
