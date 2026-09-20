package providers

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"cloudscan/internal/scanner"
)

// ScanGCP lists VPC firewall rules and reports every ingress rule whose source
// ranges include the whole internet.
//
// Credentials come from Application Default Credentials: GOOGLE_APPLICATION_
// CREDENTIALS, gcloud user credentials, or the attached service account on a
// GCE/GKE workload.
//
// Required IAM: roles/compute.networkViewer (or compute.firewalls.list).
func ScanGCP(ctx context.Context, projects []string) (*scanner.GCPSection, Outcome) {
	var out Outcome
	section := &scanner.GCPSection{FirewallRules: []scanner.FirewallRule{}}

	if len(projects) == 0 {
		if p := firstNonEmptyEnv("GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT"); p != "" {
			projects = []string{p}
		}
	}
	if len(projects) == 0 {
		out.fail("gcp", "", fmt.Errorf("no project supplied: pass -gcp-projects or set GOOGLE_CLOUD_PROJECT"))
		return section, out
	}

	// Read-only scope: the tool cannot mutate a firewall even if it is asked to.
	svc, err := compute.NewService(ctx, option.WithScopes(compute.ComputeReadonlyScope))
	if err != nil {
		out.fail("gcp", "", fmt.Errorf("create compute client: %w", err))
		return section, out
	}

	multiProject := len(projects) > 1

	for _, project := range projects {
		err := svc.Firewalls.List(project).Pages(ctx, func(page *compute.FirewallList) error {
			for _, fw := range page.Items {
				out.Examined++
				if findings := evaluateFirewall(fw); len(findings) > 0 {
					entry := scanner.FirewallRule{
						Name:          fw.Name,
						Network:       lastPathSegment(fw.Network),
						InsecureRules: findings,
					}
					if multiProject {
						entry.Project = project
					}
					section.FirewallRules = append(section.FirewallRules, entry)
				}
			}
			return nil
		})
		if err != nil {
			out.fail("gcp", project, err)
		}
	}

	sort.Slice(section.FirewallRules, func(i, j int) bool {
		a, b := section.FirewallRules[i], section.FirewallRules[j]
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		return a.Name < b.Name
	})
	return section, out
}

func evaluateFirewall(fw *compute.Firewall) []scanner.Rule {
	// An empty Direction means INGRESS in the API's default.
	if fw.Direction != "" && !strings.EqualFold(fw.Direction, "INGRESS") {
		return nil
	}
	// A disabled rule enforces nothing. Reporting it would train people to
	// ignore the tool's output.
	if fw.Disabled {
		return nil
	}
	// A rule with "denied" blocks rather than permits.
	if len(fw.Allowed) == 0 {
		return nil
	}

	var findings []scanner.Rule
	for _, allowed := range fw.Allowed {
		findings = append(findings, scanner.EvaluateGCPAllowed(
			allowed.IPProtocol,
			allowed.Ports,
			fw.SourceRanges,
		)...)
	}
	return findings
}

// lastPathSegment turns a self link such as
// https://www.googleapis.com/compute/v1/projects/p/global/networks/default
// into "default".
func lastPathSegment(url string) string {
	if url == "" {
		return ""
	}
	if i := strings.LastIndex(url, "/"); i >= 0 && i+1 < len(url) {
		return url[i+1:]
	}
	return url
}

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}
