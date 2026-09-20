package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestFixtureScanMatchesRequiredSchema is the end-to-end regression test: the
// recorded fixture is run through the same evaluation code the live providers
// use, and the result must equal the golden report byte for byte.
//
// testdata/expected-report.json is the output schema from the assessment brief,
// so this test also asserts that the tool still emits the required shape --
// including the two forms of "port" (a JSON number for 8080, a string for a
// wildcard).
func TestFixtureScanMatchesRequiredSchema(t *testing.T) {
	cfg := config{
		providers: []string{"aws", "gcp", "azure"},
		fixture:   "testdata/fixture.json",
		timeout:   time.Minute,
	}

	report, meta := scan(context.Background(), cfg)
	if len(meta.Errors) != 0 {
		t.Fatalf("unexpected scan errors: %+v", meta.Errors)
	}

	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	want, err := os.ReadFile("testdata/expected-report.json")
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}

	if string(got)+"\n" != string(want) {
		t.Errorf("report does not match testdata/expected-report.json\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// The fixture deliberately contains compliant resources. If filtering ever
// breaks, these assertions fail before the golden comparison does, pointing at
// the cause rather than at a diff.
func TestFixtureFiltersCompliantResources(t *testing.T) {
	cfg := config{providers: []string{"aws", "gcp", "azure"}, fixture: "testdata/fixture.json", timeout: time.Minute}
	report, meta := scan(context.Background(), cfg)

	if got, want := meta.ResourcesTotal, 9; got != want {
		t.Errorf("examined %d resources, want %d", got, want)
	}
	if got, want := report.ResourcesWithFindings(), 3; got != want {
		t.Errorf("flagged %d resources, want %d (one per provider)", got, want)
	}
	if got, want := report.Findings(), 4; got != want {
		t.Errorf("found %d insecure rules, want %d", got, want)
	}

	for _, sg := range report.AWS.SecurityGroups {
		if sg.Name == "app-tier-sg" || sg.Name == "legacy-sg" {
			t.Errorf("security group %q has only restricted sources and must not be reported", sg.Name)
		}
	}
	for _, fw := range report.GCP.FirewallRules {
		switch fw.Name {
		case "allow-lb-health-checks":
			t.Error("Google health-check ranges are not the internet")
		case "disabled-open-rule":
			t.Error("a disabled firewall rule enforces nothing and must not be reported")
		case "allow-egress-anywhere":
			t.Error("egress rules are out of scope")
		}
	}
	for _, nsg := range report.Azure.NSGs {
		if nsg.Name == "app-nsg" {
			t.Error("app-nsg contains only a Deny, a VirtualNetwork Allow and an Outbound rule")
		}
	}
}

func TestSelectedProvidersOnly(t *testing.T) {
	cfg := config{providers: []string{"aws"}, fixture: "testdata/fixture.json", timeout: time.Minute}
	report, _ := scan(context.Background(), cfg)

	if report.AWS == nil {
		t.Fatal("aws section missing")
	}
	// Unrequested providers are omitted entirely rather than emitted empty: an
	// empty object would read as "scanned, clean".
	if report.GCP != nil || report.Azure != nil {
		t.Error("unrequested providers must be absent from the report")
	}

	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	if _, ok := generic["gcp"]; ok {
		t.Error("gcp key present in JSON for an aws-only scan")
	}
}

func TestMissingFixtureIsReportedNotPanicked(t *testing.T) {
	cfg := config{providers: []string{"aws"}, fixture: "testdata/does-not-exist.json", timeout: time.Minute}
	_, meta := scan(context.Background(), cfg)
	if len(meta.Errors) == 0 {
		t.Fatal("a missing fixture must produce a scan error")
	}
}
