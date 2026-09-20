package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"cloudscan/internal/scanner"
)

// The fixture provider replays recorded API shapes through the *same*
// evaluation functions the live providers use. It exists so that:
//
//   - the tool can be demonstrated and reviewed without three sets of cloud
//     credentials;
//   - the detection logic has an end-to-end regression test, not just unit
//     tests of its parts;
//   - a reviewer can add a case to a JSON file instead of writing Go.
//
// It is not a stub that echoes expected output: the fixtures contain compliant
// resources too, and those must be filtered out by the real logic.

// Fixture mirrors each provider's API response closely enough that the
// translation exercised here is the translation used against the live APIs.
type Fixture struct {
	// Comment lets a fixture carry a note without tripping the strict decoder.
	Comment string `json:"_comment,omitempty"`

	AWS struct {
		Regions map[string][]FixtureSecurityGroup `json:"regions"`
	} `json:"aws"`
	GCP struct {
		Projects map[string][]FixtureFirewall `json:"projects"`
	} `json:"gcp"`
	Azure struct {
		Subscriptions map[string][]FixtureNSG `json:"subscriptions"`
	} `json:"azure"`
}

type FixtureSecurityGroup struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Ingress []struct {
		Protocol   string   `json:"protocol"`
		FromPort   *int32   `json:"from_port"`
		ToPort     *int32   `json:"to_port"`
		IPv4Ranges []string `json:"ipv4_ranges"`
		IPv6Ranges []string `json:"ipv6_ranges"`
	} `json:"ingress"`
}

type FixtureFirewall struct {
	Name         string   `json:"name"`
	Network      string   `json:"network"`
	Direction    string   `json:"direction"`
	Disabled     bool     `json:"disabled"`
	SourceRanges []string `json:"source_ranges"`
	Allowed      []struct {
		Protocol string   `json:"protocol"`
		Ports    []string `json:"ports"`
	} `json:"allowed"`
}

type FixtureNSG struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Rules []struct {
		Name                  string   `json:"name"`
		Direction             string   `json:"direction"`
		Access                string   `json:"access"`
		Protocol              string   `json:"protocol"`
		DestinationPortRange  string   `json:"destination_port_range"`
		DestinationPortRanges []string `json:"destination_port_ranges"`
		SourceAddressPrefix   string   `json:"source_address_prefix"`
		SourceAddressPrefixes []string `json:"source_address_prefixes"`
	} `json:"security_rules"`
}

// LoadFixture reads a fixture file from disk.
func LoadFixture(path string) (*Fixture, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fixture: %w", err)
	}
	var f Fixture
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(b)))
	dec.DisallowUnknownFields() // a typo'd fixture key should fail loudly
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse fixture %s: %w", path, err)
	}
	return &f, nil
}

// ScanFixtureAWS evaluates the recorded AWS data.
func ScanFixtureAWS(f *Fixture) (*scanner.AWSSection, Outcome) {
	var out Outcome
	section := &scanner.AWSSection{SecurityGroups: []scanner.SecurityGroup{}}
	multiRegion := len(f.AWS.Regions) > 1

	for _, region := range sortedKeys(f.AWS.Regions) {
		for _, sg := range f.AWS.Regions[region] {
			out.Examined++
			var findings []scanner.Rule
			for _, perm := range sg.Ingress {
				findings = append(findings, scanner.EvaluateAWSPermission(
					perm.Protocol, perm.FromPort, perm.ToPort, perm.IPv4Ranges, perm.IPv6Ranges,
				)...)
			}
			if len(findings) == 0 {
				continue
			}
			entry := scanner.SecurityGroup{ID: sg.ID, Name: sg.Name, InsecureRules: findings}
			if multiRegion {
				entry.Region = region
			}
			section.SecurityGroups = append(section.SecurityGroups, entry)
		}
	}
	return section, out
}

// ScanFixtureGCP evaluates the recorded GCP data.
func ScanFixtureGCP(f *Fixture) (*scanner.GCPSection, Outcome) {
	var out Outcome
	section := &scanner.GCPSection{FirewallRules: []scanner.FirewallRule{}}
	multiProject := len(f.GCP.Projects) > 1

	for _, project := range sortedKeys(f.GCP.Projects) {
		for _, fw := range f.GCP.Projects[project] {
			out.Examined++
			if (fw.Direction != "" && fw.Direction != "INGRESS") || fw.Disabled {
				continue
			}
			var findings []scanner.Rule
			for _, allowed := range fw.Allowed {
				findings = append(findings, scanner.EvaluateGCPAllowed(
					allowed.Protocol, allowed.Ports, fw.SourceRanges,
				)...)
			}
			if len(findings) == 0 {
				continue
			}
			entry := scanner.FirewallRule{Name: fw.Name, Network: fw.Network, InsecureRules: findings}
			if multiProject {
				entry.Project = project
			}
			section.FirewallRules = append(section.FirewallRules, entry)
		}
	}
	return section, out
}

// ScanFixtureAzure evaluates the recorded Azure data.
func ScanFixtureAzure(f *Fixture) (*scanner.AzureSection, Outcome) {
	var out Outcome
	section := &scanner.AzureSection{NSGs: []scanner.NetworkSecurityGroup{}}

	for _, sub := range sortedKeys(f.Azure.Subscriptions) {
		for _, nsg := range f.Azure.Subscriptions[sub] {
			out.Examined++
			var findings []scanner.Rule
			for _, rule := range nsg.Rules {
				findings = append(findings, scanner.EvaluateAzureRule(
					rule.Direction, rule.Access, rule.Protocol,
					rule.DestinationPortRange, rule.DestinationPortRanges,
					rule.SourceAddressPrefix, rule.SourceAddressPrefixes,
				)...)
			}
			if len(findings) == 0 {
				continue
			}
			section.NSGs = append(section.NSGs, scanner.NetworkSecurityGroup{
				ID: nsg.ID, Name: nsg.Name, InsecureRules: findings,
			})
		}
	}
	return section, out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
