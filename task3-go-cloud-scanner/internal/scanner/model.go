// Package scanner holds the provider-neutral report model and the rules that
// decide whether a firewall rule is open to the internet.
//
// Provider SDK types stop at the package boundary: providers translate into
// these structs, so the detection logic is testable without any cloud
// credentials and the JSON shape is defined in exactly one place.
package scanner

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Report is the top-level document written to stdout. Sections are pointers so
// that a provider which was not requested is omitted entirely rather than
// rendered as an empty object, which would be indistinguishable from "scanned,
// found nothing".
type Report struct {
	AWS   *AWSSection   `json:"aws,omitempty"`
	GCP   *GCPSection   `json:"gcp,omitempty"`
	Azure *AzureSection `json:"azure,omitempty"`

	// Metadata is suppressed unless --include-metadata is passed, so the default
	// output matches the required schema byte for byte.
	Metadata *Metadata `json:"scan_metadata,omitempty"`
}

type AWSSection struct {
	SecurityGroups []SecurityGroup `json:"security_groups"`
}

type GCPSection struct {
	FirewallRules []FirewallRule `json:"firewall_rules"`
}

type AzureSection struct {
	NSGs []NetworkSecurityGroup `json:"nsgs"`
}

// SecurityGroup is one AWS EC2 security group that has at least one rule open
// to the internet.
type SecurityGroup struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	InsecureRules []Rule `json:"insecure_rules"`

	// Region is emitted only when more than one region was scanned; a group ID
	// is unique per region, not globally.
	Region string `json:"region,omitempty"`
}

// FirewallRule is one GCP VPC firewall rule open to the internet.
type FirewallRule struct {
	Name          string `json:"name"`
	Network       string `json:"network"`
	InsecureRules []Rule `json:"insecure_rules"`

	Project string `json:"project,omitempty"`
}

// NetworkSecurityGroup is one Azure NSG open to the internet.
type NetworkSecurityGroup struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	InsecureRules []Rule `json:"insecure_rules"`
}

// Rule is a single offending permission, normalised across the three providers.
type Rule struct {
	Protocol string `json:"protocol"`
	Port     Port   `json:"port"`
	Source   string `json:"source"`
}

// Metadata is optional provenance: when the scan ran, what it covered, and what
// failed. Errors live here rather than on stderr alone so that a scan feeding a
// dashboard cannot silently report "no findings" when a provider call failed.
type Metadata struct {
	StartedAt       string      `json:"started_at"`
	DurationMS      int64       `json:"duration_ms"`
	ProvidersOK     []string    `json:"providers_scanned"`
	ResourcesTotal  int         `json:"resources_examined"`
	FindingsTotal   int         `json:"insecure_rules_found"`
	ResourcesOpen   int         `json:"resources_with_findings"`
	Errors          []ScanError `json:"errors,omitempty"`
	ToolVersion     string      `json:"tool_version"`
	IncludesIPv6Any bool        `json:"includes_ipv6_any"`
}

// ScanError records a provider that could not be scanned. A failure in one
// provider never aborts the others.
type ScanError struct {
	Provider string `json:"provider"`
	Scope    string `json:"scope,omitempty"`
	Message  string `json:"message"`
}

// Port renders as a JSON number for a concrete port (8080) and as a string for
// anything else ("*", "all", "8000-9000"), matching the required output format,
// which uses both forms.
type Port struct {
	number  int
	text    string
	numeric bool
}

// PortNumber returns a Port that marshals as a JSON number.
func PortNumber(n int) Port { return Port{number: n, numeric: true} }

// PortText returns a Port that marshals as a JSON string.
func PortText(s string) Port { return Port{text: s} }

// PortAny is the wildcard used when a rule covers every port.
func PortAny() Port { return Port{text: "*"} }

// ParsePort turns a provider's port expression into a Port, preferring the
// numeric form when the whole expression is a single port.
func ParsePort(s string) Port {
	switch s {
	case "", "*", "any", "Any", "ALL", "all", "0-65535", "1-65535":
		return PortAny()
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 65535 {
		return PortNumber(n)
	}
	return PortText(s)
}

// PortRange collapses a provider's from/to pair. A range that spans every port
// is reported as the wildcard rather than "0-65535", so that output from the
// three providers is comparable.
func PortRange(from, to int) Port {
	switch {
	case from <= 0 && to >= 65535:
		return PortAny()
	case from == to:
		return PortNumber(from)
	default:
		return PortText(fmt.Sprintf("%d-%d", from, to))
	}
}

func (p Port) MarshalJSON() ([]byte, error) {
	if p.numeric {
		return json.Marshal(p.number)
	}
	if p.text == "" {
		return json.Marshal("*")
	}
	return json.Marshal(p.text)
}

// UnmarshalJSON accepts either form, so fixtures and previous reports round-trip.
func (p *Port) UnmarshalJSON(b []byte) error {
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*p = PortNumber(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("port must be a number or a string: %w", err)
	}
	*p = PortText(s)
	return nil
}

// String renders the port the way a human would write it.
func (p Port) String() string {
	if p.numeric {
		return strconv.Itoa(p.number)
	}
	if p.text == "" {
		return "*"
	}
	return p.text
}

// Findings counts every insecure rule in the report.
func (r *Report) Findings() int {
	n := 0
	if r.AWS != nil {
		for _, sg := range r.AWS.SecurityGroups {
			n += len(sg.InsecureRules)
		}
	}
	if r.GCP != nil {
		for _, fw := range r.GCP.FirewallRules {
			n += len(fw.InsecureRules)
		}
	}
	if r.Azure != nil {
		for _, nsg := range r.Azure.NSGs {
			n += len(nsg.InsecureRules)
		}
	}
	return n
}

// ResourcesWithFindings counts distinct resources rather than rules.
func (r *Report) ResourcesWithFindings() int {
	n := 0
	if r.AWS != nil {
		n += len(r.AWS.SecurityGroups)
	}
	if r.GCP != nil {
		n += len(r.GCP.FirewallRules)
	}
	if r.Azure != nil {
		n += len(r.Azure.NSGs)
	}
	return n
}
