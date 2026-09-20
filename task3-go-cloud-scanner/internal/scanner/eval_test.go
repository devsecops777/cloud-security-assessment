package scanner

import (
	"encoding/json"
	"testing"
)

func i32(v int32) *int32 { return &v }

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestEvaluateAWSPermission(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		from, to *int32
		ipv4     []string
		ipv6     []string
		want     string
	}{
		{
			name: "open tcp port", protocol: "tcp", from: i32(8080), to: i32(8080),
			ipv4: []string{"0.0.0.0/0"},
			want: `[{"protocol":"tcp","port":8080,"source":"0.0.0.0/0"}]`,
		},
		{
			name: "all protocols means all ports", protocol: "-1",
			ipv4: []string{"0.0.0.0/0"},
			want: `[{"protocol":"*","port":"*","source":"0.0.0.0/0"}]`,
		},
		{
			name: "ipv6 any is equally open", protocol: "tcp", from: i32(22), to: i32(22),
			ipv6: []string{"::/0"},
			want: `[{"protocol":"tcp","port":22,"source":"::/0"}]`,
		},
		{
			name: "port range preserved", protocol: "tcp", from: i32(8000), to: i32(9000),
			ipv4: []string{"0.0.0.0/0"},
			want: `[{"protocol":"tcp","port":"8000-9000","source":"0.0.0.0/0"}]`,
		},
		{
			name: "full range collapses to wildcard", protocol: "tcp", from: i32(0), to: i32(65535),
			ipv4: []string{"0.0.0.0/0"},
			want: `[{"protocol":"tcp","port":"*","source":"0.0.0.0/0"}]`,
		},
		{
			name: "restricted cidr is not a finding", protocol: "tcp", from: i32(22), to: i32(22),
			ipv4: []string{"10.0.0.0/8", "203.0.113.0/24"},
			want: `null`,
		},
		{
			name: "mixed sources report only the open one", protocol: "tcp", from: i32(443), to: i32(443),
			ipv4: []string{"10.0.0.0/8", "0.0.0.0/0"},
			want: `[{"protocol":"tcp","port":443,"source":"0.0.0.0/0"}]`,
		},
		{
			name: "no sources at all", protocol: "tcp", from: i32(443), to: i32(443),
			want: `null`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mustJSON(t, EvaluateAWSPermission(c.protocol, c.from, c.to, c.ipv4, c.ipv6))
			if got != c.want {
				t.Errorf("got  %s\nwant %s", got, c.want)
			}
		})
	}
}

func TestEvaluateGCPAllowed(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		ports    []string
		sources  []string
		want     string
	}{
		{
			name: "icmp with no ports", protocol: "icmp", sources: []string{"0.0.0.0/0"},
			want: `[{"protocol":"icmp","port":"all","source":"0.0.0.0/0"}]`,
		},
		{
			name: "all protocols", protocol: "all", sources: []string{"0.0.0.0/0"},
			want: `[{"protocol":"*","port":"all","source":"0.0.0.0/0"}]`,
		},
		{
			name: "multiple ports produce multiple findings", protocol: "tcp",
			ports: []string{"22", "3389"}, sources: []string{"0.0.0.0/0"},
			want: `[{"protocol":"tcp","port":22,"source":"0.0.0.0/0"},{"protocol":"tcp","port":3389,"source":"0.0.0.0/0"}]`,
		},
		{
			name: "range port", protocol: "tcp", ports: []string{"8000-9000"},
			sources: []string{"0.0.0.0/0"},
			want:    `[{"protocol":"tcp","port":"8000-9000","source":"0.0.0.0/0"}]`,
		},
		{
			name: "health check range is not the internet", protocol: "tcp", ports: []string{"80"},
			sources: []string{"35.191.0.0/16", "130.211.0.0/22"},
			want:    `null`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mustJSON(t, EvaluateGCPAllowed(c.protocol, c.ports, c.sources))
			if got != c.want {
				t.Errorf("got  %s\nwant %s", got, c.want)
			}
		})
	}
}

func TestEvaluateAzureRule(t *testing.T) {
	cases := []struct {
		name                        string
		direction, access, protocol string
		portRange                   string
		portRanges                  []string
		srcPrefix                   string
		srcPrefixes                 []string
		want                        string
	}{
		{
			name: "wildcard everything", direction: "Inbound", access: "Allow",
			protocol: "*", portRange: "*", srcPrefix: "*",
			want: `[{"protocol":"*","port":"*","source":"*"}]`,
		},
		{
			name: "internet service tag", direction: "Inbound", access: "Allow",
			protocol: "Tcp", portRange: "3389", srcPrefix: "Internet",
			want: `[{"protocol":"tcp","port":3389,"source":"Internet"}]`,
		},
		{
			name: "explicit deny is not a finding", direction: "Inbound", access: "Deny",
			protocol: "*", portRange: "*", srcPrefix: "*",
			want: `null`,
		},
		{
			name: "outbound is not a finding", direction: "Outbound", access: "Allow",
			protocol: "*", portRange: "*", srcPrefix: "*",
			want: `null`,
		},
		{
			name: "virtual network tag is internal", direction: "Inbound", access: "Allow",
			protocol: "Tcp", portRange: "445", srcPrefix: "VirtualNetwork",
			want: `null`,
		},
		{
			name: "plural ports and prefixes", direction: "Inbound", access: "Allow",
			protocol: "Tcp", portRanges: []string{"80", "443"},
			srcPrefixes: []string{"10.0.0.0/8", "0.0.0.0/0"},
			want:        `[{"protocol":"tcp","port":80,"source":"0.0.0.0/0"},{"protocol":"tcp","port":443,"source":"0.0.0.0/0"}]`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mustJSON(t, EvaluateAzureRule(c.direction, c.access, c.protocol, c.portRange, c.portRanges, c.srcPrefix, c.srcPrefixes))
			if got != c.want {
				t.Errorf("got  %s\nwant %s", got, c.want)
			}
		})
	}
}
