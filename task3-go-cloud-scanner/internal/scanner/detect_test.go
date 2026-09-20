package scanner

import (
	"encoding/json"
	"testing"
)

func TestIsInternetSource(t *testing.T) {
	open := []string{
		"0.0.0.0/0",
		" 0.0.0.0/0 ", // providers and humans both add whitespace
		"::/0",
		"*",        // Azure wildcard
		"Any",      // Azure NSG source
		"Internet", // Azure service tag
		"internet", //
		"0.0.0.0",  // bare "anywhere" as some consoles render it
	}
	for _, s := range open {
		if !IsInternetSource(s) {
			t.Errorf("IsInternetSource(%q) = false, want true", s)
		}
	}

	closed := []string{
		"",
		"10.0.0.0/8",
		"192.168.1.0/24",
		"203.0.113.42/32",
		"0.0.0.0/1",         // wide but bounded: a different finding, see detect.go
		"VirtualNetwork",    // Azure service tag, internal
		"AzureLoadBalancer", // Azure infrastructure tag
		"35.191.0.0/16",     // Google health-check range
		"not-a-cidr",
		"2001:db8::/32",
	}
	for _, s := range closed {
		if IsInternetSource(s) {
			t.Errorf("IsInternetSource(%q) = true, want false", s)
		}
	}
}

func TestAnyInternetSource(t *testing.T) {
	got, ok := AnyInternetSource([]string{"10.0.0.0/8", "0.0.0.0/0"})
	if !ok || got != "0.0.0.0/0" {
		t.Fatalf("got (%q, %v), want (\"0.0.0.0/0\", true)", got, ok)
	}
	if _, ok := AnyInternetSource([]string{"10.0.0.0/8", "172.16.0.0/12"}); ok {
		t.Fatal("private ranges must not be reported as internet-facing")
	}
	if _, ok := AnyInternetSource(nil); ok {
		t.Fatal("empty source list must not be reported as internet-facing")
	}
}

func TestNormalizeProtocol(t *testing.T) {
	cases := map[string]string{
		"-1":   "*", // AWS "all protocols"
		"all":  "*", // GCP
		"Any":  "*", // Azure
		"*":    "*",
		"":     "*",
		"tcp":  "tcp",
		"Tcp":  "tcp", // Azure casing
		"UDP":  "udp",
		"icmp": "icmp",
	}
	for in, want := range cases {
		if got := NormalizeProtocol(in); got != want {
			t.Errorf("NormalizeProtocol(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPortMarshalling(t *testing.T) {
	cases := []struct {
		port Port
		want string
	}{
		{PortNumber(8080), `8080`},   // required schema uses a number here
		{PortAny(), `"*"`},           // ... and a string here
		{PortText("all"), `"all"`},   // GCP's spelling, preserved
		{PortRange(0, 65535), `"*"`}, // a full range collapses to the wildcard
		{PortRange(80, 80), `80`},    // a one-port range is a number
		{PortRange(8000, 9000), `"8000-9000"`},
		{ParsePort("123"), `123`},
		{ParsePort("*"), `"*"`},
		{ParsePort("8000-9000"), `"8000-9000"`},
	}
	for _, c := range cases {
		b, err := json.Marshal(c.port)
		if err != nil {
			t.Fatalf("marshal %v: %v", c.port, err)
		}
		if string(b) != c.want {
			t.Errorf("marshal(%v) = %s, want %s", c.port, b, c.want)
		}
	}
}

func TestPortRoundTrip(t *testing.T) {
	for _, raw := range []string{`8080`, `"*"`, `"8000-9000"`} {
		var p Port
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			t.Fatalf("unmarshal %s: %v", raw, err)
		}
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal back: %v", err)
		}
		if string(b) != raw {
			t.Errorf("round trip %s -> %s", raw, b)
		}
	}
}
