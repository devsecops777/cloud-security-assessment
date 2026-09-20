package scanner

import "strings"

// The three Evaluate* functions below are the whole decision layer. They take
// plain Go types, never SDK structs, so that:
//
//   - the real providers and the offline fixture provider run identical code;
//   - every provider quirk is unit-testable without credentials.
//
// Each returns one Rule per (protocol, port, offending source) combination, or
// nil when the rule is not internet-facing.

// EvaluateAWSPermission handles one entry of a security group's IpPermissions.
//
// AWS quirks encoded here:
//   - IpProtocol "-1" means every protocol, and in that case FromPort/ToPort are
//     absent rather than 0-65535.
//   - nil ports for a named protocol also mean "every port".
//   - IPv6 is a separate list; ::/0 is exactly as open as 0.0.0.0/0 and an
//     IPv4-only check is the classic way to miss a wide-open group.
func EvaluateAWSPermission(protocol string, fromPort, toPort *int32, ipv4Ranges, ipv6Ranges []string) []Rule {
	sources := openSources(append(append([]string{}, ipv4Ranges...), ipv6Ranges...))
	if len(sources) == 0 {
		return nil
	}

	proto := NormalizeProtocol(protocol)
	port := PortAny()
	if !IsAllProtocols(proto) && fromPort != nil && toPort != nil {
		port = PortRange(int(*fromPort), int(*toPort))
	}

	rules := make([]Rule, 0, len(sources))
	for _, src := range sources {
		rules = append(rules, Rule{Protocol: proto, Port: port, Source: src})
	}
	return rules
}

// EvaluateGCPAllowed handles one entry of a firewall rule's "allowed" block.
//
// GCP quirks encoded here:
//   - an empty ports list means every port for that protocol;
//   - IPProtocol "all" means every protocol, and then ports must be empty;
//   - a port entry may itself be a range such as "8000-9000".
//
// Direction and the disabled flag are filtered by the caller, since they belong
// to the firewall rule rather than to a single allow entry.
func EvaluateGCPAllowed(protocol string, ports []string, sourceRanges []string) []Rule {
	sources := openSources(sourceRanges)
	if len(sources) == 0 {
		return nil
	}

	proto := NormalizeProtocol(protocol)

	// GCP omits "ports" to mean every port, and spells that "all" in its own
	// API vocabulary (IPProtocol: "all"). The report keeps that spelling here
	// rather than the "*" used for AWS and Azure, because it is what the
	// provider itself says and what the required output schema shows. See
	// README.md, "Output schema notes".
	portList := []Port{PortText("all")}
	if len(ports) > 0 && !IsAllProtocols(proto) {
		portList = portList[:0]
		for _, p := range ports {
			portList = append(portList, ParsePort(p))
		}
	}

	rules := make([]Rule, 0, len(sources)*len(portList))
	for _, src := range sources {
		for _, p := range portList {
			rules = append(rules, Rule{Protocol: proto, Port: p, Source: src})
		}
	}
	return rules
}

// EvaluateAzureRule handles one NSG security rule, including the built-in
// default rules.
//
// Azure quirks encoded here:
//   - direction and access are part of the rule, so an outbound rule or an
//     explicit Deny must not be reported;
//   - the source is singular or plural (SourceAddressPrefix /
//     SourceAddressPrefixes) and is frequently a service tag such as
//     "Internet" or "*" rather than a CIDR;
//   - ports are likewise singular or plural, and "*" means every port.
//
// The built-in DenyAllInBound and AllowInternetOutBound rules are correctly
// ignored: the first is a Deny, the second is Outbound.
func EvaluateAzureRule(direction, access, protocol, portRange string, portRanges []string, srcPrefix string, srcPrefixes []string) []Rule {
	if !strings.EqualFold(direction, "Inbound") || !strings.EqualFold(access, "Allow") {
		return nil
	}

	candidates := srcPrefixes
	if srcPrefix != "" {
		candidates = append([]string{srcPrefix}, candidates...)
	}
	sources := openSources(candidates)
	if len(sources) == 0 {
		return nil
	}

	proto := NormalizeProtocol(protocol)

	portList := []Port{}
	if portRange != "" {
		portList = append(portList, ParsePort(portRange))
	}
	for _, p := range portRanges {
		if p = strings.TrimSpace(p); p != "" {
			portList = append(portList, ParsePort(p))
		}
	}
	if len(portList) == 0 {
		portList = append(portList, PortAny())
	}

	rules := make([]Rule, 0, len(sources)*len(portList))
	for _, src := range sources {
		for _, p := range portList {
			rules = append(rules, Rule{Protocol: proto, Port: p, Source: src})
		}
	}
	return rules
}

// openSources filters a source list down to the internet-wide entries,
// preserving each one as written so the report names what is actually
// configured. Duplicates are collapsed.
func openSources(candidates []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" || !IsInternetSource(c) || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}
