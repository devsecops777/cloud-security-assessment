package providers

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"cloudscan/internal/scanner"
)

// ScanAzure lists Network Security Groups across a subscription and reports
// every inbound Allow rule whose source is the internet.
//
// Credentials come from DefaultAzureCredential: environment variables, workload
// identity, managed identity, or an `az login` session.
//
// Required role: Reader on the subscription (or a custom role with
// Microsoft.Network/networkSecurityGroups/read).
func ScanAzure(ctx context.Context, subscriptions []string, includeDefaultRules bool) (*scanner.AzureSection, Outcome) {
	var out Outcome
	section := &scanner.AzureSection{NSGs: []scanner.NetworkSecurityGroup{}}

	if len(subscriptions) == 0 {
		if s := firstNonEmptyEnv("AZURE_SUBSCRIPTION_ID"); s != "" {
			subscriptions = []string{s}
		}
	}
	if len(subscriptions) == 0 {
		out.fail("azure", "", fmt.Errorf("no subscription supplied: pass -azure-subscriptions or set AZURE_SUBSCRIPTION_ID"))
		return section, out
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		out.fail("azure", "", fmt.Errorf("acquire credential: %w", err))
		return section, out
	}

	for _, sub := range subscriptions {
		client, err := armnetwork.NewSecurityGroupsClient(sub, cred, nil)
		if err != nil {
			out.fail("azure", sub, fmt.Errorf("create client: %w", err))
			continue
		}

		pager := client.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				out.fail("azure", sub, err)
				break
			}
			for _, nsg := range page.Value {
				if nsg == nil {
					continue
				}
				out.Examined++
				if findings := evaluateNSG(nsg, includeDefaultRules); len(findings) > 0 {
					section.NSGs = append(section.NSGs, scanner.NetworkSecurityGroup{
						ID:            derefString(nsg.ID),
						Name:          derefString(nsg.Name),
						InsecureRules: findings,
					})
				}
			}
		}
	}

	sort.Slice(section.NSGs, func(i, j int) bool {
		return section.NSGs[i].ID < section.NSGs[j].ID
	})
	return section, out
}

func evaluateNSG(nsg *armnetwork.SecurityGroup, includeDefaultRules bool) []scanner.Rule {
	if nsg.Properties == nil {
		return nil
	}

	rules := nsg.Properties.SecurityRules
	if includeDefaultRules {
		// The built-in rules are off by default: AllowVnetInBound and
		// AllowAzureLoadBalancerInBound are not internet-facing, and
		// DenyAllInBound is a deny -- so the platform defaults produce no
		// findings anyway. They are worth including when auditing whether a
		// custom rule has *overridden* a default at a lower priority number.
		rules = append(append([]*armnetwork.SecurityRule{}, rules...), nsg.Properties.DefaultSecurityRules...)
	}

	var findings []scanner.Rule
	for _, rule := range rules {
		if rule == nil || rule.Properties == nil {
			continue
		}
		p := rule.Properties

		findings = append(findings, scanner.EvaluateAzureRule(
			enumString(p.Direction),
			enumString(p.Access),
			enumString(p.Protocol),
			derefString(p.DestinationPortRange),
			derefStringSlice(p.DestinationPortRanges),
			derefString(p.SourceAddressPrefix),
			derefStringSlice(p.SourceAddressPrefixes),
		)...)
	}
	return findings
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func derefStringSlice(in []*string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if v := derefString(s); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// enumString renders any of the SDK's *SomeEnum pointer types as a plain string.
func enumString[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
