package providers

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"cloudscan/internal/scanner"
)

// ScanAWS lists EC2 security groups and reports every ingress permission open
// to the internet.
//
// Credentials come from the default chain: environment, shared config, SSO,
// container or instance role. The tool never takes a key on the command line --
// a credential on an argv line lands in shell history and process listings.
//
// Required IAM permissions: ec2:DescribeSecurityGroups, and
// ec2:DescribeRegions when regions are discovered rather than supplied.
func ScanAWS(ctx context.Context, regions []string) (*scanner.AWSSection, Outcome) {
	var out Outcome
	section := &scanner.AWSSection{SecurityGroups: []scanner.SecurityGroup{}}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		out.fail("aws", "", fmt.Errorf("load credentials: %w", err))
		return section, out
	}

	if len(regions) == 0 {
		regions, err = discoverRegions(ctx, cfg)
		if err != nil {
			out.fail("aws", "", fmt.Errorf("discover regions: %w", err))
			return section, out
		}
	}
	multiRegion := len(regions) > 1

	for _, region := range regions {
		client := ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Region = region })
		paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{
			MaxResults: aws.Int32(1000),
		})

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				// An opted-out region, or a missing permission in one region,
				// must not cost us the other regions' results.
				out.fail("aws", region, err)
				break
			}

			for _, sg := range page.SecurityGroups {
				out.Examined++
				if findings := evaluateSecurityGroup(sg); len(findings) > 0 {
					entry := scanner.SecurityGroup{
						ID:            aws.ToString(sg.GroupId),
						Name:          aws.ToString(sg.GroupName),
						InsecureRules: findings,
					}
					if multiRegion {
						entry.Region = region
					}
					section.SecurityGroups = append(section.SecurityGroups, entry)
				}
			}
		}
	}

	// Stable order keeps diffs between two scans meaningful.
	sort.Slice(section.SecurityGroups, func(i, j int) bool {
		a, b := section.SecurityGroups[i], section.SecurityGroups[j]
		if a.Region != b.Region {
			return a.Region < b.Region
		}
		return a.ID < b.ID
	})
	return section, out
}

// evaluateSecurityGroup walks the ingress permissions only. Egress to the
// internet is normal and is out of scope for this tool.
func evaluateSecurityGroup(sg ec2types.SecurityGroup) []scanner.Rule {
	var findings []scanner.Rule
	for _, perm := range sg.IpPermissions {
		ipv4 := make([]string, 0, len(perm.IpRanges))
		for _, r := range perm.IpRanges {
			ipv4 = append(ipv4, aws.ToString(r.CidrIp))
		}
		ipv6 := make([]string, 0, len(perm.Ipv6Ranges))
		for _, r := range perm.Ipv6Ranges {
			ipv6 = append(ipv6, aws.ToString(r.CidrIpv6))
		}

		findings = append(findings, scanner.EvaluateAWSPermission(
			aws.ToString(perm.IpProtocol),
			perm.FromPort,
			perm.ToPort,
			ipv4,
			ipv6,
		)...)
	}
	return findings
}

func discoverRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
	client := ec2.NewFromConfig(cfg)
	// AllRegions=false: regions the account has not opted into cannot be called
	// anyway, and asking for them only produces authorisation noise.
	resp, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	regions := make([]string, 0, len(resp.Regions))
	for _, r := range resp.Regions {
		regions = append(regions, aws.ToString(r.RegionName))
	}
	sort.Strings(regions)
	return regions, nil
}
