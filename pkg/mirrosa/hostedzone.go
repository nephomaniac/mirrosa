package mirrosa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

const (
	publicHostedZoneDescription = "A ROSA cluster's public hosted zone holds information about how to route traffic" +
		" on the internet to a cluster's API Server and Ingress."
	publicHostedZonePrivateLinkDescription = "A PrivateLink ROSA cluster's public hosted zone is typically empty," +
		" but is required for Let's Encrypt to complete DNS-01 challenges by populating specific TXT records" +
		" to prove ownership and renew TLS certificates for the cluster."
	privateHostedZoneDescription = "A ROSA cluster's private hosted zone holds information about how Route 53" +
		" to DNS queries within the associated VPC. Records for api-int, api, and *.apps are required." +
		"\n  - api so that the API server is routable." +
		"\n  - api.int so that the API server is routable within the cluster's VPC." +
		"\n  - *.apps so that applications running on the cluster are routable when exposed by an Ingress" +
		", including the OpenShift console."
	// \052 is ASCII for *
	privateHostedZoneAppsRecordPrefix   = "\\052.apps"
	privateHostedZoneApiRecordPrefix    = "api"
	privateHostedZoneApiIntRecordPrefix = "api-int"
)

// Ensure PublicHostedZone implements mirrosa.Component
var _ Component = &PublicHostedZone{}

type Route53AwsApi interface {
	GetHostedZone(ctx context.Context, params *route53.GetHostedZoneInput, optFns ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error)
	ListHostedZonesByName(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error)
	ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

type PublicHostedZone struct {
	log         *slog.Logger
	BaseDomain  string
	PrivateLink bool

	Route53Client Route53AwsApi
}

func (c *Client) NewPublicHostedZone() PublicHostedZone {
	return PublicHostedZone{
		log:           c.log,
		BaseDomain:    c.ClusterInfo.BaseDomain,
		PrivateLink:   c.Cluster.AWS().PrivateLink(),
		Route53Client: route53.NewFromConfig(c.AwsConfig),
	}
}

func (p PublicHostedZone) Validate(ctx context.Context) error {
	expectedName := fmt.Sprintf("%s.", p.BaseDomain)

	p.log.Info("searching for Public Hosted Zone", slog.String("name", expectedName))
	hzs, err := p.Route53Client.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{
		DNSName: aws.String(expectedName),
	})
	if err != nil {
		return err
	}

	for _, hz := range hzs.HostedZones {
		if !hz.Config.PrivateZone {
			p.log.Info("found Public Hosted Zone", slog.String("id", *hz.Id))
			return nil
		}
	}

	return fmt.Errorf("no public hosted zone for %s found", expectedName)
}

func (p PublicHostedZone) Description() string {
	if p.PrivateLink {
		return publicHostedZonePrivateLinkDescription
	}

	return publicHostedZoneDescription
}

func (p PublicHostedZone) FilterValue() string {
	return "Route53 Public Hosted Zone"
}

func (p PublicHostedZone) Title() string {
	return "Route53 Public Hosted Zone"
}

// Ensure PrivateHostedZone implements mirrosa.Component
var _ Component = &PrivateHostedZone{}

type PrivateHostedZone struct {
	log         *slog.Logger
	ClusterName string
	BaseDomain  string
	Region      types.VPCRegion
	VpcId       string

	Route53Client Route53AwsApi
}

func (c *Client) NewPrivateHostedZone() PrivateHostedZone {
	return PrivateHostedZone{
		log:           c.log,
		ClusterName:   c.ClusterInfo.Name,
		BaseDomain:    c.ClusterInfo.BaseDomain,
		Region:        types.VPCRegion(c.Cluster.Region().ID()),
		VpcId:         c.ClusterInfo.VpcId,
		Route53Client: route53.NewFromConfig(c.AwsConfig),
	}
}

type ExpectedRecord struct {
	Name   string
	Record *types.ResourceRecordSet
	Found  bool
	Error  error
}

func (p PrivateHostedZone) Validate(ctx context.Context) error {
	if p.VpcId == "" || p.BaseDomain == "" || p.ClusterName == "" {
		return errors.New("must specify a BaseDomain, ClusterName, and VpcId in order to validate PrivateHostedZone")
	}
	var privateHostedZoneId string
	prettyHostedZoneId := func() string {
		return filepath.Base(privateHostedZoneId)
	}
	expectedName := fmt.Sprintf("%s.%s.", p.ClusterName, p.BaseDomain)

	// Color table output red for failed cases, green for passing cases.
	red := color.New(color.FgHiRed, color.BgBlack)
	green := color.New(color.FgHiGreen, color.BgBlack)
	blue := color.New(color.FgHiBlue, color.BgBlack)

	// Create summary table to make results easier to parse from debug output...
	summaryTable := tablewriter.NewWriter(os.Stdout)
	summaryTable.SetHeader([]string{"HostedZone", "Record", "Type", "Alias", "Errors"})
	summaryTable.SetBorders(tablewriter.Border{Left: false, Top: true, Right: false, Bottom: false})
	summaryTable.SetCaption(true, blue.Sprintf("Ensure Private Hosted Zone for vpc:'%s', '%s'", p.VpcId, expectedName))

	var rowColor *color.Color = green
	var ErrorSummary error = nil

	renderErrorTable := func() {
		rowColor = red
		summaryTable.Append([]string{
			rowColor.Sprint(prettyHostedZoneId()),
			"",
			"",
			"",
			rowColor.Sprintf("%v", ErrorSummary),
		})
		summaryTable.SetFooter([]string{"", "", "", "HOSTED ZONE RESULT", "FAIL"})
		summaryTable.Render()
		fmt.Fprintf(os.Stdout, "\n")
	}

	// Note: At this time the route53.ListTagsForResource() api requires additional perms.
	//       r53 does not yet have a method to provide a filter by tags option/api for hosted zones.
	//       Instead serch by zone name and vpc...
	p.log.Info("searching for Private Hosted Zone", slog.String("name", fmt.Sprintf("%s.%s", p.ClusterName, p.BaseDomain)))

	resp, err := p.Route53Client.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{
		DNSName: aws.String(expectedName),
	})
	if err != nil {
		ErrorSummary = errors.Join(ErrorSummary, err)
		renderErrorTable()
		return ErrorSummary
	}
	for _, hz := range resp.HostedZones {
		if hz.Config.PrivateZone && *hz.Name == expectedName {
			p.log.Debug("considering Hosted Zone", slog.String("id", *hz.Id), slog.String("name", *hz.Name))
			private, err := p.Route53Client.GetHostedZone(ctx, &route53.GetHostedZoneInput{
				Id: hz.Id,
			})
			if err != nil {
				ErrorSummary = errors.Join(ErrorSummary, err)
				renderErrorTable()
				return err
			}
			if len(private.VPCs) == 0 {
				p.log.Debug("Hosted Zone is not associated with any VPCs", slog.String("id", *hz.Id))
				continue
			} else {
				for _, vpc := range private.VPCs {
					if *vpc.VPCId == p.VpcId {
						p.log.Info("found Private Hosted Zone", slog.String("id", *private.HostedZone.Id))
						privateHostedZoneId = *private.HostedZone.Id
						break
					}
				}
			}
		}
	}
	if privateHostedZoneId == "" {
		ErrorSummary = errors.Join(ErrorSummary, fmt.Errorf("no private hosted zone associated to %s for %s found", p.VpcId, expectedName))
		renderErrorTable()
		return ErrorSummary
	}
	p.log.Info("validating records in Private Hosted Zone", slog.String("id", privateHostedZoneId))
	// TODO: Handle pagination
	records, err := p.Route53Client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(privateHostedZoneId),
	})
	if err != nil {
		ErrorSummary = errors.Join(ErrorSummary, err)
		renderErrorTable()
		return ErrorSummary
	}

	expectedRecords := []*ExpectedRecord{
		{Name: fmt.Sprintf("%s.%s.%s.", privateHostedZoneApiRecordPrefix, p.ClusterName, p.BaseDomain)},
		{Name: fmt.Sprintf("%s.%s.%s.", privateHostedZoneApiIntRecordPrefix, p.ClusterName, p.BaseDomain)},
		{Name: fmt.Sprintf("%s.%s.%s.", privateHostedZoneAppsRecordPrefix, p.ClusterName, p.BaseDomain)},
	}

	for _, expRecord := range expectedRecords {
		for _, record := range records.ResourceRecordSets {
			if expRecord.Name == *record.Name {
				p.log.Debug("found record", slog.String("name", *record.Name))
				expRecord.Found = true
				expRecord.Record = &record
				// All expected records are A records
				if record.Type != types.RRTypeA {
					expRecord.Error = errors.Join(expRecord.Error, fmt.Errorf("%s is not type 'A' record", *record.Name))
				}
				if record.AliasTarget == nil {
					expRecord.Error = errors.Join(expRecord.Error, fmt.Errorf("%s has empty AliasTarget", *record.Name))
				}
				break
			}
		}
	}
	var result string = "PASS"
	if ErrorSummary != nil {
		rowColor = red
		result = "FAIL"
	}
	//summaryTable.SetHeader([]string{"BaseDomain", "HostedZone", "Record","Type", "Errors"})
	summaryTable.Append([]string{
		rowColor.Sprint(prettyHostedZoneId()),
		"",
		"",
		"",
		rowColor.Sprintf("%v", ErrorSummary),
	})
	for _, expRecord := range expectedRecords {
		rowColor = green
		if expRecord.Error != nil {
			rowColor = red
			ErrorSummary = errors.Join(ErrorSummary, expRecord.Error)
		}
		var eRecType string = "???"
		var eRecAlias string = "???"
		if expRecord.Record != nil {
			eRecType = rowColor.Sprint(string(expRecord.Record.Type))
			if expRecord.Record.AliasTarget != nil {
				eRecAlias = rowColor.Sprint(*expRecord.Record.AliasTarget.DNSName)
			}
		}

		summaryTable.Append([]string{
			rowColor.Sprint("--"),
			rowColor.Sprint(strings.Replace(expRecord.Name, "\\052", "*", 1)),
			rowColor.Sprintf("%s", eRecType),
			rowColor.Sprintf("%s", eRecAlias),
			rowColor.Sprintf("%v", expRecord.Error),
		})
	}
	summaryTable.SetFooter([]string{"", "", "", "PRIV HOSTEDZONE RESULT", result})
	summaryTable.Render()
	fmt.Fprintf(os.Stdout, "\n")
	return ErrorSummary
}

func (p PrivateHostedZone) Description() string {
	return privateHostedZoneDescription
}

func (p PrivateHostedZone) FilterValue() string {
	return "Route53 Private Hosted Zone"
}

func (p PrivateHostedZone) Title() string {
	return "Route53 Private Hosted Zone"
}
