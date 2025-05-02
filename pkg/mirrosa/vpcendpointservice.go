package mirrosa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

const vpceServiceDescription = "A VPC Endpoint Service allows for a load balancer to be exposed through PrivateLink, AWS' internal network, to other AWS accounts via VPC Endpoints [1]. " +
	" A PrivateLink ROSA cluster must have a VPC Endpoint Service with a single VPC Endpoint connection that allows Hive " +
	" to connect to the cluster over PrivateLink [2] to allow for management via SyncSets and backplane." +
	"\n\nReferences:\n" +
	"1. https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-share-your-services.html\n" +
	"2. https://github.com/openshift/hive/tree/master/pkg/controller/awsprivatelink"

var _ Component = &VpcEndpointService{}

// MirrosaVpcEndpointServiceAPIClient is a client that implements what's needed to validate a VpcEndpointService
type MirrosaVpcEndpointServiceAPIClient interface {
	DescribeVpcEndpointServices(ctx context.Context, params *ec2.DescribeVpcEndpointServicesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointServicesOutput, error)
	ec2.DescribeVpcEndpointConnectionsAPIClient
}

type VpcEndpointService struct {
	log         *slog.Logger
	InfraName   string
	PrivateLink bool

	Ec2Client MirrosaVpcEndpointServiceAPIClient
}

func (c *Client) NewVpcEndpointService() VpcEndpointService {
	return VpcEndpointService{
		log:         c.log,
		InfraName:   c.ClusterInfo.InfraName,
		PrivateLink: c.Cluster.AWS().PrivateLink(),
		Ec2Client:   ec2.NewFromConfig(c.AwsConfig),
	}
}

func (v VpcEndpointService) Validate(ctx context.Context) error {
	// non-PrivateLink clusters do not have a VPC Endpoint Service
	if !v.PrivateLink {
		return nil
	}

	var ErrSummary error = nil
	connectionIds := []string{}
	found := false
	// Create summary table to make results easier to parse from debug output...
	red := color.New(color.FgHiRed, color.BgBlack)
	green := color.New(color.FgHiGreen, color.BgBlack)
	blue := color.New(color.FgHiBlue, color.BgBlack)
	var rowColor *color.Color = green

	v.log.Info("searching for PrivateLink VPC Endpoint Service", slog.String("name", fmt.Sprintf("%s-vpc-endpoint-service", v.InfraName)))
	var serviceId string
	resp, err := v.Ec2Client.DescribeVpcEndpointServices(ctx, &ec2.DescribeVpcEndpointServicesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []string{fmt.Sprintf("%s-vpc-endpoint-service", v.InfraName)},
			},
			{
				Name:   aws.String("tag:hive.openshift.io/private-link-access-for"),
				Values: []string{v.InfraName},
			},
		},
	})
	if err != nil {
		ErrSummary = errors.Join(ErrSummary, err)
	}

	switch len(resp.ServiceDetails) {
	case 0:
		ErrSummary = errors.Join(ErrSummary, errors.New("no VPC Endpoint Services found for PrivateLink cluster"))
	case 1:
		v.log.Info("found VPC Endpoint Service", slog.String("id", *resp.ServiceDetails[0].ServiceId))
		serviceId = *resp.ServiceDetails[0].ServiceId
		found = true
	default:
		ErrSummary = errors.Join(ErrSummary, errors.New("multiple VPC Endpoint Services found for PrivateLink cluster"))
		found = true
	}
	if len(serviceId) > 0 {
		v.log.Info("validating VPC Endpoint Service", slog.String("id", *resp.ServiceDetails[0].ServiceId))
		cxResp, err := v.Ec2Client.DescribeVpcEndpointConnections(ctx, &ec2.DescribeVpcEndpointConnectionsInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("service-id"),
					Values: []string{serviceId},
				},
				{
					Name:   aws.String("vpc-endpoint-state"),
					Values: []string{"available"},
				},
			},
		})
		if err != nil {
			ErrSummary = errors.Join(ErrSummary, err)
		} else {
			switch len(cxResp.VpcEndpointConnections) {
			case 0:
				ErrSummary = errors.Join(ErrSummary, fmt.Errorf("no available VPC Endpoint connections found for %s", serviceId))
			case 1:
				v.log.Info("validated that one accepted VPC Endpoint connection exists", slog.String("id", serviceId))
				for _, endPt := range cxResp.VpcEndpointConnections {
					connectionIds = append(connectionIds, fmt.Sprintf("%s/%s", *endPt.VpcEndpointId, *endPt.VpcEndpointConnectionId))
				}

			default:
				ErrSummary = errors.Join(ErrSummary, fmt.Errorf("multiple available VPC Endpoint connections found for %s", serviceId))
			}
		}
	}
	if ErrSummary != nil {
		rowColor = red
	}
	summaryTable := tablewriter.NewWriter(os.Stdout)
	summaryTable.SetHeader([]string{"VPC ENDPOINT SVC", "FOUND", "AVAIL CONNS", "ERRORS"})
	summaryTable.SetBorders(tablewriter.Border{Left: false, Top: true, Right: false, Bottom: false})
	summaryTable.SetCaption(true, blue.Sprint("Ensure PrivateLink Cluster's AWS VPC Endpoint Service"))
	connJson, _ := GetJsonBytes(connectionIds, v.log)
	summaryTable.Append([]string{rowColor.Sprintf("%s", serviceId),
		rowColor.Sprintf("%t", found),
		rowColor.Sprintf("%s", connJson),
		rowColor.Sprintf("%v", ErrSummary)})
	//Colors in the footer can cause the row to fail to render properly
	var result string = "PASS"
	if ErrSummary != nil {
		result = "FAIL"
	}
	summaryTable.SetFooter([]string{"", "", "VPC PRIVATELINK ENDPOINT SERVICE RESULT", result})
	summaryTable.Render()
	fmt.Fprintf(os.Stdout, "\n")
	return ErrSummary
}

func (v VpcEndpointService) Description() string {
	return vpceServiceDescription
}

func (v VpcEndpointService) FilterValue() string {
	return "VPC Endpoint Service"
}

func (v VpcEndpointService) Title() string {
	return "VPC Endpoint Service"
}
