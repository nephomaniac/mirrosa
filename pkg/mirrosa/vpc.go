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

const vpcDescription = "A VPC is a logically isolated network in AWS and a ROSA cluster can be installed " +
	"into an existing VPC (BYOVPC) or the installer can create one for the end-user (non-BYOVPC). " +
	"Regardless, the 'enableDnsSupport' and 'enableDnsHostnames' settings must be enabled on the VPC so that the cluster can use the " +
	"private Route 53 Hosted Zones attached to the VPC to resolve internal DNS records [1]." +
	"\n\nnon-BYOVPC's must not be modified and must contain the resources exactly documented in [2], while BYOVPC's allow " +
	"for more flexibility and the only requirement is that the required network egresses are resolvable and routable [3], " +
	"which can be validated by osd-network-verifier [4]." +
	"\n\nReferences:\n" +
	"1. https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html#vpc-dns-support\n" +
	"2. https://docs.openshift.com/rosa/rosa_planning/rosa-sts-aws-prereqs.html#rosa-vpc_rosa-sts-aws-prereqs\n" +
	"3. https://docs.openshift.com/rosa/rosa_planning/rosa-sts-aws-prereqs.html#osd-aws-privatelink-firewall-prerequisites_rosa-sts-aws-prereqs\n" +
	"4. https://github.com/openshift/osd-network-verifier"

// Ensure Vpc implements Component
var _ Component = &Vpc{}

// MirrosaVpcAPIClient is a client that implements what's needed to validate a Vpc
type MirrosaVpcAPIClient interface {
	DescribeVpcAttribute(ctx context.Context, params *ec2.DescribeVpcAttributeInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcAttributeOutput, error)
}

type Vpc struct {
	log       *slog.Logger
	Id        string
	Ec2Client MirrosaVpcAPIClient
}

func (c *Client) NewVpc() Vpc {
	return Vpc{
		log:       c.log,
		Id:        c.ClusterInfo.VpcId,
		Ec2Client: ec2.NewFromConfig(c.AwsConfig),
	}
}

func (v Vpc) ValidateVPCDNSAttrs(ctx context.Context) error {
	/*
	* https://docs.aws.amazon.com/glue/latest/dg/set-up-vpc-dns.html
	* To set up DNS in your VPC, ensure that DNS hostnames and DNS resolution are both enabled in your VPC.
	* The VPC network attributes enableDnsHostnames and enableDnsSupport must be set to true.
	 */
	//
	var ErrSummary error = nil
	// Create summary table to make results easier to parse from debug output...
	red := color.New(color.FgHiRed, color.BgBlack)
	green := color.New(color.FgHiGreen, color.BgBlack)
	blue := color.New(color.FgHiBlue, color.BgBlack)
	var rowColor *color.Color = green
	summaryTable := tablewriter.NewWriter(os.Stdout)
	summaryTable.SetHeader([]string{"VPC", "Attribute", "Value", "Errors"})
	summaryTable.SetBorders(tablewriter.Border{Left: false, Top: true, Right: false, Bottom: false})
	summaryTable.SetCaption(true, blue.Sprint("Ensure that DNS hostnames and DNS resolution are both enabled in the VPC"))

	v.log.Debug("validating that enableDnsHostnames is true", slog.String("id", v.Id))
	dnsHostnames, err := v.Ec2Client.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
		Attribute: types.VpcAttributeNameEnableDnsHostnames,
		VpcId:     aws.String(v.Id),
	})
	if err != nil {
		rowColor = red
		ErrSummary = errors.Join(ErrSummary, err)
	}

	if !*dnsHostnames.EnableDnsHostnames.Value {
		rowColor = red
		err = errors.Join(err, fmt.Errorf("enableDnsHostnames is false for VPC: %s", v.Id))
	}
	summaryTable.Append([]string{rowColor.Sprintf("%s", v.Id),
		rowColor.Sprintf("%s", string(types.VpcAttributeNameEnableDnsHostnames)),
		rowColor.Sprintf("%t", *dnsHostnames.EnableDnsHostnames.Value),
		rowColor.Sprintf("%v", err)})

	err = nil
	v.log.Debug("validating that enableDnsSupport is true", slog.String("id", v.Id))
	dnsSupport, err := v.Ec2Client.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
		Attribute: types.VpcAttributeNameEnableDnsSupport,
		VpcId:     aws.String(v.Id),
	})
	if err != nil {
		rowColor = red
		ErrSummary = errors.Join(ErrSummary, err)
	}

	if !*dnsSupport.EnableDnsSupport.Value {
		rowColor = red
		err = errors.Join(err, fmt.Errorf("enableDnsSupport is false for VPC: %s", v.Id))
	}
	summaryTable.Append([]string{rowColor.Sprintf("%s", v.Id),
		rowColor.Sprintf("%s", string(types.VpcAttributeNameEnableDnsSupport)),
		rowColor.Sprintf("%t", *dnsSupport.EnableDnsSupport.Value),
		rowColor.Sprintf("%v", err)})
	//Colors in the footer can cause the row to fail to render properly
	var result string = "PASS"
	if ErrSummary != nil {
		result = "FAIL"
	}
	summaryTable.SetFooter([]string{"", "", "VPC DNS SUPPORT RESULT", result})
	summaryTable.Render()
	fmt.Fprintf(os.Stdout, "\n")

	return ErrSummary
}

func (v Vpc) Validate(ctx context.Context) error {
	v.log.Info("validating vpc", slog.String("id", v.Id))
	err := v.ValidateVPCDNSAttrs(ctx)
	return err
}

func (v Vpc) Description() string {
	return vpcDescription
}

func (v Vpc) FilterValue() string {
	return v.Title()
}

func (v Vpc) Title() string {
	return "VPC"
}
