package mirrosa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

const securityGroupDescription = "Security groups act as a virtual firewall for Elastic Network Interfaces (ENIs)." +
	" For ROSA clusters, the control plane and worker security groups restrict network traffic to the clusters nodes and" +
	" must not be modified. Here are some important required security group rules:" +
	"\n  - Control Plane: Inbound TCP port 6443 from the cluster's machine CIDR for the Kubernetes API server" +
	"\n  - Control Plane: Inbound TCP port 22623 from the cluster's machine CIDR for etcd"

//"\n  - Inbound master 10257 kube-controller-manager from worker" +
//"\n  - Inbound master 10259 kube-scheduler from worker" +
//"\n  - Inbound master 10250 kubelet from worker"

const (
	ControlPlaneRoleKey = "controlplane"
	NodeRoleKey         = "node"
	ApiServerLbRoleKey  = "apiserver-lb"
	LbRoleKey           = "lb"
)

type securityGroupValidationRule struct {
	CidrIpv4   string
	IpProtocol types.Protocol
	ToPort     int32
	FromPort   int32
	IsEgress   bool
	Found      bool
	RefGroup   *types.SecurityGroup
	FoundRules []*types.SecurityGroupRule //Rules found permiting the traffic defined by this validation rule
}

var _ Component = &SecurityGroup{}

type SecurityGroup struct {
	log         *slog.Logger
	InfraName   string
	MachineCIDR string
	ctx         context.Context
	Ec2Client   Ec2AwsApi
}

func (c *Client) NewSecurityGroup() SecurityGroup {
	return SecurityGroup{
		log:         c.log,
		InfraName:   c.ClusterInfo.InfraName,
		MachineCIDR: c.Cluster.Network().MachineCIDR(),
		ctx:         c.ctx,
		Ec2Client:   ec2.NewFromConfig(c.AwsConfig),
	}
}

type securityGroupWrapper struct {
	Description string
	Role        string
	ID          string
	Tags        []string
	Rules       []types.SecurityGroupRule
	Group       *types.SecurityGroup
	Error       error
}

// Returns an expectedGroup obj populated with the AWS security group and ID, or an error.
func (s SecurityGroup) GetSecurityGroupByNameTags(nameTags []string, role string, ctx context.Context) *securityGroupWrapper {
	expGroupObj := securityGroupWrapper{Description: fmt.Sprintf("%s security group", role), Role: role, Tags: nameTags}
	filter := []types.Filter{
		{
			Name:   aws.String("tag:Name"),
			Values: nameTags,
		},
		{
			//Name:   aws.String(fmt.Sprintf("tag:kubernetes.io/cluster/%s", s.InfraName)),
			Name:   aws.String(fmt.Sprintf("tag:sigs.k8s.io/cluster-api-provider-aws/cluster/%s", s.InfraName)),
			Values: []string{"owned"},
		},
	}
	s.log.Debug("searching for security group", slog.String("description", expGroupObj.Description))
	for _, fval := range filter {
		s.log.Debug("AWS security group filter:", slog.String("Name", *fval.Name), slog.String("Values", fmt.Sprintf("%v", *&fval.Values)))
	}
	resp, err := s.Ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: filter,
	})
	if err != nil {
		s.log.Error(fmt.Sprintf("DescribeSecurityGroups err fetching '%s'", role), slog.String("ERROR", fmt.Sprintf("%v", err)))
		expGroupObj.Error = err
		return &expGroupObj
	}
	switch len(resp.SecurityGroups) {
	case 0:
		filterJson, _ := GetJsonBytes(filter, s.log)
		s.log.Error(fmt.Sprintf("security group for '%s' not found with filters:'%s'", role, filterJson))
		expGroupObj.Error = fmt.Errorf("security group for '%s' not found", role)
	case 1:
		s.log.Info(fmt.Sprintf("found security group for %s", expGroupObj.Description), slog.String("id", *resp.SecurityGroups[0].GroupId))
		expGroupObj.ID = *resp.SecurityGroups[0].GroupId
		expGroupObj.Group = &resp.SecurityGroups[0]
	default:
		filterJson, _ := GetJsonBytes(filter, s.log)
		s.log.Error(fmt.Sprintf("multiple security groups found for '%s', using filters:'%s'", role, filterJson))
		expGroupObj.Error = fmt.Errorf("multiple security groups found for '%s'", role)
	}
	return &expGroupObj
}

func (s SecurityGroup) CheckExpectedGroups(ctx context.Context) (map[string]*securityGroupWrapper, error) {
	var (
		masterGroup      = fmt.Sprintf("%s-master-sg", s.InfraName)
		controlPlaneTag  = fmt.Sprintf("%s-controlplane", s.InfraName)
		workerGroup      = fmt.Sprintf("%s-worker-sg", s.InfraName)
		nodeGroup        = fmt.Sprintf("%s-node", s.InfraName)
		apiServerLbGroup = fmt.Sprintf("%s-apiserver-lb", s.InfraName)
		lbGroup          = fmt.Sprintf("%s-lb", s.InfraName)
	)
	controlPlaneTags := []string{masterGroup, controlPlaneTag}
	nodeTags := []string{workerGroup, nodeGroup}
	apiServerLbTags := []string{apiServerLbGroup}
	lbTags := []string{lbGroup}

	var expectedGroups = map[string]*securityGroupWrapper{}
	// Attempt to fetch the expected security groups, report the sum of errors afterward...
	expectedGroups[ControlPlaneRoleKey] = s.GetSecurityGroupByNameTags(controlPlaneTags, ControlPlaneRoleKey, ctx)
	expectedGroups[NodeRoleKey] = s.GetSecurityGroupByNameTags(nodeTags, NodeRoleKey, ctx)
	expectedGroups[ApiServerLbRoleKey] = s.GetSecurityGroupByNameTags(apiServerLbTags, ApiServerLbRoleKey, ctx)
	expectedGroups[LbRoleKey] = s.GetSecurityGroupByNameTags(lbTags, LbRoleKey, ctx)

	// Color table output red for failed cases, green for passing cases.
	red := color.New(color.FgHiRed, color.BgBlack)
	green := color.New(color.FgHiGreen, color.BgBlack)
	blue := color.New(color.FgHiBlue, color.BgBlack)

	// Create summary table to make results easier to parse from debug output...
	summaryTable := tablewriter.NewWriter(os.Stdout)
	summaryTable.SetHeader([]string{"Role", "SecurityGroupID", "SGName", "Errors"})
	summaryTable.SetBorders(tablewriter.Border{Left: false, Top: true, Right: false, Bottom: false})
	summaryTable.SetCaption(true, blue.Sprint("Ensure The Expected Security Groups ARE Found"))

	var rowColor *color.Color

	//Store and returned the joined errors (if any)
	var err error = nil
	for _, expGrp := range expectedGroups {
		rowColor = green
		var grpErr string = rowColor.Sprint("----")
		if expGrp.Error != nil {
			err = errors.Join(err, expGrp.Error)
			rowColor = red
			grpErr = rowColor.Sprintf("%s", expGrp.Error)
		}
		var grpName string = rowColor.Sprint("???")
		if expGrp.Group != nil {
			grpName = rowColor.Sprintf("%s", *expGrp.Group.GroupName)
		}
		grpID := rowColor.Sprintf("%s", expGrp.ID)
		grpRole := rowColor.Sprintf("%s", expGrp.Role)
		summaryTable.Append([]string{grpRole, grpID, grpName, grpErr})
	}
	//Colors in the footer can cause the row to fail to render properly
	var result string = "PASS"
	if err != nil {
		result = "FAIL"
	}
	summaryTable.SetFooter([]string{"", "", "FOUND SECURITY GROUPS RESULT", result})
	summaryTable.Render()
	fmt.Fprintf(os.Stdout, "\n")
	return expectedGroups, err
}

func (s SecurityGroup) UpdateSecurityGroupRules(sgWrapper *securityGroupWrapper) error {
	fmt.Fprintf(os.Stderr, "Validating control group(%s):'%+v'\n", sgWrapper.Role, sgWrapper.ID)
	resp, err := s.Ec2Client.DescribeSecurityGroupRules(s.ctx, &ec2.DescribeSecurityGroupRulesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{sgWrapper.ID},
			},
		},
	})
	if err != nil {
		s.log.Error("DescribeSecurityGroupRules err", slog.String("id", sgWrapper.ID), slog.String("ERROR", fmt.Sprintf("%v", err)))
		return err
	}
	sgWrapper.Rules = resp.SecurityGroupRules
	return nil
}

func (s SecurityGroup) ValidateSecurityGroupRules(sgWrapper *securityGroupWrapper, validations map[string]securityGroupValidationRule) error {
	err := s.UpdateSecurityGroupRules(sgWrapper)
	if err != nil {
		sgWrapper.Error = err
		return err
	}
	for ruleKey, expectedRule := range validations {
		s.log.Debug(fmt.Sprintf("Checking expectedRule[%s]...\n", ruleKey))
		for _, actualRule := range sgWrapper.Rules {
			if compareSecurityGroupRules(expectedRule, actualRule, s.log) {
				s.log.Info("security group rule validated", slog.String("component", ruleKey), slog.String("expectedRule", fmt.Sprintf("%+v", expectedRule)))
				expectedRule.Found = true
				expectedRule.FoundRules = append(expectedRule.FoundRules, &actualRule)
				validations[ruleKey] = expectedRule
				//continue //continue to exit on first, match or instead report all rules fulfilling
			}
		}
	}
	// Color table output red for failed cases, green for passing cases.
	red := color.New(color.FgHiRed, color.BgBlack)
	green := color.New(color.FgHiGreen, color.BgBlack)
	blue := color.New(color.FgHiBlue, color.BgBlack)

	// Create summary table to make results easier to parse from debug output...
	summaryTable := tablewriter.NewWriter(os.Stdout)
	summaryTable.SetHeader([]string{"Key", "Proto", "Egress", "Port Range", "Allowed Source", "SG Rules Found"})
	summaryTable.SetBorders(tablewriter.Border{Left: false, Top: true, Right: false, Bottom: false})
	summaryTable.SetCaption(true, blue.Sprintf("Ensure Expected Control Plane Rules Are Satisfied By One Or More Rules In SG:'%s/%s'", *sgWrapper.Group.GroupName, sgWrapper.ID))

	var rowColor *color.Color

	//Store and returned the joined errors (if any)
	notFound := []*securityGroupValidationRule{}
	for vkey, validation := range validations {
		rowColor = green
		var permitting string
		if validation.Found {
			permitting = rowColor.Sprint("-")
		} else {
			rowColor = red
			permitting = rowColor.Sprintf("NOT-FOUND")
			notFound = append(notFound, &validation)
		}
		var sourceStr string = rowColor.Sprintf("%s", validation.CidrIpv4)
		if validation.RefGroup != nil {
			sourceStr = rowColor.Sprintf("%s/%s", *validation.RefGroup.GroupId, *validation.RefGroup.GroupName)
		}
		summaryTable.Append([]string{rowColor.Sprintf("%s", vkey),
			rowColor.Sprintf("%s", string(validation.IpProtocol)),
			rowColor.Sprintf("%t", validation.IsEgress),
			rowColor.Sprintf("%d-%d", validation.FromPort, validation.ToPort),
			sourceStr,
			permitting,
		})
		for _, foundRule := range validation.FoundRules {
			var foundSourceStr string = "???"
			var foundFrom string = "???"
			var foundTo string = "???"
			var foundEgress string = "???"
			var foundIpProto string = "???"
			var foundID string = "???"
			if foundRule.CidrIpv4 != nil {
				foundSourceStr = *foundRule.CidrIpv4
			} else if foundRule.ReferencedGroupInfo != nil {
				foundSourceStr = *foundRule.ReferencedGroupInfo.GroupId
			}
			if foundRule.IpProtocol != nil {
				foundIpProto = string(*foundRule.IpProtocol)
			}
			if foundRule.IsEgress != nil {
				foundEgress = fmt.Sprintf("%t", *foundRule.IsEgress)
			}
			if foundRule.FromPort != nil {
				foundFrom = fmt.Sprintf("%d", *foundRule.FromPort)
			}
			if foundRule.ToPort != nil {
				foundTo = fmt.Sprintf("%d", *foundRule.ToPort)
			}
			foundRange := fmt.Sprintf("%s-%s", foundFrom, foundTo)
			if foundRule.SecurityGroupRuleId != nil {
				foundID = *foundRule.SecurityGroupRuleId
			}

			summaryTable.Append([]string{"  Allowed By -->",
				foundIpProto,
				foundEgress,
				foundRange,
				foundSourceStr,
				foundID,
			})
		}
	}
	//Colors in the footer can cause the row to fail to render properly
	var result string = "PASS"
	if len(notFound) > 0 {
		result = "FAIL"
	}
	summaryTable.SetFooter([]string{"", "", "", "", fmt.Sprintf("CONTROLPLANE %s RULES RESULT", sgWrapper.ID), result})
	summaryTable.Render()
	fmt.Fprintf(os.Stdout, "\n")
	if len(notFound) > 0 {
		return fmt.Errorf("Some expected traffic types are missing SecurityGroup rules to permit")
	}

	return nil
}

func (s SecurityGroup) Validate(ctx context.Context) error {
	s.ctx = ctx
	expectedGroups, err := s.CheckExpectedGroups(s.ctx)
	if err != nil {
		s.log.Error("Errors while checking expected security groups", slog.String("errors", fmt.Sprintf("%+v", err)))
		//return err
	}

	// First Validate the control plane rules...
	s.log.Info("Validating security group rules for control-plane security group...")
	controlPlaneSG := expectedGroups[ControlPlaneRoleKey]
	//TODO: Detect when it's appropriate to use CIDR (ie older cluster versions?)
	// In recent versions only security group references are used for allowed source, not cidr...
	controlPlaneRuleValidations, err := s.generateExpectedControlPlaneRules("", expectedGroups)
	err = s.ValidateSecurityGroupRules(controlPlaneSG, controlPlaneRuleValidations)
	if err != nil {
		s.log.Error("Errors while checking control plane security groups rules", slog.String("errors", fmt.Sprintf("%+v", err)))
		return err
	}
	return nil
}

func (s SecurityGroup) Description() string {
	return securityGroupDescription
}

func (s SecurityGroup) FilterValue() string {
	return "Security Group"
}

func (s SecurityGroup) Title() string {
	return "Security Group"
}

func containsNetwork(cidrA string, cidrB string) (bool, error) {
	cidrAStr := strings.TrimSpace(string(cidrA))
	cidrBStr := strings.TrimSpace(string(cidrA))
	if len(cidrAStr) <= 0 || len(cidrBStr) <= 0 {
		return false, fmt.Errorf("Empty network string provided for network comparison")
	}
	if cidrA == cidrB {
		return true, nil
	}
	// Parse the Allowed Source Range Cidr entry into network structures...
	_, netA, err := net.ParseCIDR(cidrAStr)
	if err != nil {
		return false, fmt.Errorf("Failed to parse network string:'%s', err:'%v'", cidrAStr, err)
	}
	_, netB, err := net.ParseCIDR(cidrBStr)
	if err != nil {
		return false, fmt.Errorf("Failed to parse network string:'%s', err:'%v'", cidrBStr, err)
	}
	// First check if network A contains the network B cidr ip...
	if !netA.Contains(netB.IP) {
		return false, nil
	}
	// Check if the network A mask includes network B.
	netASize, netABits := netA.Mask.Size()
	netBSize, netBBits := netB.Mask.Size()
	if netBBits == netABits && netASize <= netBSize {
		//Network B is contained within network A
		return true, nil
	}
	return false, nil
}

// Check if this rule matches or permits (more permissive) then our expected rule
func compareSecurityGroupRules(expected securityGroupValidationRule, actual types.SecurityGroupRule, log *slog.Logger) bool {
	log.Debug("Checking security group rule", slog.String("GroupId", *actual.GroupId), slog.String("RuleId", *actual.SecurityGroupRuleId))
	if len(expected.CidrIpv4) <= 0 && (expected.RefGroup == nil || expected.RefGroup.GroupId == nil) {
		log.Debug(fmt.Sprintf("Validation rule using empty CidrIPv4 and empty RefGroup. Expected:'%+v'", expected))
		return false
	}
	if actual.CidrIpv4 == nil && (actual.ReferencedGroupInfo == nil || actual.ReferencedGroupInfo.GroupId == nil) {
		log.Warn("SecurityGroup rule CidrIpv4 and ReferencedGroupInfo.GroupId are empty?", slog.String("ruleID", *actual.SecurityGroupRuleId))
		return false
	}
	if string(expected.IpProtocol) != *actual.IpProtocol {
		return false
	}
	if expected.IsEgress != *actual.IsEgress {
		return false
	}
	// Check if the expected port(s) are contained in this rule...
	if expected.FromPort < *actual.FromPort || expected.ToPort > *actual.ToPort {
		return false
	}
	if len(expected.CidrIpv4) > 0 {
		includesNet := false
		var actualCIDR string = ""
		if actual.CidrIpv4 != nil {
			var err error
			// Check that the expected network/ip is contained in this rule...
			includesNet, err = containsNetwork(*actual.CidrIpv4, expected.CidrIpv4)
			if err != nil {
				log.Error("compareSecurityGroupRules Error", slog.String("expectedCIDR", expected.CidrIpv4), slog.String("actualCIDR", *actual.CidrIpv4), slog.String("error", fmt.Sprintf("%v", err)))
			}
			actualCIDR = *actual.CidrIpv4
		}
		if !includesNet {
			log.Debug("Rule did contain expected network CIDR", slog.String("expectedCIDR", expected.CidrIpv4), slog.String("actualCIDR", actualCIDR))
			return false
		}
	} else if expected.RefGroup != nil {
		if expected.RefGroup == nil || expected.RefGroup.GroupId == nil {
			log.Debug("Expected RefGroup is nil")
			return false
		}
		if actual.ReferencedGroupInfo == nil || actual.ReferencedGroupInfo.GroupId == nil {
			log.Debug("actual ReferencedGroupInfo or ReferencedGroupInfo.GroupId == nil")
			return false
		}
		if *actual.ReferencedGroupInfo.GroupId != *expected.RefGroup.GroupId {
			log.Debug("Rule did not match expected ReferencedGroupInfo.GroupId",
				slog.String("ActualRefGroupID", fmt.Sprintf("%s", *actual.ReferencedGroupInfo.GroupId)),
				slog.String("ExpectedGroupID", fmt.Sprintf("%s", *expected.RefGroup.GroupId)))
			return false
		}
	}
	ruleJson, err := GetJsonBytes(actual, log)
	if err != nil {
		ruleJson = []byte(fmt.Sprintf("json marshal err: %s", err))
	}
	// Above checks out, this rule is equal to or more permissive than the expected.
	log.Debug("Security Group rule allows expected rule",
		slog.String("securityGroup", fmt.Sprintf("%s", *actual.GroupId)),
		slog.String("ruleID", fmt.Sprintf("%s", *actual.SecurityGroupRuleId)),
		slog.String("expectedIsEgress", fmt.Sprintf("%v", expected.IsEgress)),
		slog.String("expectedPorts", fmt.Sprintf("%d-%d", expected.FromPort, expected.ToPort)),
		slog.String("expectedNetwork", fmt.Sprintf("%s", expected.CidrIpv4)),
		slog.String("expectedRefGroup", fmt.Sprintf("%s", *expected.RefGroup.GroupId)),
		slog.String("securityGroupGrantingExpectation", fmt.Sprintf("%s", ruleJson)),
	)

	return true
}

func (s SecurityGroup) generateExpectedControlPlaneRules(ipv4Cidr string, refGroups map[string]*securityGroupWrapper) (map[string]securityGroupValidationRule, error) {
	var controlPlaneRules map[string]securityGroupValidationRule
	if len(ipv4Cidr) <= 0 && len(refGroups) <= 0 {
		return nil, fmt.Errorf("Must provided either an IPv4 cidr or SecurityGroup references as source for validations")
	}
	if len(ipv4Cidr) > 0 {
		controlPlaneRules = map[string]securityGroupValidationRule{
			"etcd": {
				CidrIpv4:   ipv4Cidr,
				IpProtocol: types.ProtocolTcp,
				FromPort:   22623,
				ToPort:     22623,
				IsEgress:   false,
				Found:      false,
			},
			"kube-apiserver": {
				CidrIpv4:   ipv4Cidr,
				IpProtocol: types.ProtocolTcp,
				FromPort:   6443,
				ToPort:     6443,
				IsEgress:   false,
				Found:      false,
			},
		}
	} else {
		controlPlaneRules = map[string]securityGroupValidationRule{}
	}
	if len(refGroups) > 0 {
		// control-plane security group allows etcd, and kub-api traffic from the provided SG refs...
		for _, groupKey := range []string{ControlPlaneRoleKey, ApiServerLbRoleKey, NodeRoleKey} {
			refGroup := refGroups[groupKey]
			etcdRuleKey := fmt.Sprintf("etcd-%s", refGroup.Role)
			kubeApiRuleKey := fmt.Sprintf("kube-apiserver-%s", refGroup.Role)
			if refGroup.Group == nil {
				s.log.Debug(fmt.Sprintf("refGroup.Group is nil for '%s'!!!!!\n", refGroup.Role))
			}

			controlPlaneRules[etcdRuleKey] = securityGroupValidationRule{
				CidrIpv4:   "",
				IpProtocol: types.ProtocolTcp,
				FromPort:   22623,
				ToPort:     22623,
				IsEgress:   false,
				Found:      false,
				RefGroup:   refGroup.Group,
			}
			controlPlaneRules[kubeApiRuleKey] =
				securityGroupValidationRule{
					CidrIpv4:   "",
					IpProtocol: types.ProtocolTcp,
					FromPort:   6443,
					ToPort:     6443,
					IsEgress:   false,
					Found:      false,
					RefGroup:   refGroup.Group,
				}
		}
		return controlPlaneRules, nil
	}
	return controlPlaneRules, nil
}
