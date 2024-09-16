package aws

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/loft-sh/devpod-provider-aws/pkg/options"
	"github.com/loft-sh/devpod/pkg/client"
	"github.com/loft-sh/devpod/pkg/log"
	"github.com/loft-sh/devpod/pkg/ssh"
	"github.com/pkg/errors"
)

type Machine struct {
	Status                string
	InstanceID            string
	SpotInstanceRequestId string
	PublicHostname        string
	PrivateHostname       string
	PrivateIP             string
}

func NewMachineFromInstance(instance types.Instance) Machine {
	privateHostname := *instance.PrivateIpAddress
	for _, t := range instance.Tags {
		if *t.Key != "devpod:private-hostname" {
			continue
		}
		privateHostname = *t.Value
		break
	}

	publicHostname := ""
	if instance.PublicIpAddress != nil {
		publicHostname = *instance.PublicIpAddress
	}

	spotInstanceRequestID := ""
	if instance.SpotInstanceRequestId != nil {
		spotInstanceRequestID = *instance.SpotInstanceRequestId
	}

	return Machine{
		InstanceID:            *instance.InstanceId,
		PrivateHostname:       privateHostname,
		PrivateIP:             *instance.PrivateIpAddress,
		PublicHostname:        publicHostname,
		Status:                string(instance.State.Name),
		SpotInstanceRequestId: spotInstanceRequestID,
	}

}

// detect if we're in an ec2 instance
func isEC2Instance() bool {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://instance-data.ec2.internal", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return true
}

func NewProvider(ctx context.Context, logs log.Logger) (*AwsProvider, error) {
	config, err := options.FromEnv(false)
	if err != nil {
		return nil, err
	}

	cfg, err := awsConfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	isEC2 := isEC2Instance()

	if config.DiskImage == "" && !isEC2 {
		image, err := GetDefaultAMI(ctx, cfg, config.MachineType)
		if err != nil {
			return nil, err
		}

		config.DiskImage = image
	}

	if config.RootDevice == "" && !isEC2 {
		device, err := GetAMIRootDevice(ctx, cfg, config.DiskImage)
		if err != nil {
			return nil, err
		}
		config.RootDevice = device
	}

	// create provider
	provider := &AwsProvider{
		Config:    config,
		AwsConfig: cfg,
		Log:       logs,
	}

	return provider, nil
}

type AwsProvider struct {
	Config           *options.Options
	AwsConfig        aws.Config
	Log              log.Logger
	WorkingDirectory string
}

func GetSubnetID(ctx context.Context, provider *AwsProvider) (string, error) {
	svc := ec2.NewFromConfig(provider.AwsConfig)

	// first search for a default devpod specific subnet, if it fails
	// we search the subnet with most free IPs that can do also public-ipv4
	input := &ec2.DescribeSubnetsInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					"devpod",
				},
			},
		},
	}

	result, err := svc.DescribeSubnets(ctx, input)
	if err != nil {
		return "", err
	}

	if len(result.Subnets) > 0 {
		return *result.Subnets[0].SubnetId, nil
	}

	input = &ec2.DescribeSubnetsInput{
		Filters: []types.Filter{
			{
				Name: aws.String("vpc-id"),
				Values: []string{
					provider.Config.VpcID,
				},
			},
			{
				Name: aws.String("map-public-ip-on-launch"),
				Values: []string{
					"true",
				},
			},
		},
	}

	result, err = svc.DescribeSubnets(ctx, input)
	if err != nil {
		return "", err
	}

	var maxIPCount int32

	subnetID := ""

	for _, v := range result.Subnets {
		if *v.AvailableIpAddressCount > maxIPCount {
			maxIPCount = *v.AvailableIpAddressCount
			subnetID = *v.SubnetId
		}
	}

	return subnetID, nil
}

func GetDevpodVPC(ctx context.Context, provider *AwsProvider) (string, error) {
	if provider.Config.VpcID != "" {
		return provider.Config.VpcID, nil
	}
	// Get a list of VPCs so we can associate the group with the first VPC.
	svc := ec2.NewFromConfig(provider.AwsConfig)

	result, err := svc.DescribeVpcs(ctx, nil)
	if err != nil {
		return "", err
	}

	if len(result.Vpcs) == 0 {
		return "", errors.New("There are no VPCs to associate with")
	}

	// We need to find a default vpc
	for _, vpc := range result.Vpcs {
		if *vpc.IsDefault {
			return *vpc.VpcId, nil
		}
	}

	return "", nil
}

func GetDefaultAMI(ctx context.Context, cfg aws.Config, instanceType string) (string, error) {
	svc := ec2.NewFromConfig(cfg)

	architecture := "x86_64"
	// Graviton instances terminate with g
	if strings.HasSuffix(strings.Split(instanceType, ".")[0], "g") {
		architecture = "arm64"
	}

	input := &ec2.DescribeImagesInput{
		Owners: []string{
			"amazon",
			"self",
		},
		Filters: []types.Filter{
			{
				Name: aws.String("virtualization-type"),
				Values: []string{
					"hvm",
				},
			},
			{
				Name: aws.String("architecture"),
				Values: []string{
					architecture,
				},
			},
			{
				Name: aws.String("root-device-type"),
				Values: []string{
					"ebs",
				},
			},
			{
				Name: aws.String("platform-details"),
				Values: []string{
					"Linux/UNIX",
				},
			},
			{
				Name: aws.String("description"),
				Values: []string{
					"Canonical, Ubuntu, 22.04 LTS*",
				},
			},
		},
	}

	result, err := svc.DescribeImages(ctx, input)
	if err != nil {
		return "", err
	}

	// Sort by date, so we take the latest AMI available for Ubuntu 22.04
	sort.Slice(result.Images, func(i, j int) bool {
		iTime, err := time.Parse("2006-01-02T15:04:05.000Z", *result.Images[i].CreationDate)
		if err != nil {
			return false
		}
		jTime, err := time.Parse("2006-01-02T15:04:05.000Z", *result.Images[j].CreationDate)
		if err != nil {
			return false
		}

		return iTime.After(jTime)
	})

	return *result.Images[0].ImageId, nil
}

func GetAMIRootDevice(ctx context.Context, cfg aws.Config, diskImage string) (string, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeImagesInput{
		ImageIds: []string{
			diskImage,
		},
	}
	result, err := svc.DescribeImages(ctx, input)
	if err != nil {
		return "", err
	}

	// Struct spec: https://docs.aws.amazon.com/sdk-for-go/api/service/ec2/#Image
	if len(result.Images) == 0 || *result.Images[0].RootDeviceName == "" {
		return "/dev/sda1", nil
	}

	return *result.Images[0].RootDeviceName, nil
}

func GetDevpodInstanceProfile(ctx context.Context, provider *AwsProvider) (string, error) {
	if provider.Config.InstanceProfileArn != "" {
		return provider.Config.InstanceProfileArn, nil
	}

	svc := iam.NewFromConfig(provider.AwsConfig)

	roleInput := &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String("devpod-ec2-role"),
	}

	response, err := svc.GetInstanceProfile(ctx, roleInput)
	if err != nil {
		return CreateDevpodInstanceProfile(ctx, provider)
	}

	return *response.InstanceProfile.Arn, nil
}

func CreateDevpodInstanceProfile(ctx context.Context, provider *AwsProvider) (string, error) {
	svc := iam.NewFromConfig(provider.AwsConfig)
	roleInput := &iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(`{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}`),
		RoleName: aws.String("devpod-ec2-role"),
	}

	_, err := svc.CreateRole(ctx, roleInput)
	if err != nil {
		return "", err
	}

	policyInput := &iam.PutRolePolicyInput{
		PolicyDocument: aws.String(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Describe",
      "Action": [
        "ec2:DescribeInstances"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Sid": "Stop",
      "Action": [
        "ec2:StopInstances"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringLike": {
          "aws:userid": "*:${ec2:InstanceID}"
        }
      }
    }
  ]
}`),
		PolicyName: aws.String("devpod-ec2-policy"),
		RoleName:   aws.String("devpod-ec2-role"),
	}

	_, err = svc.PutRolePolicy(ctx, policyInput)
	if err != nil {
		return "", err
	}

	ssmManagedInstanceCorePolicyInput := &iam.AttachRolePolicyInput{
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"),
		RoleName:  aws.String("devpod-ec2-role"),
	}

	_, err = svc.AttachRolePolicy(ctx, ssmManagedInstanceCorePolicyInput)
	if err != nil {
		return "", err
	}

	if provider.Config.KmsKeyARNForSessionManager != "" {
		kmsDecryptPolicyInput := &iam.PutRolePolicyInput{
			PolicyDocument: aws.String(fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DecryptSSM",
      "Action": [
        "kms:Decrypt"
      ],
      "Effect": "Allow",
      "Resource": "%s"
    }
  ]
}`, provider.Config.KmsKeyARNForSessionManager)),
			PolicyName: aws.String("ssm-kms-decrypt-policy"),
			RoleName:   aws.String("devpod-ec2-role"),
		}

		_, err = svc.PutRolePolicy(ctx, kmsDecryptPolicyInput)
		if err != nil {
			return "", err
		}
	}

	instanceProfile := &iam.CreateInstanceProfileInput{
		InstanceProfileName: aws.String("devpod-ec2-role"),
	}

	response, err := svc.CreateInstanceProfile(ctx, instanceProfile)
	if err != nil {
		return "", err
	}

	instanceRole := &iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: aws.String("devpod-ec2-role"),
		RoleName:            aws.String("devpod-ec2-role"),
	}

	_, err = svc.AddRoleToInstanceProfile(ctx, instanceRole)
	if err != nil {
		return "", err
	}

	// TODO: need to find a better way to ensure
	// role/profile propagation has succeeded
	time.Sleep(time.Second * 10)

	return *response.InstanceProfile.Arn, nil
}

func GetDevpodSecurityGroups(ctx context.Context, provider *AwsProvider) ([]string, error) {
	if provider.Config.SecurityGroupID != "" {
		return strings.Split(provider.Config.SecurityGroupID, ","), nil
	}

	svc := ec2.NewFromConfig(provider.AwsConfig)
	input := &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					"devpod",
				},
			},
		},
	}

	if provider.Config.VpcID != "" {
		input.Filters = append(input.Filters, types.Filter{
			Name: aws.String("vpc-id"),
			Values: []string{
				provider.Config.VpcID,
			},
		})
	}

	result, err := svc.DescribeSecurityGroups(ctx, input)
	// It it is not created, do it
	if len(result.SecurityGroups) == 0 || err != nil {
		sg, err := CreateDevpodSecurityGroup(ctx, provider)
		if err != nil {
			return nil, err
		}

		return []string{sg}, nil
	}

	sgs := []string{}
	for res := range result.SecurityGroups {
		sgs = append(sgs, *result.SecurityGroups[res].GroupId)
	}

	return sgs, nil
}

func CreateDevpodSecurityGroup(ctx context.Context, provider *AwsProvider) (string, error) {
	var err error

	svc := ec2.NewFromConfig(provider.AwsConfig)

	vpc, err := GetDevpodVPC(ctx, provider)
	if err != nil {
		return "", err
	}

	// Create the security group with the VPC, name, and description.
	result, err := svc.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String("devpod"),
		Description: aws.String("Default Security Group for DevPod"),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: "security-group",
				Tags: []types.Tag{
					{
						Key:   aws.String("devpod"),
						Value: aws.String("devpod"),
					},
				},
			},
		},
		VpcId: aws.String(vpc),
	})
	if err != nil {
		return "", err
	}

	groupID := *result.GroupId

	// No need to open ssh port if use session manager.
	if provider.Config.UseSessionManager {
		return groupID, nil
	}

	// Add permissions to the security group
	_, err = svc.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(groupID),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpRanges: []types.IpRange{
					{
						CidrIp: aws.String("0.0.0.0/0"),
					},
				},
			},
		},
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: "security-group-rule",
				Tags: []types.Tag{
					{
						Key:   aws.String("devpod"),
						Value: aws.String("devpod-ingress"),
					},
				},
			},
		},
	})
	if err != nil {
		return "", err
	}

	return groupID, nil
}

func GetDevpodInstance(
	ctx context.Context,
	cfg aws.Config,
	name string,
) (Machine, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					name,
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []string{
					"pending",
					"running",
					"shutting-down",
					"stopped",
					"stopping",
				},
			},
		},
	}

	result, err := svc.DescribeInstances(ctx, input)
	if err != nil {
		return Machine{}, err
	}

	// Sort slice in order to have the newest result first
	sort.Slice(result.Reservations, func(i, j int) bool {
		return result.Reservations[i].Instances[0].LaunchTime.After(
			*result.Reservations[j].Instances[0].LaunchTime,
		)
	})

	return NewMachineFromInstance(result.Reservations[0].Instances[0]), nil
}

func GetDevpodStoppedInstance(
	ctx context.Context,
	cfg aws.Config,
	name string,
) (Machine, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					name,
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []string{
					"stopped",
				},
			},
		},
	}

	result, err := svc.DescribeInstances(ctx, input)
	if err != nil {
		return Machine{}, err
	}

	// Sort slice in order to have the newest result first
	sort.Slice(result.Reservations, func(i, j int) bool {
		return result.Reservations[i].Instances[0].LaunchTime.After(
			*result.Reservations[j].Instances[0].LaunchTime,
		)
	})

	return NewMachineFromInstance(result.Reservations[0].Instances[0]), nil
}

func GetDevpodRunningInstance(
	ctx context.Context,
	cfg aws.Config,
	name string,
) (Machine, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					name,
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []string{
					"running",
				},
			},
		},
	}

	result, err := svc.DescribeInstances(ctx, input)
	if err != nil {
		return Machine{}, err
	}

	// Sort slice in order to have the newest result first
	sort.Slice(result.Reservations, func(i, j int) bool {
		return result.Reservations[i].Instances[0].LaunchTime.After(
			*result.Reservations[j].Instances[0].LaunchTime,
		)
	})

	return NewMachineFromInstance(result.Reservations[0].Instances[0]), nil
}

func GetInstanceTags(providerAws *AwsProvider, route53ZoneName string) []types.TagSpecification {
	tags := []types.Tag{
		{
			Key:   aws.String("devpod"),
			Value: aws.String(providerAws.Config.MachineID),
		},
	}
	if route53ZoneName != "" {
		tags = append(tags, types.Tag{
			Key:   aws.String("devpod:private-hostname"),
			Value: aws.String(providerAws.Config.MachineID + "." + route53ZoneName),
		})
	}

	result := []types.TagSpecification{
		{
			ResourceType: "instance",
			Tags:         tags,
		},
	}

	reg := regexp.MustCompile(`Name=([A-Za-z0-9!"#$%&'()*+\-./:;<>?@[\\\]^_{|}~]+),Value=([A-Za-z0-9!"#$%&'()*+\-./:;<>?@[\\\]^_{|}~]+)`)

	tagList := reg.FindAllString(providerAws.Config.InstanceTags, -1)
	if tagList == nil {
		return result
	}

	for _, tag := range tagList {
		tagSplit := strings.Split(tag, ",")

		name := strings.ReplaceAll(tagSplit[0], "Name=", "")
		value := strings.ReplaceAll(tagSplit[1], "Value=", "")

		tagSpec := types.Tag{
			Key:   aws.String(name),
			Value: aws.String(value),
		}

		result[0].Tags = append(result[0].Tags, tagSpec)
	}

	return result
}

func Create(
	ctx context.Context,
	cfg aws.Config,
	providerAws *AwsProvider,
) (Machine, error) {
	svc := ec2.NewFromConfig(cfg)

	r53ZoneId := ""
	var r53client *route53.Client
	if providerAws.Config.Route53ZoneName != "" {
		r53client = route53.NewFromConfig(cfg)
		listZonesOut, err := r53client.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{
			DNSName: aws.String(providerAws.Config.Route53ZoneName),
		})
		if err != nil {
			return Machine{}, err
		}

		zoneName := providerAws.Config.Route53ZoneName
		if !strings.HasSuffix(zoneName, ".") {
			zoneName += "."
		}
		for _, zone := range listZonesOut.HostedZones {
			if *zone.Name == zoneName {
				r53ZoneId = *zone.Id
				break
			}
		}
	}

	devpodSG, err := GetDevpodSecurityGroups(ctx, providerAws)
	if err != nil {
		return Machine{}, err
	}

	volSizeI32 := int32(providerAws.Config.DiskSizeGB)

	userData, err := GetInjectKeypairScript(providerAws.Config.MachineFolder)
	if err != nil {
		return Machine{}, err
	}

	instance := &ec2.RunInstancesInput{
		ImageId:          aws.String(providerAws.Config.DiskImage),
		InstanceType:     types.InstanceType(providerAws.Config.MachineType),
		MinCount:         aws.Int32(1),
		MaxCount:         aws.Int32(1),
		SecurityGroupIds: devpodSG,
		MetadataOptions: &types.InstanceMetadataOptionsRequest{
			HttpEndpoint:            types.InstanceMetadataEndpointStateEnabled,
			HttpTokens:              types.HttpTokensStateRequired,
			HttpPutResponseHopLimit: aws.Int32(1),
		},
		BlockDeviceMappings: []types.BlockDeviceMapping{
			{
				DeviceName: aws.String(providerAws.Config.RootDevice),
				Ebs: &types.EbsBlockDevice{
					VolumeSize: &volSizeI32,
				},
			},
		},
		TagSpecifications: GetInstanceTags(providerAws, providerAws.Config.Route53ZoneName),
		UserData:          &userData,
	}
	if providerAws.Config.UseSpotInstance {
		instance.InstanceMarketOptions = &types.InstanceMarketOptionsRequest{
			MarketType: "spot",
			SpotOptions: &types.SpotMarketOptions{
				SpotInstanceType:             "persistent",
				InstanceInterruptionBehavior: "stop",
			},
		}
	}

	profile, err := GetDevpodInstanceProfile(ctx, providerAws)
	if err == nil {
		instance.IamInstanceProfile = &types.IamInstanceProfileSpecification{
			Arn: aws.String(profile),
		}
	}

	if providerAws.Config.VpcID != "" && providerAws.Config.SubnetID == "" {
		subnetID, err := GetSubnetID(ctx, providerAws)
		if err != nil {
			return Machine{}, err
		}

		if subnetID == "" {
			return Machine{}, fmt.Errorf("could not find a matching SubnetID in VPC %s, please specify one", providerAws.Config.VpcID)
		}

		instance.SubnetId = &subnetID
	}

	if providerAws.Config.SubnetID != "" {
		instance.SubnetId = &providerAws.Config.SubnetID
	}

	result, err := svc.RunInstances(ctx, instance)
	if err != nil {
		return Machine{}, err
	}

	if r53ZoneId != "" {
		_, err := r53client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
			HostedZoneId: aws.String(r53ZoneId),
			ChangeBatch: &r53types.ChangeBatch{
				Changes: []r53types.Change{
					{
						Action: r53types.ChangeActionCreate,
						ResourceRecordSet: &r53types.ResourceRecordSet{
							Name: aws.String(providerAws.Config.MachineID + "." + providerAws.Config.Route53ZoneName),
							Type: r53types.RRTypeA,
							ResourceRecords: []r53types.ResourceRecord{
								{
									Value: result.Instances[0].PrivateIpAddress,
								},
							},
							TTL: aws.Int64(300),
						},
					},
				},
			},
		})
		if err != nil {
			return Machine{}, err
		}
	}

	return NewMachineFromInstance(result.Instances[0]), nil
}

func Start(ctx context.Context, cfg aws.Config, instanceID string) error {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.StartInstancesInput{
		InstanceIds: []string{
			instanceID,
		},
	}

	_, err := svc.StartInstances(ctx, input)
	if err != nil {
		return err
	}

	return err
}

func Stop(ctx context.Context, cfg aws.Config, instanceID string) error {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.StopInstancesInput{
		InstanceIds: []string{
			instanceID,
		},
	}

	_, err := svc.StopInstances(ctx, input)
	if err != nil {
		return err
	}

	return err
}

func Status(ctx context.Context, cfg aws.Config, name string) (client.Status, error) {
	result, err := GetDevpodInstance(ctx, cfg, name)
	if err != nil {
		return client.StatusNotFound, err
	}

	if result.Status == "" {
		return client.StatusNotFound, nil
	}

	status := result.Status
	switch {
	case status == "running":
		return client.StatusRunning, nil
	case status == "stopped":
		return client.StatusStopped, nil
	case status == "terminated":
		return client.StatusNotFound, nil
	default:
		return client.StatusBusy, nil
	}
}

func Delete(ctx context.Context, provider *AwsProvider, instance Machine) error {
	svc := ec2.NewFromConfig(provider.AwsConfig)

	input := &ec2.TerminateInstancesInput{
		InstanceIds: []string{
			instance.InstanceID,
		},
	}

	_, err := svc.TerminateInstances(ctx, input)
	if err != nil {
		return err
	}

	if instance.SpotInstanceRequestId != "" {
		_, err = svc.CancelSpotInstanceRequests(ctx, &ec2.CancelSpotInstanceRequestsInput{
			SpotInstanceRequestIds: []string{
				instance.SpotInstanceRequestId,
			},
		})
		if err != nil {
			return err
		}
	}

	if provider.Config.Route53ZoneName != "" {
		r53client := route53.NewFromConfig(provider.AwsConfig)
		listZonesOut, err := r53client.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{
			DNSName: aws.String(provider.Config.Route53ZoneName),
		})
		if err != nil {
			return err
		}
		zoneName := provider.Config.Route53ZoneName
		if !strings.HasSuffix(zoneName, ".") {
			zoneName += "."
		}
		r53ZoneId := ""
		for _, zone := range listZonesOut.HostedZones {
			if *zone.Name == zoneName {
				r53ZoneId = *zone.Id
				break
			}
		}
		_, err = r53client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
			HostedZoneId: aws.String(r53ZoneId),
			ChangeBatch: &r53types.ChangeBatch{
				Changes: []r53types.Change{
					{
						Action: r53types.ChangeActionDelete,
						ResourceRecordSet: &r53types.ResourceRecordSet{
							Name: aws.String(provider.Config.MachineID + "." + provider.Config.Route53ZoneName),
							Type: r53types.RRTypeA,
							ResourceRecords: []r53types.ResourceRecord{
								{
									Value: aws.String(instance.PrivateIP),
								},
							},
							TTL: aws.Int64(300),
						},
					},
				},
			},
		})
		if err != nil {
			return err
		}
	}

	return err
}

func GetInjectKeypairScript(dir string) (string, error) {
	publicKeyBase, err := ssh.GetPublicKeyBase(dir)
	if err != nil {
		return "", err
	}

	publicKey, err := base64.StdEncoding.DecodeString(publicKeyBase)
	if err != nil {
		return "", err
	}

	resultScript := `#!/bin/sh
useradd devpod -d /home/devpod
mkdir -p /home/devpod
if grep -q sudo /etc/groups; then
	usermod -aG sudo devpod
elif grep -q wheel /etc/groups; then
	usermod -aG wheel devpod
fi
echo "devpod ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/91-devpod
mkdir -p /home/devpod/.ssh
echo "` + string(publicKey) + `" >> /home/devpod/.ssh/authorized_keys
chmod 0700 /home/devpod/.ssh
chmod 0600 /home/devpod/.ssh/authorized_keys
chown -R devpod:devpod /home/devpod`

	return base64.StdEncoding.EncodeToString([]byte(resultScript)), nil
}
