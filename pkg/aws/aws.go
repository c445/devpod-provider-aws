package aws

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/loft-sh/devpod/pkg/log"
	"github.com/skratchdot/open-golang/open"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
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
	"github.com/loft-sh/devpod/pkg/ssh"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
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

	if err := OIDC(config, logs, &cfg); err != nil {
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

func OIDC(config *options.Options, logs log.Logger, cfg *aws.Config) error {
	t := AccessToken{}

	bytes, err := os.ReadFile(os.Getenv("HOME") + "/.token")
	if err == nil {
		json.Unmarshal(bytes, &t)
	}

	if t.AccessToken == "" || t.Expires < time.Now().Unix()+600 {

		// initialize the code verifier
		var codeVerifier, _ = cv.CreateCodeVerifier()

		// start a web server to listen on a callback URL
		server := &http.Server{Addr: config.IdpRedirectURL}

		token := make(chan AccessToken)

		// define a handler that will get the authorization code, call the token endpoint, and close the HTTP server
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				return
			}

			err := r.ParseForm()
			if err != nil {
				logs.Fatal(err)
			}
			// get the authorization code
			code := r.PostForm.Get("code")
			if code == "" {
				fmt.Println("idpCli: Url Param 'code' is missing")
				_, err := io.WriteString(w, "Error: could not find 'code' URL parameter\n")
				if err != nil {
					logs.Fatal(err)
				}
				return
			}

			// trade the authorization code and the code verifier for an access_token
			codeVerifier := codeVerifier.String()
			t, err := getAccessToken(config.IdpClientID, config.IdpClientSecret, codeVerifier, code, config.IdpRedirectURL, config.IdpAuthDomain)
			if err != nil {
				fmt.Println("idpCli: could not get access token")
				_, err := io.WriteString(w, "Error: could not retrieve access token\n")
				if err != nil {
					logs.Fatal(err)
				}
				return
			}
			token <- t

			// return an indication of success to the caller
			_, err = io.WriteString(w, `
		<html>
			<body>
				<h1>Login successful!</h1>
				<h2>You can close this window and return to the CLI.</h2>
			</body>
		</html>`)
			if err != nil {
				logs.Fatal(err)
			}
		})

		// parse the redirect URL for the port number
		u, err := url.Parse(config.IdpRedirectURL)
		if err != nil {
			fmt.Printf("idpCli: bad redirect URL: %s\n", err)
			os.Exit(1)
		}

		// set up a listener on the redirect port
		port := fmt.Sprintf(":%s", u.Port())
		l, err := net.Listen("tcp", port)
		if err != nil {
			fmt.Printf("idpCli: can't listen to port %s: %s\n", port, err)
			os.Exit(1)
		}

		go func() {
			_ = server.Serve(l)
		}()
		defer func(server *http.Server) {
			err := server.Close()
			if err != nil {
				logs.Fatal(err)
			}
		}(server)

		// Create code_challenge with S256 method
		codeChallenge := codeVerifier.CodeChallengeS256()

		state, err := randString(16)
		if err != nil {
			return fmt.Errorf("Internal error: %w", err)
		}
		nonce, err := randString(16)
		if err != nil {
			return fmt.Errorf("Internal error: %w", err)
		}

		// construct the authorization URL (with Auth0 as the authorization provider)

		authorizationURL := fmt.Sprintf(
			"https://%s/connect/authorize?"+
				"&scope=openid%%20profile%%20offline_access%%20daimler-aws-idp-logon-api%%20daimler-aws-idp-token-resource"+
				"&response_type=code%%20id_token"+
				"&client_id=%s"+
				"&nonce=%s"+
				"&state=%s"+
				"&code_challenge=%s"+
				"&code_challenge_method=S256"+
				"&response_mode=form_post"+
				"&redirect_uri=%s",
			config.IdpAuthDomain, config.IdpClientID, nonce, state, codeChallenge, config.IdpRedirectURL)

		// open a browser window to the authorizationURL
		if err := open.Start(authorizationURL); err != nil {
			return fmt.Errorf("idpCli: can't open browser to URL %s: %w", authorizationURL, err)
		}

		// wait for the token
		t = <-token

		file, _ := json.MarshalIndent(t, "", "  ")
		_ = os.WriteFile(os.Getenv("HOME")+"/.token", file, 0600)
	}

	accounts, err := GetAwsRoles(config, t.AccessToken)
	if err != nil {
		return err
	}

	roleID := ""
	for _, account := range accounts {
		if account.Id != config.AccountID {
			continue
		}

		for _, role := range account.Roles {
			if role.RoleName == "DhcFullAdmin" {
				roleID = role.RoleId
				break
			}
		}
	}

	credentials, err := GetAwsAssumeRole(config, t.AccessToken, roleID)
	if err != nil {
		return fmt.Errorf("idpCli: unable to get AWS credentials: %w", err)
	}

	cfg.Credentials = credentialProvider{creds: aws.Credentials{
		AccessKeyID:     credentials.AccessKey,
		SecretAccessKey: credentials.SecretAccessKey,
		SessionToken:    credentials.SessionToken,
		Source:          "idpcli",
		CanExpire:       false,
	}}
	return nil
}

type AwsProvider struct {
	Config           *options.Options
	AwsConfig        aws.Config
	Log              log.Logger
	WorkingDirectory string
}

type credentialProvider struct {
	creds aws.Credentials
}

func (c credentialProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return c.creds, nil
}

var _ aws.CredentialsProvider = (*credentialProvider)(nil)

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

	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		return Machine{}, nil
	}
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

	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		return Machine{}, nil
	}
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

	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		return Machine{}, nil
	}
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

type AccessToken struct {
	AccessToken string `json:"access_token"`
	Expires     int64  `json:"expires_in"`
}

func getAccessToken(clientID string, clientSecret string, codeVerifier string, authorizationCode string, callbackURL string, authDomain string) (AccessToken, error) {
	// set the url and form-encoded data for the POST to the access token endpoint
	tokenUrl := "https://" + authDomain + "/connect/token"

	data := fmt.Sprintf(
		"grant_type=authorization_code"+
			"&client_id=%s"+
			"&code_verifier=%s"+
			"&code=%s"+
			"&redirect_uri=%s"+
			"&client_secret=%s",
		clientID, codeVerifier, authorizationCode, callbackURL, clientSecret)
	payload := strings.NewReader(data)

	// create the request and execute it
	req, _ := http.NewRequest("POST", tokenUrl, payload)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return AccessToken{}, fmt.Errorf("idpCli: HTTP error: %w", err)
	}

	// process the response
	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	// unmarshal the json into a string map
	var responseData map[string]interface{}
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return AccessToken{}, fmt.Errorf("idpCli: JSON error: %w", err)
	}

	ttl := responseData["expires_in"].(float64)

	return AccessToken{
		AccessToken: responseData["access_token"].(string),
		Expires:     time.Now().Unix() + int64(ttl),
	}, nil
}

func GetAwsAssumeRole(opts *options.Options, bearerToken string, roleId string) (Credentials, error) {
	// create the request and execute it
	data := "{\"RoleId\":\"" + roleId + "\",\"UseFallbackSessionDuration\":false}"
	payload := strings.NewReader(data)

	// create the request and execute it
	req, _ := http.NewRequest("POST", opts.IdpAssumeRoleURI, payload)
	req.Header.Add("Authorization", "Bearer "+bearerToken)
	req.Header.Add("Content-Type", "application/json; charset=utf-8")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return Credentials{}, fmt.Errorf("idpCli: HTTP error: %w", err)
	}

	// process the response
	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	credentials := Credentials{}
	err = json.Unmarshal(body, &credentials)
	if err != nil {
		return Credentials{}, fmt.Errorf("idpCli: JSON error: %w", err)
	}

	return credentials, nil
}

func GetAwsRoles(opts *options.Options, bearerToken string) (AWSAccounts, error) {
	results := AWSAccounts{}

	// create the request and execute it
	req, err := http.NewRequest("GET", opts.IdpRolesURI, nil)
	req.Header.Add("Authorization", "Bearer "+bearerToken)
	resp, _ := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("IdpCli: Error on response: ", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("IdpCli: Error while reading the response bytes: ", err)
	}

	// unmarshal the json into a string map
	err = json.Unmarshal(body, &results)
	if err != nil {
		fmt.Printf("idpCli: JSON error: %s", err)
		return results, err
	}

	return results, nil
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type AWSAccounts []struct {
	Description string  `json:"accountDescription"`
	Id          string  `json:"accountId"`
	Name        string  `json:"accountName"`
	Roles       []Roles `json:"awsRoles"`
}

type Roles struct {
	AssumeRoleDuration string `json:"assumeRoleDuration"`
	RoleId             string `json:"roleId"`
	RoleName           string `json:"roleName"`
}

type Credentials struct {
	AccessKey           string              `json:"accessKey"`
	SecretAccessKey     string              `json:"secretAccessKey"`
	SessionToken        string              `json:"sessionToken"`
	ErrorCode           string              `json:"errorCode"`
	Status              string              `json:"status"`
	Title               string              `json:"title"`
	Message             string              `json:"message"`
	TroubleShootingInfo TroubleShootingInfo `json:"troubleshootingInfo"`
}

type TroubleShootingInfo struct {
	AccountID   string `json:"Account ID"`
	AccountName string `json:"Account name"`
	RoleName    string `json:"Role name"`
	Timestamp   string `json:"Timestamp"`
	UserID      string `json:"User ID"`
}
