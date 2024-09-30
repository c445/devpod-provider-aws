package options

import (
	"fmt"
	"os"
	"strconv"
)

var (
	AWS_AMI                             = "AWS_AMI"
	AWS_DISK_SIZE                       = "AWS_DISK_SIZE"
	AWS_ROOT_DEVICE                     = "AWS_ROOT_DEVICE"
	AWS_INSTANCE_TYPE                   = "AWS_INSTANCE_TYPE"
	AWS_REGION                          = "AWS_REGION"
	AWS_SECURITY_GROUP_ID               = "AWS_SECURITY_GROUP_ID"
	AWS_SUBNET_ID                       = "AWS_SUBNET_ID"
	AWS_VPC_ID                          = "AWS_VPC_ID"
	AWS_INSTANCE_TAGS                   = "AWS_INSTANCE_TAGS"
	AWS_INSTANCE_PROFILE_ARN            = "AWS_INSTANCE_PROFILE_ARN"
	AWS_USE_INSTANCE_CONNECT_ENDPOINT   = "AWS_USE_INSTANCE_CONNECT_ENDPOINT"
	AWS_INSTANCE_CONNECT_ENDPOINT_ID    = "AWS_INSTANCE_CONNECT_ENDPOINT_ID"
	AWS_USE_SPOT_INSTANCE               = "AWS_USE_SPOT_INSTANCE"
	AWS_USE_SESSION_MANAGER             = "AWS_USE_SESSION_MANAGER"
	AWS_KMS_KEY_ARN_FOR_SESSION_MANAGER = "AWS_KMS_KEY_ARN_FOR_SESSION_MANAGER"
	AWS_ROUTE53_ZONE_NAME               = "AWS_ROUTE53_ZONE_NAME"
	AWS_ACCOUNT_ID                      = "AWS_ACCOUNT_ID"
	IDP_REDIRECT_URL                    = "IDP_REDIRECT_URL"
	IDP_CLIENT_ID                       = "IDP_CLIENT_ID"
	IDP_CLIENT_SECRET                   = "IDP_CLIENT_SECRET"
	IDP_AUTH_DOMAIN                     = "IDP_AUTH_DOMAIN"
	IDP_ASSUME_ROLE_URI                 = "IDP_ASSUME_ROLE_URI"
	IDP_ROLES_URI                       = "IDP_ROLES_URI"
)

type Options struct {
	DiskImage                  string
	DiskSizeGB                 int
	RootDevice                 string
	MachineFolder              string
	MachineID                  string
	MachineType                string
	VpcID                      string
	SubnetID                   string
	SecurityGroupID            string
	InstanceProfileArn         string
	InstanceTags               string
	Zone                       string
	UseInstanceConnectEndpoint bool
	InstanceConnectEndpointID  string
	UseSpotInstance            bool
	UseSessionManager          bool
	KmsKeyARNForSessionManager string
	Route53ZoneName            string
	IdpRedirectURL             string
	IdpClientID                string
	IdpClientSecret            string
	IdpAuthDomain              string
	IdpAssumeRoleURI           string
	IdpRolesURI                string
	AccountID                  string
}

func FromEnv(init bool) (*Options, error) {
	retOptions := &Options{}

	var err error

	retOptions.MachineType, err = fromEnvOrError(AWS_INSTANCE_TYPE)
	if err != nil {
		return nil, err
	}

	diskSizeGB, err := fromEnvOrError(AWS_DISK_SIZE)
	if err != nil {
		return nil, err
	}

	retOptions.DiskSizeGB, err = strconv.Atoi(diskSizeGB)
	if err != nil {
		return nil, err
	}

	retOptions.DiskImage = os.Getenv(AWS_AMI)
	retOptions.RootDevice = os.Getenv(AWS_ROOT_DEVICE)
	retOptions.SecurityGroupID = os.Getenv(AWS_SECURITY_GROUP_ID)
	retOptions.SubnetID = os.Getenv(AWS_SUBNET_ID)
	retOptions.VpcID = os.Getenv(AWS_VPC_ID)
	retOptions.InstanceTags = os.Getenv(AWS_INSTANCE_TAGS)
	retOptions.InstanceProfileArn = os.Getenv(AWS_INSTANCE_PROFILE_ARN)
	retOptions.Zone = os.Getenv(AWS_REGION)
	retOptions.UseInstanceConnectEndpoint = os.Getenv(AWS_USE_INSTANCE_CONNECT_ENDPOINT) == "true"
	retOptions.InstanceConnectEndpointID = os.Getenv(AWS_INSTANCE_CONNECT_ENDPOINT_ID)
	retOptions.UseSpotInstance = os.Getenv(AWS_USE_SPOT_INSTANCE) == "true"
	retOptions.UseSessionManager = os.Getenv(AWS_USE_SESSION_MANAGER) == "true"
	retOptions.KmsKeyARNForSessionManager = os.Getenv(AWS_KMS_KEY_ARN_FOR_SESSION_MANAGER)
	retOptions.Route53ZoneName = os.Getenv(AWS_ROUTE53_ZONE_NAME)
	retOptions.AccountID = os.Getenv(AWS_ACCOUNT_ID)

	retOptions.IdpRedirectURL = os.Getenv(IDP_REDIRECT_URL)
	retOptions.IdpClientID = os.Getenv(IDP_CLIENT_ID)
	retOptions.IdpClientSecret = os.Getenv(IDP_CLIENT_SECRET)
	retOptions.IdpAuthDomain = os.Getenv(IDP_AUTH_DOMAIN)
	retOptions.IdpAssumeRoleURI = os.Getenv(IDP_ASSUME_ROLE_URI)
	retOptions.IdpRolesURI = os.Getenv(IDP_ROLES_URI)

	// Return eraly if we're just doing init
	if init {
		return retOptions, nil
	}

	retOptions.MachineID, err = fromEnvOrError("MACHINE_ID")
	if err != nil {
		return nil, err
	}
	// prefix with devpod-
	retOptions.MachineID = "devpod-" + retOptions.MachineID

	retOptions.MachineFolder, err = fromEnvOrError("MACHINE_FOLDER")
	if err != nil {
		return nil, err
	}

	return retOptions, nil
}

func fromEnvOrError(name string) (string, error) {
	val := os.Getenv(name)
	if val == "" {
		return "", fmt.Errorf(
			"couldn't find option %s in environment, please make sure %s is defined",
			name,
			name,
		)
	}

	return val, nil
}
