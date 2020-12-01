package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/utilitywarehouse/vault-kube-cloud-credentials/operator"
	"github.com/utilitywarehouse/vault-kube-cloud-credentials/sidecar"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	operatorCommand        = flag.NewFlagSet("operator", flag.ExitOnError)
	flagOperatorConfigFile = operatorCommand.String("config-file", "", "Path to a configuration file")

	awsSidecarCommand    = flag.NewFlagSet("aws-sidecar", flag.ExitOnError)
	flagAWSPrefix        = awsSidecarCommand.String("prefix", "vkcc", "The prefix used by the operator to create the login and backend roles")
	flagAWSBackend       = awsSidecarCommand.String("backend", "aws", "AWS secret backend path")
	flagAWSRoleArn       = awsSidecarCommand.String("role-arn", "", "AWS role arn to assume")
	flagAWSRole          = awsSidecarCommand.String("role", "", "AWS secret role, defaults to <prefix>_aws_<namespace>_<service-account>")
	flagAWSKubeAuthRole  = awsSidecarCommand.String("kube-auth-role", "", "Kubernetes auth role, defaults to <prefix>_aws_<namespace>_<service-account>")
	flagAWSKubeBackend   = awsSidecarCommand.String("kube-auth-backend", "kubernetes", "Kubernetes auth backend")
	flagAWSKubeTokenPath = awsSidecarCommand.String("kube-token-path", "/var/run/secrets/kubernetes.io/serviceaccount/token", "Path to the kubernetes serviceaccount token")
	flagAWSListenAddr    = awsSidecarCommand.String("listen-address", "127.0.0.1:8000", "Listen address")
	flagAWSOpsAddr       = awsSidecarCommand.String("operational-address", ":8099", "Listen address for operational status endpoints")

	gcpSidecarCommand    = flag.NewFlagSet("gcp-sidecar", flag.ExitOnError)
	flagGCPPrefix        = gcpSidecarCommand.String("prefix", "vkcc", "The prefix used by the operator to create the login and backend roles")
	flagGCPBackend       = gcpSidecarCommand.String("backend", "gcp", "GCP secret backend path")
	flagGCPRoleSet       = gcpSidecarCommand.String("roleset", "", "GCP secret roleset, defaults to <prefix>_gcp_<namespace>_<service-account>")
	flagGCPKubeAuthRole  = gcpSidecarCommand.String("kube-auth-role", "", "Kubernetes auth role, defaults to <prefix>_gcp_<namespace>_<service-account>")
	flagGCPKubeBackend   = gcpSidecarCommand.String("kube-auth-backend", "kubernetes", "Kubernetes auth backend")
	flagGCPKubeTokenPath = gcpSidecarCommand.String("kube-token-path", "/var/run/secrets/kubernetes.io/serviceaccount/token", "Path to the kubernetes serviceaccount token")
	flagGCPListenAddr    = gcpSidecarCommand.String("listen-address", "127.0.0.1:8000", "Listen address")
	flagGCPOpsAddr       = gcpSidecarCommand.String("operational-address", ":8099", "Listen address for operational status endpoints")

	log = ctrl.Log.WithName("main")
)

func usage() {
	fmt.Printf(
		`Usage:
  %s [command]

Commands:
  operator      Run the operator
  aws-sidecar   Sidecar for AWS credentials
  gcp-sidecar   Sidecar for GCP credentials
`, os.Args[0])
}

func main() {
	flag.Usage = usage

	if len(os.Args) < 2 {
		usage()
		return
	}

	logOpts := zap.Options{}

	switch os.Args[1] {
	case "operator":
		logOpts.BindFlags(operatorCommand)
		operatorCommand.Parse(os.Args[2:])
	case "aws-sidecar":
		logOpts.BindFlags(awsSidecarCommand)
		awsSidecarCommand.Parse(os.Args[2:])
	case "gcp-sidecar":
		logOpts.BindFlags(gcpSidecarCommand)
		gcpSidecarCommand.Parse(os.Args[2:])
	default:
		usage()
		return
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&logOpts)))

	if operatorCommand.Parsed() {
		if len(operatorCommand.Args()) > 0 {
			operatorCommand.PrintDefaults()
			os.Exit(1)
		}

		o, err := operator.New(*flagOperatorConfigFile)
		if err != nil {
			log.Error(err, "error creating operator")
			os.Exit(1)
		}

		if err := o.Start(); err != nil {
			log.Error(err, "error running operator")
			os.Exit(1)
		}

		return
	}

	if awsSidecarCommand.Parsed() {
		if len(awsSidecarCommand.Args()) > 0 {
			awsSidecarCommand.PrintDefaults()
			os.Exit(1)
		}

		tokenClaims, err := newKubeTokenClaimsFromFile(*flagAWSKubeTokenPath)
		if err != nil {
			log.Error(err, "error reading token from file", "file", *flagAWSKubeTokenPath)
			os.Exit(1)
		}

		kubeAuthRole := *flagAWSKubeAuthRole
		if kubeAuthRole == "" {
			kubeAuthRole = *flagAWSPrefix + "_aws_" + tokenClaims.Namespace + "_" + tokenClaims.ServiceAccountName
		}

		awsRole := *flagAWSRole
		if awsRole == "" {
			awsRole = *flagAWSPrefix + "_aws_" + tokenClaims.Namespace + "_" + tokenClaims.ServiceAccountName
		}

		sidecarConfig := &sidecar.Config{
			KubeAuthPath:  *flagAWSKubeBackend,
			KubeAuthRole:  kubeAuthRole,
			ListenAddress: *flagAWSListenAddr,
			OpsAddress:    *flagAWSOpsAddr,
			ProviderConfig: &sidecar.AWSProviderConfig{
				Path:    *flagAWSBackend,
				RoleArn: *flagAWSRoleArn,
				Role:    awsRole,
			},
			TokenPath: *flagAWSKubeTokenPath,
		}

		s, err := sidecar.New(sidecarConfig)
		if err != nil {
			log.Error(err, "error creating sidecar")
			os.Exit(1)
		}

		if err := s.Run(); err != nil {
			log.Error(err, "error running sidecar")
			os.Exit(1)
		}

		return
	}

	if gcpSidecarCommand.Parsed() {
		if len(gcpSidecarCommand.Args()) > 0 {
			gcpSidecarCommand.PrintDefaults()
			os.Exit(1)
		}

		tokenClaims, err := newKubeTokenClaimsFromFile(*flagGCPKubeTokenPath)
		if err != nil {
			log.Error(err, "error reading token from file", "file", *flagGCPKubeTokenPath)
			os.Exit(1)
		}

		kubeAuthRole := *flagGCPKubeAuthRole
		if kubeAuthRole == "" {
			kubeAuthRole = *flagGCPPrefix + "_gcp_" + tokenClaims.Namespace + "_" + tokenClaims.ServiceAccountName
		}

		gcpRoleSet := *flagGCPRoleSet
		if gcpRoleSet == "" {
			gcpRoleSet = *flagGCPPrefix + "_gcp_" + tokenClaims.Namespace + "_" + tokenClaims.ServiceAccountName
		}

		sidecarConfig := &sidecar.Config{
			KubeAuthPath:  *flagGCPKubeBackend,
			KubeAuthRole:  kubeAuthRole,
			ListenAddress: *flagGCPListenAddr,
			OpsAddress:    *flagGCPOpsAddr,
			ProviderConfig: &sidecar.GCPProviderConfig{
				Path:    *flagGCPBackend,
				RoleSet: gcpRoleSet,
			},
			TokenPath: *flagGCPKubeTokenPath,
		}

		s, err := sidecar.New(sidecarConfig)
		if err != nil {
			log.Error(err, "error creating sidecar")
			os.Exit(1)
		}

		if err := s.Run(); err != nil {
			log.Error(err, "error running sidecar")
			os.Exit(1)
		}

		return
	}

	usage()
	return
}
