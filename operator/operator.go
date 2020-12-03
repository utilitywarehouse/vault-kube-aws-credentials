package operator

import (
	"os"

	vault "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	log = ctrl.Log.WithName("operator")
)

// Operator is responsible for providing access to cloud IAM roles for
// Kubernetes serviceaccounts based on annotations
type Operator struct {
	mgr ctrl.Manager
}

// New creates a new operator from the configuration in the provided file
func New(cfg string) (*Operator, error) {
	fc, err := loadConfigFromFile(cfg)
	if err != nil {
		return nil, err
	}

	scheme := runtime.NewScheme()

	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: fc.MetricsAddress,
		LeaderElection:     false,
	})
	if err != nil {
		log.Error(err, "error creating manager")
		os.Exit(1)
	}

	vaultConfig := vault.DefaultConfig()
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		log.Error(err, "error creating vault client")
		os.Exit(1)
	}

	a, err := newAWSBackend(&awsBackendConfig{
		defaultTTL:  fc.AWS.DefaultTTL,
		path:        fc.AWS.Path,
		rules:       fc.AWS.Rules,
		vaultClient: vaultClient,
	})
	if err != nil {
		return nil, err
	}
	ab := &backendReconciler{
		backend:               a,
		kubernetesAuthBackend: fc.KubernetesAuthBackend,
		kubeClient:            mgr.GetClient(),
		log:                   log.WithName("aws"),
		prefix:                fc.Prefix,
		vaultClient:           vaultClient,
		vaultConfig:           vaultConfig,
	}
	if err := ab.SetupWithManager(mgr); err != nil {
		return nil, err
	}

	return &Operator{mgr: mgr}, nil
}

// Starts runs the operator
func (o *Operator) Start() error {
	return o.mgr.Start(ctrl.SetupSignalHandler())
}
