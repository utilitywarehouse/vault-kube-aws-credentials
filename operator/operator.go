package operator

import (
	"fmt"

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
		return nil, err
	}

	vaultConfig := vault.DefaultConfig()
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}

	var backends []secretBackend

	if fc.AWS.Enabled {
		b, err := newAWSBackend(&awsBackendConfig{
			defaultTTL:  fc.AWS.DefaultTTL,
			path:        fc.AWS.Path,
			rules:       fc.AWS.Rules,
			vaultClient: vaultClient,
		})
		if err != nil {
			return nil, err
		}
		backends = append(backends, b)
	}

	if fc.GCP.Enabled {
		b, err := newGCPBackend(&gcpBackendConfig{
			path:        fc.GCP.Path,
			rules:       fc.GCP.Rules,
			vaultClient: vaultClient,
		})
		if err != nil {
			return nil, err
		}
		backends = append(backends, b)
	}

	if len(backends) == 0 {
		return nil, fmt.Errorf("at least one backend must be enabled in the configuration file")
	}

	for _, b := range backends {
		r := &backendReconciler{
			backend:               b,
			kubernetesAuthBackend: fc.KubernetesAuthBackend,
			kubeClient:            mgr.GetClient(),
			log:                   log.WithName(b.String()),
			prefix:                fc.Prefix,
			vaultClient:           vaultClient,
			vaultConfig:           vaultConfig,
		}
		if err := r.SetupWithManager(mgr); err != nil {
			return nil, err
		}
	}

	return &Operator{mgr: mgr}, nil
}

// Start runs the operator
func (o *Operator) Start() error {
	return o.mgr.Start(ctrl.SetupSignalHandler())
}
