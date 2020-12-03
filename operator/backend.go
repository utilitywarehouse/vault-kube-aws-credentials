package operator

import (
	"context"
	"strings"

	"github.com/go-logr/logr"
	vault "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// secretBackend provides methods that allow service accounts to be reconciled
// against a secret backend in Vault
type secretBackend interface {
	// String returns the 'name' of this backend
	String() string

	// admitEvent returns a boolean indicating whether the given service
	// account event is valid for the backend
	admitEvent(namespace, name string, annotations map[string]string) bool
	// deleteRole removes a backend role
	deleteRole(role string) error
	// listRoles lists all the roles under this backend
	listRoles() ([]interface{}, error)
	// renderPolicy returns a policy that allows access to the required
	// resources under this backend for the given role name
	renderPolicy(role string) (string, error)
	// writeRole writes the data in the given annotations to the role under
	// this backend
	writeRole(role string, annotations map[string]string) error
}

// backendReconciler creates objects in Vault that allow service accounts to
// access credentials from a secret backend
type backendReconciler struct {
	backend               secretBackend
	kubernetesAuthBackend string
	kubeClient            client.Client
	log                   logr.Logger
	prefix                string
	vaultClient           *vault.Client
	vaultConfig           *vault.Config
}

// Start is ran when the manager starts. It removes items from vault that don't
// have a corresponding service account.
func (r *backendReconciler) Start(stop <-chan struct{}) error {
	r.log.Info("garbage collection started")

	// Secret backend roles
	roleList, err := r.backend.listRoles()
	if err != nil {
		return err
	}
	if err := r.garbageCollect(roleList); err != nil {
		return err
	}

	// Kubernetes auth roles
	kubeAuthRoleList, err := r.vaultClient.Logical().List("auth/" + r.kubernetesAuthBackend + "/role/")
	if err != nil {
		return err
	}
	if kubeAuthRoleList != nil {
		if keys, ok := kubeAuthRoleList.Data["keys"].([]interface{}); ok {
			err = r.garbageCollect(keys)
			if err != nil {
				return err
			}
		}
	}

	// Policies
	policies, err := r.vaultClient.Logical().List("sys/policy")
	if err != nil {
		return err
	}
	if policies != nil {
		if keys, ok := policies.Data["keys"].([]interface{}); ok {
			err = r.garbageCollect(keys)
			if err != nil {
				return err
			}
		}
	}

	r.log.Info("garbage collection finished")

	return nil
}

// Reconcile implements controller.Reconciler. It adds and removes items from
// vault on behalf of service accounts.
func (r *backendReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	if err := r.vaultConfig.ReadEnvironment(); err != nil {
		return ctrl.Result{}, err
	}

	// Check if the service account exists. If it doesn't then it's been
	// deleted and we can remove it from vault
	serviceAccount := &corev1.ServiceAccount{}
	err := r.kubeClient.Get(ctx, req.NamespacedName, serviceAccount)
	if err != nil && errors.IsNotFound(err) {
		return ctrl.Result{}, r.removeFromVault(req.Namespace, req.Name)
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// If the service account exists but isn't valid for reconciling that means
	// it could have previously been valid but the annotation has since been
	// removed or changed to a value that violates the rules described in
	// the config file. In which case it should be removed from vault.
	if !r.backend.admitEvent(req.Namespace, req.Name, serviceAccount.Annotations) {
		return ctrl.Result{}, r.removeFromVault(req.Namespace, req.Name)
	}

	return ctrl.Result{}, r.writeToVault(req.Namespace, req.Name, serviceAccount.Annotations)
}

// SetupWithManager adds the reconciler to the given manager as a runnable and a
// controller
func (r *backendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(r); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ServiceAccount{}).
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				return r.backend.admitEvent(e.Meta.GetNamespace(), e.Meta.GetName(), e.Meta.GetAnnotations())
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return r.backend.admitEvent(e.Meta.GetNamespace(), e.Meta.GetName(), e.Meta.GetAnnotations())
			},
			GenericFunc: func(e event.GenericEvent) bool {
				return r.backend.admitEvent(e.Meta.GetNamespace(), e.Meta.GetName(), e.Meta.GetAnnotations())
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				// Update events are a special case, because we
				// want to remove the roles in vault when the
				// service account transitions out of a valid
				// state
				return r.backend.admitEvent(e.MetaOld.GetNamespace(), e.MetaOld.GetName(), e.MetaOld.GetAnnotations()) ||
					r.backend.admitEvent(e.MetaNew.GetNamespace(), e.MetaNew.GetName(), e.MetaNew.GetAnnotations())
			},
		}).
		Complete(r)

}

// makeKey generates a unique key for the service account indicated by the
// namespace and name. This is used as the name for all the objects written to
// vault, allowing the operator to keep track of the state that's been written to vault.
func (r *backendReconciler) makeKey(namespace, name string) string {
	return r.prefix + "_" + r.backend.String() + "_" + namespace + "_" + name
}

// parseKey will extract the namespace and name from a key that was generated by
// makeKey. Returns a bool indicating if parsing was successful.
func (r *backendReconciler) parseKey(key string) (namespace, name string, parsed bool) {
	keyParts := strings.Split(key, "_")
	if len(keyParts) == 4 && keyParts[0] == r.prefix && keyParts[1] == r.backend.String() {
		return keyParts[2], keyParts[3], true
	}

	return "", "", false

}

// writeToVault creates the kubernetes auth role and secret backend role required
// for the given serviceaccount to login and retrieve credentials
func (r *backendReconciler) writeToVault(namespace, name string, annotations map[string]string) error {
	key := r.makeKey(namespace, name)

	// Create policy for kubernetes auth role
	policy, err := r.backend.renderPolicy(key)
	if err != nil {
		return err
	}
	if _, err := r.vaultClient.Logical().Write("sys/policy/"+key, map[string]interface{}{
		"policy": policy,
	}); err != nil {
		return err
	}
	r.log.Info("Wrote policy", "namespace", namespace, "serviceaccount", name, "key", key)

	// Create kubernetes auth backend role
	if _, err := r.vaultClient.Logical().Write("auth/"+r.kubernetesAuthBackend+"/role/"+key, map[string]interface{}{
		"bound_service_account_names":      []string{name},
		"bound_service_account_namespaces": []string{namespace},
		"policies":                         []string{"default", key},
		"ttl":                              900,
	}); err != nil {
		return err
	}
	r.log.Info("Wrote kubernetes auth backend role", "namespace", namespace, "serviceaccount", name, "key", key)

	// Create the backend role
	if err := r.backend.writeRole(key, annotations); err != nil {
		return err
	}
	r.log.Info("Wrote backend role", "namespace", namespace, "serviceaccount", name, "key", key)

	return nil
}

// removeFromVault removes the items from vault for the provided serviceaccount
func (r *backendReconciler) removeFromVault(namespace, name string) error {
	key := r.makeKey(namespace, name)

	if err := r.backend.deleteRole(key); err != nil {
		return err
	}
	r.log.Info("Deleted backend role", "namespace", namespace, "serviceaccount", name, "key", key)

	if _, err := r.vaultClient.Logical().Delete("auth/" + r.kubernetesAuthBackend + "/role/" + key); err != nil {
		return err
	}
	r.log.Info("Deleted Kubernetes auth role", "namespace", namespace, "serviceaccount", name, "key", key)

	if _, err := r.vaultClient.Logical().Delete("sys/policy/" + key); err != nil {
		return err
	}
	r.log.Info("Deleted policy", "namespace", namespace, "serviceaccount", name, "key", key)

	return nil
}

// garbageCollect iterates through a list of keys from a vault list, finds items
// managed by the operator and removes them if they don't have a corresponding
// serviceaccount in Kubernetes
func (r *backendReconciler) garbageCollect(keys []interface{}) error {
	for _, k := range keys {
		key, ok := k.(string)
		if !ok {
			continue
		}

		namespace, name, parsed := r.parseKey(key)
		if parsed {
			has, err := r.hasServiceAccount(namespace, name)
			if err != nil {
				return err
			}
			if !has {
				err := r.removeFromVault(namespace, name)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// hasServiceAccount checks if a managed service account exists for the given
// namespace+name combination and that the service account is valid for the
// backend
func (r *backendReconciler) hasServiceAccount(namespace, name string) (bool, error) {
	serviceAccountList := &corev1.ServiceAccountList{}
	err := r.kubeClient.List(context.Background(), serviceAccountList)
	if err != nil {
		return false, err
	}

	for _, serviceAccount := range serviceAccountList.Items {
		if serviceAccount.Namespace == namespace &&
			serviceAccount.Name == name &&
			r.backend.admitEvent(
				serviceAccount.Namespace,
				serviceAccount.Name,
				serviceAccount.Annotations,
			) {
			return true, nil
		}
	}

	return false, nil
}
