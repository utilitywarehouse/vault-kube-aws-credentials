package operator

import (
	"bytes"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/go-logr/logr"
	vault "github.com/hashicorp/vault/api"

	"path/filepath"
	"strings"
	"text/template"

	// Enables all auth methods for the kube client
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

const (
	awsRoleAnnotation = "vault.uw.systems/aws-role"
)

var awsPolicyTemplate = `
path "{{ .Path }}/creds/{{ .Name }}" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{ .Path }}/sts/{{ .Name }}" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`

//awsBackendConfig configures an awsBackend
type awsBackendConfig struct {
	defaultTTL  time.Duration
	path        string
	rules       AWSRules
	vaultClient *vault.Client
}

// awsBackend provides methods that allow service accounts to be reconciled
// against the AWS secret backend in Vault
type awsBackend struct {
	*awsBackendConfig
	log  logr.Logger
	tmpl *template.Template
}

// newAWSBackend returns a new configured awsBackend
func newAWSBackend(config *awsBackendConfig) (*awsBackend, error) {
	if config.path == "" {
		return nil, fmt.Errorf("path can't be empty")
	}

	tmpl, err := template.New("policy").Parse(awsPolicyTemplate)
	if err != nil {
		return nil, err
	}

	return &awsBackend{
		awsBackendConfig: config,
		log:              log.WithName("aws"),
		tmpl:             tmpl,
	}, nil
}

// String returns the 'name' of this secret backend
func (b *awsBackend) String() string {
	return "aws"
}

// admitEvent controls whether an event should be reconciled or not based on the
// presence of a role arn and whether the role arn is permitted for this
// namespace by the rules laid out in the config file
func (b *awsBackend) admitEvent(namespace, name string, annotations map[string]string) bool {
	roleArn := annotations[awsRoleAnnotation]
	if roleArn != "" {
		allowed, err := b.rules.allow(namespace, roleArn)
		if err != nil {
			b.log.Error(err, "error matching role arn against rules for namespace", "role_arn", roleArn, "namespace", namespace)
		} else if allowed {
			return true
		}
	}

	return false
}

// deleteRole removes the role indicated by 'key'
func (b *awsBackend) deleteRole(key string) error {
	if _, err := b.vaultClient.Logical().Delete(b.path + "/roles/" + key); err != nil {
		return err
	}

	return nil
}

// listRoles lists all the AWS secret backend roles
func (b *awsBackend) listRoles() ([]interface{}, error) {
	roles, err := b.vaultClient.Logical().List(b.path + "/roles/")
	if err != nil {
		return []interface{}{}, err
	}
	if roles != nil {
		if keys, ok := roles.Data["keys"].([]interface{}); ok {
			return keys, nil
		}
	}

	return []interface{}{}, nil
}

// renderPolicy injects the provided name into a policy allowing access
// to the corresponding AWS secret role
func (b *awsBackend) renderPolicy(name string) (string, error) {
	var policy bytes.Buffer
	if err := b.tmpl.Execute(&policy, struct {
		Path string
		Name string
	}{
		Path: b.path,
		Name: name,
	}); err != nil {
		return "", err
	}

	return policy.String(), nil
}

// writeRole creates/updates an AWS secret backend role
func (b *awsBackend) writeRole(key string, annotations map[string]string) error {
	if _, err := b.vaultClient.Logical().Write(b.path+"/roles/"+key, map[string]interface{}{
		"default_sts_ttl": int(b.defaultTTL.Seconds()),
		"role_arns":       []string{annotations[awsRoleAnnotation]},
		"credential_type": "assumed_role",
	}); err != nil {
		return err
	}

	return nil
}

// AWSRules are a collection of rules.
type AWSRules []AWSRule

// allow returns true if there is a rule in the list of rules which allows
// a service account in the given namespace to assume the given role. Rules are
// evaluated in order and allow returns true for the first matching rule in the
// list
func (ar AWSRules) allow(namespace, roleArn string) (bool, error) {
	a, err := arn.Parse(roleArn)
	if err != nil {
		return false, err
	}

	for _, r := range ar {
		allowed, err := r.allows(namespace, a)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}

	return len(ar) == 0, nil
}

// AWSRule restricts the arns that a service account can assume based on
// patterns which match its namespace to an arn or arns
type AWSRule struct {
	NamespacePatterns []string `yaml:"namespacePatterns"`
	RoleNamePatterns  []string `yaml:"roleNamePatterns"`
	AccountIDs        []string `yaml:"accountIDs"`
}

// allows checks whether this rule allows a namespace to assume the given role_arn
func (ar *AWSRule) allows(namespace string, roleArn arn.ARN) (bool, error) {
	accountIDAllowed := ar.matchesAccountID(roleArn.AccountID)

	namespaceAllowed, err := ar.matchesNamespace(namespace)
	if err != nil {
		return false, err
	}

	roleAllowed := false
	if strings.HasPrefix(roleArn.Resource, "role/") {
		roleAllowed, err = ar.matchesRoleName(strings.TrimPrefix(roleArn.Resource, "role/"))
		if err != nil {
			return false, err
		}
	}

	return accountIDAllowed && namespaceAllowed && roleAllowed, nil
}

// matchesAccountID returns true if the rule allows an accountID, or if it
// doesn't contain an accountID at all
func (ar *AWSRule) matchesAccountID(accountID string) bool {
	for _, id := range ar.AccountIDs {
		if id == accountID {
			return true
		}
	}

	return len(ar.AccountIDs) == 0
}

// matchesNamespace returns true if the rule allows the given namespace
func (ar *AWSRule) matchesNamespace(namespace string) (bool, error) {
	for _, np := range ar.NamespacePatterns {
		match, err := filepath.Match(np, namespace)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}

	return false, nil
}

// matchesRoleName returns true if the rule allows the given role name
func (ar *AWSRule) matchesRoleName(roleName string) (bool, error) {
	for _, rp := range ar.RoleNamePatterns {
		match, err := filepath.Match(rp, roleName)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}

	return false, nil
}
