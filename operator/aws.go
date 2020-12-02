package operator

import (
	"bytes"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/go-logr/logr"

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

// AWSOperatorConfig provides configuration when creating a new Operator
type AWSOperatorConfig struct {
	DefaultTTL time.Duration
	Path       string
	Rules      AWSRules
}

// AWSOperator provides methods that allow service accounts to be reconciled
// against the AWS secret backend in Vault
type AWSOperator struct {
	*AWSOperatorConfig
	log  logr.Logger
	tmpl *template.Template
}

// NewAWSOperator returns a configured AWSOperator
func NewAWSOperator(config *AWSOperatorConfig) (*AWSOperator, error) {
	tmpl, err := template.New("policy").Parse(awsPolicyTemplate)
	if err != nil {
		return nil, err
	}

	ar := &AWSOperator{
		AWSOperatorConfig: config,
		log:               log.WithName("aws"),
		tmpl:              tmpl,
	}

	return ar, nil
}

// String returns the 'name' of this secret backend
func (o *AWSOperator) String() string {
	return "aws"
}

// admitEvent controls whether an event should be reconciled or not based on the
// presence of a role arn and whether the role arn is permitted for this
// namespace by the rules laid out in the config file
func (o *AWSOperator) admitEvent(namespace, name string, annotations map[string]string) bool {
	roleArn := annotations[awsRoleAnnotation]
	if roleArn != "" {
		allowed, err := o.Rules.allow(namespace, roleArn)
		if err != nil {
			o.log.Error(err, "error matching role arn against rules for namespace", "role_arn", roleArn, "namespace", namespace)
		} else if allowed {
			return true
		}
	}

	return false
}

// renderPolicy injects the provided name into a policy allowing access
// to the corresponding AWS secret role
func (o *AWSOperator) renderPolicy(name string) (string, error) {
	var policy bytes.Buffer
	if err := o.tmpl.Execute(&policy, struct {
		Path string
		Name string
	}{
		Path: o.Path,
		Name: name,
	}); err != nil {
		return "", err
	}

	return policy.String(), nil
}

// roleData returns the data defined in the given annotations
func (o *AWSOperator) roleData(annotations map[string]string) map[string]interface{} {
	return map[string]interface{}{
		"default_sts_ttl": int(o.DefaultTTL.Seconds()),
		"role_arns":       []string{annotations[awsRoleAnnotation]},
		"credential_type": "assumed_role",
	}
}

// rolePath returns the path under which secret roles should be written for the
// AWS secret backend
func (o *AWSOperator) rolePath() string {
	return o.Path + "/roles"
}
