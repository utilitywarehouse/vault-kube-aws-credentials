package operator

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/go-logr/logr"
	vault "github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"

	"strings"
	"text/template"
)

const (
	gcpProjectAnnotation  = "vault.uw.systems/gcp-project"
	gcpBindingsAnnotation = "vault.uw.systems/gcp-bindings"
)

var gcpPolicyTemplate = `
path "{{ .Path }}/token/{{ .Name }}" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{ .Path }}/key/{{ .Name }}" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{ .Path }}/roleset/{{ .Name }}" {
  capabilities = ["read"]
}
`

// gcpBackendConfig configures a gcpBackend
type gcpBackendConfig struct {
	path        string
	rules       gcpRules
	vaultClient *vault.Client
}

// gcpBackend provides methods that allow service accounts to be reconciled
// against the GCP secret backend in Vault
type gcpBackend struct {
	*gcpBackendConfig
	log  logr.Logger
	tmpl *template.Template
}

// newGCPBackend returns a new configured gcpBackend
func newGCPBackend(config *gcpBackendConfig) (*gcpBackend, error) {
	if config.path == "" {
		return nil, fmt.Errorf("path can't be empty")
	}

	tmpl, err := template.New("policy").Parse(gcpPolicyTemplate)
	if err != nil {
		return nil, err
	}

	return &gcpBackend{
		gcpBackendConfig: config,
		log:              log.WithName("gcp"),
		tmpl:             tmpl,
	}, nil
}

// String returns the 'name' of this secret backend
func (b *gcpBackend) String() string {
	return "gcp"
}

// admitEvent controls whether an event should be reconciled or not based on the
// presence of a role arn and whether the role arn is permitted for this
// namespace by the rules laid out in the config file
func (b *gcpBackend) admitEvent(namespace, name string, annotations map[string]string) bool {
	project := annotations[gcpProjectAnnotation]
	bindings := annotations[gcpBindingsAnnotation]

	if project == "" {
		return false
	}

	if _, err := newGCPBindingsFromYAML([]byte(bindings)); err != nil {
		b.log.Error(err, "service account not admitted due to error parsing bindings from yaml")
		return false
	}

	allowed, err := b.rules.allow(namespace, project)
	if err != nil {
		b.log.Error(err, "error matching project against rules for namespace", "project", project, "namespace", namespace)
	} else if allowed {
		return true
	}

	return false
}

// deleteRole removes the role indicated by 'key'
func (b *gcpBackend) deleteRole(key string) error {
	if _, err := b.vaultClient.Logical().Delete(b.path + "/roleset/" + key); err != nil {
		return err
	}

	return nil
}

// listRoles lists all the GCP secret backend roles
func (b *gcpBackend) listRoles() ([]interface{}, error) {
	roles, err := b.vaultClient.Logical().List(b.path + "/roleset/")
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
// to the corresponding GCP secret roleset
func (b *gcpBackend) renderPolicy(name string) (string, error) {
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

// writeRole creates/updates an GCP secret backend roleset
func (b *gcpBackend) writeRole(key string, annotations map[string]string) error {
	bindings, err := newGCPBindingsFromYAML([]byte(annotations[gcpBindingsAnnotation]))
	if err != nil {
		return err
	}

	if _, err := b.vaultClient.Logical().Write(b.path+"/roleset/"+key, map[string]interface{}{
		"secret_type":  "access_token",
		"project":      annotations[gcpProjectAnnotation],
		"bindings":     renderGCPBindings(bindings),
		"token_scopes": []string{"https://www.googleapis.com/auth/cloud-platform"},
	}); err != nil {
		return err
	}

	return nil
}

// newGCPBindingsFromYAML parses gcp roleset bindings represented in yaml form
// into a map[string]interface{}
func newGCPBindingsFromYAML(data []byte) (map[string]interface{}, error) {
	bindings := map[string]interface{}{}

	if err := yaml.Unmarshal(data, &bindings); err != nil {
		return bindings, err
	}

	if len(bindings) == 0 {
		return bindings, fmt.Errorf("bindings are empty")
	}

	for resource, roles := range bindings {
		rawRoles, ok := roles.([]interface{})
		if !ok {
			return bindings, fmt.Errorf("roles must be of type []interface{}: %s", roles)
		}
		if len(rawRoles) == 0 {
			return bindings, fmt.Errorf("roles can't be empty for resource %s", resource)
		}
	}

	return bindings, nil
}

// renderGCPBindings returns bindings as a hcl string
func renderGCPBindings(bindings map[string]interface{}) string {
	var output string
	i := 0
	for resource, roles := range bindings {
		rawRoles, ok := roles.([]interface{})
		if !ok {
			continue
		}
		if i == 0 {
			output = fmt.Sprintf("%s", renderGCPBinding(resource, rawRoles))
		} else {
			output = fmt.Sprintf("%s\n\n%s", output, renderGCPBinding(resource, rawRoles))
		}
		i++
	}

	return output
}

// renderGCPBinding renders a binding as a hcl string
func renderGCPBinding(resource string, roles []interface{}) string {
	var rawRoles []string
	for _, role := range roles {
		if rawRole, ok := role.(string); ok {
			rawRoles = append(rawRoles, rawRole)
		}
	}
	output := fmt.Sprintf("resource \"%s\" {\n", resource)
	output = fmt.Sprintf("%s  roles = %s\n", output, fmt.Sprintf(`["%s"]`, strings.Join(rawRoles, `", "`)))
	return fmt.Sprintf("%s}\n", output)
}

// gcpRules is a collection of rules
type gcpRules []gcpRule

// allow returns true if the rules allow the namespace to create bindings in the
// project
func (gr gcpRules) allow(namespace, project string) (bool, error) {
	for _, r := range gr {
		allowed, err := r.allows(namespace, project)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}

	return len(gr) == 0, nil
}

// gcpRule is a rule that allows a list of namespaces to create bindings in
// specific projects
type gcpRule struct {
	NamespacePatterns []string `yaml:"namespacePatterns"`
	Projects          []string `yaml:"projects"`
}

// allows returns true if this rule allows the namespace to create bindings in
// the project
func (gr *gcpRule) allows(namespace, project string) (bool, error) {
	namespaceAllowed, err := gr.matchesNamespace(namespace)
	if err != nil {
		return false, err
	}

	return namespaceAllowed && gr.matchesProject(project), nil
}

// matchesNamespace returns true if the namespace matches one of the
// NamespacePatterns
func (gr *gcpRule) matchesNamespace(namespace string) (bool, error) {
	for _, np := range gr.NamespacePatterns {
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

// matchesProject returns true if the projects is in the list of Projects
func (gr *gcpRule) matchesProject(project string) bool {
	for _, p := range gr.Projects {
		if project == p {
			return true
		}
	}

	return false
}
