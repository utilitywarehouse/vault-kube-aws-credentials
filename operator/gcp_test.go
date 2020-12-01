package operator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// TestGCPBackendAdmitEvent tests that events are allowed and disallowed
// according to the rules
func TestGCPBackendAdmitEvent(t *testing.T) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	gb := &gcpBackend{
		gcpBackendConfig: &gcpBackendConfig{},
		log:              ctrl.Log.WithName("operator").WithName("gcp"),
	}

	validBindings := `
"//cloudresourcemanager.googleapis.com/projects/my-project":
  - "roles/dns.admin"
  - "roles/storage.admin" 
`

	invalidBindings := `
- "//cloudresourcemanager.googleapis.com/projects/my-project":
  - "roles/dns.admin"
  - "roles/storage.admin" 

`

	// Test that without any rules any valid event is admitted
	assert.True(t, gb.admitEvent("foobar", "", map[string]string{gcpProjectAnnotation: "my-project", gcpBindingsAnnotation: validBindings}))

	// Test that an empty project is not admitted
	assert.False(t, gb.admitEvent("foobar", "", map[string]string{gcpProjectAnnotation: "", gcpBindingsAnnotation: validBindings}))

	// Test that an event with no bindings is not admitted
	assert.False(t, gb.admitEvent("foobar", "", map[string]string{gcpProjectAnnotation: "my-project"}))

	// Test that malformed bindings are not admitted
	assert.False(t, gb.admitEvent("foobar", "", map[string]string{gcpProjectAnnotation: "my-project", gcpBindingsAnnotation: invalidBindings}))

	gb.rules = gcpRules{
		gcpRule{
			NamespacePatterns: []string{
				"foo",
				"bar-*",
			},
			Projects: []string{
				"my-project",
				"my-other-project",
			},
		},
		gcpRule{
			NamespacePatterns: []string{
				"kube-system",
				"foo?",
			},
			Projects: []string{
				"another-project",
			},
		},
		gcpRule{
			Projects: []string{
				"fuubar",
			},
		},
		gcpRule{
			NamespacePatterns: []string{
				"fuubar",
			},
		},
	}

	// Test bar-* : my-project is allowed
	assert.True(t, gb.admitEvent("bar-foo", "", map[string]string{gcpProjectAnnotation: "my-project", gcpBindingsAnnotation: validBindings}))

	// Test that foo : my-project is allowed
	assert.True(t, gb.admitEvent("foo", "", map[string]string{gcpProjectAnnotation: "my-project", gcpBindingsAnnotation: validBindings}))

	// Test the second rule is evaluated
	assert.True(t, gb.admitEvent("kube-system", "", map[string]string{gcpProjectAnnotation: "another-project", gcpBindingsAnnotation: validBindings}))

	// Test the ? match
	assert.True(t, gb.admitEvent("fooz", "", map[string]string{gcpProjectAnnotation: "another-project", gcpBindingsAnnotation: validBindings}))

	// Test that foo : another-project is not allowed
	assert.False(t, gb.admitEvent("foo", "", map[string]string{gcpProjectAnnotation: "another-project", gcpBindingsAnnotation: validBindings}))

	// Test that the matching doesn't match the namespace foo to foobar as a
	// substring
	assert.False(t, gb.admitEvent("foobar", "", map[string]string{gcpProjectAnnotation: "my-project", gcpBindingsAnnotation: validBindings}))

	// Test that a rule without a namespace pattern does not admit
	assert.False(t, gb.admitEvent("foo", "", map[string]string{gcpProjectAnnotation: "fuubar", gcpBindingsAnnotation: validBindings}))

	// Test that a rule without a project pattern does not admit
	assert.False(t, gb.admitEvent("fuubar", "", map[string]string{gcpProjectAnnotation: "my-project", gcpBindingsAnnotation: validBindings}))
}
