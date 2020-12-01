module github.com/utilitywarehouse/vault-kube-cloud-credentials

go 1.15

require (
	github.com/aws/aws-sdk-go v1.35.36
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-logr/logr v0.2.1
	github.com/go-logr/zapr v0.2.0 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/vault v1.5.0
	github.com/hashicorp/vault-plugin-auth-kubernetes v0.7.0
	github.com/hashicorp/vault/api v1.0.5-0.20200630205458-1a16f3c699c6
	github.com/hashicorp/vault/sdk v0.1.14-0.20200718021857-871b5365aa35
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/prometheus/client_golang v1.8.0
	github.com/stretchr/testify v1.6.1
	github.com/utilitywarehouse/go-operational v0.0.0-20190722153447-b0f3f6284543
	gopkg.in/yaml.v2 v2.4.0
	gotest.tools/v3 v3.0.3 // indirect
	k8s.io/api v0.19.3
	k8s.io/apimachinery v0.19.3
	k8s.io/client-go v0.19.3
	sigs.k8s.io/controller-runtime v0.6.4
)

replace github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v0.0.0-20200718022110-340cc2fa263f
