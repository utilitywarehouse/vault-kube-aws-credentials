package operator

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	defaultFileConfig = &fileConfig{
		KubernetesAuthBackend: "kubernetes",
		MetricsAddress:        ":8080",
		Prefix:                "vkcc",
		AWS: awsFileConfig{
			DefaultTTL: 15 * time.Minute,
			Path:       "aws",
		},
	}
)

type fileConfig struct {
	KubernetesAuthBackend string        `yaml:"kubernetesAuthBackend"`
	MetricsAddress        string        `yaml:"metricsAddress"`
	Prefix                string        `yaml:"prefix"`
	AWS                   awsFileConfig `yaml:"aws"`
}

type awsFileConfig struct {
	DefaultTTL time.Duration `yaml:"defaultTTL"`
	Path       string        `yaml:"path"`
	Rules      awsRules      `yaml:"rules"`
}

func loadConfigFromFile(file string) (*fileConfig, error) {
	cfg := defaultFileConfig

	if file == "" {
		return cfg, nil
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if strings.Contains(cfg.Prefix, "_") {
		return nil, fmt.Errorf("prefix must not contain a '_': %s", cfg.Prefix)
	}

	if cfg.AWS.Path == "" {
		return nil, fmt.Errorf("aws.path can't be empty")
	}

	return cfg, nil
}
