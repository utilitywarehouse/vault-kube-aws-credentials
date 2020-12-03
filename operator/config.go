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
			Enabled:    false,
			Path:       "aws",
		},
		GCP: gcpFileConfig{
			Enabled: false,
			Path:    "gcp",
		},
	}
)

type fileConfig struct {
	KubernetesAuthBackend string        `yaml:"kubernetesAuthBackend"`
	MetricsAddress        string        `yaml:"metricsAddress"`
	Prefix                string        `yaml:"prefix"`
	AWS                   awsFileConfig `yaml:"aws"`
	GCP                   gcpFileConfig `yaml:"gcp"`
}

type awsFileConfig struct {
	DefaultTTL time.Duration `yaml:"defaultTTL"`
	Enabled    bool          `yaml:"enabled"`
	Path       string        `yaml:"path"`
	Rules      awsRules      `yaml:"rules"`
}

type gcpFileConfig struct {
	Enabled bool     `yaml:"enabled"`
	Path    string   `yaml:"path"`
	Rules   gcpRules `yaml:"rules"`
}

func loadConfigFromFile(file string) (*fileConfig, error) {
	if file == "" {
		return nil, fmt.Errorf("must provide a config file")
	}

	cfg := defaultFileConfig

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

	return cfg, nil
}
