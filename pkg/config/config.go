package config

import (
	"io/ioutil"

	"github.com/naoina/toml"
	"github.com/vrischmann/envconfig"
)

type Config struct {
	Remote struct {
		Kind       string   `envconfig:"optional"`
		Base       string   `envconfig:"optional"`
		Orgs       []string `envconfig:"optional"`
		Open       bool     `envconfig:"optional"`
		Private    bool     `envconfig:"optional"`
		SkipVerify bool     `envconfig:"optional"`
	}

	Auth struct {
		Client       string   `envconfig:"optional"`
		Secret       string   `envconfig:"optional"`
		Authorize    string   `envconfig:"optional"`
		AccessToken  string   `envconfig:"optional"`
		RequestToken string   `envconfig:"optional"`
		Scope        []string `envconfig:"optional"`
	}

	Server struct {
		Base     string `envconfig:"optional"`
		Addr     string `envconfig:"optional"`
		Cert     string `envconfig:"optional"`
		Key      string `envconfig:"optional"`
		Scheme   string `envconfig:"optional"`
		Hostname string `envconfig:"optional"`
	}

	Session struct {
		Secret  string `envconfig:"optional"`
		Expires int64  `envconfig:"optional"`
	}

	Agents struct {
		Secret string `envconfig:"optional"`
	}

	Database struct {
		Driver     string `envconfig:"optional"`
		Datasource string `envconfig:"optional"`
	}

	Docker struct {
		Cert  string `envconfig:"optional"`
		Key   string `envconfig:"optional"`
		Addr  string `envconfig:"optional"`
		Swarm bool   `envconfig:"optional"`
	}

	// Environment represents a set of global environment
	// variable declarations that can be injected into
	// build plugins. An example use case might be SMTP
	// configuration.
	Environment []string `envconfig:"optional"`

	// Plugins represents a white-list of plugins
	// that the system is authorized to load.
	Plugins []string `envconfig:"optional"`

	Github struct {
		Client string   `envconfig:"optional"`
		Secret string   `envconfig:"optional"`
		Orgs   []string `envconfig:"optional"`
		Open   bool     `envconfig:"optional"`
	}

	GithubEnterprise struct {
		URL        string   `envconfig:"optional"`
		Client     string   `envconfig:"optional"`
		Secret     string   `envconfig:"optional"`
		Private    bool     `envconfig:"optional"`
		SkipVerify bool     `envconfig:"optional"`
		Open       bool     `envconfig:"optional"`
		Orgs       []string `envconfig:"optional"`
	}

	Bitbucket struct {
		Client string   `envconfig:"optional"`
		Secret string   `envconfig:"optional"`
		Open   bool     `envconfig:"optional"`
		Orgs   []string `envconfig:"optional"`
	}

	Gitlab struct {
		URL        string   `envconfig:"optional"`
		Client     string   `envconfig:"optional"`
		Secret     string   `envconfig:"optional"`
		SkipVerify bool     `envconfig:"optional"`
		Open       bool     `envconfig:"optional"`
		Orgs       []string `envconfig:"optional"`
	}
}

// Load loads the configuration file and reads
// parameters from environment variables.
func Load(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadBytes(data)
}

// LoadBytes reads the configuration file and
// reads parameters from environment variables.
func LoadBytes(data []byte) (*Config, error) {
	conf := &Config{}
	err := toml.Unmarshal(data, conf)
	if err != nil {
		return nil, err
	}
	err = envconfig.InitWithPrefix(conf, "DRONE")
	if err != nil {
		return nil, err
	}
	return applyDefaults(conf), nil
}

func applyDefaults(c *Config) *Config {
	// if no session token is provided we can
	// instead use the client secret to sign
	// our sessions and tokens.
	if len(c.Session.Secret) == 0 {
		c.Session.Secret = c.Auth.Secret
	}
	return c
}
