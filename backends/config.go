package backends

import (
	util "github.com/moooofly/confd/util"
)

type Config struct {
	Backend string `toml:"backend" yaml:"backend"`

	// used by etcd/etcdV3/consul
	ClientCaKeys   string `toml:"client_cakeys" yaml:"client_cakeys"`
	ClientCert     string `toml:"client_cert" yaml:"client_cert"`
	ClientKey      string `toml:"client_key" yaml:"client_key"`
	ClientInsecure bool   `toml:"client_insecure" yaml:"client_insecure"`
	BasicAuth      bool   `toml:"basic_auth" yaml:"basic_auth"`
	Username       string `toml:"username" yaml:"username"`
	Password       string `toml:"password" yaml:"password"`

	BackendNodes util.Nodes `toml:"nodes" yaml:"nodes"`
	Scheme       string     `toml:"scheme" yaml:"scheme"`
	Separator    string     `toml:"separator" yaml:"separator"`
	YAMLFile     util.Nodes `toml:"file" yaml:"file"`
	Filter       string     `toml:"filter" yaml:"filter"`
	Path         string     `toml:"path" yaml:"path"`
}
