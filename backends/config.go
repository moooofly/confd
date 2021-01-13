package backends

import (
	util "github.com/moooofly/confd/util"
)

type Config struct {
	AuthToken      string     `toml:"auth_token" yaml:"auth_token"`
	AuthType       string     `toml:"auth_type" yaml:"auth_type"`
	Backend        string     `toml:"backend" yaml:"backend"`
	BasicAuth      bool       `toml:"basic_auth" yaml:"basic_auth"`
	ClientCaKeys   string     `toml:"client_cakeys" yaml:"client_cakeys"`
	ClientCert     string     `toml:"client_cert" yaml:"client_cert"`
	ClientKey      string     `toml:"client_key" yaml:"client_key"`
	ClientInsecure bool       `toml:"client_insecure" yaml:"client_insecure"`
	BackendNodes   util.Nodes `toml:"nodes" yaml:"nodes"`
	Password       string     `toml:"password" yaml:"password"`
	Scheme         string     `toml:"scheme" yaml:"scheme"`
	Table          string     `toml:"table" yaml:"table"`
	Separator      string     `toml:"separator" yaml:"separator"`
	Username       string     `toml:"username" yaml:"username"`
	AppID          string     `toml:"app_id" yaml:"app_id"`
	UserID         string     `toml:"user_id" yaml:"user_id"`
	RoleID         string     `toml:"role_id" yaml:"role_id"`
	SecretID       string     `toml:"secret_id" yaml:"secret_id"`
	YAMLFile       util.Nodes `toml:"file" yaml:"file"`
	Filter         string     `toml:"filter" yaml:"filter"`
	Path           string     `toml:"path" yaml:"path"`
	Role           string
}
