package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v2"

	"github.com/moooofly/confd/backends"
	"github.com/moooofly/confd/log"
	"github.com/moooofly/confd/resource/template"
)

type TemplateConfig = template.Config
type BackendsConfig = backends.Config

// A Config structure is used to configure confd.
type Config struct {
	TemplateConfig
	BackendsConfig
	Interval     int    `toml:"interval" yaml:"interval"`
	LogLevel     string `toml:"log-level" yaml:"log-level"`
	Watch        bool   `toml:"watch" yaml:"watch"`
	PrintVersion bool
	ConfigFile   string
	OneTime      bool
}

var config Config

func init() {
	flag.StringVar(&config.AuthToken, "auth-token", "", "Auth bearer token to use")
	flag.StringVar(&config.Backend, "backend", "etcd", "backend to use")
	flag.BoolVar(&config.BasicAuth, "basic-auth", false, "Use Basic Auth to authenticate (only used with -backend=consul and -backend=etcd)")
	flag.StringVar(&config.ClientCaKeys, "client-ca-keys", "", "client ca keys")
	flag.StringVar(&config.ClientCert, "client-cert", "", "the client cert")
	flag.StringVar(&config.ClientKey, "client-key", "", "the client key")
	flag.BoolVar(&config.ClientInsecure, "client-insecure", false, "Allow connections to SSL sites without certs (only used with -backend=etcd)")

	// used as base dir for conf.d and templates
	flag.StringVar(&config.ConfDir, "confdir", "/etc/confd", "confd conf directory")

	// NOTE: support both toml and yaml
	flag.StringVar(&config.ConfigFile, "config-file", "/etc/confd/confd.yaml", "the confd config file, support both YAML and Toml format")

	flag.Var(&config.YAMLFile, "file", "the YAML file to watch for changes (only used with -backend=file)")
	flag.StringVar(&config.Filter, "filter", "*", "files filter (only used with -backend=file)")
	flag.IntVar(&config.Interval, "interval", 600, "backend polling interval")
	flag.BoolVar(&config.KeepStageFile, "keep-stage-file", false, "keep staged files")
	flag.StringVar(&config.LogLevel, "log-level", "", "level which confd should log messages")
	flag.Var(&config.BackendNodes, "node", "list of backend nodes")
	flag.BoolVar(&config.Noop, "noop", false, "only show pending changes")
	flag.BoolVar(&config.OneTime, "onetime", false, "run once and exit")
	flag.StringVar(&config.Prefix, "prefix", "", "key path prefix")
	flag.BoolVar(&config.PrintVersion, "version", false, "print version and exit")
	flag.BoolVar(&config.SyncOnly, "sync-only", false, "sync without check_cmd and reload_cmd")
	flag.StringVar(&config.Separator, "separator", "", "the separator to replace '/' with when looking up keys in the backend, prefixed '/' will also be removed (only used with -backend=redis)")
	flag.StringVar(&config.Username, "username", "", "the username to authenticate as (only used with etcd backends)")
	flag.StringVar(&config.Password, "password", "", "the password to authenticate with (only used with etcd backends)")
	flag.BoolVar(&config.Watch, "watch", false, "enable watch support")
}

// initConfig initializes the confd configuration by first setting defaults,
// then overriding settings from the confd config file, then overriding
// settings from environment variables, and finally overriding
// settings from flags set on the command line.
// It returns an error if any.
func initConfig() error {
	log.Info("[initConfig] ConfigFile (for confd) => %s", config.ConfigFile)
	_, err := os.Stat(config.ConfigFile)
	if os.IsNotExist(err) {
		log.Warning("Skipping confd config file. (IsNotExist)")
	} else {
		log.Info("Loading " + config.ConfigFile)
		configBytes, err := ioutil.ReadFile(config.ConfigFile)
		if err != nil {
			return err
		}

		name := strings.SplitN(filepath.Base(config.ConfigFile), ".", 2)
		switch name[1] {
		case "yaml", "yml":
			log.Info("[initConfig] do yaml.Unmarshal")
			err = yaml.Unmarshal(configBytes, &config)
			if err != nil {
				return err
			}
		case "toml":
			log.Info("[initConfig] do toml.Decode")
			_, err = toml.Decode(string(configBytes), &config)
			if err != nil {
				return err
			}
		default:
			log.Fatal("[initConfig] not support '%s' format", name[1])
		}
	}

	// Update config from environment variables.
	processEnv()

	if config.LogLevel != "" {
		log.SetLevel(config.LogLevel)
	}

	if len(config.BackendNodes) == 0 {
		switch config.Backend {
		case "consul":
			config.BackendNodes = []string{"127.0.0.1:8500"}
		case "etcd":
			peerstr := os.Getenv("ETCDCTL_PEERS")
			if len(peerstr) > 0 {
				config.BackendNodes = strings.Split(peerstr, ",")
			} else {
				config.BackendNodes = []string{"http://127.0.0.1:4001"}
			}
		case "etcdv3":
			config.BackendNodes = []string{"127.0.0.1:2379"}
		case "redis":
			config.BackendNodes = []string{"127.0.0.1:6379"}
		case "zookeeper":
			config.BackendNodes = []string{"127.0.0.1:2181"}
		}
	}
	// Initialize the storage client
	log.Info("Backend set to " + config.Backend)

	if config.Watch {
		unsupportedBackends := map[string]bool{}

		if unsupportedBackends[config.Backend] {
			log.Info(fmt.Sprintf("Watch is not supported for backend %s. Exiting...", config.Backend))
			os.Exit(1)
		}
	}

	log.Info("[initConfig] ConfDir (for conf.d and templates) => %s", config.ConfDir)
	config.ConfigDir = filepath.Join(config.ConfDir, "conf.d")
	config.TemplateDir = filepath.Join(config.ConfDir, "templates")
	return nil
}

func processEnv() {
	cakeys := os.Getenv("CONFD_CLIENT_CAKEYS")
	if len(cakeys) > 0 && config.ClientCaKeys == "" {
		config.ClientCaKeys = cakeys
	}

	cert := os.Getenv("CONFD_CLIENT_CERT")
	if len(cert) > 0 && config.ClientCert == "" {
		config.ClientCert = cert
	}

	key := os.Getenv("CONFD_CLIENT_KEY")
	if len(key) > 0 && config.ClientKey == "" {
		config.ClientKey = key
	}
}
