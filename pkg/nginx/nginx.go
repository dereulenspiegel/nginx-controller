package nginx

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"math"
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	ServerBlockNotFound   = errors.New("Server block not found")
	LocationBlockNotFound = errors.New("Location block not found")

	Version string
)

type EventsConfig struct {
	WorkerConnections uint64
}

type LocationConfig struct {
	Upstream string
	Auth     *AuthConfig
}

type AuthConfig struct {
	PasswdFile string
	Off        bool
}

type ServerConfig struct {
	ServerName          string
	ErrorLog            string
	AccessLog           string
	SSLSessionCacheSize uint64
	SSLCertificate      string
	SSLKey              string
	Resolver            []string
	ResolverTimeout     string
	Auth                *AuthConfig
	Locations           map[string]*LocationConfig
}

func (s *ServerConfig) SetLocation(path, upstream, auth string) {
	var authConfig *AuthConfig
	if auth == "off" {
		authConfig = &AuthConfig{
			Off: true,
		}
	} else if auth != "" {
		authConfig = &AuthConfig{
			PasswdFile: auth,
		}
	}
	s.Locations[path] = &LocationConfig{
		Upstream: upstream,
		Auth:     authConfig,
	}
}

type HTTPConfig struct {
	AccessLog                 string
	ServerNamesHashBucketSize uint64
	SendFile                  bool
	TCPNoPush                 bool
	KeepAliveTimeout          uint64
	TCPNoDelay                bool
	GZIP                      bool
	GZIPProxied               string
	GZIPTypes                 []string
	ClientMaxBodySize         uint64
	Servers                   map[string]*ServerConfig
}

func (h *HTTPConfig) AppendLocation(host, upstream, path, auth string) *ServerConfig {
	var s *ServerConfig
	var exists bool
	if s, exists = h.Servers[host]; !exists {
		s = DefaultServerTemplateConfig(host)
		h.Servers[host] = s
	}

	s.SetLocation(path, upstream, auth)
	return s
}

func (h *HTTPConfig) UpdateServerDefaultUpstream(host, upstream string) error {
	if s, exists := h.Servers[host]; exists {
		if loc, exists := s.Locations["/"]; exists {
			loc.Upstream = upstream
			return nil
		} else {
			return LocationBlockNotFound
		}
	}
	return ServerBlockNotFound
}

type TemplateConfig struct {
	User          string
	WorkProcesses uint64
	ErrorLog      string
	Pid           string
	Events        *EventsConfig
	HTTP          *HTTPConfig
}

func DefaultServerTemplateConfig(name string) *ServerConfig {
	c := &ServerConfig{
		ServerName:          name,
		ErrorLog:            "stderr",
		AccessLog:           "off",
		SSLSessionCacheSize: 10 * 1024 * 1024,
		Resolver:            []string{"8.8.8.8", "8.8.4.4"},
		ResolverTimeout:     "5s",
		Locations:           make(map[string]*LocationConfig),
	}

	return c
}

func DefaultServerTemplateConfigWithUpstream(name string, defaultUpstream ...string) *ServerConfig {
	c := &ServerConfig{
		ServerName:          name,
		ErrorLog:            "stderr",
		AccessLog:           "off",
		SSLSessionCacheSize: 10 * 1024 * 1024,
		Resolver:            []string{"8.8.8.8", "8.8.4.4"},
		ResolverTimeout:     "5s",
		Locations:           make(map[string]*LocationConfig),
	}

	if len(defaultUpstream) > 0 {
		c.Locations["/"] = &LocationConfig{
			Upstream: defaultUpstream[0],
		}
	}

	return c
}

func DefaultTemplateConfig() *TemplateConfig {
	return &TemplateConfig{
		User:          "nginx",
		WorkProcesses: 2,
		ErrorLog:      "stderr",
		Pid:           "/var/run/nginx.pid",
		Events: &EventsConfig{
			WorkerConnections: 1024,
		},
		HTTP: &HTTPConfig{
			AccessLog:                 "off",
			ServerNamesHashBucketSize: 64,
			SendFile:                  true,
			TCPNoPush:                 true,
			KeepAliveTimeout:          65,
			TCPNoDelay:                true,
			GZIP:                      true,
			GZIPProxied:               "any",
			GZIPTypes: []string{
				"text/plain",
				"text/css",
				"application/json",
				"application/x-javascript",
				"text/xml",
				"application/xml",
				"text/javascript",
			},
			ClientMaxBodySize: 25 * 1024 * 1024,
			Servers:           make(map[string]*ServerConfig),
		},
	}
}

var (
	exponents = []string{
		"",
		"K",
		"M",
		"G",
		"T",
	}

	nginxTmplFuncs = template.FuncMap{
		"hrBytes":   TmplToByteUnit,
		"nginxBool": TmplNginxBool,
		"spaceList": TmplSpaceList,
		"toLower":   strings.ToLower,
	}
)

func TmplToByteUnit(in uint64) string {
	for i := len(exponents) - 1; i >= 0; i-- {
		if val := float64(in) / math.Pow(float64(1024), float64(i)); val > 1.0 {
			intVal := uint64(val)
			return fmt.Sprintf("%d%s", intVal, exponents[i])
		}
	}
	return fmt.Sprintf("%d", in)
}

func TmplNginxBool(in bool) string {
	if in {
		return "on"
	}
	return "off"
}

func TmplSpaceList(in []string) string {
	return strings.Join(in, " ")
}

func RenderConfig(tmplString string, cfg *TemplateConfig, out io.Writer) (err error) {
	if len(cfg.HTTP.Servers) == 0 {
		logrus.Warn("No servers found in nginx template config")
	}
	for host, s := range cfg.HTTP.Servers {
		logrus.WithFields(logrus.Fields{
			"host":     host,
			"upstream": s.Locations["/"].Upstream,
		}).Info("Including host in rendering")
	}
	tmpl := template.New("nginx.conf").Funcs(nginxTmplFuncs)
	tmpl, err = tmpl.Parse(tmplString)
	if err != nil {
		logrus.WithError(err).Error("Failed to render nginx config")
		return err
	}
	return tmpl.Execute(out, cfg)
}
