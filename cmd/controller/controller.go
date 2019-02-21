package main

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/dereulenspiegel/nginx-controller/pkg/docker"
	"github.com/dereulenspiegel/nginx-controller/pkg/nginx"
	"github.com/sirupsen/logrus"
)

type NginxProcess interface {
	Restart() error
	Reload() error
	ConfigPath() string
}

type CertificateManager interface {
	CertForDomain(domain string) (string, string, bool, error)
	RenewalForDomain(domain string) bool
}

type DockerClient interface {
	CurrentConfigs() ([]*docker.ContainerConfig, error)
}

type controller struct {
	nginxTmplConf *nginx.TemplateConfig
	ngnxTmpl      string
	ngx           NginxProcess
	docker        DockerClient

	serverToBeAdded   chan *docker.ContainerConfig
	serverToBeRemoved chan *docker.ContainerConfig

	reloadChan  chan bool
	restartChan chan bool

	tmplLock *sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc

	certManager   CertificateManager
	renewalTicker *time.Ticker

	renderToFile func(string, string, *nginx.TemplateConfig) error
}

func newController(ctx context.Context, certManager CertificateManager, ngx NginxProcess, dockerClient DockerClient) *controller {
	cctx, cancel := context.WithCancel(ctx)
	c := &controller{
		tmplLock:          &sync.Mutex{},
		serverToBeAdded:   make(chan *docker.ContainerConfig, 100),
		serverToBeRemoved: make(chan *docker.ContainerConfig, 100),
		reloadChan:        make(chan bool, 1),
		restartChan:       make(chan bool, 1),
		ctx:               cctx,
		cancel:            cancel,
		certManager:       certManager,
		ngx:               ngx,
		ngnxTmpl:          nginx.DefaultTemplate,
		nginxTmplConf:     nginx.DefaultTemplateConfig(),
		renderToFile:      replaceConfig,
		docker:            dockerClient,
		renewalTicker:     time.NewTicker(time.Hour * 1),
	}

	c.renderConfig()

	go c.loopReload()
	go c.loopRestart()
	go c.loop()
	return c
}

func (c *controller) Close() error {
	c.cancel()
	close(c.serverToBeRemoved)
	close(c.serverToBeAdded)
	close(c.reloadChan)
	close(c.restartChan)
	return nil
}

func (c *controller) addContainer(ccs ...*docker.ContainerConfig) {
	for _, cc := range ccs {
		c.serverToBeAdded <- cc
	}
}

func (c *controller) removeContainer(ccs ...*docker.ContainerConfig) {
	for _, cc := range ccs {
		c.serverToBeRemoved <- cc
	}
}

func (c *controller) loopRestart() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.restartChan:
			c.renderConfig()
			if err := c.ngx.Restart(); err != nil {
				logrus.WithError(err).Error("Failed to restart nginx")
			}
			time.Sleep(time.Minute * 1)
		}
	}
}

func (c *controller) loopReload() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.reloadChan:
			c.renderConfig()
			c.ngx.Reload()
			time.Sleep(time.Second * 10)
		}
	}
}

func (c *controller) triggerRestart() {
	select {
	case c.restartChan <- true:
	default:
	}
}

func (c *controller) triggerReload() {
	select {
	case c.reloadChan <- true:
	default:
	}
}

func (c *controller) renderConfig() {
	confPath := c.ngx.ConfigPath()
	c.tmplLock.Lock()
	defer c.tmplLock.Unlock()
	if err := c.renderToFile(confPath, c.ngnxTmpl, c.nginxTmplConf); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"confPath": confPath,
		}).Error("Failed to replace config with rendered template")
	}
}

func (c *controller) addToServers(container *docker.ContainerConfig) {
	logrus.Info("Adding to servers config")
	server := nginx.DefaultServerTemplateConfig(container.Host, container.Upstream)
	certPath, keyPath, newCert, err := c.certManager.CertForDomain(container.Host)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"containerID": container.ContainerID,
			"host":        container.Host,
			"upstream":    container.Upstream,
		}).Error("Failed to ensure valid certificates for container")
		return
	}
	server.SSLCertificate = certPath
	server.SSLKey = keyPath
	c.nginxTmplConf.HTTP.Servers = append(c.nginxTmplConf.HTTP.Servers, server)
	logrus.WithFields(logrus.Fields{
		"certPath":     certPath,
		"domain":       container.Host,
		"containerID":  container.ContainerID,
		"upstream":     container.Upstream,
		"resartNgninx": newCert,
	}).Info("Added virtual host to nginx template config")
	if !newCert {
		logrus.WithFields(logrus.Fields{
			"certPath":     certPath,
			"domain":       container.Host,
			"containerID":  container.ContainerID,
			"upstream":     container.Upstream,
			"resartNgninx": newCert,
		}).Info("Triggering reload for new server config")
		c.triggerReload()
	} else {
		logrus.WithFields(logrus.Fields{
			"certPath":     certPath,
			"domain":       container.Host,
			"containerID":  container.ContainerID,
			"upstream":     container.Upstream,
			"resartNgninx": newCert,
		}).Info("Triggering restart to load new certificates")
		c.triggerRestart()
	}
}

func (c *controller) loop() {
	for {
		c.tmplLock.Lock()
		select {
		case <-c.ctx.Done():
			return

		case container := <-c.serverToBeAdded:
			if container == nil {
				// channel was most likely closed
				return
			}
			logrus.WithFields(logrus.Fields{
				"containerID": container.ContainerID,
				"host":        container.Host,
				"upstream":    container.Upstream,
			}).Info("Adding container")
			c.addToServers(container)

		case container := <-c.serverToBeRemoved:
			if container == nil {
				// channel was most likely closed
				return
			}
			logrus.WithFields(logrus.Fields{
				"containerID": container.ContainerID,
				"host":        container.Host,
				"upstream":    container.Upstream,
			}).Info("Removing container")
			for i, s := range c.nginxTmplConf.HTTP.Servers {

				if container.Host == s.ServerName {
					c.nginxTmplConf.HTTP.Servers = append(c.nginxTmplConf.HTTP.Servers[:i], c.nginxTmplConf.HTTP.Servers[i+1:]...)
					break
				}
			}
			c.triggerReload()

		case <-c.renewalTicker.C:
			for _, s := range c.nginxTmplConf.HTTP.Servers {
				if c.certManager.RenewalForDomain(s.ServerName) {
					c.triggerRestart()
				}
			}

		default:
			currentConfigs, err := c.docker.CurrentConfigs()
			if err != nil {
				logrus.WithError(err).Error("Failed to retrieve current container configs")
				continue
			}

			var servers []*nginx.ServerConfig
			for _, s := range c.nginxTmplConf.HTTP.Servers {
				found := false
				for _, c := range currentConfigs {
					if s.ServerName == c.Host {
						found = true
						break
					}
				}
				if found {
					servers = append(servers, s)
				} else {
					c.triggerReload()
				}
			}
			c.nginxTmplConf.HTTP.Servers = servers

			for _, cc := range currentConfigs {
				found := false
				for _, s := range c.nginxTmplConf.HTTP.Servers {
					if cc.Host == s.ServerName {
						found = true
						break
					}
					if !found {
						c.addToServers(cc)
					}
				}
			}
		}

		c.tmplLock.Unlock()
	}
}

func replaceConfig(confPath, tmpl string, cfg *nginx.TemplateConfig) error {

	os.Remove(confPath)
	confFile, err := os.Create(confPath)
	defer confFile.Close()
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"confPath": confPath,
		}).Error("Failed to create config file")
		return err
	}
	return nginx.RenderConfig(tmpl, cfg, confFile)
}
