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
	StoppedContainers() <-chan *docker.ContainerConfig
	StartedContainers() <-chan *docker.ContainerConfig
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
	go c.readDocker()
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

func (c *controller) readDocker() {
	startedChan := c.docker.StartedContainers()
	stoppedChan := c.docker.StoppedContainers()
	for {
		select {
		case <-c.ctx.Done():
			return
		case cc := <-startedChan:
			logrus.WithFields(logrus.Fields{
				"component":   "controller",
				"host":        cc.Host,
				"containerID": cc.ContainerID,
			}).Info("Received started container event")
			c.addContainer(cc)
		case cc := <-stoppedChan:
			logrus.WithFields(logrus.Fields{
				"component":   "controller",
				"host":        cc.Host,
				"containerID": cc.ContainerID,
			}).Info("Received stopped container event")
			c.removeContainer(cc)
		}
	}
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
			logrus.Info("Restarting nginx")
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
			logrus.Info("Reloading nginx")
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
	logrus.Info("Rendering nginx config")
	confPath := c.ngx.ConfigPath()
	c.tmplLock.Lock()
	defer c.tmplLock.Unlock()
	for host, s := range c.nginxTmplConf.HTTP.Servers {
		if s.SSLCertificate == "" || s.SSLKey == "" {
			certPath, keyPath, _, err := c.certManager.CertForDomain(host)
			if err != nil {
				logrus.WithError(err).WithFields(logrus.Fields{
					"host": host,
				}).Error("Failed to get key and cert path, removing from servers")
				delete(c.nginxTmplConf.HTTP.Servers, host)
				continue
			}
			s.SSLCertificate = certPath
			s.SSLKey = keyPath
		}
	}
	if err := c.renderToFile(confPath, c.ngnxTmpl, c.nginxTmplConf); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"confPath": confPath,
		}).Error("Failed to replace config with rendered template")
	}
}

func (c *controller) addToServers(container *docker.ContainerConfig) {
	logger := logrus.WithFields(logrus.Fields{
		"containerID": container.ContainerID,
		"host":        container.Host,
		"upstream":    container.Upstream,
	})
	logger.Info("Adding to servers config")

	certPath, keyPath, newCert, err := c.certManager.CertForDomain(container.Host)
	if err != nil {
		logger.WithError(err).Error("Failed to ensure valid certificates for container")
		return
	}
	server := c.nginxTmplConf.HTTP.AppendLocation(container.Host, container.Upstream, container.Path, container.Auth)
	server.SSLCertificate = certPath
	server.SSLKey = keyPath

	logger.WithFields(logrus.Fields{
		"certPath":     certPath,
		"resartNgninx": newCert,
	}).Info("Added virtual host to nginx template config")
	if !newCert {
		logger.WithFields(logrus.Fields{
			"certPath":     certPath,
			"resartNgninx": newCert,
		}).Info("Triggering reload for new server config")
		c.triggerReload()
	} else {
		logger.WithFields(logrus.Fields{
			"certPath":      certPath,
			"restartNgninx": newCert,
		}).Info("Triggering restart to load new certificates")
		c.triggerReload()
	}
}

func (c *controller) checkExistingContainers() {
	currentConfigs, err := c.docker.CurrentConfigs()
	if err != nil {
		logrus.WithError(err).Error("Failed to retrieve current container configs")
		return
	}

	newServers := make(map[string]*nginx.ServerConfig)
	for _, cc := range currentConfigs {
		if cc.Upstream == "" || cc.Host == "" {
			logrus.WithFields(logrus.Fields{
				"containerID": cc.ContainerID,
				"upstream":    cc.Upstream,
				"host":        cc.Host,
			}).Error("Got invalid existing container. Something is missing")
			continue
		}
		s := c.nginxTmplConf.HTTP.AppendLocation(cc.Host, cc.Upstream, cc.Path, cc.Auth)
		newServers[cc.Host] = s
	}

	restartNecessary := false
	for host, s := range newServers {
		certPath, keyPath, newCert, err := c.certManager.CertForDomain(host)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"domain": host,
			}).Error("Failed to ensure valid certificates for container")
			continue
		}
		if newCert {
			restartNecessary = true
		}
		s.SSLCertificate = certPath
		s.SSLKey = keyPath
	}

	if !restartNecessary {
		c.triggerReload()
	} else {
		c.triggerRestart()
	}
}

func (c *controller) loop() {
	c.checkExistingContainers()
	c.checkForRenewal()
	for {
		c.tmplLock.Lock()
		select {
		case <-c.ctx.Done():
			return

		case container := <-c.serverToBeAdded:
			if container == nil {
				// channel was most likely closed
				logrus.Info("Seems like the serversToBeAdded channel is closed")
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
				logrus.Info("Seems like the serverToBeRemoved channel is closed")
				return
			}
			logrus.WithFields(logrus.Fields{
				"containerID": container.ContainerID,
				"host":        container.Host,
				"upstream":    container.Upstream,
			}).Info("Removing container")
			if s, exists := c.nginxTmplConf.HTTP.Servers[container.Host]; exists {
				delete(s.Locations, container.Path)
				if len(s.Locations) == 0 {
					// Delete server configs which do not have any locations
					delete(c.nginxTmplConf.HTTP.Servers, container.Host)
				}
			} else {
				logrus.WithFields(logrus.Fields{
					"containerID": container.ContainerID,
					"host":        container.Host,
					"upstream":    container.Upstream,
					"path":        container.Path,
				}).Info("Tried removing location but it didn't exist")
			}

			c.triggerReload()

		case <-c.renewalTicker.C:
			c.checkForRenewal()

		default:
			// By default sleep a bit so we do not max out one core
			time.Sleep(time.Second * 1)
		}

		c.tmplLock.Unlock()
	}
}

func (c *controller) checkForRenewal() {
	for _, s := range c.nginxTmplConf.HTTP.Servers {
		if c.certManager.RenewalForDomain(s.ServerName) {
			c.triggerRestart()
		}
	}
}

func replaceConfig(confPath, tmpl string, cfg *nginx.TemplateConfig) error {
	logger := logrus.WithFields(logrus.Fields{
		"configPath": confPath,
	})
	logger.Info("Replacing existing nginx config")
	os.Remove(confPath)
	confFile, err := os.Create(confPath)
	defer confFile.Close()
	if err != nil {
		logger.Error("Failed to create config file")
		return err
	}

	if err := nginx.RenderConfig(tmpl, cfg, confFile); err != nil {
		logger.WithError(err).Error("Failed to render nginx config to file")
		return err
	}
	return confFile.Sync()
}
