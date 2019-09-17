package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dereulenspiegel/nginx-controller/pkg/docker"
	"github.com/dereulenspiegel/nginx-controller/pkg/nginx"
	"github.com/stretchr/testify/mock"
)

type nginxMock struct {
	mock.Mock
}

func (n *nginxMock) Restart() error {
	args := n.Called()
	return args.Error(0)
}

func (n *nginxMock) Reload() error {
	args := n.Called()
	return args.Error(0)
}

func (n *nginxMock) ConfigPath() string {
	return n.Called().String(0)
}

type certMock struct {
	mock.Mock
}

func (c *certMock) CertForDomain(domain string) (string, string, bool, error) {
	args := c.Called(domain)
	return args.String(0), args.String(1), args.Bool(2), args.Error(3)
}

func (c *certMock) RenewalForDomain(domain string) bool {
	return c.Called(domain).Bool(0)
}

type dockerMock struct {
	mock.Mock
}

func (d *dockerMock) CurrentConfigs() ([]*docker.ContainerConfig, error) {
	args := d.Called()
	return args.Get(0).([]*docker.ContainerConfig), args.Error(1)
}

func (d *dockerMock) StoppedContainers() <-chan *docker.ContainerConfig {
	return d.Called().Get(0).(chan *docker.ContainerConfig)
}
func (d *dockerMock) StartedContainers() <-chan *docker.ContainerConfig {
	return d.Called().Get(0).(chan *docker.ContainerConfig)
}

func mockReplaceConfig(confPath, tmpl string, cfg *nginx.TemplateConfig) error {
	return nil
}

func TestControlLoop(t *testing.T) {
	ngx := new(nginxMock)
	certs := new(certMock)
	dockerClient := new(dockerMock)

	ngx.On("Reload").Once().Return(nil)
	ngx.On("ConfigPath").Return("/etc/nginx/nginx.conf")

	for i := 1; i < 5; i++ {
		domain := fmt.Sprintf("foo%d.bar", i)
		certs.On("CertForDomain", domain).Once().Return("/path/to/cert", "/path/to/key", false, nil)
		certs.On("RenewalForDomain", domain).Maybe().Return(false)
	}
	startedChan := make(chan *docker.ContainerConfig, 1)
	stoppedChan := make(chan *docker.ContainerConfig, 1)
	dockerClient.On("CurrentConfigs").Return([]*docker.ContainerConfig{}, nil)
	dockerClient.On("StoppedContainers").Return(stoppedChan)
	dockerClient.On("StartedContainers").Return(startedChan)

	ctx := context.Background()
	ctr := newController(ctx, certs, ngx, dockerClient)
	ctr.renderToFile = mockReplaceConfig

	ccAdded := []*docker.ContainerConfig{
		&docker.ContainerConfig{
			ContainerID: "1",
			Host:        "foo1.bar",
			Upstream:    "172.0.0.1",
		},
		&docker.ContainerConfig{
			ContainerID: "2",
			Host:        "foo2.bar",
			Upstream:    "172.0.0.2",
		},
		&docker.ContainerConfig{
			ContainerID: "3",
			Host:        "foo3.bar",
			Upstream:    "172.0.0.3",
		},
		&docker.ContainerConfig{
			ContainerID: "4",
			Host:        "foo4.bar",
			Upstream:    "172.0.0.4",
		},
	}

	ccRemoved := []*docker.ContainerConfig{
		&docker.ContainerConfig{
			ContainerID: "1",
			Host:        "foo1.bar",
			Upstream:    "172.0.0.1",
		},
		&docker.ContainerConfig{
			ContainerID: "2",
			Host:        "foo2.bar",
			Upstream:    "172.0.0.2",
		},
		&docker.ContainerConfig{
			ContainerID: "3",
			Host:        "foo3.bar",
			Upstream:    "172.0.0.3",
		},
		&docker.ContainerConfig{
			ContainerID: "4",
			Host:        "foo4.bar",
			Upstream:    "172.0.0.4",
		},
	}

	ctr.addContainer(ccAdded...)
	time.Sleep(time.Millisecond * 50)
	ctr.removeContainer(ccRemoved...)
	time.Sleep(time.Millisecond * 50)
	time.Sleep(time.Second * 2)
	ctr.Close()

	ngx.AssertExpectations(t)
	certs.AssertExpectations(t)
}
