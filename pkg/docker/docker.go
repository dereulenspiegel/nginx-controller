package docker

import (
	"context"
	"fmt"
	"strconv"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	docker "github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
)

const (
	HostLabel          = "nginx-controller.akuz.de/host"
	PathLabel          = "nginx-controller.akuz.de/path"
	PortLabel          = "nginx-controller.akuz.de/port"
	AuthLabel          = "nginx-controller.akuz.de/auth"
	NetworkLabel       = "nginx-controller.akuz.de/network"
	DisableBufferLabel = "nginx-controller.akuz.de/disable_buffer"
)

type dockerClient interface {
	Events(ctx context.Context, options types.EventsOptions) (<-chan events.Message, <-chan error)
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
	ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error)
}

type Watcher struct {
	client dockerClient
	ctx    context.Context
}

func New(ctx context.Context) (*Watcher, error) {
	c, err := docker.NewEnvClient()
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		client: c,
		ctx:    ctx,
	}

	return w, nil
}

type ContainerConfig struct {
	Upstream      string
	Host          string
	Path          string
	Auth          string
	ContainerID   string
	DisableBuffer bool
}

func (w *Watcher) watchEvents(filterArgs filters.Args) <-chan *ContainerConfig {
	out := make(chan *ContainerConfig, 100)

	eventFilter := types.EventsOptions{
		Filters: filterArgs,
	}
	in, errChan := w.client.Events(w.ctx, eventFilter)

	go func(in <-chan error) {
		for err := range in {
			logrus.WithError(err).WithFields(logrus.Fields{}).Error("Received error while listening for events")
		}
	}(errChan)
	go func(in <-chan events.Message) {
		for event := range in {
			logrus.WithFields(logrus.Fields{
				"containerID": event.Actor.ID,
				"action":      event.Action,
				"type":        event.Type,
			}).Info("Received docker event")
			containerID := event.Actor.ID
			cc, err := w.getContainerConfig(containerID)
			if err != nil {
				logrus.WithError(err).Error("Could not inspect container")
			}
			if cc != nil {
				logrus.WithFields(logrus.Fields{
					"containerID": event.Actor.ID,
					"action":      event.Action,
					"type":        event.Type,
				}).Info("Forwarding container event")
				out <- cc
			} else {
				logrus.WithFields(logrus.Fields{
					"containerID": event.Actor.ID,
				}).Warn("Container config generated for this event was nil")
			}
		}
		close(out)
	}(in)
	return out
}

func (w *Watcher) getContainerConfig(containerID string) (*ContainerConfig, error) {
	logger := logrus.WithFields(logrus.Fields{
		"containerID": containerID,
	})
	eventContainer, err := w.client.ContainerInspect(w.ctx, containerID)
	if err != nil {
		logger.WithError(err).Error("Could not inspect container after receiving event")
		return nil, err
	}

	labels := eventContainer.Config.Labels
	host := labels[HostLabel]
	path := labels[PathLabel]
	auth := labels[AuthLabel]
	network := labels[NetworkLabel]
	disableBuffer := false
	if labels[DisableBufferLabel] == "true" {
		disableBuffer = true
	}

	logger = logger.WithFields(logrus.Fields{
		"labelHost":    host,
		"labelPath":    path,
		"labelAuth":    auth,
		"labelNetwork": network,
	})

	var ipAddress string
	if network != "" {
		if net, exists := eventContainer.NetworkSettings.Networks[network]; exists {
			ipAddress = net.IPAddress
		}
	}

	if ipAddress == "" {
		ipAddress = eventContainer.NetworkSettings.IPAddress
	}

	if ipAddress == "" {
		logger.Error("Failed to determine IP address of container")
		return nil, fmt.Errorf("Failed to determine IP address of container %s", containerID)
	}

	if path == "" {
		path = "/"
	}
	port, err := strconv.Atoi(labels[PortLabel])
	if err != nil {
		port = -1
	}
	if port == -1 {
		for p := range eventContainer.NetworkSettings.Ports {
			// Just take the first tcp port for now
			if p.Proto() == "tcp" {
				port = p.Int()
				break
			}
		}
	}
	if host != "" {
		cc := &ContainerConfig{
			ContainerID:   containerID,
			Upstream:      fmt.Sprintf("http://%s:%d", ipAddress, port),
			Host:          host,
			Path:          path,
			Auth:          auth,
			DisableBuffer: disableBuffer,
		}
		return cc, nil
	}
	return nil, nil
}

func (w *Watcher) StoppedContainers() <-chan *ContainerConfig {
	filterArgs := filters.NewArgs()
	filterArgs.Add("type", "container")
	filterArgs.Add("event", "stop")

	return w.watchEvents(filterArgs)
}

func (w *Watcher) StartedContainers() <-chan *ContainerConfig {
	filterArgs := filters.NewArgs()
	filterArgs.Add("type", "container")
	filterArgs.Add("event", "start")

	return w.watchEvents(filterArgs)
}

func (w *Watcher) CurrentConfigs() (configs []*ContainerConfig, err error) {
	//filterArgs := filters.NewArgs(filters.Arg("state", "started"))
	listOptions := types.ContainerListOptions{}
	containers, err := w.client.ContainerList(w.ctx, listOptions)

	if err != nil {
		return nil, err
	}

	for _, c := range containers {
		cc, err := w.getContainerConfig(c.ID)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"containerID": c.ID,
			}).Error("Could not inspect container for current configs")
		}
		if cc != nil {
			configs = append(configs, cc)
		}
	}
	return
}
