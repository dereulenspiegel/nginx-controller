package docker

import (
	"context"
	"fmt"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func onContainerInspect(dc *dockerMock, id, hostLabel, ip, port string) {
	dc.On("ContainerInspect",
		mock.MatchedBy(func(in interface{}) bool { return true }), id).
		Return(types.ContainerJSON{
			Config: &container.Config{
				Labels: map[string]string{
					HostLabel: hostLabel,
				},
			},
			NetworkSettings: &types.NetworkSettings{
				Networks: map[string]*network.EndpointSettings{
					"net1": &network.EndpointSettings{
						IPAddress: ip,
					},
				},
				NetworkSettingsBase: types.NetworkSettingsBase{
					Ports: nat.PortMap{
						nat.Port(fmt.Sprintf("%s/tcp", port)): []nat.PortBinding{
							{
								HostIP:   "",
								HostPort: port,
							},
						},
					},
				},
			},
		}, nil)
}

type dockerMock struct {
	mock.Mock
}

func (d *dockerMock) Events(ctx context.Context, options types.EventsOptions) (<-chan events.Message, <-chan error) {
	args := d.Called(ctx, options)
	return args.Get(0).(<-chan events.Message), args.Get(1).(<-chan error)
}

func (d *dockerMock) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	args := d.Called(ctx, containerID)
	return args.Get(0).(types.ContainerJSON), args.Error(1)
}

func (d *dockerMock) ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error) {
	args := d.Called(ctx, options)
	return args.Get(0).([]types.Container), args.Error(1)
}

func TestGetContainerConfig(t *testing.T) {
	dc := new(dockerMock)
	onContainerInspect(dc, "foo1", "example.com", "127.12.0.1", "8081")

	w := &Watcher{
		client: dc,
		ctx:    context.Background(),
	}

	container, err := w.getContainerConfig("foo1")
	require.NoError(t, err)
	require.NotEmpty(t, container)

	assert.Equal(t, "example.com", container.Host)
	assert.Equal(t, "http://127.12.0.1:8081", container.Upstream)
	assert.Equal(t, "/", container.Path)
}

func TestCurrentConfigs(t *testing.T) {
	dc := new(dockerMock)
	dc.On("ContainerList",
		mock.MatchedBy(func(in interface{}) bool { return true }),
		mock.MatchedBy(func(in interface{}) bool { return true })).
		Return([]types.Container{
			types.Container{
				ID: "foo1",
			},
			types.Container{
				ID: "foo2",
			},
		}, nil)
	w := &Watcher{
		client: dc,
		ctx:    context.Background(),
	}

	onContainerInspect(dc, "foo1", "example1.com", "127.12.0.1", "8081")
	onContainerInspect(dc, "foo2", "example2.com", "127.13.0.1", "8082")

	containers, err := w.CurrentConfigs()
	require.NoError(t, err)
	assert.NotEmpty(t, containers)
	assert.Len(t, containers, 2)
}
