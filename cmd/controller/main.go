package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dereulenspiegel/nginx-controller/pkg/certs"
	"github.com/dereulenspiegel/nginx-controller/pkg/docker"
	"github.com/dereulenspiegel/nginx-controller/pkg/nginx"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
)

var (
	pathToNginx      = flag.String("nginx.binary", "/usr/sbin/nginx", "Specify the path to the nginx command")
	emailAddr        = flag.String("email", "", "Email address for the LetsEncrypt account")
	nginxConfPath    = flag.String("nginx.conf", "/etc/nginx/nginx.conf", "Path to the nginx configuration file")
	acmeDirectoryUrl = flag.String("acme.url", acme.LetsEncryptURL, "URL to the ACME directory")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	logrus.WithFields(logrus.Fields{
		"version":       nginx.Version,
		"email":         *emailAddr,
		"nginxPath":     *pathToNginx,
		"nginxConfPath": *nginxConfPath,
		"directoryURL":  *acmeDirectoryUrl,
	}).Info("Starting nginx controller")

	if *emailAddr == "" {
		logrus.Panic("No email address specified")
	}

	dockerClient, err := docker.New(ctx)
	if err != nil {
		logrus.WithError(err).Panic("Could not create docker client")
	}
	cc, _ := dockerClient.CurrentConfigs()
	logrus.WithFields(logrus.Fields{
		"containerCount": len(cc),
		"err":            fmt.Sprintf("%s", err),
	}).Info("Inspected currently running containers")
	certClient, err := certs.NewManager(ctx, *emailAddr, *acmeDirectoryUrl)
	if err != nil {
		logrus.WithError(err).Panic("Failed to create certificate manager")
	}

	startedContainers := dockerClient.StartedContainers()
	stoppedContainers := dockerClient.StoppedContainers()

	ngx, err := nginx.NewNginx(ctx, *pathToNginx, *nginxConfPath)
	if err != nil {
		logrus.WithError(err).Panic("Failed to create nginx process")
	}

	if err := ngx.Start(); err != nil {
		logrus.WithError(err).Panic("Failed to start nginx process")
	}

	ctrl := newController(ctx, certClient, ngx, dockerClient)

	var gracefulStop = make(chan os.Signal)
	signal.Notify(gracefulStop, syscall.SIGTERM)
	signal.Notify(gracefulStop, syscall.SIGINT)

	go func() {
		for container := range startedContainers {
			ctrl.addContainer(container)
		}
	}()

	go func() {
		for container := range stoppedContainers {
			ctrl.removeContainer(container)
		}
	}()

	<-gracefulStop
	if err := ctrl.Close(); err != nil {
		logrus.WithError(err).Error("Failed to shutdown controller loop properly")
	}
	// TODO close docker client
	if err := ngx.Stop(); err != nil {
		logrus.WithError(err).Panic("Failed to stop nginx")
	}
	os.Exit(0)
}
