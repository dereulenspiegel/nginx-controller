package nginx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

type Nginx struct {
	cmd *exec.Cmd

	confPath string
	ctx      context.Context
}

func NewNginx(ctx context.Context, binPath, confPath string) (*Nginx, error) {
	cmd := exec.Command(binPath, "-g", "daemon off;", "-c", confPath)

	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	n := &Nginx{
		cmd:      cmd,
		confPath: confPath,
	}
	return n, nil
}

func (n *Nginx) loop() {
	for {
		select {
		case <-n.ctx.Done():
			return
		default:
			if n.cmd.ProcessState.Exited() {
				logrus.Warn("nginx process exited, starting again")
				n.Start()
			}
			time.Sleep(time.Millisecond * 100)
		}
	}
}

func (n *Nginx) ConfigPath() string {
	return n.confPath
}

func (n *Nginx) Start() error {
	logrus.WithFields(logrus.Fields{}).Info("Starting nginx process")
	return n.cmd.Start()
}

func (n *Nginx) Stop() error {
	logrus.WithFields(logrus.Fields{
		"pid": n.cmd.Process.Pid,
	}).Info("Stopping nginx process")
	if err := n.cmd.Process.Signal(syscall.SIGQUIT); err != nil {
		return err
	}
	state, err := n.cmd.Process.Wait()
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"pid": n.cmd.Process.Pid,
		}).Error("Failed to wait for porcess to stop")
		return err
	}
	if !state.Exited() {
		logrus.WithError(err).WithFields(logrus.Fields{
			"pid":   n.cmd.Process.Pid,
			"state": state.String(),
		}).Error("nginx process is not in exited state after stopping")
		return errors.New("nginx process is not exited after SIGTERM")
	}
	return nil
}

func (n *Nginx) Restart() error {
	if err := n.Stop(); err != nil {
		return err
	}
	return n.Start()
}

func (n *Nginx) Reload() error {
	logrus.WithFields(logrus.Fields{
		"pid": n.cmd.Process.Pid,
	}).Info("Reloading nginx process")
	err := n.cmd.Process.Signal(syscall.SIGHUP)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"pid": n.cmd.Process.Pid,
		}).Error("Failed to send SIGHUP to nginx process to reload it")
	}
	return err
}
