// Copyright 2025 Flant JSC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssh_testing

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
)

const (
	tmpGlobalDirName = "test-lib-connection"
	dockerNamePrefix = "test_lib_connection"
)

type ContainerSettings struct {
	PublicKey     string
	PublicKeyPath string
	Password      string
	Username      string
	NodeTmpPath   string
	LocalPort     int
	SudoAccess    bool
}

func (s ContainerSettings) LocalPortString() string {
	return strconv.Itoa(s.LocalPort)
}

type SSHContainer struct {
	settings       ContainerSettings
	id             string
	ip             string
	sshdConfigPath string
	network        string
	testName       string
	testID         string
	localTmpDir    string
}

func NewSSHContainer(settings ContainerSettings, testName string) (*SSHContainer, error) {
	if settings.NodeTmpPath == "" {
		settings.NodeTmpPath = "/opt/deckhouse/tmp"
	}

	if settings.LocalPort <= 0 {
		settings.LocalPort = randRange(22000, 29999)
	}

	id := testID(testName)

	c := &SSHContainer{
		settings: settings,
		testName: testName,
		testID:   id,
	}

	localTmpDirStr := filepath.Join(os.TempDir(), tmpGlobalDirName, id)
	err := os.MkdirAll(localTmpDirStr, 0777)
	if err != nil {
		return nil, c.wrapError("failed to create local tmp dir %s: %v", localTmpDirStr, err)
	}
	localTmpDir, err := os.MkdirTemp(localTmpDirStr, "ssh")
	if err != nil {
		return nil, c.wrapError("failed to create temporary local tmp dir %s: %v", localTmpDirStr, err)
	}
	c.localTmpDir = localTmpDir

	return c, nil
}

// force AllowTcpForwarding yes to allow connection throufh bastion
func (c *SSHContainer) WriteConfig() error {
	conf, err := os.CreateTemp(c.localTmpDir, "sshd_config")
	if err != nil {
		return err
	}

	passwordAuthEnabled := "no"
	if len(c.ContainerSettings().Password) > 0 {
		passwordAuthEnabled = "yes"
	}

	configTpl := `
Port %s
AuthorizedKeysFile	.ssh/authorized_keys
AllowTcpForwarding yes
GatewayPorts no
X11Forwarding no
PidFile /config/sshd.pid
Subsystem	sftp	internal-sftp
PasswordAuthentication %s
`
	config := fmt.Sprintf(configTpl, c.RemotePortString(), passwordAuthEnabled)

	_, err = conf.WriteString(config)
	c.sshdConfigPath = conf.Name()
	return err
}

func (c *SSHContainer) RemoveSSHDConfig() error {
	path := c.GetSSHDConfigPath()
	if path == "" {
		return nil
	}

	if err := os.Remove(path); err != nil {
		return c.wrapError("failed to remove config file: %v", err)
	}

	return nil
}

func (c *SSHContainer) Start() error {
	err := c.createNetwork()
	if err != nil {
		return err
	}

	cmd := append([]string{"run"}, c.runContainerArgs()...)

	id, err := c.runDockerWithOut("start container", cmd...)
	if err != nil {
		loopParams := defaultRetryParams(fmt.Sprintf("Remove network %s after fail run container", c.GetNetwork()))
		removeNetworkErr := retry.NewLoopWithParams(loopParams).Run(func() error {
			return c.removeNetwork()
		})
		if removeNetworkErr != nil {
			err = c.wrapError("%v and failed to remove network %s: %v", err, c.GetNetwork(), removeNetworkErr)
		}

		return err
	}

	c.id = strings.TrimSpace(id)

	c.ip, err = c.discoveryContainerIP()
	if err != nil {
		if stopErr := c.Stop(); stopErr != nil {
			err = c.wrapError("%v and cannot cleanup: %v", err, stopErr)
		}
		return err
	}

	return nil
}

func (c *SSHContainer) Stop() error {
	resError := ""
	if err := c.stopContainer(); err != nil {
		resError = err.Error()
	}

	if err := c.removeNetwork(); err != nil {
		resError = fmt.Sprintf("%s/%s", resError, err.Error())
	}

	if resError != "" {
		return errors.New(resError)
	}

	return nil
}

func (c *SSHContainer) Disconnect() error {
	return c.runDockerNetworkConnect(false)
}

func (c *SSHContainer) Connect() error {
	return c.runDockerNetworkConnect(true)
}

func (c *SSHContainer) ExecToContainer(description string, command ...string) error {
	if err := c.isContainerStarted(description); err != nil {
		return err
	}

	args := append([]string{"exec", c.GetContainerId()}, command...)

	return c.runDocker(description, args...)
}

func (c *SSHContainer) CreateDeckhouseDirs() error {
	description := func(name string) string {
		d := "node tmp dir"
		if name == "" {
			return d
		}

		return fmt.Sprintf("%s %s", d, name)
	}

	nodeTmpPath := c.ContainerSettings().NodeTmpPath

	if nodeTmpPath == "" {
		return c.wrapError("cannot create %s. Path is empty", description(""))
	}

	if err := c.ExecToContainer(description("create"), "mkdir", "-p", nodeTmpPath); err != nil {
		return err
	}

	return c.ExecToContainer(description("set mode"), "chmod", "-R", "777", nodeTmpPath)
}

func (c *SSHContainer) GetContainerId() string {
	return c.id
}

func (c *SSHContainer) GetNetwork() string {
	return c.network
}

func (c *SSHContainer) GetContainerIP() string {
	return c.ip
}

func (c *SSHContainer) GetSSHDConfigPath() string {
	return c.sshdConfigPath
}

func (c *SSHContainer) ContainerSettings() ContainerSettings {
	return c.settings
}

func (c *SSHContainer) RemotePortString() string {
	return "2222"
}

func (c *SSHContainer) dockerName() string {
	return fmt.Sprintf("%s_%s", dockerNamePrefix, c.testID)
}

func (c *SSHContainer) runDockerWithOut(description string, command ...string) (string, error) {
	if len(command) == 0 {
		return "", c.wrapError("%s: docker command is empty", description)
	}

	cmd := exec.Command("docker", command...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", c.wrapError("cannot run docker %s: '%v', output: %s", description, err, string(out))
	}

	return string(out), nil
}

func (c *SSHContainer) runDocker(description string, command ...string) error {
	_, err := c.runDockerWithOut(description, command...)
	return err
}

func (c *SSHContainer) wrapError(format string, args ...any) error {
	f := c.testName + ": " + format
	return fmt.Errorf(f, args...)
}

func (c *SSHContainer) isContainerStarted(description string) error {
	if c.GetContainerId() != "" {
		return nil
	}

	return c.wrapError("%s: container seems to be not started. Call Start() first", description)
}

func (c *SSHContainer) runContainerArgs() []string {
	settings := c.ContainerSettings()

	ports := fmt.Sprintf("%d:%s", settings.LocalPort, c.RemotePortString())
	name := c.dockerName()
	args := []string{
		"-d",
		"-e", "USER_NAME=" + settings.Username,
		"-p", ports,
		"--name", name,
		"--network", c.GetNetwork(),
	}

	if len(settings.PublicKey) > 0 {
		args = append(args, "-e")
		args = append(args, "PUBLIC_KEY="+settings.PublicKey)
	}
	if len(settings.PublicKeyPath) > 0 {
		args = append(args, "-e")
		args = append(args, "PUBLIC_KEY_FILE="+settings.PublicKeyPath)
	}
	// set default password if no auth methods present
	if len(settings.PublicKey) == 0 && len(settings.PublicKeyPath) == 0 && len(settings.Password) == 0 {
		c.settings.Password = "password"
	}

	settings = c.ContainerSettings()

	if len(settings.Password) > 0 {
		args = append(args, "-e")
		args = append(args, "PASSWORD_ACCESS=true")
		args = append(args, "-e")
		args = append(args, "USER_PASSWORD="+settings.Password)
	}
	args = append(args, "-e")
	args = append(args, "SUDO_ACCESS="+fmt.Sprintf("%v", settings.SudoAccess))
	args = append(args, "--restart")
	args = append(args, "unless-stopped")

	sshdConfigPath := c.GetSSHDConfigPath()
	if sshdConfigPath != "" {
		args = append(args, "-v")
		args = append(args, sshdConfigPath+":/config/sshd/sshd_config")
	}

	image := os.Getenv("DHCTL_TESTS_OPENSSH_IMAGE")
	if image == "" {
		image = "lscr.io/linuxserver/openssh-server:10.0_p1-r9-ls209"
	}

	args = append(args, image)

	return args
}

func (c *SSHContainer) stopContainer() error {
	if err := c.isContainerStarted("stop container"); err == nil {
		return nil
	}

	description := func(name string) string {
		return fmt.Sprintf("%s %s", name, c.GetContainerId())
	}

	if err := c.runDocker(description("stop container"), "stop", c.GetContainerId()); err != nil {
		return err
	}

	return c.runDocker(description("remove container"), "rm", c.GetContainerId())
}

func (c *SSHContainer) isNetworkCreated(description string) error {
	if c.GetNetwork() != "" {
		return nil
	}

	return c.wrapError("%s: docker network is not created. Container seems to be not connected to named bridge", description)
}

func (c *SSHContainer) createNetwork() error {
	if err := c.isContainerStarted("create network"); err == nil {
		return c.wrapError("container %s is already running", c.GetContainerId())
	}

	if err := c.isNetworkCreated("create network"); err == nil {
		return c.wrapError("network %s is already created", c.GetContainerId())
	}

	network := c.dockerName()

	if err := c.runDocker(fmt.Sprintf("create network %s", network), "network", "create", network); err != nil {
		return err
	}

	c.network = network

	return nil
}

func (c *SSHContainer) removeNetwork() error {
	if err := c.isNetworkCreated("remove network"); err != nil {
		return nil
	}

	network := c.GetNetwork()

	if err := c.runDocker(fmt.Sprintf("remove network %s", network), "network", "rm", network); err != nil {
		return err
	}

	c.network = ""

	return nil
}

func (c *SSHContainer) runDockerNetworkConnect(isDisconnect bool) error {
	cmdName := "connect"
	if isDisconnect {
		cmdName = "disconnect"
	}

	description := fmt.Sprintf("network %s", cmdName)

	if err := c.isContainerStarted(description); err != nil {
		return err
	}

	if err := c.isNetworkCreated(description); err != nil {
		return err
	}

	return c.runDocker(cmdName, "network", cmdName, c.GetNetwork(), c.GetContainerId())
}

func (c *SSHContainer) discoveryContainerIP() (string, error) {
	description := "Getting IP address of container"
	if err := c.isNetworkCreated(description); err != nil {
		return "", err
	}

	if err := c.isContainerStarted(description); err != nil {
		return "", err
	}

	getIPLoopParams := defaultRetryParams(fmt.Sprintf(" %s", c.GetContainerId()))
	getIPCmd := []string{
		"inspect",
		"-f", "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
		c.GetContainerId(),
	}

	ip := ""

	err := retry.NewLoopWithParams(getIPLoopParams).Run(func() error {
		ipFromRun, err := c.runDockerWithOut(description, getIPCmd...)
		if err != nil {
			return err
		}

		ipFromRun = strings.TrimSpace(ipFromRun)
		if ipFromRun == "" {
			return errors.New("container IP is empty")
		}

		ip = ipFromRun

		return nil
	})

	if err != nil {
		return "", err
	}

	return ip, nil
}

func defaultRetryParams(name string) retry.Params {
	return retry.NewEmptyParams(
		retry.WithName(name),
		retry.WithAttempts(5),
		retry.WithWait(3*time.Second),
		retry.WithLogger(log.NewSimpleLogger(log.LoggerOptions{})),
	)
}
