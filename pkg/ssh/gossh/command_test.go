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

package gossh

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"

	sshtesting "github.com/deckhouse/lib-connection/pkg/ssh/gossh/testing"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

func TestCommandOutput(t *testing.T) {
	testName := "TestCommandOutput"

	sshtesting.CheckSkipSSHTest(t, testName)

	logger := log.NewSimpleLogger(log.LoggerOptions{})

	// genetaring ssh keys
	path, publicKey, err := sshtesting.GenerateKeys("")
	if err != nil {
		return
	}

	// starting openssh container without password auth
	container, err := sshtesting.NewSSHContainer(sshtesting.ContainerSettings{
		PublicKey:  publicKey,
		Username:   "user",
		LocalPort:  20027,
		SudoAccess: true,
	}, testName)
	require.NoError(t, err)

	err = container.Start()
	require.NoError(t, err)

	os.Setenv("SSH_AUTH_SOCK", "")

	settings := session.NewSession(session.Input{
		AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
		User:           "user",
		Port:           "20027"})
	keys := []session.AgentPrivateKey{{Key: path}}

	t.Cleanup(func() {
		sshtesting.StopContainerAndRemoveKeys(t, container, logger, path)
	})

	t.Run("Get command Output", func(t *testing.T) {
		cases := []struct {
			title             string
			command           string
			args              []string
			expectedOutput    string
			expectedErrOutput string
			timeout           time.Duration
			prepareFunc       func(c *SSHCommand) error
			wantErr           bool
			err               string
		}{
			{
				title:          "Just echo, success",
				command:        "echo",
				args:           []string{"\"test output\""},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
			{
				title:          "With context",
				command:        "while true; do echo \"test\"; sleep 5; done",
				args:           []string{},
				expectedOutput: "test\ntest\n",
				timeout:        7 * time.Second,
				wantErr:        false,
			},
			{
				title:             "Command return error",
				command:           "cat",
				args:              []string{"\"/etc/sudoers\""},
				wantErr:           true,
				err:               "Process exited with status 1",
				expectedErrOutput: "cat: /etc/sudoers: Permission denied\n",
			},
			{
				title:   "With opened stdout pipe",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					return c.Run(context.Background())
				},
				wantErr: true,
				err:     "open stdout pipe",
			},
			{
				title:   "With opened stderr pipe",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					buf := new(bytes.Buffer)
					c.session.Stderr = buf
					return nil
				},
				wantErr: true,
				err:     "open stderr pipe",
			},
			{
				title:   "With nil session",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					err := c.session.Close()
					c.session = nil
					return err
				},
				wantErr: true,
				err:     "ssh session not started",
			},
			{
				title:   "With defined buffers",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					c.out = new(bytes.Buffer)
					c.err = new(bytes.Buffer)
					return nil
				},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				ctx := context.Background()
				var emptyDuration time.Duration
				var cancel context.CancelFunc
				if c.timeout != emptyDuration {
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(c.timeout))
				}
				if cancel != nil {
					defer cancel()
				}
				sshSettings, _ := sshtesting.CreateDefaultTestSettings()
				sshClient := NewClient(ctx, sshSettings, settings, keys).
					WithLoopsParams(newSessionTestLoopParams())
				err = sshClient.Start()
				// expecting no error on client start
				require.NoError(t, err)
				cmd := NewSSHCommand(sshClient, c.command, c.args...)

				if c.prepareFunc != nil {
					err = c.prepareFunc(cmd)
					require.NoError(t, err)
				}
				out, errBytes, err := cmd.Output(ctx)
				if !c.wantErr {
					require.NoError(t, err)
					require.Equal(t, c.expectedOutput, string(out))
				} else {
					require.Error(t, err)
					require.Equal(t, c.expectedErrOutput, string(errBytes))
					require.Contains(t, err.Error(), c.err)
				}
				sshClient.Stop()
			})
		}
	})
}

func TestCommandCombinedOutput(t *testing.T) {
	testName := "TestCommandCombinedOutput"

	sshtesting.CheckSkipSSHTest(t, testName)

	logger := log.NewSimpleLogger(log.LoggerOptions{})

	os.Setenv("DHCTL_DEBUG", "yes")
	// genetaring ssh keys
	path, publicKey, err := sshtesting.GenerateKeys("")
	if err != nil {
		return
	}

	// starting openssh container without password auth
	container, err := sshtesting.NewSSHContainer(sshtesting.ContainerSettings{
		PublicKey:  publicKey,
		Username:   "user",
		LocalPort:  20028,
		SudoAccess: true,
	}, testName)
	require.NoError(t, err)

	err = container.Start()
	require.NoError(t, err)

	os.Setenv("SSH_AUTH_SOCK", "")

	settings := session.NewSession(session.Input{
		AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
		User:           "user",
		Port:           "20028"})
	keys := []session.AgentPrivateKey{{Key: path}}

	t.Cleanup(func() {
		sshtesting.StopContainerAndRemoveKeys(t, container, logger, path)
	})

	t.Run("Get command CombinedOutput", func(t *testing.T) {
		cases := []struct {
			title             string
			command           string
			args              []string
			expectedOutput    string
			expectedErrOutput string
			timeout           time.Duration
			prepareFunc       func(c *SSHCommand) error
			wantErr           bool
			err               string
		}{
			{
				title:          "Just echo, success",
				command:        "echo",
				args:           []string{"\"test output\""},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
			{
				title:          "With context",
				command:        "while true; do echo \"test\"; sleep 5; done",
				args:           []string{},
				expectedOutput: "test\ntest\n",
				timeout:        7 * time.Second,
				wantErr:        false,
			},
			{
				title:             "Command return error",
				command:           "cat",
				args:              []string{"\"/etc/sudoers\""},
				wantErr:           true,
				err:               "Process exited with status 1",
				expectedErrOutput: "cat: /etc/sudoers: Permission denied\n",
			},
			{
				title:   "With opened stdout pipe",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					return c.Run(context.Background())
				},
				wantErr: true,
				err:     "open stdout pipe",
			},
			{
				title:   "With opened stderr pipe",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					buf := new(bytes.Buffer)
					c.session.Stderr = buf
					return nil
				},
				wantErr: true,
				err:     "open stderr pipe",
			},
			{
				title:   "With nil session",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					err := c.session.Close()
					c.session = nil
					return err
				},
				wantErr: true,
				err:     "ssh session not started",
			},
			{
				title:   "With defined buffers",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					c.out = new(bytes.Buffer)
					c.err = new(bytes.Buffer)
					return nil
				},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				ctx := context.Background()
				var emptyDuration time.Duration
				var cancel context.CancelFunc
				if c.timeout != emptyDuration {
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(c.timeout))
				}
				if cancel != nil {
					defer cancel()
				}
				sshSettings, _ := sshtesting.CreateDefaultTestSettings()
				sshClient := NewClient(ctx, sshSettings, settings, keys).
					WithLoopsParams(newSessionTestLoopParams())
				err = sshClient.Start()
				// expecting no error on client start
				require.NoError(t, err)
				cmd := NewSSHCommand(sshClient, c.command, c.args...)
				if c.prepareFunc != nil {
					err = c.prepareFunc(cmd)
					require.NoError(t, err)
				}
				combined, err := cmd.CombinedOutput(ctx)
				if !c.wantErr {
					require.NoError(t, err)
					require.Equal(t, c.expectedOutput, string(combined))
				} else {
					require.Error(t, err)
					require.Equal(t, c.expectedErrOutput, string(combined))
					require.Contains(t, err.Error(), c.err)
				}
				sshClient.Stop()
			})
		}
	})
}

func TestCommandRun(t *testing.T) {
	testName := "TestCommandRun"

	sshtesting.CheckSkipSSHTest(t, testName)

	logger := log.NewSimpleLogger(log.LoggerOptions{})

	// genetaring ssh keys
	path, publicKey, err := sshtesting.GenerateKeys("")
	if err != nil {
		return
	}

	// starting openssh container without password auth
	container, err := sshtesting.NewSSHContainer(sshtesting.ContainerSettings{
		PublicKey:  publicKey,
		Username:   "user",
		LocalPort:  20028,
		SudoAccess: true,
	}, testName)
	require.NoError(t, err)

	err = container.Start()
	require.NoError(t, err)

	os.Setenv("SSH_AUTH_SOCK", "")

	settings := session.NewSession(session.Input{
		AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
		User:           "user",
		Port:           "20028"})
	keys := []session.AgentPrivateKey{{Key: path}}

	t.Cleanup(func() {
		sshtesting.StopContainerAndRemoveKeys(t, container, logger, path)
	})

	// evns test
	envs := make(map[string]string)
	envs["TEST_ENV"] = "test"

	t.Run("Run a command", func(t *testing.T) {
		cases := []struct {
			title             string
			command           string
			args              []string
			expectedOutput    string
			expectedErrOutput string
			timeout           time.Duration
			prepareFunc       func(c *SSHCommand) error
			envs              map[string]string
			wantErr           bool
			err               string
		}{
			{
				title:          "Just echo, success",
				command:        "echo",
				args:           []string{"\"test output\""},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
			{
				title:          "Just echo, with envs, success",
				command:        "echo",
				args:           []string{"\"test output\""},
				expectedOutput: "test output\n",
				envs:           envs,
				wantErr:        false,
			},
			{
				title:          "With context",
				command:        "while true; do echo \"test\"; sleep 5; done",
				args:           []string{},
				expectedOutput: "test\ntest\n",
				timeout:        7 * time.Second,
				wantErr:        false,
			},
			{
				title:             "Command return error",
				command:           "cat",
				args:              []string{"\"/etc/sudoers\""},
				wantErr:           true,
				err:               "Process exited with status 1",
				expectedErrOutput: "cat: /etc/sudoers: Permission denied\n",
			},
			{
				title:   "With opened stdout pipe",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					return c.Run(context.Background())
				},
				wantErr: true,
				err:     "ssh: session already started",
			},
			{
				title:   "With nil session",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					err := c.session.Close()
					c.session = nil
					return err
				},
				wantErr: true,
				err:     "ssh session not started",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				ctx := context.Background()
				var emptyDuration time.Duration
				var cancel context.CancelFunc
				if c.timeout != emptyDuration {
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(c.timeout))
				}
				if cancel != nil {
					defer cancel()
				}
				sshSettings, _ := sshtesting.CreateDefaultTestSettings()
				sshClient := NewClient(ctx, sshSettings, settings, keys).
					WithLoopsParams(newSessionTestLoopParams())
				err = sshClient.Start()
				// expecting no error on client start
				require.NoError(t, err)
				cmd := NewSSHCommand(sshClient, c.command, c.args...)
				if c.prepareFunc != nil {
					err = c.prepareFunc(cmd)
					require.NoError(t, err)
				}
				if len(c.envs) > 0 {
					cmd.WithEnv(c.envs)
				}

				err = cmd.Run(ctx)
				if !c.wantErr {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}

				// second run for context after deadline exceeded
				if c.timeout != emptyDuration {
					cmd2 := NewSSHCommand(sshClient, c.command, c.args...)
					if c.prepareFunc != nil {
						err = c.prepareFunc(cmd2)
						require.NoError(t, err)
					}
					if len(c.envs) > 0 {
						cmd2.WithEnv(c.envs)
					}
					err = cmd2.Run(ctx)
					// command should fail to run
					require.Error(t, err)
					require.Contains(t, err.Error(), "context deadline exceeded")

				}
				sshClient.Stop()
			})
		}
	})
}

func TestCommandStart(t *testing.T) {
	testName := "TestCommandStart"

	sshtesting.CheckSkipSSHTest(t, testName)

	logger := log.NewSimpleLogger(log.LoggerOptions{})

	// genetaring ssh keys
	path, publicKey, err := sshtesting.GenerateKeys("")
	if err != nil {
		return
	}

	// starting openssh container without password auth
	container, err := sshtesting.NewSSHContainer(sshtesting.ContainerSettings{
		PublicKey:  publicKey,
		Username:   "user",
		LocalPort:  20029,
		SudoAccess: true,
	}, testName)
	require.NoError(t, err)

	err = container.Start()
	require.NoError(t, err)

	os.Setenv("SSH_AUTH_SOCK", "")

	settings := session.NewSession(session.Input{
		AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
		User:           "user",
		Port:           "20029"})
	keys := []session.AgentPrivateKey{{Key: path}}
	ctx := context.Background()
	sshSettings, _ := sshtesting.CreateDefaultTestSettings()
	sshClient := NewClient(ctx, sshSettings, settings, keys).
		WithLoopsParams(newSessionTestLoopParams())
	err = sshClient.Start()
	// expecting no error on client start
	require.NoError(t, err)

	t.Cleanup(func() {
		sshClient.Stop()
		sshtesting.StopContainerAndRemoveKeys(t, container, logger, path)
	})

	t.Run("Start and stop a command", func(t *testing.T) {
		cases := []struct {
			title             string
			command           string
			args              []string
			expectedOutput    string
			expectedErrOutput string
			timeout           time.Duration
			prepareFunc       func(c *SSHCommand) error
			wantErr           bool
			err               string
		}{
			{
				title:          "Just echo, success",
				command:        "echo",
				args:           []string{"\"test output\""},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
			{
				title:          "With context",
				command:        "while true; do echo \"test\"; sleep 5; done",
				args:           []string{},
				expectedOutput: "test\ntest\n",
				timeout:        7 * time.Second,
				wantErr:        false,
			},
			{
				title:             "Command return error",
				command:           "cat",
				args:              []string{"\"/etc/sudoers\""},
				wantErr:           true,
				err:               "Process exited with status 1",
				expectedErrOutput: "cat: /etc/sudoers: Permission denied\n",
			},
			{
				title:   "With opened stdout pipe",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					return c.Run(context.Background())
				},
				wantErr: true,
				err:     "ssh: session already started",
			},
			{
				title:   "With nil session",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					err := c.session.Close()
					c.session = nil
					return err
				},
				wantErr: true,
				err:     "ssh session not started",
			},
			{
				title:   "waitHandler",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					c.WithWaitHandler(func(err error) {
						if err != nil {
							logger.ErrorF("SSH-agent process exited, now stop. Wait error: %v", err)
							return
						}
						logger.InfoF("SSH-agent process exited, now stop")
					})
					return nil
				},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				cmd := NewSSHCommand(sshClient, c.command, c.args...)
				var emptyDuration time.Duration
				if c.timeout != emptyDuration {
					cmd.WithTimeout(c.timeout)
				}
				if c.prepareFunc != nil {
					err = c.prepareFunc(cmd)
					require.NoError(t, err)
				}
				cmd.Cmd(ctx)
				err = cmd.Start()
				if !c.wantErr {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}
				cmd.Stop()
			})
		}
	})
}

func TestCommandSudoRun(t *testing.T) {
	testName := "TestCommandSudoRun"

	sshtesting.CheckSkipSSHTest(t, testName)

	logger := log.NewSimpleLogger(log.LoggerOptions{})

	// genetaring ssh keys
	path, publicKey, err := sshtesting.GenerateKeys("")
	if err != nil {
		return
	}

	// starting openssh container without password auth
	container, err := sshtesting.NewSSHContainer(sshtesting.ContainerSettings{
		PublicKey:  publicKey,
		Username:   "user",
		LocalPort:  20030,
		SudoAccess: true,
	}, testName)
	require.NoError(t, err)

	err = container.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		sshtesting.StopContainerAndRemoveKeys(t, container, logger, path)
	})

	// starting openssh container with password auth
	containerWithPass, err := sshtesting.NewSSHContainer(sshtesting.ContainerSettings{
		PublicKey:  publicKey,
		Username:   "user",
		LocalPort:  20031,
		SudoAccess: true,
		Password:   "VeryStrongPasswordWhatCannotBeGuessed",
	}, testName)
	require.NoError(t, err)

	err = containerWithPass.Start()
	require.NoError(t, err)

	os.Setenv("SSH_AUTH_SOCK", "")

	settings := session.NewSession(session.Input{
		AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
		User:           "user",
		Port:           "20030"})
	keys := []session.AgentPrivateKey{{Key: path}}
	settings2 := session.NewSession(session.Input{
		AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
		User:           "user",
		Port:           "20031",
		BecomePass:     "VeryStrongPasswordWhatCannotBeGuessed",
	})

	// client with wrong sudo password
	settings3 := session.NewSession(session.Input{
		AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
		User:           "user",
		Port:           "20031",
		BecomePass:     "WrongPassword",
	})

	t.Cleanup(func() {
		sshtesting.StopContainerAndRemoveKeys(t, containerWithPass, logger)
	})

	t.Run("Run a command with sudo", func(t *testing.T) {
		cases := []struct {
			title       string
			settings    *session.Session
			keys        []session.AgentPrivateKey
			command     string
			args        []string
			timeout     time.Duration
			prepareFunc func(c *SSHCommand) error
			wantErr     bool
			err         string
			errorOutput string
		}{
			{
				title:    "Just echo, success",
				settings: settings,
				keys:     keys,
				command:  "echo",
				args:     []string{"\"test output\""},
				wantErr:  false,
			},
			{
				title:    "Just echo, success, with password",
				settings: settings2,
				keys:     make([]session.AgentPrivateKey, 0, 1),
				command:  "echo",
				args:     []string{"\"test output\""},
				wantErr:  false,
			},
			{
				title:       "Just echo, failure, with wrong password",
				settings:    settings3,
				keys:        keys,
				command:     "echo",
				args:        []string{"\"test output\""},
				wantErr:     true,
				err:         "Process exited with status 1",
				errorOutput: "SudoPasswordSorry, try again.\nSudoPasswordSorry, try again.\nSudoPasswordsudo: 3 incorrect password attempts\n",
			},
			{
				title:    "With context",
				settings: settings,
				keys:     keys,
				command:  "while true; do echo \"test\"; sleep 5; done",
				args:     []string{},
				timeout:  7 * time.Second,
				wantErr:  false,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				ctx := context.Background()
				var emptyDuration time.Duration
				var cancel context.CancelFunc
				if c.timeout != emptyDuration {
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(c.timeout))
				}
				if cancel != nil {
					defer cancel()
				}
				sshSettings, _ := sshtesting.CreateDefaultTestSettings()
				sshClient := NewClient(ctx, sshSettings, c.settings, c.keys).WithLoopsParams(newSessionTestLoopParams())
				err = sshClient.Start()
				// expecting no error on client start
				require.NoError(t, err)
				cmd := NewSSHCommand(sshClient, c.command, c.args...).CaptureStderr(nil)
				if c.prepareFunc != nil {
					err = c.prepareFunc(cmd)
					require.NoError(t, err)
				}
				cmd.Sudo(ctx)
				err = cmd.Run(ctx)
				if !c.wantErr {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
					errBytes := cmd.StderrBytes()

					require.Contains(t, string(errBytes), c.errorOutput)
				}
				sshClient.Stop()
			})
		}
	})
}

func newSessionTestLoopParams() ClientLoopsParams {
	return ClientLoopsParams{
		NewSession: retry.NewEmptyParams(
			retry.WithWait(2*time.Second),
			retry.WithAttempts(5),
		),
	}
}
