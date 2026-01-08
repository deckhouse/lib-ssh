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
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/stretchr/testify/require"

	connection "github.com/deckhouse/lib-connection/pkg"
	sshtesting "github.com/deckhouse/lib-connection/pkg/ssh/gossh/testing"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

func TestOnlyPreparePrivateKeys(t *testing.T) {
	sshtesting.CheckSkipSSHTest(t, "TestOnlyPreparePrivateKeys")

	// genetaring ssh keys
	path, _, err := sshtesting.GenerateKeys("")
	if err != nil {
		return
	}
	tmpFile, _ := os.CreateTemp("/tmp", "wrong-key")
	_, err = tmpFile.WriteString("Hello world")
	if err != nil {
		return
	}
	keyWithPass, _, err := sshtesting.GenerateKeys("password")
	if err != nil {
		return
	}

	logger := log.NewSimpleLogger(log.LoggerOptions{})

	t.Cleanup(func() {
		sshtesting.RemoveFiles(t, logger, path, tmpFile.Name(), keyWithPass)
	})

	t.Run("OnlyPrepareKeys cases", func(t *testing.T) {
		cases := []struct {
			title    string
			settings *session.Session
			keys     []session.AgentPrivateKey
			wantErr  bool
			err      string
		}{
			{
				title: "No keys",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20022",
					BecomePass:     "VeryStrongPasswordWhatCannotBeGuessed"}),
				keys:    make([]session.AgentPrivateKey, 0, 1),
				wantErr: false,
			},
			{
				title: "Key auth, no password",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20022"}),
				keys:    []session.AgentPrivateKey{{Key: path}},
				wantErr: false,
			},
			{
				title: "Key auth, no password, noexistent key",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20022"}),
				keys:    []session.AgentPrivateKey{{Key: "/tmp/noexistent-key"}},
				wantErr: true,
				err:     "open /tmp/noexistent-key: no such file or directory",
			},
			{
				title: "Key auth, no password, wrong key",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20022"}),
				keys:    []session.AgentPrivateKey{{Key: tmpFile.Name()}},
				wantErr: true,
				err:     "ssh: no key found",
			},
			{
				title: "Key auth, with passphrase",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20022"}),
				keys:    []session.AgentPrivateKey{{Key: keyWithPass, Passphrase: "password"}},
				wantErr: false,
			},
			{
				title: "Key auth, with wrong passphrase",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20022"}),
				keys:    []session.AgentPrivateKey{{Key: keyWithPass, Passphrase: "wrongpassword"}},
				wantErr: true,
				err:     "x509: decryption password incorrect",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				var sshClient *Client
				sshSettings, _ := sshtesting.CreateDefaultTestSettings()
				sshClient = NewClient(context.Background(), sshSettings, c.settings, c.keys)
				err := sshClient.OnlyPreparePrivateKeys()
				if !c.wantErr {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}

				// double run
				err = sshClient.OnlyPreparePrivateKeys()
				if !c.wantErr {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}

			})
		}

	})
}

func TestClientStart(t *testing.T) {
	testName := "TestClientStart"

	sshtesting.CheckSkipSSHTest(t, testName)

	logger := log.NewSimpleLogger(log.LoggerOptions{})

	// genetaring ssh keys
	path, publicKey, err := sshtesting.GenerateKeys("")
	if err != nil {
		return
	}

	// starting openssh container with password auth
	container, err := sshtesting.NewSSHContainer(sshtesting.ContainerSettings{
		PublicKey:  publicKey,
		Password:   "VeryStrongPasswordWhatCannotBeGuessed",
		Username:   "user",
		LocalPort:  20022,
		SudoAccess: true,
	}, "client start")
	require.NoError(t, err)

	err = container.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		sshtesting.StopContainerAndRemoveKeys(t, container, logger, path)
	})

	// starting openssh container (bastion) with key auth and AllowTcpForwarding yes in config
	bastion, err := sshtesting.NewSSHContainer(sshtesting.ContainerSettings{
		PublicKey:  publicKey,
		Password:   "VeryStrongPasswordWhatCannotBeGuessed",
		Username:   "bastionuser",
		LocalPort:  20023,
		SudoAccess: true,
	}, "client start bastion")
	require.NoError(t, err)

	bastion.WithExternalNetwork(container.GetNetwork())

	err = bastion.WriteConfig()
	if err != nil {
		return
	}
	err = bastion.Start()
	if err != nil {
		return
	}

	authSock := sshtesting.AddSSHKeyToAgent(t, path)

	t.Cleanup(func() {
		sshtesting.StopContainerAndRemoveKeys(t, bastion, logger)
		sshtesting.RemoveSSHKeyFromAgent(t, path, logger)
	})

	t.Run("Start ssh client", func(t *testing.T) {
		cases := []struct {
			title      string
			settings   *session.Session
			keys       []session.AgentPrivateKey
			wantErr    bool
			err        string
			authSock   string
			loopParams ClientLoopsParams
		}{
			{
				title: "Password auth, no keys",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20022",
					BecomePass:     "VeryStrongPasswordWhatCannotBeGuessed"}),
				keys:    make([]session.AgentPrivateKey, 0, 1),
				wantErr: false,
			},
			{
				title: "Key auth, no password",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20022"}),
				keys:    []session.AgentPrivateKey{{Key: path}},
				wantErr: false,
			},
			{
				title: "SSH_AUTH_SOCK auth",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20022"}),
				keys:     []session.AgentPrivateKey{{Key: path}},
				wantErr:  false,
				authSock: authSock,
			},
			{
				title: "SSH_AUTH_SOCK auth, wrong socket",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20022"}),
				keys:     make([]session.AgentPrivateKey, 0, 1),
				wantErr:  true,
				err:      "Failed to open SSH_AUTH_SOCK",
				authSock: "/run/nonexistent",
			},
			{
				title: "Key auth, no password, wrong key",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20022"}),
				keys:    []session.AgentPrivateKey{{Key: "/tmp/noexistent-key"}},
				wantErr: true,
			},
			{
				title:    "No session",
				settings: nil,
				keys:     []session.AgentPrivateKey{{Key: "/tmp/noexistent-key"}},
				wantErr:  true,
				err:      "possible bug in ssh client: session should be created before start",
			},
			{
				title: "No auth",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20022"}),
				keys:     make([]session.AgentPrivateKey, 0, 1),
				wantErr:  true,
				err:      "one of SSH keys, SSH_AUTH_SOCK environment variable or become password should be not empty",
				authSock: "",
			},
			{
				title: "Wrong port",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
					User:           "user",
					Port:           "20021"}),
				keys:     []session.AgentPrivateKey{{Key: path}},
				wantErr:  true,
				err:      "Failed to connect to master host",
				authSock: "",
				loopParams: ClientLoopsParams{
					ConnectToHostDirectly: sshtesting.GetTestLoopParamsForFailed(),
				},
			},
			{
				title: "With bastion, key auth",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: container.GetContainerIP(), Name: container.GetContainerIP()}},
					User:           "user",
					Port:           container.RemotePortString(),
					BastionHost:    "localhost",
					BastionPort:    bastion.ContainerSettings().LocalPortString(),
					BastionUser:    bastion.ContainerSettings().Username,
				}),
				keys:     []session.AgentPrivateKey{{Key: path}},
				wantErr:  false,
				authSock: "",
			},
			{
				title: "With bastion, password auth",
				settings: session.NewSession(session.Input{
					AvailableHosts:  []session.Host{{Host: container.GetContainerIP(), Name: container.GetContainerIP()}},
					User:            "user",
					Port:            container.RemotePortString(),
					BecomePass:      "VeryStrongPasswordWhatCannotBeGuessed",
					BastionHost:     "localhost",
					BastionPort:     bastion.ContainerSettings().LocalPortString(),
					BastionUser:     bastion.ContainerSettings().Username,
					BastionPassword: "VeryStrongPasswordWhatCannotBeGuessed",
				}),
				keys:     make([]session.AgentPrivateKey, 0, 1),
				wantErr:  false,
				authSock: "",
			},
			{
				title: "With bastion, no auth",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: container.GetContainerIP(), Name: container.GetContainerIP()}},
					User:           "user",
					Port:           container.RemotePortString(),
					BecomePass:     "VeryStrongPasswordWhatCannotBeGuessed",
					BastionHost:    "localhost",
					BastionPort:    bastion.ContainerSettings().LocalPortString(),
					BastionUser:    bastion.ContainerSettings().Username,
				}),
				keys:     make([]session.AgentPrivateKey, 0, 1),
				wantErr:  true,
				err:      "No credentials present to connect to bastion host",
				authSock: "",
			},
			{
				title: "With bastion, SSH_AUTH_SOCK auth",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: container.GetContainerIP(), Name: container.GetContainerIP()}},
					User:           "user",
					Port:           container.RemotePortString(),
					BastionHost:    "localhost",
					BastionPort:    bastion.ContainerSettings().LocalPortString(),
					BastionUser:    bastion.ContainerSettings().Username,
				}),
				keys:     []session.AgentPrivateKey{{Key: path}},
				wantErr:  false,
				authSock: authSock,
			},
			{
				title: "With bastion, key auth, wrong target host",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: container.GetContainerIP(), Name: container.GetContainerIP()}},
					User:           "user",
					Port:           "20022",
					BastionHost:    "localhost",
					BastionPort:    bastion.ContainerSettings().LocalPortString(),
					BastionUser:    bastion.ContainerSettings().Username,
				}),
				keys:     []session.AgentPrivateKey{{Key: path}},
				wantErr:  true,
				err:      "Failed to connect to target host through bastion host",
				authSock: "",
				loopParams: ClientLoopsParams{
					ConnectToHostViaBastion: sshtesting.GetTestLoopParamsForFailed(),
				},
			},
			{
				title: "With bastion, key auth, wrong bastion port",
				settings: session.NewSession(session.Input{
					AvailableHosts: []session.Host{{Host: container.GetContainerIP(), Name: container.GetContainerIP()}},
					User:           "user",
					Port:           container.RemotePortString(),
					BastionHost:    "localhost",
					BastionPort:    "20021",
					BastionUser:    bastion.ContainerSettings().Username,
				}),
				keys:     []session.AgentPrivateKey{{Key: path}},
				wantErr:  true,
				err:      "Could not connect to bastion host",
				authSock: "",
				loopParams: ClientLoopsParams{
					ConnectToBastion: sshtesting.GetTestLoopParamsForFailed(),
				},
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				os.Setenv("SSH_AUTH_SOCK", c.authSock)
				var sshClient *Client

				sshSettings, _ := sshtesting.CreateDefaultTestSettings()

				sshClient = NewClient(context.Background(), sshSettings, c.settings, c.keys).
					WithLoopsParams(c.loopParams)

				err = sshClient.Start()
				if !c.wantErr {
					require.NoError(t, err)
					logger.InfoLn("client started successfully")
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}
				sshClient.Stop()
			})
		}

	})
}

func TestClientKeepalive(t *testing.T) {
	testName := "TestClientKeepalive"

	sshtesting.CheckSkipSSHTest(t, testName)

	logger := log.NewSimpleLogger(log.LoggerOptions{})

	// genetaring ssh keys
	path, publicKey, err := sshtesting.GenerateKeys("")
	if err != nil {
		return
	}

	// starting openssh container with password auth
	container, err := sshtesting.NewSSHContainer(sshtesting.ContainerSettings{
		PublicKey:  publicKey,
		Username:   "user",
		Password:   "VeryStrongPasswordWhatCannotBeGuessed",
		LocalPort:  20022,
		SudoAccess: true,
	}, testName)
	require.NoError(t, err)

	err = container.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		sshtesting.StopContainerAndRemoveKeys(t, container, logger, path)
	})

	os.Setenv("SSH_AUTH_SOCK", "")

	t.Run("keepalive test", func(t *testing.T) {
		settings := session.NewSession(session.Input{
			AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
			User:           "user",
			Port:           "20022"})
		keys := []session.AgentPrivateKey{{Key: path}}
		sshSettings, _ := sshtesting.CreateDefaultTestSettings()
		sshClient := NewClient(context.Background(), sshSettings, settings, keys)
		err := sshClient.Start()
		// expecting no error on client start
		require.NoError(t, err)
		// test case: stopping container for a while, waiting for client recreation, creating new session, expecting no error
		time.Sleep(2 * time.Second)
		container.Stop()
		time.Sleep(5 * time.Second)
		container.Start()
		time.Sleep(30 * time.Second)
		sess, err := sshClient.GetClient().NewSession()
		require.NoError(t, err)
		sshClient.RegisterSession(sess)
		sshClient.Stop()
	})

	t.Run("keepalive with context test", func(t *testing.T) {
		settings := session.NewSession(session.Input{
			AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
			User:           "user",
			Port:           "20022"})
		keys := []session.AgentPrivateKey{{Key: path}}
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
		defer cancel()
		sshSettings, _ := sshtesting.CreateDefaultTestSettings()
		sshClient := NewClient(ctx, sshSettings, settings, keys)
		err := sshClient.Start()
		// expecting no error on client start
		require.NoError(t, err)
		time.Sleep(30 * time.Second)
		// expecting client is not live
		sshClient.Stop()
		err = sshClient.Start()
		require.Error(t, err)
		require.Contains(t, err.Error(), "deadline exceeded")
	})

	t.Run("client start with context test", func(t *testing.T) {
		settings := session.NewSession(session.Input{
			AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
			User:           "user",
			Port:           "20062"})
		keys := []session.AgentPrivateKey{{Key: path}}
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(20*time.Second))
		defer cancel()
		sshSettings, _ := sshtesting.CreateDefaultTestSettings()
		sshClient := NewClient(ctx, sshSettings, settings, keys)
		err := sshClient.Start()
		// expecting error on client start: host is unreachable, but loop should exit on context deadline exceeded
		require.Error(t, err)
		require.Contains(t, err.Error(), "Loop was canceled: context deadline exceeded")
		// expecting client is not live
		sshClient.Stop()
		err = sshClient.Start()
		require.Error(t, err)
		require.Contains(t, err.Error(), "deadline exceeded")
	})
}

func TestClientWithDebug(t *testing.T) {
	testName := "TestClientWithDebug"

	sshtesting.CheckSkipSSHTest(t, testName)

	logger := log.NewSimpleLogger(log.LoggerOptions{})

	// genetaring ssh keys
	path, publicKey, err := sshtesting.GenerateKeys("")
	if err != nil {
		return
	}

	// starting openssh container with password auth
	container, err := sshtesting.NewSSHContainer(sshtesting.ContainerSettings{
		PublicKey:  publicKey,
		Username:   "user",
		Password:   "VeryStrongPasswordWhatCannotBeGuessed",
		LocalPort:  20042,
		SudoAccess: true,
	}, testName)
	require.NoError(t, err)

	err = container.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		sshtesting.StopContainerAndRemoveKeys(t, container, logger, path)
	})

	os.Setenv("SSH_AUTH_SOCK", "")

	t.Run("start with debug test", func(t *testing.T) {
		settings := session.NewSession(session.Input{
			AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
			User:           "user",
			Port:           "20042"})
		keys := []session.AgentPrivateKey{{Key: path}}
		sshSettings, _ := sshtesting.CreateDefaultTestSettings()
		sshClient := NewClient(context.Background(), sshSettings, settings, keys)
		err := sshClient.Start()
		require.NoError(t, err)
		cmd := sshClient.Command("echo", "test")
		err = cmd.Run(context.Background())
		require.NoError(t, err)
	})
}

func TestDialContext(t *testing.T) {
	sshtesting.CheckSkipSSHTest(t, "TestDialContext")

	t.Run("client start with small context test", func(t *testing.T) {
		settings := session.NewSession(session.Input{
			AvailableHosts: []session.Host{{Host: "1.2.3.4", Name: "1.2.3.4"}},
			User:           "user",
			Port:           "22",
			BecomePass:     "VeryStrongPasswordWhatCannotBeGuessed",
		})
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(200*time.Millisecond))
		defer cancel()
		sshSettings, _ := sshtesting.CreateDefaultTestSettings()
		sshClient := NewClient(ctx, sshSettings, settings, make([]session.AgentPrivateKey, 0, 1))
		err := sshClient.Start()
		// expecting error on client start: host is unreachable, but loop should exit on context deadline exceeded
		require.Error(t, err)
		require.Contains(t, err.Error(), "Loop was canceled: context deadline exceeded")
		// expecting client is not live
		sshClient.Stop()
		err = sshClient.Start()
		require.Error(t, err)
		require.Contains(t, err.Error(), "deadline exceeded")
	})
}

func TestClientLoop(t *testing.T) {
	sshtesting.CheckSkipSSHTest(t, "TestClientLoop")

	t.Run("SSH client Loop test", func(t *testing.T) {
		settings := session.NewSession(session.Input{
			AvailableHosts: []session.Host{{Host: "127.0.0.1", Name: "localhost"}, {Host: "127.0.0.2"}},
			User:           "user",
			Port:           "20022",
			BecomePass:     "VeryStrongPasswordWhatCannotBeGuessed"})
		keys := make([]session.AgentPrivateKey, 0, 1)
		sshSettings, _ := sshtesting.CreateDefaultTestSettings()
		sshClient := NewClient(context.Background(), sshSettings, settings, keys)

		err := sshClient.Loop(func(s connection.SSHClient) error {
			keys := s.PrivateKeys()
			if len(keys) == 0 {
				return fmt.Errorf("keys are empty")
			}
			return nil
		})
		require.Error(t, err)
		err = sshClient.Loop(func(s connection.SSHClient) error {
			keys := s.PrivateKeys()
			if len(keys) == 0 {
				return nil
			}
			return fmt.Errorf("keys are not empty")
		})
		require.NoError(t, err)
	})
}

func TestClientSettings(t *testing.T) {
	sshtesting.CheckSkipSSHTest(t, "TestClientSettings")

	t.Run("SSH client settings test", func(t *testing.T) {
		settings := session.NewSession(session.Input{
			AvailableHosts: []session.Host{{Host: "127.0.0.1", Name: "localhost"}, {Host: "127.0.0.2"}},
			User:           "user",
			Port:           "20022",
			BecomePass:     "VeryStrongPasswordWhatCannotBeGuessed"})
		keys := make([]session.AgentPrivateKey, 0, 1)
		sshSettings, _ := sshtesting.CreateDefaultTestSettings()
		sshClient := NewClient(context.Background(), sshSettings, settings, keys)
		s := sshClient.Session()
		require.Equal(t, settings, s)
	})
}

func TestClientLive(t *testing.T) {
	sshtesting.CheckSkipSSHTest(t, "TestClientLive")

	t.Run("SSH client live test", func(t *testing.T) {
		settings := session.NewSession(session.Input{
			AvailableHosts: []session.Host{{Host: "127.0.0.1", Name: "localhost"}, {Host: "127.0.0.2"}},
			User:           "user",
			Port:           "20022",
			BecomePass:     "VeryStrongPasswordWhatCannotBeGuessed"})
		keys := make([]session.AgentPrivateKey, 0, 1)
		sshSettings, _ := sshtesting.CreateDefaultTestSettings()
		sshClient := NewClient(context.Background(), sshSettings, settings, keys)
		live := sshClient.Live()
		require.Equal(t, false, live)
	})
}
