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
	"path/filepath"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"

	sshtesting "github.com/deckhouse/lib-connection/pkg/ssh/gossh/testing"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

func TestReverseTunnel(t *testing.T) {
	testName := "TestReverseTunnel"

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
		LocalPort:  20031,
		SudoAccess: true,
	}, testName)
	require.NoError(t, err)

	err = container.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		sshtesting.StopContainerAndRemoveKeys(t, container, logger, path)
	})

	err = container.WriteConfig()
	require.NoError(t, err)

	os.Setenv("SSH_AUTH_SOCK", "")

	settings := session.NewSession(session.Input{
		AvailableHosts: []session.Host{{Host: "localhost", Name: "localhost"}},
		User:           "user",
		Port:           "20031"})
	keys := []session.AgentPrivateKey{{Key: path}}
	sshSettings, _ := sshtesting.CreateDefaultTestSettings()
	sshClient := NewClient(context.Background(), sshSettings, settings, keys)
	err = sshClient.Start()
	// expecting no error on client start
	require.NoError(t, err)

	go func() {
		err = sshtesting.StartWebServer(":8088")
		require.NoError(t, err)
	}()

	t.Cleanup(func() {
		sshClient.Stop()
	})

	// we don't have /opt/deckhouse in the container, so we should create it before start any UploadScript with sudo
	err = container.CreateDeckhouseDirs()
	require.NoError(t, err)

	t.Run("Reverse tunnel from container to host", func(t *testing.T) {
		cases := []struct {
			title       string
			address     string
			wantErr     bool
			err         string
			errFromChan string
		}{
			{
				title:   "Tunnel, success",
				address: "127.0.0.1:8080:127.0.0.1:8088",
				wantErr: false,
			},
			{
				title:   "Invalid address",
				address: fmt.Sprintf("22050:127.0.0.1:%s", container.RemotePortString()),
				wantErr: true,
				err:     "invalid address must be 'remote_bind:remote_port:local_bind:local_port'",
			},
			{
				title:   "Invalid local bind",
				address: fmt.Sprintf("127.0.0.1:%s:127.0.0.1:22", container.RemotePortString()),
				wantErr: true,
				err:     fmt.Sprintf("failed to listen remote on 127.0.0.1:%s", container.RemotePortString()),
			},
			{
				title:       "Wrong local bind",
				address:     "127.0.0.1:8080:127.0.0.1:8087",
				wantErr:     false,
				errFromChan: "Cannot dial to 127.0.0.1:8087",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				tun := NewReverseTunnel(sshClient, c.address)
				err = tun.Up()
				if !c.wantErr {
					require.NoError(t, err)
					// try to up again: expectiong error
					err = tun.Up()
					require.Error(t, err)
					require.Equal(t, err.Error(), "already up")
					// try to get a response from local web server
					cmd := NewSSHCommand(sshClient, "curl", "-s", "http://127.0.0.1:8080")
					cmd.WithTimeout(2 * time.Second)
					out, err := cmd.CombinedOutput(context.Background())
					require.NoError(t, err)
					if len(c.errFromChan) == 0 {
						require.Equal(t, "This is a simple web server response", string(out))
					} else {
						errMsg := <-tun.errorCh
						require.Contains(t, errMsg.err.Error(), c.errFromChan)
					}
					tun.Stop()
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}
				// call stop on closed tun should not cause any problems
				tun.Stop()
			})
		}
	})

	t.Run("String func test", func(t *testing.T) {
		cases := []struct {
			title    string
			address  string
			expected string
		}{
			{
				title:    "Normal address",
				address:  fmt.Sprintf("127.0.0.1:%s:127.0.0.1:22050", container.RemotePortString()),
				expected: fmt.Sprintf("R:127.0.0.1:%s:127.0.0.1:22050", container.RemotePortString()),
			},
			{
				title:    "Invalid address",
				address:  fmt.Sprintf("22050:127.0.0.1:%s", container.RemotePortString()),
				expected: fmt.Sprintf("R:22050:127.0.0.1:%s", container.RemotePortString()),
			},
			{
				title:    "Remote FQDN",
				address:  "www.example.com:8080:127.0.0.1:8080",
				expected: "R:www.example.com:8080:127.0.0.1:8080",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				tun := NewReverseTunnel(sshClient, c.address)
				require.Equal(t, c.expected, tun.String())

			})
		}
	})

	t.Run("HealthMonitor test", func(t *testing.T) {
		tun := NewReverseTunnel(sshClient, "127.0.0.1:8080:127.0.0.1:8088")
		err := tun.Up()
		require.NoError(t, err)
		// creating direactory to upload
		testDir := filepath.Join(os.TempDir(), "dhctltests", "script")
		err = os.MkdirAll(testDir, 0755)
		require.NoError(t, err)

		testFile, err := os.Create(filepath.Join(testDir, "test.sh"))
		require.NoError(t, err)
		script := `#!/bin/bash
URL="http://127.0.0.1:8080"

curl -s $URL > /dev/null
exit $?
`
		testFile.WriteString(script)
		testFile.Chmod(0o755)
		checker := utils.NewRunScriptReverseTunnelChecker(sshClient, testFile.Name())
		killer := utils.EmptyReverseTunnelKiller{}

		err = retry.NewSilentLoop("check tunnel", 30, 2*time.Second).Run(func() error {
			out, err := checker.CheckTunnel(context.Background())
			if err != nil {
				logger.InfoF("failed to check tunnel: %s %v", out, err)
				return err
			}
			return nil
		})
		require.NoError(t, err)

		tun.StartHealthMonitor(context.Background(), checker, killer)
		time.Sleep(5 * time.Second)
		err = container.Stop()
		require.NoError(t, err)
		time.Sleep(5 * time.Second)
		err = container.Start()
		require.NoError(t, err)
		err = container.CreateDeckhouseDirs()
		require.NoError(t, err)

		time.Sleep(30 * time.Second)
		err = retry.NewSilentLoop("check tunnel", 10, 5*time.Second).Run(func() error {
			out, err := checker.CheckTunnel(context.Background())
			if err != nil {
				logger.InfoF("failed to check tunnel: %s %v", out, err)
				return err
			}
			return nil
		})
		require.NoError(t, err)

		// disconnect/connect case
		err = container.Disconnect()
		require.NoError(t, err)
		time.Sleep(5 * time.Second)
		err = container.Connect()
		require.NoError(t, err)
		time.Sleep(30 * time.Second)
		err = retry.NewSilentLoop("check tunnel", 10, 5*time.Second).Run(func() error {
			out, err := checker.CheckTunnel(context.Background())
			if err != nil {
				logger.InfoF("failed to check tunnel: %s %v", out, err)
				return err
			}
			return nil
		})
		require.NoError(t, err)
		tun.Stop()
	})
}
