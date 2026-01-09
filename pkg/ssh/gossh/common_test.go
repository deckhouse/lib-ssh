package gossh

import "testing"

func registerStopClient(t *testing.T, sshClient *Client) {
	t.Cleanup(func() {
		sshClient.Stop()
	})
}
