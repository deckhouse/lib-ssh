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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	gossh "github.com/deckhouse/lib-gossh"
	"github.com/name212/govalue"
	"github.com/stretchr/testify/require"
)

// helper func to generate SSH keys
func GenerateKeys(passphrase string) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	var privateKeyPem *pem.Block
	if len(passphrase) == 0 {
		privateKeyPem, err = gossh.MarshalPrivateKey(privateKey, "")
		if err != nil {
			return "", "", err
		}
	} else {
		privateKeyPem, err = gossh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte(passphrase))
		if err != nil {
			return "", "", err
		}
	}

	publicKey, err := gossh.NewPublicKey(privateKey.Public())
	if err != nil {
		return "", "", err
	}
	file, err := os.CreateTemp(os.TempDir(), "key")
	if err != nil {
		return "", "", err
	}
	pemBytes := pem.EncodeToMemory(privateKeyPem)
	_, err = io.Copy(file, bytes.NewReader(pemBytes))
	if err != nil {
		return "", "", err
	}

	return file.Name(), string(gossh.MarshalAuthorizedKey(publicKey)), nil
}

func PrepareFakeBashibleBundle(parentDir, entrypoint, bundleDir string) (err error) {
	err = nil
	bundle := filepath.Join(parentDir, bundleDir)
	err = os.MkdirAll(bundle, 0755)
	if err != nil {
		return
	}

	testFile, err := os.Create(filepath.Join(bundle, entrypoint))
	if err != nil {
		return
	}
	script := `#!/bin/bash

echo "starting execute steps..."

BUNDLE_STEPS_DIR=/var/lib/bashible/bundle_steps
BOOTSTRAP_DIR=/var/lib/bashible
MAX_RETRIES=30

for arg in "$@"; do
  if [[ "$arg" == "--add-failure" ]]
    then
      echo "failures included"
      export INCLUDE_FAILURE=true
  fi
done

# Execute bashible steps
for step in $BUNDLE_STEPS_DIR/*; do
  echo ===
  echo === Step: $step
  echo ===
  attempt=0
  sx=""
  until /bin/bash --noprofile --norc -"$sx"eEo pipefail -c "export TERM=xterm-256color; unset CDPATH; cd $BOOTSTRAP_DIR; source $step" 2> >(tee /var/lib/bashible/step.log >&2)
  do
    attempt=$(( attempt + 1 ))
    if [ -n "${MAX_RETRIES-}" ] && [ "$attempt" -gt "${MAX_RETRIES}" ]; then
      >&2 echo "ERROR: Failed to execute step $step. Retry limit is over."
      exit 1
    fi
    >&2 echo "Failed to execute step "$step" ... retry in 10 seconds."
    sleep 10
    echo ===
    echo === Step: $step
    echo ===
    if [ "$attempt" -gt 2 ]; then
      sx=x
    fi
  done
done

`
	_, err = testFile.WriteString(script)
	if err != nil {
		return
	}
	err = testFile.Chmod(0o755)
	if err != nil {
		return
	}

	stepsDir := filepath.Join(bundle, "bundle_steps")
	err = os.MkdirAll(stepsDir, 0755)
	if err != nil {
		return
	}

	firstStep, err := os.Create(filepath.Join(stepsDir, "01-step.sh"))
	if err != nil {
		return
	}

	script = `#!/bin/bash

echo "just a step"

for i in {0..9}
do
  sleep $(( $RANDOM % 3 ))
  echo $i  
done
`
	_, err = firstStep.WriteString(script)
	if err != nil {
		return
	}
	err = firstStep.Chmod(0o755)
	if err != nil {
		return
	}
	secondStep, err := os.Create(filepath.Join(stepsDir, "02-step.sh"))
	if err != nil {
		return
	}

	script = `#!/bin/bash

echo "second step"

for i in {0..9}
do
  sleep $(( $RANDOM % 3 ))
  echo $i
  if [[ $i -gt 5 && $INCLUDE_FAILURE == "true" ]]
    then
      echo "oops! failure!"
      exit 1
  fi
done
`
	_, err = secondStep.WriteString(script)
	if err != nil {
		return
	}
	err = secondStep.Chmod(0o755)
	if err != nil {
		return
	}

	return
}

func simpleHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "This is a simple web server response")
}

func StartWebServer(port string) error {
	http.HandleFunc("/", simpleHandler)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		return err
	}
	return nil
}

func randRange(min, max int) int {
	rnd := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	return rnd.Intn(max-min) + min
}

func testID(name string) string {
	rndID := mathrand.New(mathrand.NewSource(time.Now().UnixNano())).Int()
	sumString := fmt.Sprintf("%s/%d", name, rndID)
	sum := sha256Encode(sumString)
	return fmt.Sprintf("%.12s", sum)
}

func sha256Encode(input string) string {
	hasher := sha256.New()

	hasher.Write([]byte(input))

	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func AddSSHKeyToAgent(t *testing.T, path string) string {
	authSock := os.Getenv("SSH_AUTH_SOCK")
	if authSock == "" {
		return ""
	}

	// add key to agent
	cmd := exec.Command("ssh-add", path)
	err := cmd.Run()
	require.NoError(t, err, "failed to add key '%s' to agent", path)

	return authSock
}

func LogErrorOrAssert(t *testing.T, description string, err error, logger log.Logger) {
	if err == nil {
		return
	}

	if govalue.Nil(logger) {
		require.NoError(t, err, description)
		return
	}

	logger.ErrorF("%s: %v", description, err)
}

func RemoveSSHKeyFromAgent(t *testing.T, path string, logger log.Logger) {
	authSock := os.Getenv("SSH_AUTH_SOCK")
	if authSock == "" {
		return
	}

	cmd := exec.Command("ssh-add", "-d", path)
	err := cmd.Run()

	LogErrorOrAssert(t, fmt.Sprintf("failed to remove key '%s' from agent", path), err, logger)
}

func StopContainerAndRemoveKeys(t *testing.T, container *SSHContainer, logger log.Logger, keyPaths ...string) {
	containerStopError := container.Stop()
	removeSSHDConfigError := container.RemoveSSHDConfig()
	removeErrors := removeFiles(keyPaths...)

	LogErrorOrAssert(t, "failed to stop container", containerStopError, logger)
	LogErrorOrAssert(t, "remove sshd config", removeSSHDConfigError, logger)
	for _, removeError := range removeErrors {
		LogErrorOrAssert(t, "failed to remove private key", removeError, logger)
	}
}

func RemoveFiles(t *testing.T, logger log.Logger, paths ...string) {
	removeErrors := removeFiles(paths...)

	for _, removeError := range removeErrors {
		LogErrorOrAssert(t, "failed to remove private key", removeError, logger)
	}
}

func CheckSkipSSHTest(t *testing.T, testName string) {
	if os.Getenv("SKIP_GOSSH_TEST") == "true" {
		t.Skipf("Skipping %s test", testName)
	}
}

func GetTestLoopParamsForFailed() retry.Params {
	return retry.NewEmptyParams(
		retry.WithWait(2*time.Second),
		retry.WithAttempts(4),
	)
}

func removeFiles(paths ...string) []error {
	removeErrors := make([]error, 0, len(paths))
	for _, path := range paths {
		err := os.Remove(path)
		if err != nil && !os.IsNotExist(err) {
			removeErrors = append(removeErrors, err)
		}
	}

	return removeErrors
}
