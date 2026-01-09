package ssh_testing

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/name212/govalue"
	"github.com/stretchr/testify/require"
)

type TestOpt func(*Test)

func WithLogger(logger *log.InMemoryLogger) TestOpt {
	return func(t *Test) {
		t.Logger = logger
	}
}

type Test struct {
	LocalTmpDir string
	ID          string
	TestName    string
	Logger      *log.InMemoryLogger

	noLogger bool
}

func ShouldNewTest(t *testing.T, testName string, opts ...TestOpt) *Test {
	CheckSkipSSHTest(t, testName)
	tst, err := NewTest(testName, opts...)
	require.NoError(t, err, "failed to create Test '%s'", testName)
	tst.RegisterCleanup(t)
	return tst
}

func NewTest(testName string, opts ...TestOpt) (*Test, error) {
	if testName == "" {
		return nil, fmt.Errorf("testName is empty")
	}

	id := GenerateID(testName)

	resTest := &Test{
		TestName: testName,
		ID:       id,
	}

	for _, opt := range opts {
		opt(resTest)
	}

	if govalue.Nil(resTest.Logger) {
		resTest.Logger = TestLogger()
	}

	localTmpDirStr := filepath.Join(os.TempDir(), tmpGlobalDirName, id)

	err := os.MkdirAll(localTmpDirStr, 0777)
	if err != nil {
		return nil, resTest.WrapError("failed to create local tmp dir %s: %v", localTmpDirStr, err)
	}

	resTest.LocalTmpDir = localTmpDirStr

	return resTest, nil
}

func (s *Test) IsZero() bool {
	return s.LocalTmpDir == "" || s.ID == "" || s.TestName == ""
}

func (s *Test) WrapError(format string, args ...any) error {
	f := s.TestName + ": " + format
	return fmt.Errorf(f, args...)
}

func (s *Test) RegisterCleanup(t *testing.T) {
	t.Cleanup(func() {
		s.Cleanup(t)
	})
}

func (s *Test) Cleanup(t *testing.T) {
	if s.LocalTmpDir == "" {
		return
	}

	err := os.RemoveAll(s.LocalTmpDir)
	if err != nil && !os.IsNotExist(err) {
		LogErrorOrAssert(t, fmt.Sprintf("Remove local tmp dir: %s", s.LocalTmpDir), err, s.Logger)
		return
	}

	if !govalue.Nil(s.Logger) {
		s.Logger.InfoF("Temp dir removed for test %s: %s", s.TestName, s.LocalTmpDir)
	}
}
