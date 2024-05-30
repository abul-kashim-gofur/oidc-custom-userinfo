package test

import (
	"io"
	"sync"
	"testing"
)

// testIO turns a testing.TB instance into a io.Writer
type testIO struct {
	sync.Mutex
	tb testing.TB
}

func (tio *testIO) Write(p []byte) (n int, err error) {
	tio.Lock()
	defer tio.Unlock()
	tio.tb.Log(string(p))
	return len(p), nil
}

// TBWriter converts a testing.TB into and io.Writer, allowing
// output to be written the test output.
func TBWriter(tb testing.TB) io.Writer { return &testIO{tb: tb} }
