package workspace

import (
	"os"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// The fixes are tested in legacy mode with each one forced on (fixes_test.go); the differential
// tests for this package run through the CLI corpus (internal/cli).
func TestMain(m *testing.M) {
	deviation.SetLegacy(true)
	os.Exit(m.Run())
}
