package act

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFakeVtysh writes an executable shell script and returns its path. It stands in
// for the vtysh binary so the ExecRunner's transport — the temp batch file, the
// framing, and the rejection scan — is exercised without FRR.
func writeFakeVtysh(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-vtysh")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture, executable by design
		t.Fatalf("write fake vtysh: %v", err)
	}
	return path
}
