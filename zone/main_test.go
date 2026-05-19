package zone_test

import (
	"testing"

	"github.com/shigeya/dnsdata-go/zone"
)

// TestMain installs the bundled zone RR handlers (TLSA, SMIMEA, SSHFP,
// …) once per test binary. RegisterHandlers is idempotent (each call
// overwrites the previous registration atomically), so subsequent
// invocations from individual tests are safe.
func TestMain(m *testing.M) {
	zone.RegisterHandlers()
	m.Run()
}
